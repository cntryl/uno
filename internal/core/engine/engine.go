// Package engine resolves and synchronizes direct secret mappings.
package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
	tpl "github.com/cntryl/uno/internal/core/template"
)

// maxConcurrentOperations bounds how many provider round-trips run at once
// within a single Resolve/write/diff fan-out, so a template with hundreds of
// distinct containers or mappings can't thunder a provider's API with
// hundreds of simultaneous requests.
const maxConcurrentOperations = 16

// runLimited runs task(0)..task(n-1) concurrently, at most
// maxConcurrentOperations at a time, and waits for all of them to finish.
func runLimited(n int, task func(i int)) {
	limiter := make(chan struct{}, maxConcurrentOperations)
	var workers sync.WaitGroup
	for i := range n {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			limiter <- struct{}{}
			defer func() { <-limiter }()
			task(i)
		}(i)
	}
	workers.Wait()
}

type Mapping struct {
	Environment         string
	Source, Destination provider.Reference
}
type Plan struct {
	Mappings []Mapping
	Registry *provider.Registry
}
type Receipt struct{ Completed []string }
type Error struct {
	Message   string
	Completed []string
}

func (e *Error) Error() string { return e.Message }

func Bind(file *tpl.File, registry *provider.Registry) (*Plan, error) {
	p := &Plan{Registry: registry}
	destinations := make([]provider.Reference, 0, len(file.Entries))
	for _, entry := range file.Entries {
		source, err := registry.Parse(entry.Source)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid source reference: %s", entry.Line, provider.BindingDetail(err))
		}
		destination, err := registry.Parse(entry.Destination)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid destination reference: %s", entry.Line, provider.BindingDetail(err))
		}
		p.Mappings = append(p.Mappings, Mapping{entry.Key, source, destination})
		destinations = append(destinations, destination)
	}
	if err := provider.ValidateDestinations(destinations); err != nil {
		var conflict *provider.DestinationConflictError
		if errors.As(err, &conflict) {
			current, previous := file.Entries[conflict.Index], file.Entries[conflict.Previous]
			if conflict.Mixed {
				return nil, fmt.Errorf("line %d: destination mixes blob and keyed writes with line %d (%s)", current.Line, previous.Line, previous.Key)
			}
			return nil, fmt.Errorf("line %d: destination duplicates line %d (%s)", current.Line, previous.Line, previous.Key)
		}
		return nil, fmt.Errorf("invalid destination bindings")
	}
	return p, nil
}

// Resolve reads every source before returning any values. It never writes.
func Resolve(ctx context.Context, p *Plan) (map[string]secret.Value, error) {
	values := make(map[string]secret.Value, len(p.Mappings))
	defer func() {
		if values != nil {
			secret.DestroyMap(values)
		}
	}()
	adapters := newAdapterCache(p.Registry)
	groups := groupSources(p.Mappings)
	type result struct {
		values map[string]secret.Value
		err    error
	}
	results := make([]result, len(groups))
	runLimited(len(groups), func(i int) {
		results[i].values, results[i].err = resolveGroup(ctx, adapters, groups[i])
	})
	for i := range results {
		if results[i].err != nil {
			for j := range results {
				secret.DestroyMap(results[j].values)
			}
			return nil, results[i].err
		}
		for key, value := range results[i].values {
			values[key] = value
		}
		results[i].values = nil
	}
	resultValues := values
	values = nil
	return resultValues, nil
}

func resolveGroup(ctx context.Context, adapters *adapterCache, group sourceGroup) (map[string]secret.Value, error) {
	values := make(map[string]secret.Value, len(group.mappings))
	defer func() {
		if values != nil {
			secret.DestroyMap(values)
		}
	}()
	adapter, err := adapters.get(ctx, group.reference)
	if err != nil {
		return nil, safeOperationError("read", err)
	}
	refs := make([]provider.Reference, 0, len(group.mappings))
	seen := make(map[string]bool)
	for _, mapping := range group.mappings {
		if binding := mapping.Source.Binding(); !seen[binding] {
			seen[binding] = true
			refs = append(refs, mapping.Source)
		}
	}
	got, err := adapter.ReadMany(ctx, refs)
	if err != nil {
		secret.DestroyMap(got)
		return nil, safeOperationError("read", err)
	}
	valid := len(got) == len(refs)
	for _, ref := range refs {
		if _, ok := got[ref.Binding()]; !ok {
			valid = false
		}
	}
	for key := range got {
		if !seen[key] {
			valid = false
		}
	}
	if !valid {
		secret.DestroyMap(got)
		return nil, safeOperationError("read", &provider.Error{Kind: provider.InvalidState})
	}
	for _, mapping := range group.mappings {
		values[mapping.Environment] = got[mapping.Source.Binding()].Clone()
	}
	secret.DestroyMap(got)
	resultValues := values
	values = nil
	return resultValues, nil
}

func Sync(ctx context.Context, p *Plan) (Receipt, error) {
	values, err := Resolve(ctx, p)
	if err != nil {
		return Receipt{}, err
	}
	defer secret.DestroyMap(values)
	return writeDestinations(ctx, p, values)
}

func writeDestinations(ctx context.Context, p *Plan, values map[string]secret.Value) (Receipt, error) {
	groups := groupDestinations(p.Mappings, values)
	type writeResult struct {
		receipt provider.Receipt
		err     error
	}
	results := make([]writeResult, len(groups))
	adapters := newAdapterCache(p.Registry)
	runLimited(len(groups), func(i int) {
		group := groups[i]
		adapter, err := adapters.get(ctx, group.reference)
		if err != nil {
			results[i].err = err
			return
		}
		results[i].receipt, results[i].err = adapter.WriteMany(ctx, group.writes)
	})
	completed := []string{}
	var firstErr error
	for _, result := range results {
		completed = append(completed, result.receipt.Completed...)
		if firstErr == nil && result.err != nil {
			firstErr = result.err
		}
	}
	sort.Strings(completed)
	if firstErr != nil {
		return Receipt{}, &Error{Message: safeKind("write", firstErr), Completed: completed}
	}
	return Receipt{Completed: completed}, nil
}

// ChangeKind classifies how a mapping's destination compares to its
// resolved source value.
type ChangeKind string

const (
	// Unchanged means the destination already holds the resolved value.
	Unchanged ChangeKind = "unchanged"
	// Create means the destination binding could not be read back — it (or
	// its container) doesn't exist yet.
	Create ChangeKind = "create"
	// Update means the destination exists but holds a different value.
	Update ChangeKind = "update"
)

// Change describes what would happen to a single mapping's destination.
type Change struct {
	Environment string     `json:"environment"`
	Kind        ChangeKind `json:"kind"`
}

// Diff resolves every source, then compares each destination's current
// value (if readable) against the resolved value, without writing anything.
func Diff(ctx context.Context, p *Plan) ([]Change, error) {
	values, err := Resolve(ctx, p)
	if err != nil {
		return nil, err
	}
	defer secret.DestroyMap(values)
	return diffValues(ctx, p, values), nil
}

func diffValues(ctx context.Context, p *Plan, values map[string]secret.Value) []Change {
	adapters := newAdapterCache(p.Registry)
	changes := make([]Change, len(p.Mappings))
	runLimited(len(p.Mappings), func(i int) {
		mapping := p.Mappings[i]
		changes[i] = Change{Environment: mapping.Environment, Kind: diffOne(ctx, adapters, mapping, values[mapping.Environment])}
	})
	sort.Slice(changes, func(i, j int) bool { return changes[i].Environment < changes[j].Environment })
	return changes
}

// diffOne reads the destination's current value and compares it against
// desired. A destination that can't be read back because the binding (or
// its container) doesn't exist yet is Create; a destination whose adapter
// can't even be built, or whose read fails for an unrecognized reason, is
// conservatively treated as Update — the safer default is "assume a pending
// change" rather than silently classifying an unknown state as Unchanged.
func diffOne(ctx context.Context, adapters *adapterCache, mapping Mapping, desired secret.Value) ChangeKind {
	adapter, err := adapters.get(ctx, mapping.Destination)
	if err != nil {
		return Update
	}
	current, err := adapter.ReadMany(ctx, []provider.Reference{mapping.Destination})
	if err != nil {
		secret.DestroyMap(current)
		var typed *provider.Error
		if errors.As(err, &typed) && typed.Kind == provider.InvalidBinding {
			return Create
		}
		return Update
	}
	existing, ok := current[mapping.Destination.Binding()]
	same := ok && existing.Reveal() == desired.Reveal()
	secret.DestroyMap(current)
	if same {
		return Unchanged
	}
	return Update
}

// SyncChanged resolves every source, diffs against current destination
// values, and writes only the mappings that would actually create or update
// a value — mappings whose destination already matches are skipped, so a
// sync with nothing pending never calls a provider's write API and never
// bumps a secret's version history for no reason.
//
// confirm, if non-nil, is invoked with the pending (non-Unchanged) changes
// before any write happens; returning false, or a non-nil error, aborts
// without writing. confirm is never called when nothing is pending.
func SyncChanged(ctx context.Context, p *Plan, confirm func([]Change) (bool, error)) ([]Change, Receipt, error) {
	values, err := Resolve(ctx, p)
	if err != nil {
		return nil, Receipt{}, err
	}
	defer secret.DestroyMap(values)
	changes := diffValues(ctx, p, values)
	pending := make([]Change, 0, len(changes))
	pendingEnvironments := map[string]bool{}
	for _, c := range changes {
		if c.Kind != Unchanged {
			pending = append(pending, c)
			pendingEnvironments[c.Environment] = true
		}
	}
	if len(pending) == 0 {
		return changes, Receipt{}, nil
	}
	if confirm != nil {
		ok, err := confirm(pending)
		if err != nil {
			return changes, Receipt{}, err
		}
		if !ok {
			return changes, Receipt{}, &Error{Message: "sync aborted: not confirmed"}
		}
	}
	filtered := &Plan{Registry: p.Registry}
	for _, m := range p.Mappings {
		if pendingEnvironments[m.Environment] {
			filtered.Mappings = append(filtered.Mappings, m)
		}
	}
	receipt, err := writeDestinations(ctx, filtered, values)
	return changes, receipt, err
}

// RollbackStatus classifies the outcome of reverting one mapping's
// destination.
type RollbackStatus string

const (
	// Reverted means the destination's container was successfully rolled
	// back to its previous value.
	Reverted RollbackStatus = "reverted"
	// Unsupported means the destination's provider adapter doesn't
	// implement provider.Rollbacker — nothing was attempted.
	Unsupported RollbackStatus = "unsupported"
	// Failed means a rollback was attempted and the provider rejected it
	// (e.g. there is no distinct previous value to revert to).
	Failed RollbackStatus = "failed"
)

// RollbackResult reports what happened when rolling back one mapping's
// destination.
type RollbackResult struct {
	Environment string         `json:"environment"`
	Status      RollbackStatus `json:"status"`
	Detail      string         `json:"detail,omitempty"`
}

// Rollback reverts every mapping's destination container to its previous
// value, one call per distinct container (mirroring how writes are grouped).
// It never reads or writes a source, and never contacts a provider that
// doesn't implement provider.Rollbacker for the mapping's destination
// scheme — those mappings are reported Unsupported rather than attempted.
// Rollback returns its per-mapping results even when some containers fail;
// it only returns a non-nil error for a failure that prevents reporting at
// all (there is none today, but the signature stays symmetric with Sync).
func Rollback(ctx context.Context, p *Plan) ([]RollbackResult, error) {
	adapters := newAdapterCache(p.Registry)
	groups := groupDestinationContainers(p.Mappings)
	results := make([][]RollbackResult, len(groups))
	runLimited(len(groups), func(i int) {
		group := groups[i]
		environments := make([]string, len(group.mappings))
		for j, m := range group.mappings {
			environments[j] = m.Environment
		}
		adapter, err := adapters.get(ctx, group.reference)
		if err != nil {
			results[i] = rollbackStatusForAll(environments, Failed, safeKind("rollback", err))
			return
		}
		roller, ok := adapter.(provider.Rollbacker)
		if !ok {
			results[i] = rollbackStatusForAll(environments, Unsupported, "")
			return
		}
		if err := roller.Rollback(ctx, group.reference); err != nil {
			results[i] = rollbackStatusForAll(environments, Failed, safeKind("rollback", err))
			return
		}
		results[i] = rollbackStatusForAll(environments, Reverted, "")
	})
	flat := make([]RollbackResult, 0, len(p.Mappings))
	for _, group := range results {
		flat = append(flat, group...)
	}
	sort.Slice(flat, func(i, j int) bool { return flat[i].Environment < flat[j].Environment })
	return flat, nil
}

func rollbackStatusForAll(environments []string, status RollbackStatus, detail string) []RollbackResult {
	results := make([]RollbackResult, len(environments))
	for i, environment := range environments {
		results[i] = RollbackResult{Environment: environment, Status: status, Detail: detail}
	}
	return results
}

func safeOperationError(op string, err error) error {
	return fmt.Errorf("%s failed: %s", op, kind(err))
}
func safeKind(op string, err error) string { return fmt.Sprintf("%s failed: %s", op, kind(err)) }
func kind(err error) provider.ErrorKind {
	var typed *provider.Error
	if errors.As(err, &typed) {
		return typed.Kind
	}
	return provider.Other
}
