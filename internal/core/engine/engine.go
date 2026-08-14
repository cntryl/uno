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
	Cause     error
}

func (e *Error) Error() string { return e.Message }
func (e *Error) Unwrap() error { return e.Cause }

func Bind(file *tpl.File, registry *provider.Registry) (*Plan, error) {
	return bind(file, registry, true)
}

// BindSources validates and binds only source references for source-only
// commands. Destination validation remains part of Bind for commands that use
// destinations.
func BindSources(file *tpl.File, registry *provider.Registry) (*Plan, error) {
	return bind(file, registry, false)
}

func bind(file *tpl.File, registry *provider.Registry, bindDestinations bool) (*Plan, error) {
	p := &Plan{Registry: registry}
	destinations := make([]provider.Reference, 0, len(file.Entries))
	for _, entry := range file.Entries {
		source, err := registry.Parse(entry.Source)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid source reference: %s", entry.Line, provider.BindingDetail(err))
		}
		if !bindDestinations {
			p.Mappings = append(p.Mappings, Mapping{Environment: entry.Key, Source: source})
			continue
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
	return resolveWithAdapters(ctx, p, newAdapterCache(p.Registry))
}

func resolveWithAdapters(ctx context.Context, p *Plan, adapters *adapterCache) (map[string]secret.Value, error) {
	values := make(map[string]secret.Value, len(p.Mappings))
	defer func() {
		if values != nil {
			secret.DestroyMap(values)
		}
	}()
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
		provider.DestroyReadResults(got)
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
		provider.DestroyReadResults(got)
		return nil, safeOperationError("read", &provider.Error{Kind: provider.InvalidState})
	}
	for _, mapping := range group.mappings {
		result := got[mapping.Source.Binding()]
		if !result.Found {
			provider.DestroyReadResults(got)
			return nil, safeOperationError("read", &provider.Error{Kind: provider.InvalidBinding})
		}
		values[mapping.Environment] = result.Clone()
	}
	provider.DestroyReadResults(got)
	resultValues := values
	values = nil
	return resultValues, nil
}

func writeDestinations(ctx context.Context, p *Plan, values map[string]secret.Value, adapters *adapterCache) (Receipt, error) {
	groups := groupDestinations(p.Mappings, values)
	type writeResult struct {
		receipt provider.Receipt
		err     error
	}
	results := make([]writeResult, len(groups))
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
		return Receipt{}, &Error{Message: safeKind("write", firstErr), Completed: completed, Cause: contextCause(firstErr)}
	}
	return Receipt{Completed: completed}, nil
}

type SyncOptions struct {
	DryRun  bool
	Confirm func([]Change) (bool, error)
}

type SyncResult struct {
	DryRun    bool     `json:"dryRun"`
	Changes   []Change `json:"changes"`
	Completed []string `json:"completed"`
}

// Sync resolves all sources, inspects every destination container once, and
// writes only changed mappings. No confirmation or write occurs unless every
// source and destination snapshot was read successfully.
func Sync(ctx context.Context, p *Plan, options SyncOptions) (SyncResult, error) {
	result := SyncResult{DryRun: options.DryRun, Changes: []Change{}, Completed: []string{}}
	adapters := newAdapterCache(p.Registry)
	values, err := resolveWithAdapters(ctx, p, adapters)
	if err != nil {
		return result, err
	}
	defer secret.DestroyMap(values)

	changes, err := inspectDestinations(ctx, p, values, adapters)
	result.Changes = changes
	if err != nil {
		return result, err
	}
	pending := make(map[string]bool)
	var actionable []Change
	for _, change := range changes {
		if change.Kind != Unchanged {
			pending[change.Environment] = true
			actionable = append(actionable, change)
		}
	}
	if options.DryRun || len(actionable) == 0 {
		return result, nil
	}
	if options.Confirm != nil {
		ok, confirmErr := options.Confirm(actionable)
		if confirmErr != nil {
			return result, confirmErr
		}
		if !ok {
			return result, &Error{Message: "sync aborted: not confirmed"}
		}
	}
	filtered := &Plan{Registry: p.Registry}
	for _, mapping := range p.Mappings {
		if pending[mapping.Environment] {
			filtered.Mappings = append(filtered.Mappings, mapping)
		}
	}
	receipt, err := writeDestinations(ctx, filtered, values, adapters)
	result.Completed = receiptCompleted(receipt, err)
	return result, err
}

func receiptCompleted(receipt Receipt, err error) []string {
	if workflow := (*Error)(nil); errors.As(err, &workflow) {
		return workflow.Completed
	}
	return receipt.Completed
}

func inspectDestinations(ctx context.Context, p *Plan, desired map[string]secret.Value, adapters *adapterCache) ([]Change, error) {
	groups := groupDestinationContainers(p.Mappings)
	type groupResult struct {
		changes []Change
		err     error
	}
	results := make([]groupResult, len(groups))
	runLimited(len(groups), func(i int) {
		group := groups[i]
		adapter, err := adapters.get(ctx, group.reference)
		if err != nil {
			results[i].err = safeOperationError("inspect", err)
			return
		}
		refs := make([]provider.Reference, 0, len(group.mappings))
		for _, mapping := range group.mappings {
			refs = append(refs, mapping.Destination)
		}
		var got map[string]provider.ReadResult
		if reader, ok := adapter.(provider.DestinationReader); ok {
			got, err = reader.ReadDestinations(ctx, refs)
		} else {
			got, err = adapter.ReadMany(ctx, refs)
		}
		if err != nil {
			provider.DestroyReadResults(got)
			results[i].err = safeOperationError("inspect", err)
			return
		}
		defer provider.DestroyReadResults(got)
		if len(got) != len(refs) {
			results[i].err = safeOperationError("inspect", &provider.Error{Kind: provider.InvalidState})
			return
		}
		for _, mapping := range group.mappings {
			current, ok := got[mapping.Destination.Binding()]
			if !ok {
				results[i].err = safeOperationError("inspect", &provider.Error{Kind: provider.InvalidState})
				return
			}
			kind := Create
			if current.Found {
				kind = Update
				if current.Value.Reveal() == desired[mapping.Environment].Reveal() {
					kind = Unchanged
				}
			}
			results[i].changes = append(results[i].changes, Change{Environment: mapping.Environment, Kind: kind})
		}
	})
	changes := make([]Change, 0, len(p.Mappings))
	for _, result := range results {
		if result.err != nil {
			return changes, result.err
		}
		changes = append(changes, result.changes...)
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Environment < changes[j].Environment })
	return changes, nil
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
	if cause := contextCause(err); cause != nil {
		return cause
	}
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

func contextCause(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}
