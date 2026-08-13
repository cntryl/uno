// Package engine resolves and synchronizes direct secret mappings.
package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
	tpl "github.com/cntryl/uno/internal/core/template"
)

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
	for _, group := range groupSources(p.Mappings) {
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
	}
	result := values
	values = nil
	return result, nil
}

func Sync(ctx context.Context, p *Plan) (Receipt, error) {
	values, err := Resolve(ctx, p)
	if err != nil {
		return Receipt{}, err
	}
	defer secret.DestroyMap(values)
	completed := []string{}
	adapters := newAdapterCache(p.Registry)
	for _, group := range groupDestinations(p.Mappings, values) {
		adapter, initErr := adapters.get(ctx, group.reference)
		if initErr != nil {
			return Receipt{}, &Error{Message: safeKind("write", initErr), Completed: completed}
		}
		receipt, writeErr := adapter.WriteMany(ctx, group.writes)
		completed = append(completed, receipt.Completed...)
		if writeErr != nil {
			return Receipt{}, &Error{Message: safeKind("write", writeErr), Completed: completed}
		}
	}
	return Receipt{Completed: completed}, nil
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
