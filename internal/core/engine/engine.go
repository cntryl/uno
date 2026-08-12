// Package engine resolves and synchronizes direct secret mappings.
package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"

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
			return nil, fmt.Errorf("line %d: invalid source reference", entry.Line)
		}
		destination, err := registry.Parse(entry.Destination)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid destination reference", entry.Line)
		}
		p.Mappings = append(p.Mappings, Mapping{entry.Key, source, destination})
		destinations = append(destinations, destination)
	}
	if err := provider.ValidateDestinations(destinations); err != nil {
		return nil, fmt.Errorf("invalid destination bindings")
	}
	return p, nil
}

// Resolve reads every source before returning any values. It never writes.
func Resolve(ctx context.Context, p *Plan) (map[string]secret.Value, error) {
	values := make(map[string]secret.Value, len(p.Mappings))
	destroy := func() {
		for key, value := range values {
			value.Destroy()
			delete(values, key)
		}
	}
	adapters := map[string]provider.Adapter{}
	type sourceGroup struct {
		ref     provider.Reference
		indexes []int
	}
	groups := map[string]*sourceGroup{}
	keys := []string{}
	for i, mapping := range p.Mappings {
		key := mapping.Source.Scheme + "\x00" + mapping.Source.Region + "\x00" + mapping.Source.Container
		if groups[key] == nil {
			groups[key] = &sourceGroup{ref: mapping.Source}
			keys = append(keys, key)
		}
		groups[key].indexes = append(groups[key].indexes, i)
	}
	sort.Strings(keys)
	for _, key := range keys {
		group := groups[key]
		adapter, err := adapterFor(ctx, p.Registry, group.ref, adapters)
		if err != nil {
			destroy()
			return nil, safeOperationError("read", err)
		}
		refs := make([]provider.Reference, len(group.indexes))
		for i, index := range group.indexes {
			refs[i] = p.Mappings[index].Source
		}
		got, err := adapter.ReadMany(ctx, refs)
		if err != nil {
			destroy()
			return nil, safeOperationError("read", err)
		}
		if len(got) != len(refs) {
			for i := range got {
				got[i].Destroy()
			}
			destroy()
			return nil, safeOperationError("read", &provider.Error{Kind: provider.InvalidState})
		}
		for i, index := range group.indexes {
			values[p.Mappings[index].Environment] = got[i].Clone()
			got[i].Destroy()
		}
	}
	return values, nil
}

func Sync(ctx context.Context, p *Plan) (Receipt, error) {
	values, err := Resolve(ctx, p)
	if err != nil {
		return Receipt{}, err
	}
	defer func() {
		for key, value := range values {
			value.Destroy()
			delete(values, key)
		}
	}()
	groups := map[string][]provider.Write{}
	refs := map[string]provider.Reference{}
	for _, mapping := range p.Mappings {
		key := mapping.Destination.Scheme + "\x00" + mapping.Destination.Region + "\x00" + mapping.Destination.Container
		groups[key] = append(groups[key], provider.Write{Environment: mapping.Environment, Reference: mapping.Destination, Value: values[mapping.Environment]})
		refs[key] = mapping.Destination
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	completed := []string{}
	adapters := map[string]provider.Adapter{}
	for _, key := range keys {
		writes := groups[key]
		provider.SortedWrites(writes)
		adapter, initErr := adapterFor(ctx, p.Registry, refs[key], adapters)
		if initErr != nil {
			return Receipt{}, &Error{Message: safeKind("write", initErr), Completed: completed}
		}
		receipt, writeErr := adapter.WriteMany(ctx, writes)
		completed = append(completed, receipt.Completed...)
		if writeErr != nil {
			return Receipt{}, &Error{Message: safeKind("write", writeErr), Completed: completed}
		}
	}
	return Receipt{Completed: completed}, nil
}

func adapterFor(ctx context.Context, registry *provider.Registry, ref provider.Reference, cache map[string]provider.Adapter) (provider.Adapter, error) {
	key := ref.Scheme + "\x00" + ref.Region
	if adapter := cache[key]; adapter != nil {
		return adapter, nil
	}
	adapter, err := registry.Adapter(ctx, ref)
	if err == nil {
		cache[key] = adapter
	}
	return adapter, err
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
