// Package provider defines provider-neutral secret references and operations.
package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cntryl/uno/internal/core/secret"
)

type ErrorKind string

const (
	AccessDenied         ErrorKind = "AccessDenied"
	Authentication       ErrorKind = "Authentication"
	Ambiguous            ErrorKind = "Ambiguous"
	InvalidBinding       ErrorKind = "InvalidBinding"
	Indeterminate        ErrorKind = "Indeterminate"
	PendingCleanupFailed ErrorKind = "PendingCleanupFailed"
	InvalidState         ErrorKind = "InvalidState"
	Other                ErrorKind = "Other"
)

type Error struct {
	Kind   ErrorKind
	Detail string
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return fmt.Sprintf("provider operation failed: %s", e.Kind)
}

func InvalidReference(detail string) error { return &Error{Kind: InvalidBinding, Detail: detail} }

func BindingDetail(err error) string {
	var typed *Error
	if errors.As(err, &typed) && typed.Detail != "" {
		return typed.Detail
	}
	return string(InvalidBinding)
}

// Reference is an adapter-owned parsed locator. Container is the unit grouped
// into one remote update; Key is empty for a complete-blob binding.
type Reference struct {
	Scheme, Region, Container, Key string
	// AdapterKey is an opaque factory-owned client-sharing key. It is not part
	// of the secret binding identity.
	AdapterKey string
}

func (r Reference) Binding() string {
	return strings.Join([]string{r.Scheme, r.Region, r.Container, r.Key}, "\x00")
}
func (r Reference) Blob() bool { return r.Key == "" }

type Write struct {
	Environment string
	Reference   Reference
	Value       secret.Value
}
type Receipt struct{ Completed []string }

type Reader interface {
	ReadMany(context.Context, []Reference) (map[string]secret.Value, error)
}
type Writer interface {
	WriteMany(context.Context, []Write) (Receipt, error)
}
type Adapter interface {
	Reader
	Writer
}
type Factory interface {
	Parse(string) (Reference, error)
	Adapter(context.Context, Reference) (Adapter, error)
}
type capabilityFactory interface{ CapabilityPrefixes() []string }
type Registry struct{ factories map[string]Factory }

func NewRegistry() *Registry                          { return &Registry{factories: map[string]Factory{}} }
func (r *Registry) Register(scheme string, f Factory) { r.factories[scheme] = f }
func (r *Registry) CapabilityPrefixes() []string {
	seen := map[string]bool{}
	for _, factory := range r.factories {
		if capable, ok := factory.(capabilityFactory); ok {
			for _, prefix := range capable.CapabilityPrefixes() {
				seen[prefix] = true
			}
		}
	}
	prefixes := make([]string, 0, len(seen))
	for prefix := range seen {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)
	return prefixes
}
func (r *Registry) Parse(raw string) (Reference, error) {
	i := strings.Index(raw, "://")
	if i <= 0 {
		return Reference{}, InvalidReference("expected provider reference with scheme://")
	}
	f := r.factories[raw[:i]]
	if f == nil {
		return Reference{}, InvalidReference("unknown provider scheme")
	}
	return f.Parse(raw)
}
func (r *Registry) Adapter(ctx context.Context, ref Reference) (Adapter, error) {
	f := r.factories[ref.Scheme]
	if f == nil {
		return nil, &Error{Kind: InvalidBinding}
	}
	return f.Adapter(ctx, ref)
}

func ValidateDestinations(refs []Reference) error {
	seen := map[string]int{}
	type containerMode struct {
		blob  bool
		index int
	}
	mode := map[string]containerMode{}
	for i, ref := range refs {
		binding := ref.Binding()
		if previous, ok := seen[binding]; ok {
			return &DestinationConflictError{Index: i, Previous: previous, Mixed: false}
		}
		seen[binding] = i
		container := strings.Join([]string{ref.Scheme, ref.Region, ref.Container}, "\x00")
		if previous, ok := mode[container]; ok && previous.blob != ref.Blob() {
			return &DestinationConflictError{Index: i, Previous: previous.index, Mixed: true}
		}
		mode[container] = containerMode{blob: ref.Blob(), index: i}
	}
	return nil
}

type DestinationConflictError struct {
	Index, Previous int
	Mixed           bool
}

func (e *DestinationConflictError) Error() string { return "invalid destination bindings" }

func SortedWrites(w []Write) {
	sort.Slice(w, func(i, j int) bool {
		a, b := w[i].Reference, w[j].Reference
		if a.Container != b.Container {
			return a.Container < b.Container
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		return w[i].Environment < w[j].Environment
	})
}

func Environments(writes []Write) []string {
	result := make([]string, 0, len(writes))
	for _, write := range writes {
		result = append(result, write.Environment)
	}
	sort.Strings(result)
	return result
}
