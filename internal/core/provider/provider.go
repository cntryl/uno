// Package provider defines provider-neutral secret references and operations.
package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/cntryl/uno/internal/core/secret"
)

type ErrorKind string

const (
	AccessDenied   ErrorKind = "AccessDenied"
	Authentication ErrorKind = "Authentication"
	Ambiguous      ErrorKind = "Ambiguous"
	InvalidBinding ErrorKind = "InvalidBinding"
	Indeterminate  ErrorKind = "Indeterminate"
	InvalidState   ErrorKind = "InvalidState"
	Other          ErrorKind = "Other"
)

type Error struct{ Kind ErrorKind }

func (e *Error) Error() string { return fmt.Sprintf("provider operation failed: %s", e.Kind) }

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
type capabilityFactory interface{ CapabilityVariables() []string }
type Registry struct{ factories map[string]Factory }

func NewRegistry() *Registry                          { return &Registry{factories: map[string]Factory{}} }
func (r *Registry) Register(scheme string, f Factory) { r.factories[scheme] = f }
func (r *Registry) CapabilityVariables() []string {
	seen := map[string]bool{}
	for _, factory := range r.factories {
		if capable, ok := factory.(capabilityFactory); ok {
			for _, key := range capable.CapabilityVariables() {
				seen[key] = true
			}
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func (r *Registry) Parse(raw string) (Reference, error) {
	i := strings.Index(raw, "://")
	if i <= 0 {
		return Reference{}, &Error{Kind: InvalidBinding}
	}
	f := r.factories[raw[:i]]
	if f == nil {
		return Reference{}, &Error{Kind: InvalidBinding}
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
	seen := map[string]bool{}
	mode := map[string]bool{}
	for _, ref := range refs {
		binding := ref.Binding()
		if seen[binding] {
			return &Error{Kind: InvalidBinding}
		}
		seen[binding] = true
		container := strings.Join([]string{ref.Scheme, ref.Region, ref.Container}, "\x00")
		if blob, ok := mode[container]; ok && blob != ref.Blob() {
			return &Error{Kind: InvalidBinding}
		}
		mode[container] = ref.Blob()
	}
	return nil
}

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
