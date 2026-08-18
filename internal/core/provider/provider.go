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

// Diagnostic is a closed set of safe, provider-neutral explanations for
// operational read failures. Adapters must never construct diagnostics from
// SDK text or reference data; the engine renders only these fixed messages.
type Diagnostic uint8

const (
	NoDiagnostic Diagnostic = iota
	SecretNotFound
	BindingNotFound
	AmbiguousContainer
	AmbiguousSection
	AmbiguousField
	AmbiguousFile
	SectionNotFound
	FieldNotFound
	FileNotFound
	MalformedContainer
	UnsupportedContent
	InvalidResponse
	diagnosticCount
)

func (d Diagnostic) Message() string {
	messages := map[Diagnostic]string{
		SecretNotFound:     "source secret not found in provider",
		BindingNotFound:    "source field not found in provider container",
		AmbiguousContainer: "source container is ambiguous in provider",
		AmbiguousSection:   "source section is ambiguous in provider container",
		AmbiguousField:     "source field is ambiguous in provider container",
		AmbiguousFile:      "source file is ambiguous in provider container",
		SectionNotFound:    "source section not found in provider container",
		FieldNotFound:      "source field not found in provider container",
		FileNotFound:       "source file not found in provider container",
		MalformedContainer: "provider container contents are malformed",
		UnsupportedContent: "provider item or content type is unsupported",
		InvalidResponse:    "provider returned an incomplete or invalid response",
	}
	return messages[d]
}

type Error struct {
	Kind       ErrorKind
	Diagnostic Diagnostic
	Detail     string
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return fmt.Sprintf("provider operation failed: %s", e.Kind)
}

func InvalidReference(detail string) error { return &Error{Kind: InvalidBinding, Detail: detail} }

// InvalidParse builds the (Reference{}, error) pair every provider's
// Factory.Parse implementation returns on a rejected raw reference — every
// provider package defined this exact one-liner itself before it moved
// here.
func InvalidParse(detail string) (Reference, error) {
	return Reference{}, InvalidReference(detail)
}

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

// ReadResult distinguishes an absent binding from a present empty value.
// Adapters must return one result for every requested binding.
type ReadResult struct {
	Value      secret.Value
	Found      bool
	Diagnostic Diagnostic
}

func (r ReadResult) Reveal() string      { return r.Value.Reveal() }
func (r ReadResult) Clone() secret.Value { return r.Value.Clone() }

func MissingResults(refs []Reference) map[string]ReadResult {
	return MissingResultsWithDiagnostic(refs, NoDiagnostic)
}

func MissingResultsWithDiagnostic(refs []Reference, diagnostic Diagnostic) map[string]ReadResult {
	results := make(map[string]ReadResult, len(refs))
	for _, ref := range refs {
		results[ref.Binding()] = ReadResult{Diagnostic: diagnostic}
	}
	return results
}

// ReadError identifies which entry in a ReadMany request produced a
// reference-specific failure. It intentionally retains only the slice index,
// never the provider reference itself.
type ReadError struct {
	Index int
	Err   error
}

func (e *ReadError) Error() string { return "provider read failed" }
func (e *ReadError) Unwrap() error { return e.Err }

func ReadFailure(index int, err error) error { return &ReadError{Index: index, Err: err} }

func DestroyReadResults(results map[string]ReadResult) {
	for key, result := range results {
		result.Value.Destroy()
		delete(results, key)
	}
}

type Reader interface {
	ReadMany(context.Context, []Reference) (map[string]ReadResult, error)
}

// DestinationReader is an optional adapter capability for providers whose
// valid source bindings differ from their valid destination bindings.
type DestinationReader interface {
	ReadDestinations(context.Context, []Reference) (map[string]ReadResult, error)
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

// Rollbacker is an optional adapter capability. An adapter that can revert a
// container to its previous value implements it; callers must type-assert
// since not every provider (or every reference kind) supports this — an
// adapter that doesn't implement it simply doesn't offer rollback.
type Rollbacker interface {
	// Rollback reverts ref's container to its previous value. It returns an
	// *Error (InvalidState is conventional) if there is no distinct previous
	// value to revert to.
	Rollback(ctx context.Context, ref Reference) error
}
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

func ValidateWriteGroup(writes []Write) error {
	if len(writes) == 0 {
		return nil
	}
	first := writes[0].Reference
	for _, write := range writes {
		ref := write.Reference
		if ref.Scheme != first.Scheme || ref.Region != first.Region || ref.Container != first.Container || ref.Blob() != first.Blob() {
			return &Error{Kind: InvalidBinding}
		}
	}
	return nil
}

func ValidateReadGroup(refs []Reference) error {
	if len(refs) == 0 {
		return nil
	}
	first := refs[0]
	for _, ref := range refs {
		if ref.Scheme != first.Scheme || ref.Region != first.Region || ref.Container != first.Container {
			return &Error{Kind: InvalidBinding}
		}
	}
	return nil
}
