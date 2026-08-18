package provider

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/cntryl/uno/internal/core/secret"
)

func TestEverySafeDiagnosticHasAFixedMessage(t *testing.T) {
	if NoDiagnostic.Message() != "" || diagnosticCount.Message() != "" || Diagnostic(255).Message() != "" {
		t.Fatal("non-diagnostic values must not produce messages")
	}
	for diagnostic := SecretNotFound; diagnostic < diagnosticCount; diagnostic++ {
		if diagnostic.Message() == "" {
			t.Fatalf("diagnostic %d has no fixed message", diagnostic)
		}
	}
}

func TestShouldPreserveUnwrittenSiblingsGivenKeyedMerge(t *testing.T) {
	property := func(siblings map[string]string, replacement string) bool {
		delete(siblings, "__uno_target__")
		existing, err := json.Marshal(siblings)
		if err != nil {
			return false
		}
		write := Write{Reference: Reference{Key: "__uno_target__"}, Value: secret.New(replacement)}
		payload, err := MergeJSONDocument(existing, []Write{write})
		if err != nil {
			return false
		}
		var got, want map[string]string
		if json.Unmarshal(existing, &want) != nil || json.Unmarshal(payload, &got) != nil {
			return false
		}
		want["__uno_target__"] = replacement
		return reflect.DeepEqual(got, want)
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 1_000}); err != nil {
		t.Fatal(err)
	}
}

func TestShouldReturnRawValueGivenBlobWrite(t *testing.T) {
	write := Write{Reference: Reference{}, Value: secret.New("raw-value")}
	payload, err := MergeJSONDocument([]byte(`{"ignored":"doc"}`), []Write{write})
	if err != nil || string(payload) != "raw-value" {
		t.Fatalf("payload=%s err=%v", payload, err)
	}
}

func TestShouldFailMergeGivenMalformedExistingDocument(t *testing.T) {
	write := Write{Reference: Reference{Key: "a"}, Value: secret.New("v")}
	_, err := MergeJSONDocument([]byte("not json"), []Write{write})
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != InvalidState {
		t.Fatalf("err=%v", err)
	}
}

// A stored document that's the literal JSON value "null" unmarshals without
// error but leaves the target map nil; writing to it would otherwise panic
// with "assignment to entry in nil map" instead of failing cleanly.
func TestShouldFailMergeRatherThanPanicGivenLiteralNullDocument(t *testing.T) {
	write := Write{Reference: Reference{Key: "a"}, Value: secret.New("v")}
	_, err := MergeJSONDocument([]byte("null"), []Write{write})
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != InvalidState {
		t.Fatalf("err=%v", err)
	}
}

func TestShouldReadBlobAndKeyedValuesGivenSharedDocument(t *testing.T) {
	refs := []Reference{
		{Scheme: "x", Container: "c"},              // blob
		{Scheme: "x", Container: "c", Key: "a"},    // present
		{Scheme: "x", Container: "c", Key: "gone"}, // absent
	}
	raw := []byte(`{"a":"one"}`)
	values, err := ReadJSONDocument(refs, raw)
	if err != nil {
		t.Fatal(err)
	}
	if values[refs[0].Binding()].Reveal() != string(raw) || !values[refs[0].Binding()].Found {
		t.Fatalf("blob=%v", values[refs[0].Binding()])
	}
	if values[refs[1].Binding()].Reveal() != "one" || !values[refs[1].Binding()].Found {
		t.Fatalf("keyed=%v", values[refs[1].Binding()])
	}
	if values[refs[2].Binding()].Found {
		t.Fatalf("absent key reported found: %v", values[refs[2].Binding()])
	}
	if values[refs[2].Binding()].Diagnostic != BindingNotFound {
		t.Fatalf("absent key diagnostic=%v", values[refs[2].Binding()].Diagnostic)
	}
}

func TestShouldFailReadGivenNullOrMalformedValue(t *testing.T) {
	for name, raw := range map[string][]byte{
		"null field":            []byte(`{"a":null}`),
		"malformed json":        []byte("not json"),
		"literal null document": []byte("null"),
	} {
		ref := Reference{Scheme: "x", Container: "c", Key: "a"}
		if _, err := ReadJSONDocument([]Reference{ref}, raw); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestShouldClassifyMalformedDocumentSeparatelyFromUnsupportedFieldContent(t *testing.T) {
	ref := Reference{Scheme: "x", Container: "c", Key: "a"}

	_, malformedErr := ReadJSONDocument([]Reference{ref}, []byte("not json"))
	var malformed *Error
	if !errors.As(malformedErr, &malformed) || malformed.Kind != InvalidState || malformed.Diagnostic != MalformedContainer {
		t.Fatalf("malformed err=%v", malformedErr)
	}

	_, contentErr := ReadJSONDocument([]Reference{ref}, []byte(`{"a":42}`))
	var indexed *ReadError
	var content *Error
	if !errors.As(contentErr, &indexed) || indexed.Index != 0 || !errors.As(contentErr, &content) || content.Kind != InvalidState || content.Diagnostic != UnsupportedContent {
		t.Fatalf("content err=%v", contentErr)
	}
}
