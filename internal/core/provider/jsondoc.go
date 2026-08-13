package provider

import (
	"encoding/json"

	"github.com/cntryl/uno/internal/core/secret"
)

// Several adapters (AWS Secrets Manager, GCP Secret Manager, Azure Key
// Vault) multiplex several bindings into one remote container by storing a
// flat JSON object and addressing individual top-level string fields by
// key — a Blob() reference instead addresses the whole raw document. These
// two functions hold that shared encoding so each adapter only supplies the
// provider-specific part: how the raw document is fetched and stored.

// ReadJSONDocument splits a container's raw document among refs, which must
// already share one container (callers call ValidateReadGroup first). A
// Blob() ref gets the entire raw document as its value; a keyed ref gets
// its named top-level string field, or a not-found result if the key is
// absent. On any decode failure every value already produced is destroyed
// and the error is returned instead of a partial map.
func ReadJSONDocument(refs []Reference, raw []byte) (map[string]ReadResult, error) {
	values := make(map[string]ReadResult, len(refs))
	fail := func(err error) (map[string]ReadResult, error) {
		DestroyReadResults(values)
		return nil, err
	}
	doc := map[string]json.RawMessage{}
	parsed := false
	for _, ref := range refs {
		if ref.Blob() {
			values[ref.Binding()] = ReadResult{Value: secret.New(string(raw)), Found: true}
			continue
		}
		if !parsed {
			// A stored document that's the literal JSON value "null"
			// unmarshals without error but leaves doc itself nil (see the
			// matching comment in MergeJSONDocument); reading from a nil map
			// doesn't panic, so without this check every key would silently
			// report "not found" instead of surfacing the real corruption.
			if json.Unmarshal(raw, &doc) != nil || doc == nil {
				return fail(&Error{Kind: InvalidState})
			}
			parsed = true
		}
		rawValue, ok := doc[ref.Key]
		if !ok {
			values[ref.Binding()] = ReadResult{}
			continue
		}
		if string(rawValue) == "null" {
			return fail(&Error{Kind: InvalidState})
		}
		var value string
		if json.Unmarshal(rawValue, &value) != nil {
			return fail(&Error{Kind: InvalidState})
		}
		values[ref.Binding()] = ReadResult{Value: secret.New(value), Found: true}
	}
	return values, nil
}

// MergeJSONDocument merges every write's value into existing (nil or empty
// for "the container doesn't exist yet"), keyed by each write's
// Reference.Key, preserving every other top-level field already present.
// writes must be non-empty and share one container. A Blob() write bypasses
// JSON entirely: its single value becomes the whole new document.
func MergeJSONDocument(existing []byte, writes []Write) ([]byte, error) {
	if writes[0].Reference.Blob() {
		return []byte(writes[0].Value.Reveal()), nil
	}
	doc := map[string]json.RawMessage{}
	if len(existing) > 0 {
		// A stored document that's the literal JSON value "null" unmarshals
		// successfully but sets doc itself to nil (encoding/json's documented
		// behavior for null into a map) — writing to it below would then
		// panic. Treat that the same as any other document that isn't a JSON
		// object: reject it rather than silently reinitializing it.
		if json.Unmarshal(existing, &doc) != nil || doc == nil {
			return nil, &Error{Kind: InvalidState}
		}
	}
	for _, write := range writes {
		encoded, err := json.Marshal(write.Value.Reveal())
		if err != nil {
			return nil, &Error{Kind: InvalidState}
		}
		doc[write.Reference.Key] = encoded
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return nil, &Error{Kind: InvalidState}
	}
	return encoded, nil
}
