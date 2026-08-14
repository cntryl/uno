// Package secret provides explicitly revealed, redacted, best-effort wipeable values.
package secret

import (
	"runtime"
	"sort"
)

// Value owns a best-effort wipeable copy. Reveal is deliberately explicit.
// Go strings, SDKs, JSON encoders, and child environments can retain copies,
// so guaranteed zeroization is not possible.
type Value struct{ b []byte }

func New(s string) Value         { return Value{b: append([]byte(nil), s...)} }
func NewBytes(b []byte) Value    { return Value{b: append([]byte(nil), b...)} }
func (v Value) Reveal() string   { return string(v.b) }
func (v Value) String() string   { return "[REDACTED]" }
func (v Value) GoString() string { return "secret.Value([REDACTED])" }
func (v Value) Clone() Value     { return Value{b: append([]byte(nil), v.b...)} }
func (v *Value) Destroy() {
	DestroyBytes(v.b)
	v.b = nil
	runtime.KeepAlive(v)
}

// DestroyBytes best-effort wipes an owned provider buffer after its contents
// have been copied into a Value.
func DestroyBytes(value []byte) {
	clear(value)
	runtime.KeepAlive(value)
}

// DestroyMap destroys every owned value and empties the map.
func DestroyMap(values map[string]Value) {
	for key, value := range values {
		value.Destroy()
		delete(values, key)
	}
}

func SortedKeys(values map[string]Value) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
