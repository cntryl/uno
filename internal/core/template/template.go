// Package template parses direct secret-to-secret mapping files.
package template

import (
	"fmt"
	"os"
	"strings"
)

type Entry struct {
	Key, Source, Destination string
	Line                     int
}
type File struct{ Entries []Entry }
type Error struct {
	Line, Column int
	Message      string
}

func (e *Error) Error() string      { return fmt.Sprintf("%d:%d: %s", e.Line, e.Column, e.Message) }
func terr(l, c int, m string) error { return &Error{l, c, m} }

func Parse(input string) (*File, error) { return ParseEnv(input, os.LookupEnv) }
func ParseEnv(input string, env func(string) (string, bool)) (*File, error) {
	if strings.ContainsRune(input, 0) {
		return nil, terr(1, 1, "templates cannot contain NUL")
	}
	f := &File{}
	seen := map[string]bool{}
	for i, raw := range strings.Split(input, "\n") {
		line := strings.TrimSuffix(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, terr(i+1, 1, "mapping must contain =")
		}
		key := strings.TrimSpace(line[:eq])
		if !validKey(key) {
			return nil, terr(i+1, 1, "invalid environment key")
		}
		if seen[key] {
			return nil, terr(i+1, 1, "duplicate environment key")
		}
		seen[key] = true
		rest := line[eq+1:]
		arrow := strings.Index(rest, "->")
		if arrow < 0 || strings.Contains(rest[arrow+2:], "->") {
			return nil, terr(i+1, eq+2, "mapping must contain exactly one ->")
		}
		sourceRaw, destinationRaw := strings.TrimSpace(rest[:arrow]), strings.TrimSpace(rest[arrow+2:])
		if sourceRaw == "" || destinationRaw == "" {
			return nil, terr(i+1, eq+2, "source and destination references are required")
		}
		source, err := expand(sourceRaw, env)
		if err != nil {
			return nil, terr(i+1, eq+2, err.Error())
		}
		destination, err := expand(destinationRaw, env)
		if err != nil {
			return nil, terr(i+1, eq+arrow+4, err.Error())
		}
		f.Entries = append(f.Entries, Entry{key, source, destination, i + 1})
	}
	if len(f.Entries) == 0 {
		return nil, terr(1, 1, "template must contain at least one mapping")
	}
	return f, nil
}

func expand(s string, env func(string) (string, bool)) (string, error) {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '$' {
			out.WriteByte(s[i])
			i++
			continue
		}
		i++
		var name string
		if i < len(s) && s[i] == '{' {
			end := strings.IndexByte(s[i+1:], '}')
			if end < 0 {
				return "", fmt.Errorf("malformed environment interpolation")
			}
			name = s[i+1 : i+1+end]
			i += end + 2
		} else {
			j := i
			for j < len(s) && ((s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= 'a' && s[j] <= 'z') || (j > i && s[j] >= '0' && s[j] <= '9') || s[j] == '_') {
				j++
			}
			name = s[i:j]
			i = j
		}
		if name == "" || !validKey(name) {
			return "", fmt.Errorf("malformed environment interpolation")
		}
		value, ok := env(name)
		if !ok {
			return "", fmt.Errorf("environment variable %s is not set", name)
		}
		if strings.ContainsRune(value, 0) {
			return "", fmt.Errorf("environment variable %s contains NUL", name)
		}
		out.WriteString(value)
	}
	return out.String(), nil
}
func validKey(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range []byte(s) {
		if i == 0 && !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_') {
			return false
		}
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}
