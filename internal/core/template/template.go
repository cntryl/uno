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

type destinationAlias struct {
	prefix string
	line   int
	used   bool
}

func (e *Error) Error() string      { return fmt.Sprintf("%d:%d: %s", e.Line, e.Column, e.Message) }
func terr(l, c int, m string) error { return &Error{l, c, m} }

func Parse(input string) (*File, error) { return ParseEnv(input, os.LookupEnv) }
func ParseEnv(input string, env func(string) (string, bool)) (*File, error) {
	return parseEnv(input, env, true)
}

// ParseSourcesEnv validates the template structure and expands only source
// references. Destination configuration is intentionally left unresolved for
// commands that never inspect or write destinations.
func ParseSourcesEnv(input string, env func(string) (string, bool)) (*File, error) {
	return parseEnv(input, env, false)
}

func parseEnv(input string, env func(string) (string, bool), expandDestinations bool) (*File, error) {
	if strings.ContainsRune(input, 0) {
		return nil, terr(1, 1, "templates cannot contain NUL")
	}
	f := &File{}
	seen := map[string]bool{}
	aliases := map[string]*destinationAlias{}
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
		if strings.HasPrefix(trimmed, "@") {
			if !validAlias(key) {
				return nil, terr(i+1, 1, "invalid destination alias name")
			}
			if aliases[key] != nil {
				return nil, terr(i+1, 1, "duplicate destination alias")
			}
			prefixRaw := strings.TrimSpace(line[eq+1:])
			if prefixRaw == "" {
				return nil, terr(i+1, eq+2, "destination alias prefix is required")
			}
			if strings.HasPrefix(prefixRaw, "@") {
				return nil, terr(i+1, eq+2, "destination aliases cannot reference aliases")
			}
			prefix := prefixRaw
			if expandDestinations {
				var err error
				prefix, err = expand(prefixRaw, env)
				if err != nil {
					return nil, terr(i+1, eq+2, err.Error())
				}
			}
			if strings.HasPrefix(prefix, "@") {
				return nil, terr(i+1, eq+2, "destination aliases cannot reference aliases")
			}
			if strings.HasSuffix(prefix, "/") {
				return nil, terr(i+1, eq+2, "destination alias prefix must not end with /")
			}
			aliases[key] = &destinationAlias{prefix: prefix, line: i + 1}
			continue
		}
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
		if strings.HasPrefix(sourceRaw, "@") {
			return nil, terr(i+1, eq+2, "destination aliases cannot be used as sources")
		}
		source, err := expand(sourceRaw, env)
		if err != nil {
			return nil, terr(i+1, eq+2, err.Error())
		}
		var destination string
		switch {
		case strings.HasPrefix(destinationRaw, "@"):
			if !validAlias(destinationRaw) {
				return nil, terr(i+1, eq+arrow+4, "destination alias must be the entire destination")
			}
			alias := aliases[destinationRaw]
			if alias == nil {
				return nil, terr(i+1, eq+arrow+4, "destination alias is undefined or declared after use")
			}
			alias.used = true
			destination = alias.prefix + "/" + key
		case expandDestinations:
			destination, err = expand(destinationRaw, env)
			if err != nil {
				return nil, terr(i+1, eq+arrow+4, err.Error())
			}
		default:
			destination = destinationRaw
		}
		f.Entries = append(f.Entries, Entry{key, source, destination, i + 1})
	}
	for _, alias := range aliases {
		if !alias.used {
			return nil, terr(alias.line, 1, "destination alias is unused")
		}
	}
	if len(f.Entries) == 0 {
		return nil, terr(1, 1, "template must contain at least one mapping")
	}
	return f, nil
}

func validAlias(s string) bool {
	return strings.HasPrefix(s, "@") && validKey(strings.TrimPrefix(s, "@"))
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
