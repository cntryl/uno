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
		if err := parseLine(f, seen, aliases, line, trimmed, i+1, env, expandDestinations); err != nil {
			return nil, err
		}
	}
	for _, alias := range aliases {
		if !alias.used {
			return nil, terr(alias.line, 1, "destination alias is unused")
		}
	}
	return f, nil
}

func parseLine(f *File, seen map[string]bool, aliases map[string]*destinationAlias, line, trimmed string, number int, env func(string) (string, bool), expandDestinations bool) error {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return terr(number, 1, "mapping must contain =")
	}
	key := strings.TrimSpace(line[:eq])
	if strings.HasPrefix(trimmed, "@") {
		return parseAlias(aliases, key, strings.TrimSpace(line[eq+1:]), number, eq, env, expandDestinations)
	}
	if !validKey(key) {
		return terr(number, 1, "invalid environment key")
	}
	if seen[key] {
		return terr(number, 1, "duplicate environment key")
	}
	seen[key] = true
	sourceRaw, destinationRaw, arrow, err := mappingParts(line[eq+1:], number, eq)
	if err != nil {
		return err
	}
	source, err := expand(sourceRaw, env)
	if err != nil {
		return terr(number, eq+2, err.Error())
	}
	destination, err := resolveDestination(destinationRaw, key, aliases, env, expandDestinations)
	if err != nil {
		return terr(number, eq+arrow+4, err.Error())
	}
	f.Entries = append(f.Entries, Entry{key, source, destination, number})
	return nil
}
func mappingParts(rest string, line, eq int) (string, string, int, error) {
	arrow := strings.Index(rest, "->")
	if arrow < 0 || strings.Contains(rest[arrow+2:], "->") {
		return "", "", 0, terr(line, eq+2, "mapping must contain exactly one ->")
	}
	source, destination := strings.TrimSpace(rest[:arrow]), strings.TrimSpace(rest[arrow+2:])
	if source == "" || destination == "" {
		return "", "", 0, terr(line, eq+2, "source and destination references are required")
	}
	if strings.HasPrefix(source, "@") {
		return "", "", 0, terr(line, eq+2, "destination aliases cannot be used as sources")
	}
	return source, destination, arrow, nil
}
func parseAlias(aliases map[string]*destinationAlias, key, prefix string, line, eq int, env func(string) (string, bool), expandDestinations bool) error {
	if !validAlias(key) {
		return terr(line, 1, "invalid destination alias name")
	}
	if aliases[key] != nil {
		return terr(line, 1, "duplicate destination alias")
	}
	if prefix == "" {
		return terr(line, eq+2, "destination alias prefix is required")
	}
	if strings.HasPrefix(prefix, "@") {
		return terr(line, eq+2, "destination aliases cannot reference aliases")
	}
	if expandDestinations {
		expanded, err := expand(prefix, env)
		if err != nil {
			return terr(line, eq+2, err.Error())
		}
		prefix = expanded
	}
	if strings.HasPrefix(prefix, "@") {
		return terr(line, eq+2, "destination aliases cannot reference aliases")
	}
	if strings.HasSuffix(prefix, "/") {
		return terr(line, eq+2, "destination alias prefix must not end with /")
	}
	aliases[key] = &destinationAlias{prefix: prefix, line: line}
	return nil
}
func resolveDestination(raw, key string, aliases map[string]*destinationAlias, env func(string) (string, bool), expandDestinations bool) (string, error) {
	if strings.HasPrefix(raw, "@") {
		if !validAlias(raw) {
			return "", fmt.Errorf("destination alias must be the entire destination")
		}
		alias := aliases[raw]
		if alias == nil {
			return "", fmt.Errorf("destination alias is undefined or declared after use")
		}
		alias.used = true
		return alias.prefix + "/" + key, nil
	}
	if expandDestinations {
		return expand(raw, env)
	}
	return raw, nil
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
		name, next, err := interpolation(s, i+1)
		if err != nil {
			return "", err
		}
		i = next
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
func interpolation(s string, start int) (string, int, error) {
	if start < len(s) && s[start] == '{' {
		end := strings.IndexByte(s[start+1:], '}')
		if end < 0 {
			return "", 0, fmt.Errorf("malformed environment interpolation")
		}
		return s[start+1 : start+1+end], start + end + 2, nil
	}
	end := start
	for end < len(s) && identifierByte(s[end], end == start) {
		end++
	}
	return s[start:end], end, nil
}
func identifierByte(c byte, first bool) bool {
	letter := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
	return letter || c == '_' || (!first && c >= '0' && c <= '9')
}
func validKey(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range []byte(s) {
		if !identifierByte(c, i == 0) {
			return false
		}
	}
	return true
}
