package cli

import "strings"

func SafeChildEnvironment(environment, capabilityPrefixes []string, resolvedKeys ...[]string) []string {
	resolved := map[string]bool{}
	if len(resolvedKeys) > 0 {
		for _, key := range resolvedKeys[0] {
			resolved[strings.ToLower(key)] = true
		}
	}
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		key, _, ok := strings.Cut(entry, "=")
		if ok {
			denied := resolved[strings.ToLower(key)]
			for _, prefix := range capabilityPrefixes {
				if len(key) >= len(prefix) && strings.EqualFold(key[:len(prefix)], prefix) {
					denied = true
					break
				}
			}
			if denied {
				continue
			}
		}
		result = append(result, entry)
	}
	return result
}
