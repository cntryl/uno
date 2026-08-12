package main

import "strings"

func safeChildEnvironment(environment, capabilities []string) []string {
	denied := make(map[string]bool, len(capabilities))
	for _, key := range capabilities {
		denied[key] = true
	}
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		key, _, ok := strings.Cut(entry, "=")
		if ok && denied[key] {
			continue
		}
		result = append(result, entry)
	}
	return result
}
