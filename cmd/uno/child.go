package main

import "strings"

func safeChildEnvironment(environment, capabilityPrefixes []string) []string {
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		key, _, ok := strings.Cut(entry, "=")
		if ok {
			denied := false
			for _, prefix := range capabilityPrefixes {
				if strings.HasPrefix(key, prefix) {
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
