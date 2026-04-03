package policy

import "strings"

func NormalizeHostname(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimRight(host, ".")
	host = strings.ToLower(host)
	return host
}

func hasDotOnlyWildcardSuffix(pattern string) bool {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	if !strings.HasPrefix(pattern, "*") || pattern == "*" {
		return false
	}

	rest := strings.TrimLeft(pattern, "*")
	return rest != "" && isAllDots(rest)
}

func isAllDots(s string) bool {
	for _, ch := range s {
		if ch != '.' {
			return false
		}
	}
	return true
}
