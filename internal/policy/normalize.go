package policy

import "strings"

const (
	maxDNSLabelLength = 63
	maxDNSNameLength  = 253
)

// NormalizeHostname trims surrounding whitespace, strips trailing dots, and
// lowercases the input. It does not validate hostname syntax or perform IDNA
// processing.
func NormalizeHostname(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimRight(host, ".")
	host = strings.ToLower(host)
	return host
}

func hasDotOnlyWildcardSuffix(pattern string) bool {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	return isAllDots(strings.TrimPrefix(pattern, "*"))
}

func isAllDots(s string) bool {
	for _, ch := range s {
		if ch != '.' {
			return false
		}
	}
	return true
}
