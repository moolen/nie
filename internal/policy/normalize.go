package policy

import "strings"

func NormalizeHostname(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimRight(host, ".")
	host = strings.ToLower(host)
	return host
}
