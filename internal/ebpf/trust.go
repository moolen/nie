package ebpf

import (
	"fmt"
	"net/netip"
	"time"
)

func NewEntry(rawIP string, port uint16, ttl uint32, now time.Time, maxTTL time.Duration) (TrustEntry, error) {
	ip, err := netip.ParseAddr(rawIP)
	if err != nil || !ip.Is4() {
		return TrustEntry{}, fmt.Errorf("invalid IPv4: %q", rawIP)
	}

	d := time.Duration(ttl) * time.Second
	if d <= 0 || d > maxTTL {
		d = maxTTL
	}

	return TrustEntry{
		IPv4:      ip,
		Port:      port,
		ExpiresAt: now.Add(d),
	}, nil
}
