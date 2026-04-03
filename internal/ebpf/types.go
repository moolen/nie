package ebpf

import (
	"context"
	"net/netip"
	"time"
)

type TrustEntry struct {
	IPv4      netip.Addr
	ExpiresAt time.Time
}

type TrustWriter interface {
	Allow(ctx context.Context, entry TrustEntry) error
}
