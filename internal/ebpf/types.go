package ebpf

import (
	"context"
	"fmt"
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

type EgressReason uint32

const (
	EgressReasonNotAllowed EgressReason = 1
	EgressReasonExpired    EgressReason = 2
)

func (r EgressReason) String() string {
	switch r {
	case EgressReasonNotAllowed:
		return "not_allowed"
	case EgressReasonExpired:
		return "expired"
	default:
		return fmt.Sprintf("unknown(%d)", uint32(r))
	}
}

type EgressAction uint32

const (
	EgressActionAllow EgressAction = 0
	EgressActionDrop  EgressAction = 2
)

type EgressEvent struct {
	Destination netip.Addr
	Reason      EgressReason
	Action      EgressAction
}

type EventReader interface {
	Read() (EgressEvent, error)
	Close() error
}
