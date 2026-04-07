package ebpf

import (
	"context"
	"fmt"
	"net/netip"
	"time"
)

type TrustEntry struct {
	IPv4      netip.Addr
	Port      uint16
	ExpiresAt time.Time
}

type TrustWriter interface {
	Allow(ctx context.Context, entry TrustEntry) error
}

type CIDRAllowRule struct {
	Prefix   netip.Prefix
	Protocol CIDRProtocol
}

type CIDRAllowWriter interface {
	AllowCIDR(ctx context.Context, rule CIDRAllowRule) error
}

type TrustDeleter interface {
	Delete(ctx context.Context, ipv4 netip.Addr, port uint16) error
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
	Protocol    EgressProtocol
	Port        uint16
}

type EgressProtocol uint8

const (
	EgressProtocolUnknown EgressProtocol = 0
	EgressProtocolICMP    EgressProtocol = 1
	EgressProtocolTCP     EgressProtocol = 6
	EgressProtocolUDP     EgressProtocol = 17
)

func (p EgressProtocol) String() string {
	switch p {
	case EgressProtocolICMP:
		return "icmp"
	case EgressProtocolTCP:
		return "tcp"
	case EgressProtocolUDP:
		return "udp"
	case EgressProtocolUnknown:
		return "unknown"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(p))
	}
}

type CIDRProtocol uint8

const (
	CIDRProtocolTCP  CIDRProtocol = 1 << 0
	CIDRProtocolUDP  CIDRProtocol = 1 << 1
	CIDRProtocolICMP CIDRProtocol = 1 << 2
	CIDRProtocolAny  CIDRProtocol = 0xff
)

func (p CIDRProtocol) String() string {
	switch p {
	case CIDRProtocolTCP:
		return "tcp"
	case CIDRProtocolUDP:
		return "udp"
	case CIDRProtocolICMP:
		return "icmp"
	case CIDRProtocolAny:
		return "any"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(p))
	}
}

type EventReader interface {
	Read() (EgressEvent, error)
	Close() error
}
