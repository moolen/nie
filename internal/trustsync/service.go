package trustsync

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

type Destination struct {
	IP       netip.Addr
	Port     uint16
	Protocol Protocol
}

type Protocol uint8

const (
	ProtocolUnspecified Protocol = 0
	ProtocolTCP         Protocol = 6
	ProtocolUDP         Protocol = 17
)

type AggregateState struct {
	RefCount   int
	Stale      bool
	StaleSince time.Time
}

type ConntrackInspector interface {
	HasActiveTCPFlow(dst Destination) (bool, error)
}

type ServiceConfig struct {
	MaxStaleHold time.Duration
	Now          func() time.Time
	Conntrack    ConntrackInspector
}

type Service struct {
	maxStaleHold time.Duration
	now          func() time.Time
	conntrack    ConntrackInspector

	mu           sync.Mutex
	hostLeases   map[string]map[Destination]struct{}
	destinations map[Destination]AggregateState
}

func New(cfg ServiceConfig) *Service {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	conntrack := cfg.Conntrack
	if conntrack == nil {
		conntrack = newConntrackInspector()
	}

	return &Service{
		maxStaleHold: cfg.MaxStaleHold,
		now:          now,
		conntrack:    conntrack,
		hostLeases:   make(map[string]map[Destination]struct{}),
		destinations: make(map[Destination]AggregateState),
	}
}

func (s *Service) ReplaceHostAnswers(host string, destinations []Destination) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()

	next := make(map[Destination]struct{}, len(destinations))
	for _, dst := range destinations {
		next[dst] = struct{}{}
	}

	prev := s.hostLeases[host]
	for dst := range prev {
		if _, stillPresent := next[dst]; stillPresent {
			continue
		}
		s.decrementRefLocked(dst, now)
	}

	for dst := range next {
		if _, alreadyPresent := prev[dst]; alreadyPresent {
			continue
		}
		s.incrementRefLocked(dst)
	}

	if len(next) == 0 {
		delete(s.hostLeases, host)
		return
	}
	s.hostLeases[host] = next
}

func (s *Service) PruneStale() []Destination {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneStaleLocked(s.now())
}

func (s *Service) State(dst Destination) (AggregateState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.destinations[dst]
	if !ok {
		return AggregateState{}, false
	}
	return state, true
}

func (s *Service) incrementRefLocked(dst Destination) {
	state := s.destinations[dst]
	state.RefCount++
	state.Stale = false
	state.StaleSince = time.Time{}
	s.destinations[dst] = state
}

func (s *Service) decrementRefLocked(dst Destination, now time.Time) {
	state, ok := s.destinations[dst]
	if !ok {
		return
	}
	if state.RefCount > 0 {
		state.RefCount--
	}
	if state.RefCount == 0 {
		state.Stale = true
		if state.StaleSince.IsZero() {
			state.StaleSince = now
		}
	}
	s.destinations[dst] = state
}

func (s *Service) pruneStaleLocked(now time.Time) []Destination {
	var pruned []Destination

	for dst, state := range s.destinations {
		if !state.Stale || state.RefCount != 0 || state.StaleSince.IsZero() {
			continue
		}
		if s.maxStaleHold > 0 && now.Sub(state.StaleSince) < s.maxStaleHold {
			continue
		}
		if dst.Protocol == ProtocolTCP && s.conntrack != nil {
			active, err := s.conntrack.HasActiveTCPFlow(dst)
			if err != nil {
				continue
			}
			if active {
				continue
			}
		}
		delete(s.destinations, dst)
		pruned = append(pruned, dst)
	}

	sort.Slice(pruned, func(i, j int) bool {
		if pruned[i].IP == pruned[j].IP {
			if pruned[i].Port == pruned[j].Port {
				return pruned[i].Protocol < pruned[j].Protocol
			}
			return pruned[i].Port < pruned[j].Port
		}
		return pruned[i].IP.Less(pruned[j].IP)
	})

	return pruned
}
