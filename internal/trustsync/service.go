package trustsync

import (
	"context"
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

type DestinationDeleter interface {
	DeleteDestination(context.Context, Destination) error
}

type ServiceConfig struct {
	MaxStaleHold  time.Duration
	SweepInterval time.Duration
	Now           func() time.Time
	Conntrack     ConntrackInspector
	Deleter       DestinationDeleter
}

type Service struct {
	maxStaleHold  time.Duration
	sweepInterval time.Duration
	now           func() time.Time
	conntrack     ConntrackInspector
	deleter       DestinationDeleter

	mu           sync.Mutex
	hostLeases   map[string]map[Destination]struct{}
	destinations map[Destination]AggregateState
	runCancel    context.CancelFunc
	runDone      chan struct{}
}

const defaultSweepInterval = 30 * time.Second

func New(cfg ServiceConfig) *Service {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	sweepInterval := cfg.SweepInterval
	if sweepInterval <= 0 {
		sweepInterval = defaultSweepInterval
	}
	conntrack := cfg.Conntrack
	if conntrack == nil {
		conntrack = newConntrackInspector()
	}

	return &Service{
		maxStaleHold:  cfg.MaxStaleHold,
		sweepInterval: sweepInterval,
		now:           now,
		conntrack:     conntrack,
		deleter:       cfg.Deleter,
		hostLeases:    make(map[string]map[Destination]struct{}),
		destinations:  make(map[Destination]AggregateState),
	}
}

func (s *Service) Start(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.runCancel != nil {
		return nil
	}

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.runCancel = cancel
	s.runDone = done

	go s.runPruner(runCtx, done)
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	cancel := s.runCancel
	done := s.runDone
	s.runCancel = nil
	s.runDone = nil
	s.mu.Unlock()

	if cancel == nil || done == nil {
		return nil
	}

	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) runPruner(ctx context.Context, done chan struct{}) {
	ticker := time.NewTicker(s.sweepInterval)
	defer ticker.Stop()
	defer close(done)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.pruneStale(ctx)
		}
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

func (s *Service) ReconcileHostAnswers(host string, destinations []Destination) {
	s.ReplaceHostAnswers(host, destinations)
}

func (s *Service) PruneStale() []Destination {
	return s.pruneStale(context.Background())
}

func (s *Service) pruneStale(ctx context.Context) []Destination {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneStaleLocked(ctx, s.now())
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

func (s *Service) pruneStaleLocked(ctx context.Context, now time.Time) []Destination {
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
		if s.deleter != nil {
			if err := s.deleter.DeleteDestination(ctx, dst); err != nil {
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
