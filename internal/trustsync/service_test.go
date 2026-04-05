package trustsync

import (
	"net/netip"
	"testing"
	"time"
)

func TestReplaceHostAnswersReplacesSet(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	svc := New(ServiceConfig{
		MaxStaleHold: 10 * time.Minute,
		Now:          clock,
	})

	dstA := mustDestination(t, "203.0.113.10", 443)
	dstB := mustDestination(t, "203.0.113.11", 443)

	svc.ReplaceHostAnswers("api.example.com", []Destination{dstA, dstB})

	assertState(t, svc, dstA, AggregateState{RefCount: 1})
	assertState(t, svc, dstB, AggregateState{RefCount: 1})

	now = now.Add(30 * time.Second)
	svc.ReplaceHostAnswers("api.example.com", []Destination{dstB})

	assertState(t, svc, dstB, AggregateState{RefCount: 1})
	assertState(t, svc, dstA, AggregateState{
		RefCount:   0,
		Stale:      true,
		StaleSince: now,
	})
}

func TestReplaceHostAnswersSharedDestinationReferences(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	svc := New(ServiceConfig{
		MaxStaleHold: 10 * time.Minute,
		Now:          clock,
	})

	dst := mustDestination(t, "203.0.113.10", 443)

	svc.ReplaceHostAnswers("api.example.com", []Destination{dst})
	svc.ReplaceHostAnswers("cdn.example.com", []Destination{dst})

	assertState(t, svc, dst, AggregateState{RefCount: 2})

	now = now.Add(45 * time.Second)
	svc.ReplaceHostAnswers("api.example.com", nil)
	assertState(t, svc, dst, AggregateState{RefCount: 1})

	now = now.Add(15 * time.Second)
	svc.ReplaceHostAnswers("cdn.example.com", nil)
	assertState(t, svc, dst, AggregateState{
		RefCount:   0,
		Stale:      true,
		StaleSince: now,
	})
}

func TestReplaceHostAnswersMarksDroppedDestinationStale(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	svc := New(ServiceConfig{
		MaxStaleHold: 10 * time.Minute,
		Now:          clock,
	})

	dst := mustDestination(t, "203.0.113.10", 443)
	svc.ReplaceHostAnswers("api.example.com", []Destination{dst})

	now = now.Add(1 * time.Minute)
	svc.ReplaceHostAnswers("api.example.com", nil)

	assertState(t, svc, dst, AggregateState{
		RefCount:   0,
		Stale:      true,
		StaleSince: now,
	})

	now = now.Add(2 * time.Minute)
	svc.ReplaceHostAnswers("api.example.com", []Destination{dst})
	assertState(t, svc, dst, AggregateState{RefCount: 1})
}

func TestPruneStaleRemovesAfterMaxHold(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	svc := New(ServiceConfig{
		MaxStaleHold: 3 * time.Minute,
		Now:          clock,
	})

	dst := mustDestination(t, "203.0.113.10", 443)

	svc.ReplaceHostAnswers("api.example.com", []Destination{dst})
	now = now.Add(30 * time.Second)
	svc.ReplaceHostAnswers("api.example.com", nil)

	now = now.Add(2*time.Minute + 29*time.Second)
	pruned := svc.PruneStale()
	if len(pruned) != 0 {
		t.Fatalf("PruneStale() pruned %v, want none before max hold", pruned)
	}

	assertState(t, svc, dst, AggregateState{
		RefCount:   0,
		Stale:      true,
		StaleSince: time.Date(2026, 4, 5, 12, 0, 30, 0, time.UTC),
	})

	now = now.Add(31 * time.Second)
	pruned = svc.PruneStale()
	if len(pruned) != 1 || pruned[0] != dst {
		t.Fatalf("PruneStale() = %v, want [%v]", pruned, dst)
	}

	if _, ok := svc.State(dst); ok {
		t.Fatalf("State(%v) present after prune, want absent", dst)
	}
}

func TestReplaceHostAnswersDoesNotImplicitlyPruneExpiredStale(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	svc := New(ServiceConfig{
		MaxStaleHold: 1 * time.Minute,
		Now:          clock,
	})

	staleDst := mustDestination(t, "203.0.113.10", 443)
	activeDst := mustDestination(t, "203.0.113.11", 443)

	svc.ReplaceHostAnswers("api.example.com", []Destination{staleDst})
	now = now.Add(10 * time.Second)
	svc.ReplaceHostAnswers("api.example.com", nil)

	now = now.Add(2 * time.Minute)
	svc.ReplaceHostAnswers("cdn.example.com", []Destination{activeDst})

	assertState(t, svc, staleDst, AggregateState{
		RefCount:   0,
		Stale:      true,
		StaleSince: time.Date(2026, 4, 5, 12, 0, 10, 0, time.UTC),
	})
	assertState(t, svc, activeDst, AggregateState{RefCount: 1})

	pruned := svc.PruneStale()
	if len(pruned) != 1 || pruned[0] != staleDst {
		t.Fatalf("PruneStale() = %v, want [%v]", pruned, staleDst)
	}
}

func TestPruneStalePinsTCPDestinationWhileConntrackActive(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	conntrack := &fakeConntrackInspector{
		activeByDestination: map[Destination]bool{},
	}
	svc := New(ServiceConfig{
		MaxStaleHold: 1 * time.Minute,
		Now:          clock,
		Conntrack:    conntrack,
	})

	dst := mustDestinationWithProtocol(t, "203.0.113.10", 443, ProtocolTCP)
	conntrack.activeByDestination[dst] = true

	svc.ReplaceHostAnswers("api.example.com", []Destination{dst})
	now = now.Add(10 * time.Second)
	svc.ReplaceHostAnswers("api.example.com", nil)

	now = now.Add(2 * time.Minute)
	pruned := svc.PruneStale()
	if len(pruned) != 0 {
		t.Fatalf("PruneStale() pruned %v, want no prune while conntrack active", pruned)
	}
	assertState(t, svc, dst, AggregateState{
		RefCount:   0,
		Stale:      true,
		StaleSince: time.Date(2026, 4, 5, 12, 0, 10, 0, time.UTC),
	})

	conntrack.activeByDestination[dst] = false
	pruned = svc.PruneStale()
	if len(pruned) != 1 || pruned[0] != dst {
		t.Fatalf("PruneStale() = %v, want [%v] when conntrack is idle", pruned, dst)
	}
}

func TestPruneStaleIgnoresConntrackForUDP(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	conntrack := &fakeConntrackInspector{
		activeByDestination: map[Destination]bool{},
	}
	svc := New(ServiceConfig{
		MaxStaleHold: 1 * time.Minute,
		Now:          clock,
		Conntrack:    conntrack,
	})

	dst := mustDestinationWithProtocol(t, "203.0.113.20", 53, ProtocolUDP)
	conntrack.activeByDestination[dst] = true

	svc.ReplaceHostAnswers("dns.example.com", []Destination{dst})
	now = now.Add(5 * time.Second)
	svc.ReplaceHostAnswers("dns.example.com", nil)

	now = now.Add(2 * time.Minute)
	pruned := svc.PruneStale()
	if len(pruned) != 1 || pruned[0] != dst {
		t.Fatalf("PruneStale() = %v, want UDP destination pruned regardless of conntrack", pruned)
	}
	if conntrack.calls != 0 {
		t.Fatalf("conntrack calls = %d, want 0 for UDP prune", conntrack.calls)
	}
}

func assertState(t *testing.T, svc *Service, dst Destination, want AggregateState) {
	t.Helper()
	got, ok := svc.State(dst)
	if !ok {
		t.Fatalf("State(%v) missing", dst)
	}
	if got.RefCount != want.RefCount {
		t.Fatalf("State(%v).RefCount = %d, want %d", dst, got.RefCount, want.RefCount)
	}
	if got.Stale != want.Stale {
		t.Fatalf("State(%v).Stale = %v, want %v", dst, got.Stale, want.Stale)
	}
	if !got.StaleSince.Equal(want.StaleSince) {
		t.Fatalf("State(%v).StaleSince = %v, want %v", dst, got.StaleSince, want.StaleSince)
	}
}

func mustDestination(t *testing.T, rawIP string, port uint16) Destination {
	t.Helper()
	return mustDestinationWithProtocol(t, rawIP, port, ProtocolTCP)
}

func mustDestinationWithProtocol(t *testing.T, rawIP string, port uint16, protocol Protocol) Destination {
	t.Helper()
	ip, err := netip.ParseAddr(rawIP)
	if err != nil {
		t.Fatalf("ParseAddr(%q) error = %v", rawIP, err)
	}
	if !ip.Is4() {
		t.Fatalf("ParseAddr(%q) = %v, want IPv4", rawIP, ip)
	}
	return Destination{
		IP:   ip,
		Port: port,
		// Keep tests explicit about transport to validate pruning behavior.
		Protocol: protocol,
	}
}

type fakeConntrackInspector struct {
	activeByDestination map[Destination]bool
	calls               int
}

func (f *fakeConntrackInspector) HasActiveTCPFlow(dst Destination) (bool, error) {
	f.calls++
	return f.activeByDestination[dst], nil
}
