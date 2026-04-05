package trustsync

import (
	"context"
	"errors"
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
		Conntrack:    newFakeConntrackInspector(),
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
		Conntrack:    newFakeConntrackInspector(),
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
		Conntrack:    newFakeConntrackInspector(),
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
		Conntrack:    newFakeConntrackInspector(),
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
		Conntrack:    newFakeConntrackInspector(),
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
	conntrack := newFakeConntrackInspector()
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
	conntrack := newFakeConntrackInspector()
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

func TestPruneStaleSkipsTCPDestinationWhenConntrackErrors(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	conntrack := newFakeConntrackInspector()
	refresher := newFakeDestinationRefresher()
	svc := New(ServiceConfig{
		MaxStaleHold: 1 * time.Minute,
		Now:          clock,
		Conntrack:    conntrack,
		Refresher:    refresher,
	})

	dst := mustDestinationWithProtocol(t, "203.0.113.30", 443, ProtocolTCP)
	conntrack.errByDestination[dst] = errors.New("conntrack unavailable")

	svc.ReplaceHostAnswers("api.example.com", []Destination{dst})
	now = now.Add(10 * time.Second)
	svc.ReplaceHostAnswers("api.example.com", nil)
	refresher.calls = nil

	now = now.Add(2 * time.Minute)
	pruned := svc.PruneStale()
	if len(pruned) != 0 {
		t.Fatalf("PruneStale() pruned %v, want no prune when conntrack lookup errors", pruned)
	}
	assertState(t, svc, dst, AggregateState{
		RefCount:   0,
		Stale:      true,
		StaleSince: time.Date(2026, 4, 5, 12, 0, 10, 0, time.UTC),
	})
	if len(refresher.calls) != 0 {
		t.Fatalf("refresher calls = %v, want none on conntrack error", refresher.calls)
	}
}

func TestPruneStaleDeletesThroughConfiguredDeleter(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	deleter := newFakeDestinationDeleter()
	svc := New(ServiceConfig{
		MaxStaleHold: 1 * time.Minute,
		Now:          clock,
		Conntrack:    newFakeConntrackInspector(),
		Deleter:      deleter,
	})

	dst := mustDestinationWithProtocol(t, "203.0.113.40", 443, ProtocolTCP)

	svc.ReplaceHostAnswers("api.example.com", []Destination{dst})
	now = now.Add(10 * time.Second)
	svc.ReplaceHostAnswers("api.example.com", nil)

	now = now.Add(2 * time.Minute)
	pruned := svc.PruneStale()
	if len(pruned) != 1 || pruned[0] != dst {
		t.Fatalf("PruneStale() = %v, want [%v]", pruned, dst)
	}
	if len(deleter.calls) != 1 || deleter.calls[0] != dst {
		t.Fatalf("deleter calls = %v, want [%v]", deleter.calls, dst)
	}
	if _, ok := svc.State(dst); ok {
		t.Fatalf("State(%v) present after successful delete, want absent", dst)
	}
}

func TestPruneStaleKeepsStateWhenDeleterFails(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	deleter := newFakeDestinationDeleter()
	refresher := newFakeDestinationRefresher()
	svc := New(ServiceConfig{
		MaxStaleHold: 1 * time.Minute,
		Now:          clock,
		Conntrack:    newFakeConntrackInspector(),
		Deleter:      deleter,
		Refresher:    refresher,
	})

	dst := mustDestinationWithProtocol(t, "203.0.113.41", 443, ProtocolTCP)
	deleter.errByDestination[dst] = errors.New("delete failed")

	svc.ReplaceHostAnswers("api.example.com", []Destination{dst})
	now = now.Add(10 * time.Second)
	svc.ReplaceHostAnswers("api.example.com", nil)
	refresher.calls = nil

	now = now.Add(2 * time.Minute)
	pruned := svc.PruneStale()
	if len(pruned) != 0 {
		t.Fatalf("PruneStale() = %v, want no successful prunes on delete failure", pruned)
	}
	if len(deleter.calls) != 1 || deleter.calls[0] != dst {
		t.Fatalf("deleter calls = %v, want [%v]", deleter.calls, dst)
	}
	assertState(t, svc, dst, AggregateState{
		RefCount:   0,
		Stale:      true,
		StaleSince: time.Date(2026, 4, 5, 12, 0, 10, 0, time.UTC),
	})
	if len(refresher.calls) != 0 {
		t.Fatalf("refresher calls = %v, want none on delete failure", refresher.calls)
	}
}

func TestReplaceHostAnswersRefreshesDestinationWhenItBecomesStaleWithinConfiguredHold(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	refresher := newFakeDestinationRefresher()
	svc := New(ServiceConfig{
		MaxStaleHold:  1 * time.Minute,
		SweepInterval: 30 * time.Second,
		Now:           clock,
		Conntrack:     newFakeConntrackInspector(),
		Refresher:     refresher,
	})

	dst := mustDestinationWithProtocol(t, "203.0.113.50", 443, ProtocolTCP)

	svc.ReplaceHostAnswers("api.example.com", []Destination{dst})
	now = now.Add(10 * time.Second)
	svc.ReplaceHostAnswers("api.example.com", nil)

	if len(refresher.calls) != 1 {
		t.Fatalf("refresher calls = %v, want one call", refresher.calls)
	}
	if refresher.calls[0].dst != dst {
		t.Fatalf("refresher dst = %v, want %v", refresher.calls[0].dst, dst)
	}
	if got, want := refresher.calls[0].expiresAt, now.Add(60*time.Second); !got.Equal(want) {
		t.Fatalf("refresher expiresAt = %v, want %v", got, want)
	}
}

func TestReplaceHostAnswersDoesNotRefreshStaleDestinationWithoutHoldOrActiveFlow(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	refresher := newFakeDestinationRefresher()
	svc := New(ServiceConfig{
		MaxStaleHold:  0,
		SweepInterval: 30 * time.Second,
		Now:           clock,
		Conntrack:     newFakeConntrackInspector(),
		Refresher:     refresher,
	})

	dst := mustDestinationWithProtocol(t, "203.0.113.60", 443, ProtocolUDP)

	svc.ReplaceHostAnswers("api.example.com", []Destination{dst})
	now = now.Add(10 * time.Second)
	svc.ReplaceHostAnswers("api.example.com", nil)

	if len(refresher.calls) != 0 {
		t.Fatalf("refresher calls = %v, want no refresh without hold or active flow", refresher.calls)
	}
}

func TestReplaceHostAnswersRefreshesStaleDestinationWhenActiveTCPFlowIsConfirmed(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	conntrack := newFakeConntrackInspector()
	refresher := newFakeDestinationRefresher()
	svc := New(ServiceConfig{
		MaxStaleHold:  0,
		SweepInterval: 30 * time.Second,
		Now:           clock,
		Conntrack:     conntrack,
		Refresher:     refresher,
	})

	dst := mustDestinationWithProtocol(t, "203.0.113.61", 443, ProtocolTCP)
	conntrack.activeByDestination[dst] = true

	svc.ReplaceHostAnswers("api.example.com", []Destination{dst})
	now = now.Add(10 * time.Second)
	svc.ReplaceHostAnswers("api.example.com", nil)

	if len(refresher.calls) != 1 {
		t.Fatalf("refresher calls = %v, want one refresh for active TCP flow", refresher.calls)
	}
	if refresher.calls[0].dst != dst {
		t.Fatalf("refresher dst = %v, want %v", refresher.calls[0].dst, dst)
	}
	if got, want := refresher.calls[0].expiresAt, now.Add(60*time.Second); !got.Equal(want) {
		t.Fatalf("refresher expiresAt = %v, want %v", got, want)
	}
}

func TestReplaceHostAnswersDoesNotRefreshStaleDestinationWhenConntrackLookupErrors(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	conntrack := newFakeConntrackInspector()
	refresher := newFakeDestinationRefresher()
	svc := New(ServiceConfig{
		MaxStaleHold:  0,
		SweepInterval: 30 * time.Second,
		Now:           clock,
		Conntrack:     conntrack,
		Refresher:     refresher,
	})

	dst := mustDestinationWithProtocol(t, "203.0.113.62", 443, ProtocolTCP)
	conntrack.errByDestination[dst] = errors.New("conntrack unavailable")

	svc.ReplaceHostAnswers("api.example.com", []Destination{dst})
	now = now.Add(10 * time.Second)
	svc.ReplaceHostAnswers("api.example.com", nil)

	if len(refresher.calls) != 0 {
		t.Fatalf("refresher calls = %v, want no refresh when conntrack lookup errors", refresher.calls)
	}
}

func TestPruneStaleRefreshesDestinationWhenRetainedByActiveConntrack(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	conntrack := newFakeConntrackInspector()
	refresher := newFakeDestinationRefresher()
	svc := New(ServiceConfig{
		MaxStaleHold:  1 * time.Minute,
		SweepInterval: 30 * time.Second,
		Now:           clock,
		Conntrack:     conntrack,
		Refresher:     refresher,
	})

	dst := mustDestinationWithProtocol(t, "203.0.113.51", 443, ProtocolTCP)
	conntrack.activeByDestination[dst] = true

	svc.ReplaceHostAnswers("api.example.com", []Destination{dst})
	now = now.Add(10 * time.Second)
	svc.ReplaceHostAnswers("api.example.com", nil)
	refresher.calls = nil

	now = now.Add(2 * time.Minute)
	pruned := svc.PruneStale()
	if len(pruned) != 0 {
		t.Fatalf("PruneStale() pruned %v, want none while conntrack active", pruned)
	}
	if len(refresher.calls) != 1 {
		t.Fatalf("refresher calls = %v, want one call", refresher.calls)
	}
	if refresher.calls[0].dst != dst {
		t.Fatalf("refresher dst = %v, want %v", refresher.calls[0].dst, dst)
	}
	if got, want := refresher.calls[0].expiresAt, now.Add(60*time.Second); !got.Equal(want) {
		t.Fatalf("refresher expiresAt = %v, want %v", got, want)
	}
}

func TestPruneStaleRefreshesRetainedDestinationWithMinimumFutureExpiry(t *testing.T) {
	now := time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	conntrack := newFakeConntrackInspector()
	refresher := newFakeDestinationRefresher()
	svc := New(ServiceConfig{
		MaxStaleHold:  0,
		SweepInterval: 1 * time.Nanosecond,
		Now:           clock,
		Conntrack:     conntrack,
		Refresher:     refresher,
	})

	dst := mustDestinationWithProtocol(t, "203.0.113.52", 443, ProtocolTCP)
	conntrack.activeByDestination[dst] = true

	svc.ReplaceHostAnswers("api.example.com", []Destination{dst})
	now = now.Add(10 * time.Second)
	svc.ReplaceHostAnswers("api.example.com", nil)
	refresher.calls = nil

	pruned := svc.PruneStale()
	if len(pruned) != 0 {
		t.Fatalf("PruneStale() pruned %v, want none while conntrack active", pruned)
	}
	if len(refresher.calls) != 1 {
		t.Fatalf("refresher calls = %v, want one call", refresher.calls)
	}
	if got, want := refresher.calls[0].expiresAt, now.Add(minRetainedRefreshTTL); !got.Equal(want) {
		t.Fatalf("refresher expiresAt = %v, want %v", got, want)
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
	errByDestination    map[Destination]error
	calls               int
}

func newFakeConntrackInspector() *fakeConntrackInspector {
	return &fakeConntrackInspector{
		activeByDestination: map[Destination]bool{},
		errByDestination:    map[Destination]error{},
	}
}

func (f *fakeConntrackInspector) HasActiveTCPFlow(dst Destination) (bool, error) {
	f.calls++
	if err := f.errByDestination[dst]; err != nil {
		return false, err
	}
	return f.activeByDestination[dst], nil
}

type fakeDestinationDeleter struct {
	errByDestination map[Destination]error
	calls            []Destination
}

func newFakeDestinationDeleter() *fakeDestinationDeleter {
	return &fakeDestinationDeleter{
		errByDestination: map[Destination]error{},
	}
}

func (f *fakeDestinationDeleter) DeleteDestination(_ context.Context, dst Destination) error {
	f.calls = append(f.calls, dst)
	if err := f.errByDestination[dst]; err != nil {
		return err
	}
	return nil
}

type fakeDestinationRefresher struct {
	calls []refreshCall
}

type refreshCall struct {
	dst       Destination
	expiresAt time.Time
}

func newFakeDestinationRefresher() *fakeDestinationRefresher {
	return &fakeDestinationRefresher{}
}

func (f *fakeDestinationRefresher) RefreshDestination(_ context.Context, dst Destination, expiresAt time.Time) error {
	f.calls = append(f.calls, refreshCall{
		dst:       dst,
		expiresAt: expiresAt,
	})
	return nil
}
