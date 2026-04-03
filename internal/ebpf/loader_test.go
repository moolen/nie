package ebpf

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

type fakeMap struct {
	entries map[allowKey]allowValue
}

func newFakeMap() *fakeMap {
	return &fakeMap{
		entries: make(map[allowKey]allowValue),
	}
}

func (m *fakeMap) Put(key allowKey, value allowValue) error {
	m.entries[key] = value
	return nil
}

func TestPinnedPaths(t *testing.T) {
	paths := PinnedPaths("/sys/fs/bpf/nie")
	if paths.AllowMap != "/sys/fs/bpf/nie/allow_map" {
		t.Fatalf("AllowMap = %q", paths.AllowMap)
	}
	if paths.Events != "/sys/fs/bpf/nie/events" {
		t.Fatalf("Events = %q", paths.Events)
	}
}

func TestAllowStoresIPv4Key(t *testing.T) {
	fake := newFakeMap()
	prev := monotonicNowNs
	monotonicNowNs = func() (uint64, error) { return 1000, nil }
	t.Cleanup(func() { monotonicNowNs = prev })

	now := func() time.Time { return time.Unix(1700000000, 0) }
	writer := NewTrustWriter(fake, now)

	expiresAt := time.Unix(1700000600, 0)
	err := writer.Allow(context.Background(), TrustEntry{
		IPv4:      netip.MustParseAddr("203.0.113.10"),
		ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	wantKey := allowKey{203, 0, 113, 10}
	if _, ok := fake.entries[wantKey]; !ok {
		t.Fatal("IPv4 key not written to fake map")
	}
	if got := fake.entries[wantKey]; got.ExpiresAtMonoNs != 1000+600*1_000_000_000 {
		t.Fatalf("expiry = %d, want %d", got.ExpiresAtMonoNs, 1000+600*1_000_000_000)
	}
}

func TestAllowRejectsAlreadyExpired(t *testing.T) {
	fake := newFakeMap()
	now := func() time.Time { return time.Unix(1700000600, 0) }
	writer := NewTrustWriter(fake, now)

	expiresAt := time.Unix(1700000599, 0)
	err := writer.Allow(context.Background(), TrustEntry{
		IPv4:      netip.MustParseAddr("203.0.113.10"),
		ExpiresAt: expiresAt,
	})
	if err == nil {
		t.Fatal("Allow() error = nil, want expired error")
	}
	if len(fake.entries) != 0 {
		t.Fatalf("fake map has %d entries, want 0", len(fake.entries))
	}
}

func TestAllowAcceptsExpiryEqualNow(t *testing.T) {
	fake := newFakeMap()
	prev := monotonicNowNs
	monotonicNowNs = func() (uint64, error) { return 4242, nil }
	t.Cleanup(func() { monotonicNowNs = prev })

	now := func() time.Time { return time.Unix(1700000600, 0) }
	writer := NewTrustWriter(fake, now)

	expiresAt := time.Unix(1700000600, 0)
	err := writer.Allow(context.Background(), TrustEntry{
		IPv4:      netip.MustParseAddr("203.0.113.10"),
		ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	wantKey := allowKey{203, 0, 113, 10}
	if got, ok := fake.entries[wantKey]; !ok {
		t.Fatal("IPv4 key not written to fake map")
	} else if got.ExpiresAtMonoNs != 4242 {
		t.Fatalf("expiry = %d, want %d", got.ExpiresAtMonoNs, 4242)
	}
}

func TestMapValueEncodingIncludesExpiryMonotonicNanoseconds(t *testing.T) {
	now := time.Unix(1700000000, 0)
	entry := TrustEntry{
		IPv4:      netip.MustParseAddr("203.0.113.10"),
		ExpiresAt: time.Unix(1700000600, 0),
	}

	key, value := encodeEntry(entry, now, 1000)
	if key != [4]byte{203, 0, 113, 10} {
		t.Fatalf("key = %v", key)
	}
	if value.ExpiresAtMonoNs != 1000+600*1_000_000_000 {
		t.Fatalf("ExpiresAtMonoNs = %d", value.ExpiresAtMonoNs)
	}
}
