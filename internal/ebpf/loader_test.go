package ebpf

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

type fakeMap struct {
	entries map[[4]byte]uint64
}

func newFakeMap() *fakeMap {
	return &fakeMap{
		entries: make(map[[4]byte]uint64),
	}
}

func (m *fakeMap) Put(key [4]byte, value uint64) error {
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
	if _, ok := fake.entries[[4]byte{203, 0, 113, 10}]; !ok {
		t.Fatal("IPv4 key not written to fake map")
	}
	if got, ok := fake.entries[[4]byte{203, 0, 113, 10}]; !ok || got != uint64(expiresAt.Unix()) {
		t.Fatalf("expiry = %d, want %d", got, expiresAt.Unix())
	}
}

func TestAllowRejectsAlreadyExpired(t *testing.T) {
	fake := newFakeMap()
	now := func() time.Time { return time.Unix(1700000600, 0) }
	writer := NewTrustWriter(fake, now)

	expiresAt := time.Unix(1700000600, 0)
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
