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
}

func TestAllowStoresIPv4Key(t *testing.T) {
	fake := newFakeMap()
	writer := NewTrustWriter(fake, time.Now)

	err := writer.Allow(context.Background(), TrustEntry{
		IPv4:      netip.MustParseAddr("203.0.113.10"),
		ExpiresAt: time.Unix(1700000600, 0),
	})
	if err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	if _, ok := fake.entries[[4]byte{203, 0, 113, 10}]; !ok {
		t.Fatal("IPv4 key not written to fake map")
	}
}
