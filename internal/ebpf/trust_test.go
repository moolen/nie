package ebpf

import (
	"net/netip"
	"testing"
	"time"
)

func TestNewEntryClampsTTLToMax(t *testing.T) {
	now := time.Unix(1700000000, 0)
	entry, err := NewEntry("203.0.113.10", 600, now, 300*time.Second)
	if err != nil {
		t.Fatalf("NewEntry() error = %v", err)
	}
	if got, want := entry.IPv4, netip.MustParseAddr("203.0.113.10"); got != want {
		t.Fatalf("IPv4 = %v, want %v", got, want)
	}
	if got, want := entry.ExpiresAt.Unix(), now.Add(300*time.Second).Unix(); got != want {
		t.Fatalf("ExpiresAt = %d, want %d", got, want)
	}
}

func TestNewEntryClampsZeroTTLToMax(t *testing.T) {
	now := time.Unix(1700000000, 0)
	entry, err := NewEntry("203.0.113.10", 0, now, 300*time.Second)
	if err != nil {
		t.Fatalf("NewEntry() error = %v", err)
	}
	if got, want := entry.ExpiresAt.Unix(), now.Add(300*time.Second).Unix(); got != want {
		t.Fatalf("ExpiresAt = %d, want %d", got, want)
	}
}

func TestNewEntryRejectsInvalidIPv4(t *testing.T) {
	_, err := NewEntry("2001:db8::1", 60, time.Now(), 5*time.Minute)
	if err == nil {
		t.Fatal("NewEntry() error = nil, want invalid IPv4 error")
	}
}
