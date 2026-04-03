package ebpf

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

type Paths struct {
	AllowMap string
	Events   string
}

func PinnedPaths(root string) Paths {
	return Paths{
		AllowMap: filepath.Join(root, "allow_map"),
		Events:   filepath.Join(root, "events"),
	}
}

// allowKey/allowValue mirror bpf/include/common.h structs:
//   struct allow_key { __u8 addr[4]; };
//   struct allow_value { __u64 expires_at_mono_ns; };
type allowKey = [4]byte

type allowValue struct {
	ExpiresAtMonoNs uint64
}

type allowMap interface {
	Put(key allowKey, value allowValue) error
}

var monotonicNowNs = func() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

func encodeEntry(entry TrustEntry, now time.Time, nowMonoNs uint64) (allowKey, allowValue) {
	d := entry.ExpiresAt.Sub(now)
	dNs := d.Nanoseconds()
	if dNs < 0 {
		// Callers should reject expired entries before encoding, but keep this safe.
		return entry.IPv4.As4(), allowValue{ExpiresAtMonoNs: nowMonoNs}
	}
	if uint64(dNs) > math.MaxUint64-nowMonoNs {
		return entry.IPv4.As4(), allowValue{ExpiresAtMonoNs: math.MaxUint64}
	}
	return entry.IPv4.As4(), allowValue{ExpiresAtMonoNs: nowMonoNs + uint64(dNs)}
}

type trustWriter struct {
	m   allowMap
	now func() time.Time
}

func NewTrustWriter(m allowMap, now func() time.Time) TrustWriter {
	if now == nil {
		now = time.Now
	}
	return &trustWriter{
		m:   m,
		now: now,
	}
}

func (w *trustWriter) Allow(_ context.Context, entry TrustEntry) error {
	if !entry.IPv4.Is4() {
		return fmt.Errorf("invalid IPv4: %q", entry.IPv4.String())
	}
	if entry.ExpiresAt.IsZero() {
		return fmt.Errorf("invalid ExpiresAt: zero time")
	}

	nowWall := w.now()
	if entry.ExpiresAt.Before(nowWall) {
		return fmt.Errorf("entry expired at %s (now %s)", entry.ExpiresAt.UTC().Format(time.RFC3339), nowWall.UTC().Format(time.RFC3339))
	}
	nowMono, err := monotonicNowNs()
	if err != nil {
		return fmt.Errorf("monotonic time: %w", err)
	}

	key, value := encodeEntry(entry, nowWall, nowMono)
	return w.m.Put(key, value)
}
