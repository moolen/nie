package ebpf

import (
	"context"
	"fmt"
	"path/filepath"
	"time"
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

type allowMap interface {
	Put(key [4]byte, expiresAtUnix uint64) error
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

	key := entry.IPv4.As4()
	expiresAtUnixSigned := entry.ExpiresAt.Unix()
	if expiresAtUnixSigned <= 0 {
		return fmt.Errorf("invalid ExpiresAt: %s", entry.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if nowUnix := w.now().Unix(); expiresAtUnixSigned <= nowUnix {
		return fmt.Errorf("entry expired at %d (now %d)", expiresAtUnixSigned, nowUnix)
	}
	expiresAtUnix := uint64(expiresAtUnixSigned)

	return w.m.Put(key, expiresAtUnix)
}
