package ebpf

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strconv"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/moolen/nie/internal/config"
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

func TestManagerStartPreparesBpffsLoadsObjectsAndAttachesTC(t *testing.T) {
	recorder := &callRecorder{}
	host := &fakeHostOps{recorder: recorder}
	objects := &fakeRuntimeObjects{
		recorder:  recorder,
		allow:     newFakeMap(),
		programFD: 77,
	}
	loader := &fakeObjectLoader{
		recorder: recorder,
		objects:  objects,
	}
	tc := &fakeTCOps{recorder: recorder}

	manager, err := NewManager(ManagerConfig{
		Interface:  "eth0",
		Mode:       config.ModeAudit,
		BypassMark: 42,
	}, Dependencies{
		Host:   host,
		Loader: loader,
		TC:     tc,
		Now:    func() time.Time { return time.Unix(1700000000, 0) },
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	wantCalls := []string{
		"host.ensureDir:/sys/fs/bpf",
		"host.bpffsMounted:/sys/fs/bpf",
		"host.mountBPFFS:/sys/fs/bpf",
		"host.ensureDir:/sys/fs/bpf/nie",
		"loader.load",
		"objects.setMode:1",
		"objects.setBypassMark:42",
		"objects.pinMaps:/sys/fs/bpf/nie/allow_map:/sys/fs/bpf/nie/events",
		"tc.ensureClsact:eth0",
		"objects.programFD:77",
		"tc.attachEgress:eth0:77:nie_egress",
	}
	assertCalls(t, recorder.calls, wantCalls)
	if objects.mode != 1 {
		t.Fatalf("cfg_mode = %d, want 1", objects.mode)
	}
	if objects.bypassMark != 42 {
		t.Fatalf("cfg_bypass_mark = %d, want 42", objects.bypassMark)
	}
	if objects.pinned.AllowMap != "/sys/fs/bpf/nie/allow_map" {
		t.Fatalf("AllowMap pin = %q", objects.pinned.AllowMap)
	}
	if objects.pinned.Events != "/sys/fs/bpf/nie/events" {
		t.Fatalf("Events pin = %q", objects.pinned.Events)
	}
}

func TestManagerTrustWriterFailsBeforeStart(t *testing.T) {
	recorder := &callRecorder{}
	allowMap := newFakeMap()
	manager, err := NewManager(ManagerConfig{
		Interface:  "eth0",
		Mode:       config.ModeEnforce,
		BypassMark: 7,
	}, Dependencies{
		Host: &fakeHostOps{
			recorder:     recorder,
			bpffsMounted: true,
		},
		Loader: &fakeObjectLoader{
			recorder: recorder,
			objects: &fakeRuntimeObjects{
				recorder:  recorder,
				allow:     allowMap,
				programFD: 55,
			},
		},
		TC:  &fakeTCOps{recorder: recorder},
		Now: func() time.Time { return time.Unix(1700000000, 0) },
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if _, err := manager.TrustWriter(); !errors.Is(err, ErrManagerNotStarted) {
		t.Fatalf("TrustWriter() before Start() error = %v, want %v", err, ErrManagerNotStarted)
	}

	prev := monotonicNowNs
	monotonicNowNs = func() (uint64, error) { return 4242, nil }
	t.Cleanup(func() { monotonicNowNs = prev })

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	writer, err := manager.TrustWriter()
	if err != nil {
		t.Fatalf("TrustWriter() after Start() error = %v", err)
	}

	err = writer.Allow(context.Background(), TrustEntry{
		IPv4:      netip.MustParseAddr("203.0.113.10"),
		ExpiresAt: time.Unix(1700000300, 0),
	})
	if err != nil {
		t.Fatalf("Allow() error = %v", err)
	}

	wantKey := allowKey{203, 0, 113, 10}
	if _, ok := allowMap.entries[wantKey]; !ok {
		t.Fatal("TrustWriter() did not write through to allow map")
	}
}

func TestManagerEventReaderFailsBeforeStart(t *testing.T) {
	manager, err := NewManager(ManagerConfig{
		Interface:  "eth0",
		Mode:       config.ModeAudit,
		BypassMark: 7,
	}, Dependencies{
		Host: &fakeHostOps{
			recorder:     &callRecorder{},
			bpffsMounted: true,
		},
		Loader: &fakeObjectLoader{
			recorder: &callRecorder{},
			objects: &fakeRuntimeObjects{
				recorder: &callRecorder{},
				allow:    newFakeMap(),
				events:   &cebpf.Map{},
			},
		},
		TC: &fakeTCOps{recorder: &callRecorder{}},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if _, err := manager.EventReader(); !errors.Is(err, ErrManagerNotStarted) {
		t.Fatalf("EventReader() before Start() error = %v, want %v", err, ErrManagerNotStarted)
	}
}

func TestManagerEventReaderAfterStartUsesReaderFactory(t *testing.T) {
	recorder := &callRecorder{}
	manager, err := NewManager(ManagerConfig{
		Interface:  "eth0",
		Mode:       config.ModeAudit,
		BypassMark: 7,
	}, Dependencies{
		Host: &fakeHostOps{
			recorder:     recorder,
			bpffsMounted: true,
		},
		Loader: &fakeObjectLoader{
			recorder: recorder,
			objects: &fakeRuntimeObjects{
				recorder:  recorder,
				allow:     newFakeMap(),
				events:    &cebpf.Map{},
				programFD: 55,
			},
		},
		TC: &fakeTCOps{recorder: recorder},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	prevFactory := newEventReader
	fakeReader := &fakeEventReader{}
	newEventReader = func(*cebpf.Map) (EventReader, error) { return fakeReader, nil }
	t.Cleanup(func() { newEventReader = prevFactory })

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	reader, err := manager.EventReader()
	if err != nil {
		t.Fatalf("EventReader() after Start() error = %v", err)
	}
	if reader != fakeReader {
		t.Fatalf("EventReader() reader = %#v, want %#v", reader, fakeReader)
	}
}

func TestManagerStopDetachesAndCleansPinnedState(t *testing.T) {
	recorder := &callRecorder{}
	host := &fakeHostOps{
		recorder:     recorder,
		bpffsMounted: true,
	}
	objects := &fakeRuntimeObjects{
		recorder:  recorder,
		allow:     newFakeMap(),
		programFD: 99,
	}
	manager, err := NewManager(ManagerConfig{
		Interface:  "eth0",
		Mode:       config.ModeEnforce,
		BypassMark: 9,
	}, Dependencies{
		Host: host,
		Loader: &fakeObjectLoader{
			recorder: recorder,
			objects:  objects,
		},
		TC:  &fakeTCOps{recorder: recorder, clsactCreated: true},
		Now: func() time.Time { return time.Unix(1700000000, 0) },
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	wantCalls := []string{
		"host.ensureDir:/sys/fs/bpf",
		"host.bpffsMounted:/sys/fs/bpf",
		"host.ensureDir:/sys/fs/bpf/nie",
		"loader.load",
		"objects.setMode:0",
		"objects.setBypassMark:9",
		"objects.pinMaps:/sys/fs/bpf/nie/allow_map:/sys/fs/bpf/nie/events",
		"tc.ensureClsact:eth0",
		"objects.programFD:99",
		"tc.attachEgress:eth0:99:nie_egress",
		"tc.detachEgress:eth0:nie_egress",
		"objects.close",
		"host.removeAll:/sys/fs/bpf/nie",
		"tc.removeClsact:eth0",
	}
	assertCalls(t, recorder.calls, wantCalls)
	if objects.closeCalls != 1 {
		t.Fatalf("object close count = %d, want 1", objects.closeCalls)
	}
	if !reflect.DeepEqual(host.removed, []string{"/sys/fs/bpf/nie"}) {
		t.Fatalf("removed paths = %v, want [/sys/fs/bpf/nie]", host.removed)
	}
}

func TestManagerStopLeavesPreexistingClsactInPlace(t *testing.T) {
	recorder := &callRecorder{}
	host := &fakeHostOps{
		recorder:     recorder,
		bpffsMounted: true,
	}
	tc := &fakeTCOps{recorder: recorder, clsactCreated: false}
	manager, err := NewManager(ManagerConfig{
		Interface:  "eth0",
		Mode:       config.ModeEnforce,
		BypassMark: 9,
	}, Dependencies{
		Host: host,
		Loader: &fakeObjectLoader{
			recorder: recorder,
			objects: &fakeRuntimeObjects{
				recorder:  recorder,
				allow:     newFakeMap(),
				programFD: 99,
			},
		},
		TC:  tc,
		Now: func() time.Time { return time.Unix(1700000000, 0) },
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if tc.removeClsactCalls != 0 {
		t.Fatalf("remove clsact call count = %d, want 0", tc.removeClsactCalls)
	}
}

func TestManagerStartCleansUpWhenAttachFails(t *testing.T) {
	recorder := &callRecorder{}
	host := &fakeHostOps{
		recorder:     recorder,
		bpffsMounted: true,
	}
	objects := &fakeRuntimeObjects{
		recorder:  recorder,
		allow:     newFakeMap(),
		programFD: 88,
	}
	attachErr := errors.New("attach failed")

	manager, err := NewManager(ManagerConfig{
		Interface:  "eth0",
		Mode:       config.ModeEnforce,
		BypassMark: 3,
	}, Dependencies{
		Host: host,
		Loader: &fakeObjectLoader{
			recorder: recorder,
			objects:  objects,
		},
		TC:  &fakeTCOps{recorder: recorder, attachErr: attachErr},
		Now: func() time.Time { return time.Unix(1700000000, 0) },
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	err = manager.Start(context.Background())
	if !errors.Is(err, attachErr) {
		t.Fatalf("Start() error = %v, want wrapped %v", err, attachErr)
	}

	wantCalls := []string{
		"host.ensureDir:/sys/fs/bpf",
		"host.bpffsMounted:/sys/fs/bpf",
		"host.ensureDir:/sys/fs/bpf/nie",
		"loader.load",
		"objects.setMode:0",
		"objects.setBypassMark:3",
		"objects.pinMaps:/sys/fs/bpf/nie/allow_map:/sys/fs/bpf/nie/events",
		"tc.ensureClsact:eth0",
		"objects.programFD:88",
		"tc.attachEgress:eth0:88:nie_egress",
		"objects.close",
		"host.removeAll:/sys/fs/bpf/nie",
	}
	assertCalls(t, recorder.calls, wantCalls)
	if objects.closeCalls != 1 {
		t.Fatalf("object close count = %d, want 1", objects.closeCalls)
	}
	if !reflect.DeepEqual(host.removed, []string{"/sys/fs/bpf/nie"}) {
		t.Fatalf("removed paths = %v, want [/sys/fs/bpf/nie]", host.removed)
	}
	if _, err := manager.TrustWriter(); !errors.Is(err, ErrManagerNotStarted) {
		t.Fatalf("TrustWriter() after failed Start() error = %v, want %v", err, ErrManagerNotStarted)
	}
}

func TestManagerStopPropagatesDetachFailure(t *testing.T) {
	recorder := &callRecorder{}
	detachErr := errors.New("detach failed")
	host := &fakeHostOps{
		recorder:     recorder,
		bpffsMounted: true,
	}
	manager, err := NewManager(ManagerConfig{
		Interface:  "eth0",
		Mode:       config.ModeEnforce,
		BypassMark: 3,
	}, Dependencies{
		Host: host,
		Loader: &fakeObjectLoader{
			recorder: recorder,
			objects: &fakeRuntimeObjects{
				recorder:  recorder,
				allow:     newFakeMap(),
				programFD: 88,
			},
		},
		TC:  &fakeTCOps{recorder: recorder, detachErr: detachErr, clsactCreated: true},
		Now: func() time.Time { return time.Unix(1700000000, 0) },
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	err = manager.Stop(context.Background())
	if !errors.Is(err, detachErr) {
		t.Fatalf("Stop() error = %v, want wrapped %v", err, detachErr)
	}
	wantCalls := []string{
		"host.ensureDir:/sys/fs/bpf",
		"host.bpffsMounted:/sys/fs/bpf",
		"host.ensureDir:/sys/fs/bpf/nie",
		"loader.load",
		"objects.setMode:0",
		"objects.setBypassMark:3",
		"objects.pinMaps:/sys/fs/bpf/nie/allow_map:/sys/fs/bpf/nie/events",
		"tc.ensureClsact:eth0",
		"objects.programFD:88",
		"tc.attachEgress:eth0:88:nie_egress",
		"tc.detachEgress:eth0:nie_egress",
		"objects.close",
		"host.removeAll:/sys/fs/bpf/nie",
	}
	assertCalls(t, recorder.calls, wantCalls)
	if !reflect.DeepEqual(host.removed, []string{"/sys/fs/bpf/nie"}) {
		t.Fatalf("removed paths = %v, want [/sys/fs/bpf/nie]", host.removed)
	}
}

type callRecorder struct {
	calls []string
}

func (r *callRecorder) add(call string) {
	r.calls = append(r.calls, call)
}

type fakeHostOps struct {
	recorder     *callRecorder
	bpffsMounted bool
	removed      []string
}

func (h *fakeHostOps) EnsureDir(path string) error {
	h.recorder.add("host.ensureDir:" + path)
	return nil
}

func (h *fakeHostOps) BPFFSMounted(path string) (bool, error) {
	h.recorder.add("host.bpffsMounted:" + path)
	return h.bpffsMounted, nil
}

func (h *fakeHostOps) MountBPFFS(path string) error {
	h.recorder.add("host.mountBPFFS:" + path)
	h.bpffsMounted = true
	return nil
}

func (h *fakeHostOps) RemoveAll(path string) error {
	h.recorder.add("host.removeAll:" + path)
	h.removed = append(h.removed, path)
	return nil
}

type fakeObjectLoader struct {
	recorder *callRecorder
	objects  runtimeObjects
}

func (l *fakeObjectLoader) Load() (runtimeObjects, error) {
	l.recorder.add("loader.load")
	return l.objects, nil
}

type fakeRuntimeObjects struct {
	recorder   *callRecorder
	allow      allowMap
	events     *cebpf.Map
	programFD  int
	mode       uint32
	bypassMark uint32
	pinned     Paths
	closeCalls int
}

func (o *fakeRuntimeObjects) AllowMap() allowMap {
	return o.allow
}

func (o *fakeRuntimeObjects) EventsMap() *cebpf.Map {
	return o.events
}

func (o *fakeRuntimeObjects) SetMode(mode uint32) error {
	o.recorder.add("objects.setMode:" + strconv.FormatUint(uint64(mode), 10))
	o.mode = mode
	return nil
}

func (o *fakeRuntimeObjects) SetBypassMark(mark uint32) error {
	o.recorder.add("objects.setBypassMark:" + strconv.FormatUint(uint64(mark), 10))
	o.bypassMark = mark
	return nil
}

func (o *fakeRuntimeObjects) PinMaps(paths Paths) error {
	o.recorder.add("objects.pinMaps:" + paths.AllowMap + ":" + paths.Events)
	o.pinned = paths
	return nil
}

func (o *fakeRuntimeObjects) ProgramFD() int {
	o.recorder.add("objects.programFD:" + strconv.Itoa(o.programFD))
	return o.programFD
}

func (o *fakeRuntimeObjects) Close() error {
	o.recorder.add("objects.close")
	o.closeCalls++
	return nil
}

type fakeTCOps struct {
	recorder          *callRecorder
	attachErr         error
	detachErr         error
	removeClsactErr   error
	clsactCreated     bool
	removeClsactCalls int
}

type fakeEventReader struct{}

func (*fakeEventReader) Read() (EgressEvent, error) { return EgressEvent{}, nil }
func (*fakeEventReader) Close() error               { return nil }

func (tc *fakeTCOps) EnsureClsact(iface string) (bool, error) {
	tc.recorder.add("tc.ensureClsact:" + iface)
	return tc.clsactCreated, nil
}

func (tc *fakeTCOps) AttachEgress(iface string, progFD int, progName string) error {
	tc.recorder.add("tc.attachEgress:" + iface + ":" + strconv.Itoa(progFD) + ":" + progName)
	return tc.attachErr
}

func (tc *fakeTCOps) DetachEgress(iface string, progName string) error {
	tc.recorder.add("tc.detachEgress:" + iface + ":" + progName)
	return tc.detachErr
}

func (tc *fakeTCOps) RemoveClsact(iface string) error {
	tc.recorder.add("tc.removeClsact:" + iface)
	tc.removeClsactCalls++
	return tc.removeClsactErr
}

func assertCalls(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("calls = %#v, want %#v", got, want)
	}
}
