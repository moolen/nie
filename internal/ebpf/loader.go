package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/moolen/nie/internal/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	bpffsRoot     = "/sys/fs/bpf"
	pinnedMapRoot = "/sys/fs/bpf/nie"
	tcProgramName = "nie_egress"
)

const (
	nieModeEnforce uint32 = 0
	nieModeAudit   uint32 = 1
)

var ErrManagerNotStarted = errors.New("ebpf manager not started")

var newEventReader = func(events *cebpf.Map) (EventReader, error) {
	reader, err := ringbuf.NewReader(events)
	if err != nil {
		return nil, err
	}
	return &liveEventReader{reader: reader}, nil
}

type ManagerConfig struct {
	Interface  string
	Mode       config.Mode
	BypassMark uint32
}

type Dependencies struct {
	Host   hostOps
	Loader objectLoader
	TC     tcOps
	Now    func() time.Time
}

type Manager struct {
	iface      string
	mode       uint32
	bypassMark uint32

	host   hostOps
	loader objectLoader
	tc     tcOps
	now    func() time.Time

	started bool
	objects runtimeObjects
	writer  TrustWriter

	createdClsact bool
}

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

func NewManager(cfg ManagerConfig, deps Dependencies) (*Manager, error) {
	mode, err := runtimeMode(cfg.Mode)
	if err != nil {
		return nil, err
	}
	if cfg.Interface == "" {
		return nil, errors.New("interface must be set")
	}

	host := deps.Host
	if host == nil {
		host = defaultHostOps{}
	}

	loader := deps.Loader
	if loader == nil {
		loader = &defaultObjectLoader{
			mode:       mode,
			bypassMark: cfg.BypassMark,
		}
	}

	tc := deps.TC
	if tc == nil {
		tc = defaultTCOps{}
	}

	now := deps.Now
	if now == nil {
		now = time.Now
	}

	return &Manager{
		iface:      cfg.Interface,
		mode:       mode,
		bypassMark: cfg.BypassMark,
		host:       host,
		loader:     loader,
		tc:         tc,
		now:        now,
	}, nil
}

func (m *Manager) Start(_ context.Context) error {
	if m.started {
		return nil
	}

	if err := m.host.EnsureDir(bpffsRoot); err != nil {
		return fmt.Errorf("ensure bpffs root: %w", err)
	}

	mounted, err := m.host.BPFFSMounted(bpffsRoot)
	if err != nil {
		return fmt.Errorf("check bpffs mount: %w", err)
	}
	if !mounted {
		if err := m.host.MountBPFFS(bpffsRoot); err != nil {
			return fmt.Errorf("mount bpffs: %w", err)
		}
	}

	if err := m.host.EnsureDir(pinnedMapRoot); err != nil {
		return fmt.Errorf("ensure pinned map root: %w", err)
	}

	objects, err := m.loader.Load()
	if err != nil {
		return fmt.Errorf("load ebpf objects: %w", err)
	}

	createdClsact, err := m.configureAndAttach(objects)
	if err != nil {
		m.cleanupStartFailure(objects, createdClsact)
		return err
	}

	m.objects = objects
	m.writer = NewTrustWriter(objects.AllowMap(), m.now)
	m.createdClsact = createdClsact
	m.started = true
	return nil
}

func (m *Manager) Stop(_ context.Context) error {
	if !m.started {
		return nil
	}

	var firstErr error
	detached := true
	if err := m.tc.DetachEgress(m.iface, tcProgramName); err != nil {
		detached = false
		firstErr = fmt.Errorf("detach tc egress: %w", err)
	}
	if err := m.objects.Close(); err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("close ebpf objects: %w", err)
		}
	}
	if err := m.host.RemoveAll(pinnedMapRoot); err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("remove pinned state: %w", err)
		}
	}
	if m.createdClsact && detached {
		if err := m.tc.RemoveClsact(m.iface); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("remove clsact qdisc: %w", err)
			}
		}
	}

	m.objects = nil
	m.writer = nil
	m.started = false
	m.createdClsact = false
	return firstErr
}

func (m *Manager) TrustWriter() (TrustWriter, error) {
	if !m.started || m.writer == nil {
		return nil, ErrManagerNotStarted
	}
	return m.writer, nil
}

func (m *Manager) EventReader() (EventReader, error) {
	if !m.started {
		return nil, ErrManagerNotStarted
	}
	return newEventReader(m.objects.EventsMap())
}

func (m *Manager) configureAndAttach(objects runtimeObjects) (bool, error) {
	if err := objects.SetMode(m.mode); err != nil {
		return false, fmt.Errorf("configure cfg_mode: %w", err)
	}
	if err := objects.SetBypassMark(m.bypassMark); err != nil {
		return false, fmt.Errorf("configure cfg_bypass_mark: %w", err)
	}

	paths := PinnedPaths(pinnedMapRoot)
	if err := objects.PinMaps(paths); err != nil {
		return false, fmt.Errorf("pin maps: %w", err)
	}

	createdClsact, err := m.tc.EnsureClsact(m.iface)
	if err != nil {
		return false, fmt.Errorf("ensure clsact qdisc: %w", err)
	}
	if err := m.tc.AttachEgress(m.iface, objects.ProgramFD(), tcProgramName); err != nil {
		return createdClsact, fmt.Errorf("attach tc egress: %w", err)
	}

	return createdClsact, nil
}

func (m *Manager) cleanupStartFailure(objects runtimeObjects, createdClsact bool) {
	_ = objects.Close()
	_ = m.host.RemoveAll(pinnedMapRoot)
	if createdClsact {
		_ = m.tc.RemoveClsact(m.iface)
	}
}

func runtimeMode(mode config.Mode) (uint32, error) {
	switch mode {
	case config.ModeEnforce:
		return nieModeEnforce, nil
	case config.ModeAudit:
		return nieModeAudit, nil
	default:
		return 0, fmt.Errorf("invalid mode %q", mode)
	}
}

// allowKey/allowValue mirror bpf/include/common.h structs:
//
//	struct allow_key { __u8 addr[4]; __u16 dport; __u16 pad; };
//	struct allow_value { __u64 expires_at_mono_ns; };
type allowKey struct {
	Addr  [4]byte
	Dport uint16
	Pad   uint16
}

type allowValue struct {
	ExpiresAtMonoNs uint64
}

type allowMap interface {
	Put(key allowKey, value allowValue) error
}

type runtimeObjects interface {
	AllowMap() allowMap
	EventsMap() *cebpf.Map
	SetMode(mode uint32) error
	SetBypassMark(mark uint32) error
	PinMaps(paths Paths) error
	ProgramFD() int
	Close() error
}

type objectLoader interface {
	Load() (runtimeObjects, error)
}

type hostOps interface {
	EnsureDir(path string) error
	BPFFSMounted(path string) (bool, error)
	MountBPFFS(path string) error
	RemoveAll(path string) error
}

type tcOps interface {
	EnsureClsact(iface string) (bool, error)
	AttachEgress(iface string, progFD int, progName string) error
	DetachEgress(iface string, progName string) error
	RemoveClsact(iface string) error
}

type defaultObjectLoader struct {
	mode       uint32
	bypassMark uint32
}

func (l *defaultObjectLoader) Load() (runtimeObjects, error) {
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("load embedded bpf spec: %w", err)
	}

	var specs bpfSpecs
	if err := spec.Assign(&specs); err != nil {
		return nil, fmt.Errorf("assign bpf specs: %w", err)
	}
	if specs.CfgMode == nil || specs.CfgBypassMark == nil {
		return nil, errors.New("bpf config variables are missing")
	}
	if err := specs.CfgMode.Set(l.mode); err != nil {
		return nil, fmt.Errorf("set cfg_mode spec: %w", err)
	}
	if err := specs.CfgBypassMark.Set(l.bypassMark); err != nil {
		return nil, fmt.Errorf("set cfg_bypass_mark spec: %w", err)
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, &cebpf.CollectionOptions{
		Maps: cebpf.MapOptions{PinPath: pinnedMapRoot},
	}); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	return &liveRuntimeObjects{
		objs:       objs,
		mode:       l.mode,
		bypassMark: l.bypassMark,
	}, nil
}

type liveRuntimeObjects struct {
	objs       bpfObjects
	mode       uint32
	bypassMark uint32
}

func (o *liveRuntimeObjects) AllowMap() allowMap {
	return liveAllowMap{m: o.objs.AllowMap}
}

func (o *liveRuntimeObjects) EventsMap() *cebpf.Map {
	return o.objs.Events
}

func (o *liveRuntimeObjects) SetMode(mode uint32) error {
	o.mode = mode
	if o.objs.CfgMode == nil {
		return nil
	}
	err := o.objs.CfgMode.Set(mode)
	if err == nil || errors.Is(err, cebpf.ErrNotSupported) || errors.Is(err, cebpf.ErrReadOnly) {
		return nil
	}
	return err
}

func (o *liveRuntimeObjects) SetBypassMark(mark uint32) error {
	o.bypassMark = mark
	if o.objs.CfgBypassMark == nil {
		return nil
	}
	err := o.objs.CfgBypassMark.Set(mark)
	if err == nil || errors.Is(err, cebpf.ErrNotSupported) || errors.Is(err, cebpf.ErrReadOnly) {
		return nil
	}
	return err
}

func (o *liveRuntimeObjects) PinMaps(paths Paths) error {
	if o.objs.AllowMap == nil || o.objs.Events == nil {
		return errors.New("bpf maps are not loaded")
	}
	if err := o.objs.AllowMap.Pin(paths.AllowMap); err != nil {
		return err
	}
	if err := o.objs.Events.Pin(paths.Events); err != nil {
		return err
	}
	return nil
}

func (o *liveRuntimeObjects) ProgramFD() int {
	if o.objs.NieEgress == nil {
		return -1
	}
	return o.objs.NieEgress.FD()
}

func (o *liveRuntimeObjects) Close() error {
	return o.objs.Close()
}

type liveAllowMap struct {
	m *cebpf.Map
}

func (m liveAllowMap) Put(key allowKey, value allowValue) error {
	if m.m == nil {
		return errors.New("allow map is not loaded")
	}
	return m.m.Put(key, value)
}

type liveEventReader struct {
	reader *ringbuf.Reader
}

func (r *liveEventReader) Read() (EgressEvent, error) {
	record, err := r.reader.Read()
	if err != nil {
		return EgressEvent{}, err
	}
	return decodeEgressEvent(record.RawSample)
}

func (r *liveEventReader) Close() error {
	return r.reader.Close()
}

func decodeEgressEvent(raw []byte) (EgressEvent, error) {
	if len(raw) < 16 {
		return EgressEvent{}, fmt.Errorf("short egress event record: %d", len(raw))
	}

	dst := binary.NativeEndian.Uint32(raw[0:4])
	reason := binary.NativeEndian.Uint32(raw[4:8])
	action := binary.NativeEndian.Uint32(raw[8:12])
	protocol := raw[12]
	dport := binary.NativeEndian.Uint16(raw[14:16])

	return EgressEvent{
		Destination: netip.AddrFrom4([4]byte{
			byte(dst >> 24),
			byte(dst >> 16),
			byte(dst >> 8),
			byte(dst),
		}),
		Reason: EgressReason(reason),
		Action: EgressAction(action),
		Protocol: EgressProtocol(protocol),
		Port:     dport,
	}, nil
}

type defaultHostOps struct{}

func (defaultHostOps) EnsureDir(path string) error {
	return os.MkdirAll(path, 0o755)
}

func (defaultHostOps) BPFFSMounted(path string) (bool, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return false, err
	}
	return stat.Type == unix.BPF_FS_MAGIC, nil
}

func (defaultHostOps) MountBPFFS(path string) error {
	err := unix.Mount("bpffs", path, "bpf", 0, "")
	if err == nil || errors.Is(err, unix.EBUSY) {
		return nil
	}
	return err
}

func (defaultHostOps) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

type defaultTCOps struct{}

func (defaultTCOps) EnsureClsact(iface string) (bool, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return false, err
	}
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return false, err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			return false, nil
		}
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return false, err
	}
	return true, nil
}

func (defaultTCOps) AttachEgress(iface string, progFD int, progName string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           progFD,
		Name:         progName,
		DirectAction: true,
	}
	return netlink.FilterReplace(filter)
}

func (defaultTCOps) DetachEgress(iface string, progName string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return err
	}
	for _, filter := range filters {
		bpfFilter, ok := filter.(*netlink.BpfFilter)
		if !ok {
			continue
		}
		if bpfFilter.Name != progName {
			continue
		}
		if err := netlink.FilterDel(filter); err != nil {
			return err
		}
	}
	return nil
}

func (defaultTCOps) RemoveClsact(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	for _, parent := range []uint32{netlink.HANDLE_MIN_EGRESS, netlink.HANDLE_MIN_INGRESS} {
		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			return err
		}
		if len(filters) != 0 {
			return nil
		}
	}

	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() != "clsact" {
			continue
		}
		return netlink.QdiscDel(qdisc)
	}
	return nil
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
		return allowKey{Addr: entry.IPv4.As4(), Dport: entry.Port}, allowValue{ExpiresAtMonoNs: nowMonoNs}
	}
	if uint64(dNs) > math.MaxUint64-nowMonoNs {
		return allowKey{Addr: entry.IPv4.As4(), Dport: entry.Port}, allowValue{ExpiresAtMonoNs: math.MaxUint64}
	}
	return allowKey{Addr: entry.IPv4.As4(), Dport: entry.Port}, allowValue{ExpiresAtMonoNs: nowMonoNs + uint64(dNs)}
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
