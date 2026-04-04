package redirect

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	nieTableName = "nie"
	nieChainName = "output"
)

var nieOwnedRuleTag = []byte("nie-owned")

var ErrLegacyIptablesUnsupported = errors.New("legacy iptables backend is not supported")
var ErrConflictingRedirectState = errors.New("conflicting preexisting nie redirect state")

type Protocol string

const (
	protocolUDP Protocol = "udp"
	protocolTCP Protocol = "tcp"
)

type RedirectRule struct {
	Protocol        Protocol
	DestinationPort uint16
}

type HostCapabilities struct {
	NFTables       bool
	LegacyIptables bool
}

type CapabilityDetector interface {
	Detect(ctx context.Context) (HostCapabilities, error)
}

type NFTBackend interface {
	InstallRedirects(ctx context.Context, tableName, chainName string, listenPort uint16, redirects []RedirectRule) error
	RemoveOwnedObjects(ctx context.Context, tableName, chainName string) error
}

type Dependencies struct {
	Detector CapabilityDetector
	Backend  NFTBackend
}

type Manager struct {
	detector   CapabilityDetector
	backend    NFTBackend
	listenPort uint16
	started    bool
}

func NewManager(cfg Config, deps Dependencies) (*Manager, error) {
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return nil, fmt.Errorf("invalid listen port %d", cfg.ListenPort)
	}

	detector := deps.Detector
	if detector == nil {
		detector = newDefaultCapabilityDetector()
	}

	backend := deps.Backend
	if backend == nil {
		backend = newNativeNFTBackend()
	}

	return &Manager{
		detector:   detector,
		backend:    backend,
		listenPort: uint16(cfg.ListenPort),
	}, nil
}

func (m *Manager) Start(ctx context.Context) error {
	if m.started {
		return nil
	}

	caps, err := m.detector.Detect(ctx)
	if err != nil {
		return fmt.Errorf("detect host firewall capabilities: %w", err)
	}
	if !caps.NFTables {
		if caps.LegacyIptables {
			return ErrLegacyIptablesUnsupported
		}
		return errors.New("nftables backend is not available")
	}

	redirects := []RedirectRule{
		{Protocol: protocolUDP, DestinationPort: 53},
		{Protocol: protocolTCP, DestinationPort: 53},
	}
	if err := m.backend.InstallRedirects(ctx, nieTableName, nieChainName, m.listenPort, redirects); err != nil {
		return fmt.Errorf("install nftables redirects: %w", err)
	}

	m.started = true
	return nil
}

func (m *Manager) Stop(ctx context.Context) error {
	if !m.started {
		return nil
	}

	if err := m.backend.RemoveOwnedObjects(ctx, nieTableName, nieChainName); err != nil {
		if errors.Is(err, ErrConflictingRedirectState) {
			m.started = false
		}
		return fmt.Errorf("remove nftables objects: %w", err)
	}
	m.started = false
	return nil
}

type defaultCapabilityDetector struct {
	lookPath     func(file string) (string, error)
	evalSymlinks func(path string) (string, error)
	listTables   func() ([]*nftables.Table, error)
}

func newDefaultCapabilityDetector() *defaultCapabilityDetector {
	return &defaultCapabilityDetector{
		lookPath:     exec.LookPath,
		evalSymlinks: filepath.EvalSymlinks,
		listTables: func() ([]*nftables.Table, error) {
			conn := &nftables.Conn{}
			return conn.ListTables()
		},
	}
}

func (d *defaultCapabilityDetector) Detect(_ context.Context) (HostCapabilities, error) {
	if d.listTables == nil {
		return HostCapabilities{}, errors.New("listTables dependency is not configured")
	}
	if _, err := d.listTables(); err != nil {
		return HostCapabilities{}, fmt.Errorf("list nftables tables: %w", err)
	}

	return HostCapabilities{
		NFTables:       true,
		LegacyIptables: d.legacyIptablesSelected(),
	}, nil
}

func (d *defaultCapabilityDetector) legacyIptablesSelected() bool {
	path, err := d.lookPath("iptables")
	if err != nil {
		return false
	}
	resolved, err := d.evalSymlinks(path)
	if err == nil {
		path = resolved
	}
	return strings.Contains(path, "iptables-legacy")
}

type nativeNFTBackend struct{}

func newNativeNFTBackend() *nativeNFTBackend {
	return &nativeNFTBackend{}
}

func (b *nativeNFTBackend) InstallRedirects(_ context.Context, tableName, chainName string, listenPort uint16, redirects []RedirectRule) error {
	conn := &nftables.Conn{}
	tables, err := conn.ListTables()
	if err != nil {
		return err
	}
	for _, table := range tables {
		if table != nil && table.Name == tableName && table.Family == nftables.TableFamilyINet {
			return ErrConflictingRedirectState
		}
	}

	table := &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	}
	conn.AddTable(table)

	chain := &nftables.Chain{
		Table:    table,
		Name:     chainName,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
	}
	conn.AddChain(chain)

	for _, redirect := range redirects {
		conn.AddRule(&nftables.Rule{
			Table:    table,
			Chain:    chain,
			Exprs:    redirectExpressions(redirect.Protocol, redirect.DestinationPort, listenPort),
			UserData: append([]byte(nil), nieOwnedRuleTag...),
		})
	}

	if err := conn.Flush(); err != nil {
		return err
	}
	return nil
}

func (b *nativeNFTBackend) RemoveOwnedObjects(_ context.Context, tableName, chainName string) error {
	conn := &nftables.Conn{}
	chains, err := conn.ListChains()
	if err != nil {
		return err
	}

	chainState, err := findNieOutputChainState(chains, tableName, chainName)
	if err != nil {
		return err
	}

	rules, err := conn.GetRules(chainState.target.Table, chainState.target)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		if !isNieOwnedRule(rule) {
			return ErrConflictingRedirectState
		}
		if err := conn.DelRule(rule); err != nil {
			return err
		}
	}
	conn.DelChain(chainState.target)
	if !chainState.hasAdditionalChains {
		conn.DelTable(chainState.target.Table)
	}

	if err := conn.Flush(); err != nil {
		return err
	}
	if chainState.hasAdditionalChains {
		return ErrConflictingRedirectState
	}
	return nil
}

func redirectExpressions(protocol Protocol, destinationPort, listenPort uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{byte(protocolNumber(protocol))},
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     be16(destinationPort),
		},
		&expr.Immediate{
			Register: 1,
			Data:     be16(listenPort),
		},
		&expr.Redir{
			RegisterProtoMin: 1,
			RegisterProtoMax: 1,
		},
	}
}

func isNieOwnedRule(rule *nftables.Rule) bool {
	return rule != nil && bytes.Equal(rule.UserData, nieOwnedRuleTag)
}

type nieOutputChainState struct {
	target              *nftables.Chain
	hasAdditionalChains bool
}

func findNieOutputChainState(chains []*nftables.Chain, tableName, chainName string) (nieOutputChainState, error) {
	var state nieOutputChainState
	for _, chain := range chains {
		if chain == nil || chain.Table == nil {
			continue
		}
		if chain.Table.Name != tableName || chain.Table.Family != nftables.TableFamilyINet {
			continue
		}
		if chain.Name == chainName {
			if state.target != nil {
				return nieOutputChainState{}, ErrConflictingRedirectState
			}
			state.target = chain
			continue
		}
		state.hasAdditionalChains = true
	}

	if state.target == nil {
		return nieOutputChainState{}, ErrConflictingRedirectState
	}
	return state, nil
}

func protocolNumber(protocol Protocol) uint8 {
	switch protocol {
	case protocolTCP:
		return unix.IPPROTO_TCP
	case protocolUDP:
		return unix.IPPROTO_UDP
	default:
		return 0
	}
}

func be16(v uint16) []byte {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, v)
	return data
}
