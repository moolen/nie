package redirect

import (
	"context"
	"errors"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestManagerStartInstallsDNSAndHTTPSRedirects(t *testing.T) {
	fakeDetector := &fakeCapabilityDetector{
		capabilities: HostCapabilities{
			NFTables:       true,
			LegacyIptables: false,
		},
	}
	fakeBackend := &fakeNFTBackend{}

	manager, err := NewManager(testManagerConfig(), Dependencies{
		Detector: fakeDetector,
		Backend:  fakeBackend,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if len(fakeBackend.installCalls) != 1 {
		t.Fatalf("install call count = %d, want 1", len(fakeBackend.installCalls))
	}
	install := fakeBackend.installCalls[0]
	if install.TableName != nieTableName {
		t.Fatalf("install table = %q, want %q", install.TableName, nieTableName)
	}
	if install.ChainName != nieChainName {
		t.Fatalf("install chain = %q, want %q", install.ChainName, nieChainName)
	}
	want := []RedirectRule{
		{Protocol: protocolUDP, DestinationPort: 53, ListenPort: 1053, BypassMark: 4242},
		{Protocol: protocolTCP, DestinationPort: 53, ListenPort: 1053, BypassMark: 4242},
		{Protocol: protocolTCP, DestinationPort: 443, ListenPort: 9443, BypassMark: 4242},
		{Protocol: protocolTCP, DestinationPort: 8443, ListenPort: 9443, BypassMark: 4242},
	}
	if len(install.Redirects) != len(want) {
		t.Fatalf("redirect rule count = %d, want %d", len(install.Redirects), len(want))
	}
	for i := range want {
		if install.Redirects[i] != want[i] {
			t.Fatalf("redirect[%d] = %+v, want %+v", i, install.Redirects[i], want[i])
		}
	}
}

func TestManagerStartInstallsBypassAwareRedirects(t *testing.T) {
	fakeBackend := &fakeNFTBackend{}
	manager, err := NewManager(testManagerConfig(), Dependencies{
		Detector: &fakeCapabilityDetector{
			capabilities: HostCapabilities{NFTables: true},
		},
		Backend: fakeBackend,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if len(fakeBackend.installCalls) != 1 {
		t.Fatalf("install call count = %d, want 1", len(fakeBackend.installCalls))
	}
	for i, redirect := range fakeBackend.installCalls[0].Redirects {
		if redirect.BypassMark != 4242 {
			t.Fatalf("redirect[%d].BypassMark = %d, want 4242", i, redirect.BypassMark)
		}
	}
}

func TestManagerStartRejectsLegacyIptablesBackend(t *testing.T) {
	manager, err := NewManager(testManagerConfig(), Dependencies{
		Detector: &fakeCapabilityDetector{
			capabilities: HostCapabilities{
				NFTables:       false,
				LegacyIptables: true,
			},
		},
		Backend: &fakeNFTBackend{},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	err = manager.Start(context.Background())
	if !errors.Is(err, ErrLegacyIptablesUnsupported) {
		t.Fatalf("Start() error = %v, want %v", err, ErrLegacyIptablesUnsupported)
	}
}

func TestManagerStartFailsOnConflictingExistingState(t *testing.T) {
	manager, err := NewManager(testManagerConfig(), Dependencies{
		Detector: &fakeCapabilityDetector{
			capabilities: HostCapabilities{NFTables: true},
		},
		Backend: &fakeNFTBackend{installErr: ErrConflictingRedirectState},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	err = manager.Start(context.Background())
	if !errors.Is(err, ErrConflictingRedirectState) {
		t.Fatalf("Start() error = %v, want wrapped %v", err, ErrConflictingRedirectState)
	}
}

func TestManagerStopRemovesNieOwnedObjects(t *testing.T) {
	fakeBackend := &fakeNFTBackend{}
	manager, err := NewManager(testManagerConfig(), Dependencies{
		Detector: &fakeCapabilityDetector{
			capabilities: HostCapabilities{NFTables: true},
		},
		Backend: fakeBackend,
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

	if len(fakeBackend.removeCalls) != 1 {
		t.Fatalf("remove call count = %d, want 1", len(fakeBackend.removeCalls))
	}
	remove := fakeBackend.removeCalls[0]
	if remove.TableName != nieTableName {
		t.Fatalf("remove table = %q, want %q", remove.TableName, nieTableName)
	}
	if remove.ChainName != nieChainName {
		t.Fatalf("remove chain = %q, want %q", remove.ChainName, nieChainName)
	}
}

func TestManagerStartPropagatesDetectorFailure(t *testing.T) {
	detectErr := errors.New("detect failed")
	manager, err := NewManager(testManagerConfig(), Dependencies{
		Detector: &fakeCapabilityDetector{err: detectErr},
		Backend:  &fakeNFTBackend{},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	err = manager.Start(context.Background())
	if !errors.Is(err, detectErr) {
		t.Fatalf("Start() error = %v, want wrapped %v", err, detectErr)
	}
}

func TestManagerStartPropagatesInstallFailure(t *testing.T) {
	installErr := errors.New("install failed")
	manager, err := NewManager(testManagerConfig(), Dependencies{
		Detector: &fakeCapabilityDetector{
			capabilities: HostCapabilities{NFTables: true},
		},
		Backend: &fakeNFTBackend{installErr: installErr},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	err = manager.Start(context.Background())
	if !errors.Is(err, installErr) {
		t.Fatalf("Start() error = %v, want wrapped %v", err, installErr)
	}
}

func TestManagerStopPropagatesRemoveFailure(t *testing.T) {
	removeErr := errors.New("remove failed")
	manager, err := NewManager(testManagerConfig(), Dependencies{
		Detector: &fakeCapabilityDetector{
			capabilities: HostCapabilities{NFTables: true},
		},
		Backend: &fakeNFTBackend{removeErr: removeErr},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	err = manager.Stop(context.Background())
	if !errors.Is(err, removeErr) {
		t.Fatalf("Stop() error = %v, want wrapped %v", err, removeErr)
	}
}

func TestManagerStopClearsStartedAfterConflictCleanup(t *testing.T) {
	fakeBackend := &fakeNFTBackend{removeErr: ErrConflictingRedirectState}
	manager, err := NewManager(testManagerConfig(), Dependencies{
		Detector: &fakeCapabilityDetector{
			capabilities: HostCapabilities{NFTables: true},
		},
		Backend: fakeBackend,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	err = manager.Stop(context.Background())
	if !errors.Is(err, ErrConflictingRedirectState) {
		t.Fatalf("Stop() error = %v, want wrapped %v", err, ErrConflictingRedirectState)
	}

	if err := manager.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop() error = %v, want nil after started state is cleared", err)
	}
	if len(fakeBackend.removeCalls) != 1 {
		t.Fatalf("remove call count = %d, want 1", len(fakeBackend.removeCalls))
	}
}

func TestManagerStopIsIdempotent(t *testing.T) {
	fakeBackend := &fakeNFTBackend{}
	manager, err := NewManager(testManagerConfig(), Dependencies{
		Detector: &fakeCapabilityDetector{
			capabilities: HostCapabilities{NFTables: true},
		},
		Backend: fakeBackend,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if err := manager.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() before Start() error = %v", err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatalf("first Stop() error = %v", err)
	}
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop() error = %v", err)
	}

	if len(fakeBackend.removeCalls) != 1 {
		t.Fatalf("remove call count = %d, want 1", len(fakeBackend.removeCalls))
	}
}

func TestDefaultCapabilityDetectorDetectReturnsErrorOnListTablesFailure(t *testing.T) {
	listTablesErr := errors.New("netlink permission denied")
	detector := &defaultCapabilityDetector{
		listTables: func() ([]*nftables.Table, error) {
			return nil, listTablesErr
		},
	}

	_, err := detector.Detect(context.Background())
	if !errors.Is(err, listTablesErr) {
		t.Fatalf("Detect() error = %v, want wrapped %v", err, listTablesErr)
	}
}

func TestRedirectExpressionsUseRedirectSemantics(t *testing.T) {
	exprs := redirectExpressions(protocolUDP, 53, 1053, 4242)

	if len(exprs) != 8 {
		t.Fatalf("expression count = %d, want 8", len(exprs))
	}
	markMeta, ok := exprs[0].(*expr.Meta)
	if !ok || markMeta.Key != expr.MetaKeyMARK {
		t.Fatalf("first expression = %T (%#v), want Meta mark lookup", exprs[0], exprs[0])
	}
	markCmp, ok := exprs[1].(*expr.Cmp)
	if !ok || markCmp.Op != expr.CmpOpNeq {
		t.Fatalf("second expression = %T (%#v), want mark inequality compare", exprs[1], exprs[1])
	}
	if _, ok := exprs[len(exprs)-1].(*expr.Redir); !ok {
		t.Fatalf("last expression type = %T, want *expr.Redir", exprs[len(exprs)-1])
	}
	if _, isNAT := exprs[len(exprs)-1].(*expr.NAT); isNAT {
		t.Fatalf("last expression type = %T, want non-*expr.NAT redirect", exprs[len(exprs)-1])
	}
	redir := exprs[len(exprs)-1].(*expr.Redir)
	if redir.RegisterProtoMin != 1 || redir.RegisterProtoMax != 1 {
		t.Fatalf("redir registers = (%d,%d), want (1,1)", redir.RegisterProtoMin, redir.RegisterProtoMax)
	}
}

func TestIsNieOwnedRule(t *testing.T) {
	if isNieOwnedRule(nil) {
		t.Fatal("nil rule should not be nie-owned")
	}

	if !isNieOwnedRule(&nftables.Rule{UserData: append([]byte(nil), nieOwnedRuleTag...)}) {
		t.Fatal("rule with nie tag should be nie-owned")
	}

	if isNieOwnedRule(&nftables.Rule{UserData: []byte("other")}) {
		t.Fatal("rule with different userdata should not be nie-owned")
	}
}

func TestFindNieOutputChainState(t *testing.T) {
	table := &nftables.Table{Name: nieTableName, Family: nftables.TableFamilyINet}
	chains := []*nftables.Chain{
		{Name: nieChainName, Table: table},
	}

	state, err := findNieOutputChainState(chains, nieTableName, nieChainName)
	if err != nil {
		t.Fatalf("findNieOutputChainState() error = %v", err)
	}
	if state.target == nil || state.target.Name != nieChainName {
		t.Fatalf("chain = %#v, want %q chain", state.target, nieChainName)
	}
	if state.hasAdditionalChains {
		t.Fatal("hasAdditionalChains = true, want false")
	}
}

func TestFindNieOutputChainStateMarksAdditionalChainConflict(t *testing.T) {
	table := &nftables.Table{Name: nieTableName, Family: nftables.TableFamilyINet}
	chains := []*nftables.Chain{
		{Name: nieChainName, Table: table},
		{Name: "other", Table: table},
	}

	state, err := findNieOutputChainState(chains, nieTableName, nieChainName)
	if err != nil {
		t.Fatalf("findNieOutputChainState() error = %v", err)
	}
	if state.target == nil || state.target.Name != nieChainName {
		t.Fatalf("chain = %#v, want %q chain", state.target, nieChainName)
	}
	if !state.hasAdditionalChains {
		t.Fatal("hasAdditionalChains = false, want true")
	}
}

func TestFindNieOutputChainStateRejectsDuplicateOutputChains(t *testing.T) {
	table := &nftables.Table{Name: nieTableName, Family: nftables.TableFamilyINet}
	chains := []*nftables.Chain{
		{Name: nieChainName, Table: table},
		{Name: nieChainName, Table: table},
	}

	_, err := findNieOutputChainState(chains, nieTableName, nieChainName)
	if !errors.Is(err, ErrConflictingRedirectState) {
		t.Fatalf("findNieOutputChainState() error = %v, want %v", err, ErrConflictingRedirectState)
	}
}

type fakeCapabilityDetector struct {
	capabilities HostCapabilities
	err          error
}

func (f *fakeCapabilityDetector) Detect(context.Context) (HostCapabilities, error) {
	return f.capabilities, f.err
}

type installCall struct {
	TableName string
	ChainName string
	Redirects []RedirectRule
}

type removeCall struct {
	TableName string
	ChainName string
}

type fakeNFTBackend struct {
	installCalls []installCall
	removeCalls  []removeCall
	installErr   error
	removeErr    error
}

func (f *fakeNFTBackend) InstallRedirects(_ context.Context, tableName, chainName string, redirects []RedirectRule) error {
	f.installCalls = append(f.installCalls, installCall{
		TableName: tableName,
		ChainName: chainName,
		Redirects: append([]RedirectRule(nil), redirects...),
	})
	return f.installErr
}

func (f *fakeNFTBackend) RemoveOwnedObjects(_ context.Context, tableName, chainName string) error {
	f.removeCalls = append(f.removeCalls, removeCall{
		TableName: tableName,
		ChainName: chainName,
	})
	return f.removeErr
}

func testManagerConfig() Config {
	return Config{
		DNSListenPort:   1053,
		HTTPSListenPort: 9443,
		HTTPSPorts:      []int{443, 8443},
		Mark:            4242,
	}
}
