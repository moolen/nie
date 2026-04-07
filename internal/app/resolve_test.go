package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/moolen/nie/internal/config"
)

func TestResolveRuntimeConfig_InterfaceExplicitUsesConfiguredName(t *testing.T) {
	cfg := testConfig(t)

	resolved, err := resolveRuntimeConfig(context.Background(), cfg, resolverDeps{})
	if err != nil {
		t.Fatalf("resolveRuntimeConfig() error = %v", err)
	}
	if resolved.Interface != "eth0" {
		t.Fatalf("resolved.Interface = %q, want %q", resolved.Interface, "eth0")
	}
}

func TestResolveRuntimeConfig_InterfaceAutoUsesSingleDefaultRouteInterface(t *testing.T) {
	cfg := testConfig(t)
	cfg.Interface = config.InterfaceSelector{Mode: "auto"}

	resolved, err := resolveRuntimeConfig(context.Background(), cfg, resolverDeps{
		routeDetector: fakeRouteDetector{ifaces: []string{"ens5"}},
	})
	if err != nil {
		t.Fatalf("resolveRuntimeConfig() error = %v", err)
	}
	if resolved.Interface != "ens5" {
		t.Fatalf("resolved.Interface = %q, want %q", resolved.Interface, "ens5")
	}
}

func TestResolveRuntimeConfig_InterfaceAutoRejectsNoDefaultRoute(t *testing.T) {
	cfg := testConfig(t)
	cfg.Interface = config.InterfaceSelector{Mode: "auto"}

	_, err := resolveRuntimeConfig(context.Background(), cfg, resolverDeps{
		routeDetector: fakeRouteDetector{},
	})
	if err == nil {
		t.Fatal("resolveRuntimeConfig() error = nil, want non-nil")
	}
}

func TestResolveRuntimeConfig_InterfaceAutoRejectsMultipleInterfaces(t *testing.T) {
	cfg := testConfig(t)
	cfg.Interface = config.InterfaceSelector{Mode: "auto"}

	_, err := resolveRuntimeConfig(context.Background(), cfg, resolverDeps{
		routeDetector: fakeRouteDetector{ifaces: []string{"ens5", "eth0"}},
	})
	if err == nil {
		t.Fatal("resolveRuntimeConfig() error = nil, want non-nil")
	}
}

func TestResolveRuntimeConfig_DNSUpstreamsExplicitUsesConfiguredAddresses(t *testing.T) {
	cfg := testConfig(t)

	resolved, err := resolveRuntimeConfig(context.Background(), cfg, resolverDeps{})
	if err != nil {
		t.Fatalf("resolveRuntimeConfig() error = %v", err)
	}
	if got, want := resolved.Upstreams, []string{"1.1.1.1:53"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved.Upstreams = %v, want %v", got, want)
	}
}

func TestResolveRuntimeConfig_DNSUpstreamsAutoReadsResolvableIPv4Nameservers(t *testing.T) {
	cfg := testConfig(t)
	cfg.DNS.Upstreams = config.UpstreamSelector{Mode: "auto"}

	resolved, err := resolveRuntimeConfig(context.Background(), cfg, resolverDeps{
		resolvConfReader: fakeResolvConfReader{raw: []byte("nameserver 1.1.1.1\nnameserver 9.9.9.9\n")},
	})
	if err != nil {
		t.Fatalf("resolveRuntimeConfig() error = %v", err)
	}
	if got, want := resolved.Upstreams, []string{"1.1.1.1:53", "9.9.9.9:53"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved.Upstreams = %v, want %v", got, want)
	}
}

func TestResolveRuntimeConfig_DNSUpstreamsAutoFiltersLoopbackAndIPv6(t *testing.T) {
	cfg := testConfig(t)
	cfg.DNS.Upstreams = config.UpstreamSelector{Mode: "auto"}

	resolved, err := resolveRuntimeConfig(context.Background(), cfg, resolverDeps{
		resolvConfReader: fakeResolvConfReader{raw: []byte("nameserver 127.0.0.53\nnameserver 2001:4860:4860::8888\nnameserver 1.1.1.1\nnameserver 1.1.1.1\n")},
	})
	if err != nil {
		t.Fatalf("resolveRuntimeConfig() error = %v", err)
	}
	if got, want := resolved.Upstreams, []string{"1.1.1.1:53"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved.Upstreams = %v, want %v", got, want)
	}
}

func TestResolveRuntimeConfig_DNSUpstreamsAutoRejectsEmptyUsableSet(t *testing.T) {
	cfg := testConfig(t)
	cfg.DNS.Upstreams = config.UpstreamSelector{Mode: "auto"}

	_, err := resolveRuntimeConfig(context.Background(), cfg, resolverDeps{
		resolvConfReader: fakeResolvConfReader{raw: []byte("nameserver 127.0.0.53\n")},
	})
	if err == nil {
		t.Fatal("resolveRuntimeConfig() error = nil, want non-nil")
	}
}

type fakeRouteDetector struct {
	ifaces []string
	err    error
}

func (d fakeRouteDetector) DefaultRouteInterfaces(context.Context) ([]string, error) {
	if d.err != nil {
		return nil, d.err
	}
	return append([]string(nil), d.ifaces...), nil
}

type fakeResolvConfReader struct {
	raw []byte
	err error
}

func (r fakeResolvConfReader) ReadResolvConf() ([]byte, error) {
	if r.err != nil {
		return nil, r.err
	}
	return append([]byte(nil), r.raw...), nil
}

func TestResolveRuntimeConfig_DNSUpstreamsAutoReadError(t *testing.T) {
	cfg := testConfig(t)
	cfg.DNS.Upstreams = config.UpstreamSelector{Mode: "auto"}
	boom := errors.New("read boom")

	_, err := resolveRuntimeConfig(context.Background(), cfg, resolverDeps{
		resolvConfReader: fakeResolvConfReader{err: boom},
	})
	if err == nil {
		t.Fatal("resolveRuntimeConfig() error = nil, want non-nil")
	}
}
