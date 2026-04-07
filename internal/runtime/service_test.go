package runtime

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type fakeLifecycleImpl struct {
	name     string
	calls    *[]string
	startErr error
	stopErr  error
}

func fakeLifecycle(name string, calls *[]string) *fakeLifecycleImpl {
	return &fakeLifecycleImpl{name: name, calls: calls}
}

func (f *fakeLifecycleImpl) Start(context.Context) error {
	*f.calls = append(*f.calls, f.name+":start")
	return f.startErr
}

func (f *fakeLifecycleImpl) Stop(context.Context) error {
	*f.calls = append(*f.calls, f.name+":stop")
	return f.stopErr
}

func TestServiceStartOrdersDependencies(t *testing.T) {
	var calls []string
	svc := Service{
		Redirect:  fakeLifecycle("redirect", &calls),
		EBPF:      fakeLifecycle("ebpf", &calls),
		CIDRAllow: fakeLifecycle("cidr", &calls),
		Trust:     fakeLifecycle("trust", &calls),
		DNS:       fakeLifecycle("dns", &calls),
		HTTPS:     fakeLifecycle("https", &calls),
	}

	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if diff := cmp.Diff([]string{"ebpf:start", "cidr:start", "trust:start", "dns:start", "https:start", "redirect:start"}, calls); diff != "" {
		t.Fatalf("call order mismatch (-want +got):\n%s", diff)
	}
}

func TestServiceStopOrdersDependencies(t *testing.T) {
	var calls []string
	svc := Service{
		Redirect:  fakeLifecycle("redirect", &calls),
		EBPF:      fakeLifecycle("ebpf", &calls),
		CIDRAllow: fakeLifecycle("cidr", &calls),
		Trust:     fakeLifecycle("trust", &calls),
		DNS:       fakeLifecycle("dns", &calls),
		HTTPS:     fakeLifecycle("https", &calls),
	}

	if err := svc.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if diff := cmp.Diff([]string{"redirect:stop", "https:stop", "dns:stop", "trust:stop", "cidr:stop", "ebpf:stop"}, calls); diff != "" {
		t.Fatalf("call order mismatch (-want +got):\n%s", diff)
	}
}

func TestServiceStopContinuesAfterError(t *testing.T) {
	var calls []string
	dnsLC := fakeLifecycle("dns", &calls)
	dnsLC.stopErr = errors.New("boom")

	svc := Service{
		Redirect:  fakeLifecycle("redirect", &calls),
		EBPF:      fakeLifecycle("ebpf", &calls),
		CIDRAllow: fakeLifecycle("cidr", &calls),
		Trust:     fakeLifecycle("trust", &calls),
		DNS:       dnsLC,
		HTTPS:     fakeLifecycle("https", &calls),
	}

	if err := svc.Stop(context.Background()); err == nil {
		t.Fatalf("Stop() error = nil, want non-nil")
	}
	if diff := cmp.Diff([]string{"redirect:stop", "https:stop", "dns:stop", "trust:stop", "cidr:stop", "ebpf:stop"}, calls); diff != "" {
		t.Fatalf("call order mismatch (-want +got):\n%s", diff)
	}
}

func TestServiceStartPropagatesError(t *testing.T) {
	t.Run("ebpf", func(t *testing.T) {
		var calls []string
		ebpfLC := fakeLifecycle("ebpf", &calls)
		ebpfLC.startErr = errors.New("boom")

		svc := Service{
			Redirect:  fakeLifecycle("redirect", &calls),
			EBPF:      ebpfLC,
			CIDRAllow: fakeLifecycle("cidr", &calls),
			Trust:     fakeLifecycle("trust", &calls),
			DNS:       fakeLifecycle("dns", &calls),
			HTTPS:     fakeLifecycle("https", &calls),
		}

		if err := svc.Start(context.Background()); err == nil {
			t.Fatalf("Start() error = nil, want non-nil")
		}
		if diff := cmp.Diff([]string{"ebpf:start"}, calls); diff != "" {
			t.Fatalf("call order mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("redirect", func(t *testing.T) {
		var calls []string
		redirectLC := fakeLifecycle("redirect", &calls)
		redirectLC.startErr = errors.New("boom")

		svc := Service{
			Redirect:  redirectLC,
			EBPF:      fakeLifecycle("ebpf", &calls),
			CIDRAllow: fakeLifecycle("cidr", &calls),
			Trust:     fakeLifecycle("trust", &calls),
			DNS:       fakeLifecycle("dns", &calls),
			HTTPS:     fakeLifecycle("https", &calls),
		}

		if err := svc.Start(context.Background()); err == nil {
			t.Fatalf("Start() error = nil, want non-nil")
		}
		if diff := cmp.Diff([]string{"ebpf:start", "cidr:start", "trust:start", "dns:start", "https:start", "redirect:start", "https:stop", "dns:stop", "trust:stop", "cidr:stop", "ebpf:stop"}, calls); diff != "" {
			t.Fatalf("call order mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("cidr allow", func(t *testing.T) {
		var calls []string
		cidrLC := fakeLifecycle("cidr", &calls)
		cidrLC.startErr = errors.New("boom")

		svc := Service{
			Redirect:  fakeLifecycle("redirect", &calls),
			EBPF:      fakeLifecycle("ebpf", &calls),
			CIDRAllow: cidrLC,
			Trust:     fakeLifecycle("trust", &calls),
			DNS:       fakeLifecycle("dns", &calls),
			HTTPS:     fakeLifecycle("https", &calls),
		}

		if err := svc.Start(context.Background()); err == nil {
			t.Fatalf("Start() error = nil, want non-nil")
		}
		if diff := cmp.Diff([]string{"ebpf:start", "cidr:start", "ebpf:stop"}, calls); diff != "" {
			t.Fatalf("call order mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("trust", func(t *testing.T) {
		var calls []string
		trustLC := fakeLifecycle("trust", &calls)
		trustLC.startErr = errors.New("boom")

		svc := Service{
			Redirect:  fakeLifecycle("redirect", &calls),
			EBPF:      fakeLifecycle("ebpf", &calls),
			CIDRAllow: fakeLifecycle("cidr", &calls),
			Trust:     trustLC,
			DNS:       fakeLifecycle("dns", &calls),
			HTTPS:     fakeLifecycle("https", &calls),
		}

		if err := svc.Start(context.Background()); err == nil {
			t.Fatalf("Start() error = nil, want non-nil")
		}
		if diff := cmp.Diff([]string{"ebpf:start", "cidr:start", "trust:start", "cidr:stop", "ebpf:stop"}, calls); diff != "" {
			t.Fatalf("call order mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("dns", func(t *testing.T) {
		var calls []string
		dnsLC := fakeLifecycle("dns", &calls)
		dnsLC.startErr = errors.New("boom")

		svc := Service{
			Redirect:  fakeLifecycle("redirect", &calls),
			EBPF:      fakeLifecycle("ebpf", &calls),
			CIDRAllow: fakeLifecycle("cidr", &calls),
			Trust:     fakeLifecycle("trust", &calls),
			DNS:       dnsLC,
			HTTPS:     fakeLifecycle("https", &calls),
		}

		if err := svc.Start(context.Background()); err == nil {
			t.Fatalf("Start() error = nil, want non-nil")
		}
		if diff := cmp.Diff([]string{"ebpf:start", "cidr:start", "trust:start", "dns:start", "trust:stop", "cidr:stop", "ebpf:stop"}, calls); diff != "" {
			t.Fatalf("call order mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("https", func(t *testing.T) {
		var calls []string
		httpsLC := fakeLifecycle("https", &calls)
		httpsLC.startErr = errors.New("boom")

		svc := Service{
			Redirect:  fakeLifecycle("redirect", &calls),
			EBPF:      fakeLifecycle("ebpf", &calls),
			CIDRAllow: fakeLifecycle("cidr", &calls),
			Trust:     fakeLifecycle("trust", &calls),
			DNS:       fakeLifecycle("dns", &calls),
			HTTPS:     httpsLC,
		}

		if err := svc.Start(context.Background()); err == nil {
			t.Fatalf("Start() error = nil, want non-nil")
		}
		if diff := cmp.Diff([]string{"ebpf:start", "cidr:start", "trust:start", "dns:start", "https:start", "dns:stop", "trust:stop", "cidr:stop", "ebpf:stop"}, calls); diff != "" {
			t.Fatalf("call order mismatch (-want +got):\n%s", diff)
		}
	})
}
