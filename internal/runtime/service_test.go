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
		Redirect: fakeLifecycle("redirect", &calls),
		EBPF:     fakeLifecycle("ebpf", &calls),
		DNS:      fakeLifecycle("dns", &calls),
	}

	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if diff := cmp.Diff([]string{"ebpf:start", "redirect:start", "dns:start"}, calls); diff != "" {
		t.Fatalf("call order mismatch (-want +got):\n%s", diff)
	}
}

func TestServiceStopOrdersDependencies(t *testing.T) {
	var calls []string
	svc := Service{
		Redirect: fakeLifecycle("redirect", &calls),
		EBPF:     fakeLifecycle("ebpf", &calls),
		DNS:      fakeLifecycle("dns", &calls),
	}

	if err := svc.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if diff := cmp.Diff([]string{"dns:stop", "redirect:stop", "ebpf:stop"}, calls); diff != "" {
		t.Fatalf("call order mismatch (-want +got):\n%s", diff)
	}
}

func TestServiceStartPropagatesError(t *testing.T) {
	t.Run("ebpf", func(t *testing.T) {
		var calls []string
		ebpfLC := fakeLifecycle("ebpf", &calls)
		ebpfLC.startErr = errors.New("boom")

		svc := Service{
			Redirect: fakeLifecycle("redirect", &calls),
			EBPF:     ebpfLC,
			DNS:      fakeLifecycle("dns", &calls),
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
			Redirect: redirectLC,
			EBPF:     fakeLifecycle("ebpf", &calls),
			DNS:      fakeLifecycle("dns", &calls),
		}

		if err := svc.Start(context.Background()); err == nil {
			t.Fatalf("Start() error = nil, want non-nil")
		}
		if diff := cmp.Diff([]string{"ebpf:start", "redirect:start"}, calls); diff != "" {
			t.Fatalf("call order mismatch (-want +got):\n%s", diff)
		}
	})
}

