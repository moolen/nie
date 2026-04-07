package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/moolen/nie/internal/config"
)

func TestCLIRequiresConfigFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runMain(nil, cliDeps{
		stdout: &stdout,
		stderr: &stderr,
	})

	if code != 0 {
		t.Fatalf("runMain() code = %d, want 0", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty stderr", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Usage:") || !strings.Contains(stdout.String(), "run") {
		t.Fatalf("stdout = %q, want Cobra help with run command", stdout.String())
	}
}

func TestCLIReportsConfigReadFailure(t *testing.T) {
	var stderr bytes.Buffer
	boom := errors.New("no such file")

	code := runMain([]string{"run", "--config", "/tmp/nie.yaml"}, cliDeps{
		readFile: func(path string) ([]byte, error) {
			if path != "/tmp/nie.yaml" {
				t.Fatalf("readFile() path = %q, want /tmp/nie.yaml", path)
			}
			return nil, boom
		},
		stderr: &stderr,
	})

	if code != 1 {
		t.Fatalf("runMain() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "read config") || !strings.Contains(stderr.String(), boom.Error()) {
		t.Fatalf("stderr = %q, want read config error", stderr.String())
	}
}

func TestCLIReportsConfigLoadFailure(t *testing.T) {
	var stderr bytes.Buffer
	boom := errors.New("invalid yaml")

	code := runMain([]string{"run", "--config", "/tmp/nie.yaml"}, cliDeps{
		readFile: func(string) ([]byte, error) { return []byte("mode: nope"), nil },
		loadConfig: func(raw []byte) (config.Config, error) {
			if string(raw) != "mode: nope" {
				t.Fatalf("loadConfig() raw = %q, want injected config bytes", raw)
			}
			return config.Config{}, boom
		},
		stderr: &stderr,
	})

	if code != 1 {
		t.Fatalf("runMain() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "load config") || !strings.Contains(stderr.String(), boom.Error()) {
		t.Fatalf("stderr = %q, want load config error", stderr.String())
	}
}

func TestCLIReturnsAppRunError(t *testing.T) {
	var stderr bytes.Buffer
	boom := errors.New("start: boom")

	code := runMain([]string{"run", "--config", "/tmp/nie.yaml"}, cliDeps{
		readFile:   func(string) ([]byte, error) { return []byte("ok"), nil },
		loadConfig: func([]byte) (config.Config, error) { return config.Config{}, nil },
		runApp: func(context.Context, config.Config, *slog.Logger) error {
			return boom
		},
		stderr: &stderr,
	})

	if code != 1 {
		t.Fatalf("runMain() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), boom.Error()) {
		t.Fatalf("stderr = %q, want %q", stderr.String(), boom.Error())
	}
}

func TestCLIRunRequiresConfigFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runMain([]string{"run"}, cliDeps{
		stdout: &stdout,
		stderr: &stderr,
	})

	if code != 2 {
		t.Fatalf("runMain() code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty stdout", stdout.String())
	}
	if !strings.Contains(stderr.String(), `required flag(s) "config" not set`) {
		t.Fatalf("stderr = %q, want required config flag error", stderr.String())
	}
}
