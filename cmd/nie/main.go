package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/moolen/nie/internal/app"
	"github.com/moolen/nie/internal/config"
)

type cliDeps struct {
	readFile      func(string) ([]byte, error)
	loadConfig    func([]byte) (config.Config, error)
	runApp        func(context.Context, config.Config, *slog.Logger) error
	notifyContext func(context.Context, ...os.Signal) (context.Context, context.CancelFunc)
	stderr        io.Writer
}

func main() {
	os.Exit(runMain(os.Args[1:], cliDeps{}))
}

func runMain(args []string, deps cliDeps) int {
	deps = deps.withDefaults()

	fs := flag.NewFlagSet("nie", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var configPath string
	fs.StringVar(&configPath, "config", "", "path to YAML config")
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintf(deps.stderr, "%v\n", err)
		return 2
	}

	if configPath == "" {
		_, _ = fmt.Fprintln(deps.stderr, "missing required -config")
		return 2
	}

	raw, err := deps.readFile(configPath)
	if err != nil {
		_, _ = fmt.Fprintf(deps.stderr, "read config: %v\n", err)
		return 1
	}

	cfg, err := deps.loadConfig(raw)
	if err != nil {
		_, _ = fmt.Fprintf(deps.stderr, "load config: %v\n", err)
		return 1
	}

	logger := slog.Default()
	ctx, stopSignals := deps.notifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	if err := deps.runApp(ctx, cfg, logger); err != nil {
		_, _ = fmt.Fprintf(deps.stderr, "%v\n", err)
		return 1
	}

	return 0
}

func (d cliDeps) withDefaults() cliDeps {
	if d.readFile == nil {
		d.readFile = os.ReadFile
	}
	if d.loadConfig == nil {
		d.loadConfig = config.Load
	}
	if d.runApp == nil {
		d.runApp = app.Run
	}
	if d.notifyContext == nil {
		d.notifyContext = signal.NotifyContext
	}
	if d.stderr == nil {
		d.stderr = os.Stderr
	}
	return d
}
