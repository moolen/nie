package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"

	"github.com/moolen/nie/internal/app"
	"github.com/moolen/nie/internal/config"
	"github.com/spf13/cobra"
)

type cliDeps struct {
	readFile      func(string) ([]byte, error)
	loadConfig    func([]byte) (config.Config, error)
	runApp        func(context.Context, config.Config, *slog.Logger) error
	notifyContext func(context.Context, ...os.Signal) (context.Context, context.CancelFunc)
	stdout        io.Writer
	stderr        io.Writer
}

type cliError struct {
	code int
	err  error
}

func (e *cliError) Error() string {
	return e.err.Error()
}

func (e *cliError) Unwrap() error {
	return e.err
}

func runMain(args []string, deps cliDeps) int {
	deps = deps.withDefaults()

	cmd := newRootCmd(deps)
	cmd.SetArgs(args)
	cmd.SetOut(deps.stdout)
	cmd.SetErr(deps.stderr)

	if err := cmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(deps.stderr, err)

		var cliErr *cliError
		if errors.As(err, &cliErr) {
			return cliErr.code
		}

		return 2
	}

	return 0
}

func newRootCmd(deps cliDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "nie",
		Short:         "Single-host Linux egress policy agent",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newRunCmd(deps))
	return cmd
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
	if d.stdout == nil {
		d.stdout = os.Stdout
	}
	if d.stderr == nil {
		d.stderr = os.Stderr
	}
	return d
}
