package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"syscall"

	"github.com/spf13/cobra"
)

func newRunCmd(deps cliDeps) *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the NIE daemon",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				return &cliError{code: 2, err: fmt.Errorf(`required flag(s) "config" not set`)}
			}

			raw, err := deps.readFile(configPath)
			if err != nil {
				return &cliError{code: 1, err: fmt.Errorf("read config: %w", err)}
			}

			cfg, err := deps.loadConfig(raw)
			if err != nil {
				return &cliError{code: 1, err: fmt.Errorf("load config: %w", err)}
			}

			logger := slog.Default()
			ctx, stopSignals := deps.notifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stopSignals()

			if err := deps.runApp(ctx, cfg, logger); err != nil {
				return &cliError{code: 1, err: err}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "path to YAML config")
	return cmd
}
