package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/moolen/nie/internal/config"
)

func Run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	return run(ctx, cfg, logger, componentBuilders{}, func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 5*time.Second)
	})
}

func run(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
	builders componentBuilders,
	newStopContext func() (context.Context, context.CancelFunc),
) error {
	svc, ebpfMgr, err := buildRuntimeService(cfg, logger, builders)
	if err != nil {
		return err
	}

	if err := svc.Start(ctx); err != nil {
		return fmt.Errorf("start: %w", err)
	}

	var stopAuditLogger func()
	if cfg.Mode == config.ModeAudit {
		stopAuditLogger, err = startAuditEgressLogger(ctx, logger, ebpfMgr)
		if err != nil {
			stopCtx, cancel := newStopContext()
			defer cancel()
			_ = svc.Stop(stopCtx)
			return fmt.Errorf("start egress event logger: %w", err)
		}
	}

	<-ctx.Done()

	if stopAuditLogger != nil {
		stopAuditLogger()
	}

	stopCtx, cancel := newStopContext()
	defer cancel()
	if err := svc.Stop(stopCtx); err != nil {
		return fmt.Errorf("stop: %w", err)
	}
	return nil
}
