package app

import (
	"context"
	"log/slog"

	"github.com/moolen/nie/internal/ebpf"
)

func startAuditEgressLogger(
	ctx context.Context,
	logger *slog.Logger,
	source interface {
		EventReader() (ebpf.EventReader, error)
	},
) (func(), error) {
	reader, err := source.EventReader()
	if err != nil {
		return nil, err
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		logAuditEgressEvents(ctx, logger, reader)
	}()

	return func() {
		_ = reader.Close()
		<-done
	}, nil
}

func logAuditEgressEvents(ctx context.Context, logger *slog.Logger, reader ebpf.EventReader) {
	for {
		event, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Error("read_egress_event", "err", err)
			return
		}
		if event.Action != ebpf.EgressActionAllow {
			continue
		}

		logger.Info("would_deny_egress",
			"dst", event.Destination.String(),
			"reason", event.Reason.String(),
			"proto", event.Protocol.String(),
			"port", event.Port,
		)
	}
}
