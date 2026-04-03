package runtime

import "context"

type Lifecycle interface {
	Start(context.Context) error
	Stop(context.Context) error
}

type Service struct {
	Redirect Lifecycle
	EBPF     Lifecycle
	DNS      Lifecycle
}

func (s Service) Start(ctx context.Context) error {
	var started []Lifecycle
	rollback := func() {
		rollbackCtx := context.WithoutCancel(ctx)
		for i := len(started) - 1; i >= 0; i-- {
			_ = started[i].Stop(rollbackCtx)
		}
	}

	if s.EBPF != nil {
		if err := s.EBPF.Start(ctx); err != nil {
			return err
		}
		started = append(started, s.EBPF)
	}
	if s.Redirect != nil {
		if err := s.Redirect.Start(ctx); err != nil {
			rollback()
			return err
		}
		started = append(started, s.Redirect)
	}
	if s.DNS != nil {
		if err := s.DNS.Start(ctx); err != nil {
			rollback()
			return err
		}
	}
	return nil
}

func (s Service) Stop(ctx context.Context) error {
	if s.DNS != nil {
		if err := s.DNS.Stop(ctx); err != nil {
			return err
		}
	}
	if s.Redirect != nil {
		if err := s.Redirect.Stop(ctx); err != nil {
			return err
		}
	}
	if s.EBPF != nil {
		return s.EBPF.Stop(ctx)
	}
	return nil
}
