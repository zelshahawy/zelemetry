package monitor

import (
	"context"
	"time"

	"go.uber.org/fx"
)

// Scheduler runs automatic checks based on website intervals.
type Scheduler struct {
	service *Service
	stopCh  chan struct{}
}

// NewScheduler creates and wires the scheduler to the app lifecycle.
func NewScheduler(lifecycle fx.Lifecycle, service *Service) *Scheduler {
	s := &Scheduler{service: service, stopCh: make(chan struct{})}

	lifecycle.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			go s.run()
			return nil
		},
		OnStop: func(_ context.Context) error {
			close(s.stopCh)
			return nil
		},
	})

	return s
}

func (s *Scheduler) run() {
	ticker := time.NewTicker(schedulerTickRate)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.service.CheckDue(time.Now().UTC())
		case <-s.stopCh:
			return
		}
	}
}
