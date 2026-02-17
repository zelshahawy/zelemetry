package internal

import (
	"github.com/zelshahawy/zelemetry/internal/monitor"
	"go.uber.org/fx"
)

func Register() fx.Option {
	return fx.Options(
		fx.Provide(
			monitor.OpenDatabase,
			monitor.NewHTTPClient,
			monitor.NewService,
			monitor.NewScheduler,
		),
		fx.Invoke(
			func(_ *monitor.Scheduler) {},
		),
	)
}
