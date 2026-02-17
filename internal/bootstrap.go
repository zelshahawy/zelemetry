package internal

import (
	"context"
	"fmt"
	"testing"

	"github.com/ankorstore/yokai/fxconfig"
	"github.com/ankorstore/yokai/fxcore"
	"github.com/ankorstore/yokai/fxhttpserver"
	"go.uber.org/fx"
)

func init() {
	RootDir = fxcore.RootDir(1)
}

var RootDir string

var Bootstrapper = fxcore.NewBootstrapper().WithOptions(
	fxhttpserver.FxHttpServerModule,
	Register(),
	Router(),
)

func Run(ctx context.Context) {
	Bootstrapper.WithContext(ctx).RunApp()
}

func RunTest(tb testing.TB, options ...fx.Option) {
	tb.Helper()

	Bootstrapper.RunTestApp(
		tb,
		fxconfig.AsConfigPath(fmt.Sprintf("%s/configs/", RootDir)),
		fx.Options(options...),
	)
}
