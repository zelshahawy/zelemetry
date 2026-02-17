package internal

import (
	"github.com/zelshahawy/zelemetry/internal/handler"
	"github.com/ankorstore/yokai/fxhttpserver"
	"go.uber.org/fx"
)

// Router is used to register the application HTTP middlewares and handlers.
func Router() fx.Option {
	return fx.Options(
		fxhttpserver.AsHandler("GET", "/", handler.NewDashboardHandler),
		fxhttpserver.AsHandler("POST", "/websites", handler.NewAddWebsiteHandler),
		fxhttpserver.AsHandler("POST", "/websites/:id/check", handler.NewCheckWebsiteHandler),
		fxhttpserver.AsHandler("POST", "/websites/:id/settings", handler.NewUpdateWebsiteSettingsHandler),
		fxhttpserver.AsHandler("POST", "/websites/:id/delete", handler.NewDeleteWebsiteHandler),
		fxhttpserver.AsHandler("POST", "/checks/run", handler.NewRunChecksHandler),
		fxhttpserver.AsHandler("GET", "/api/websites", handler.NewWebsitesAPIHandler),
	)
}
