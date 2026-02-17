package internal

import (
	"github.com/ankorstore/yokai/fxhttpserver"
	"github.com/zelshahawy/zelemetry/internal/handler"
	"go.uber.org/fx"
)

// Router is used to register the application HTTP middlewares and handlers.
func Router() fx.Option {
	return fx.Options(
		fxhttpserver.AsHandler("GET", "/setup", handler.NewSetupGetHandler),
		fxhttpserver.AsHandler("POST", "/setup", handler.NewSetupPostHandler),
		fxhttpserver.AsHandler("GET", "/login", handler.NewLoginGetHandler),
		fxhttpserver.AsHandler("POST", "/login", handler.NewLoginPostHandler),
		fxhttpserver.AsHandler("POST", "/logout", handler.NewLogoutHandler),
		fxhttpserver.AsHandler("GET", "/", handler.NewDashboardHandler),
		fxhttpserver.AsHandler("POST", "/websites", handler.NewAddWebsiteHandler),
		fxhttpserver.AsHandler("POST", "/websites/:id/check", handler.NewCheckWebsiteHandler),
		fxhttpserver.AsHandler("POST", "/websites/:id/check-alert", handler.NewCheckWebsiteAndAlertHandler),
		fxhttpserver.AsHandler("POST", "/websites/:id/settings", handler.NewUpdateWebsiteSettingsHandler),
		fxhttpserver.AsHandler("POST", "/websites/:id/delete", handler.NewDeleteWebsiteHandler),
		fxhttpserver.AsHandler("POST", "/checks/run", handler.NewRunChecksHandler),
		fxhttpserver.AsHandler("GET", "/api/websites", handler.NewWebsitesAPIHandler),
		fxhttpserver.AsHandler("GET", "/api/slack/config", handler.NewSlackConfigGetHandler),
		fxhttpserver.AsHandler("POST", "/api/slack/config", handler.NewSlackConfigPostHandler),
		fxhttpserver.AsHandler("POST", "/api/slack/test", handler.NewSlackTestHandler),
	)
}
