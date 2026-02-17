package handler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/zelshahawy/zelemetry/internal/handler/view"
	"github.com/zelshahawy/zelemetry/internal/monitor"
)

type DashboardHandler struct {
	service *monitor.Service
}

func NewDashboardHandler(service *monitor.Service) *DashboardHandler {
	return &DashboardHandler{service: service}
}

func (h *DashboardHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := requireAppAuth(c, h.service); err != nil {
			return err
		}
		c.Response().Header().Set(echo.HeaderContentType, echo.MIMETextHTMLCharsetUTF8)
		c.Response().WriteHeader(http.StatusOK)
		return view.Dashboard().Render(c.Request().Context(), c.Response().Writer)
	}
}

type AddWebsiteHandler struct {
	service *monitor.Service
}

func NewAddWebsiteHandler(service *monitor.Service) *AddWebsiteHandler {
	return &AddWebsiteHandler{service: service}
}

func (h *AddWebsiteHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := requireAppAuth(c, h.service); err != nil {
			return err
		}
		timeoutMS, _ := strconv.Atoi(c.FormValue("timeout_ms"))
		interval, _ := strconv.Atoi(c.FormValue("check_interval_seconds"))
		enabled := c.FormValue("enabled") == "on"
		slackAlertEnabled := c.FormValue("slack_alert_enabled") == "on"

		_, err := h.service.AddWebsite(monitor.AddWebsiteInput{
			Name:                 c.FormValue("name"),
			BaseURL:              c.FormValue("base_url"),
			Route:                c.FormValue("route"),
			Enabled:              enabled,
			SlackAlertEnabled:    slackAlertEnabled,
			CheckIntervalSeconds: interval,
			TimeoutMS:            timeoutMS,
		})
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		return c.Redirect(http.StatusSeeOther, "/")
	}
}

type CheckWebsiteHandler struct {
	service *monitor.Service
}

func NewCheckWebsiteHandler(service *monitor.Service) *CheckWebsiteHandler {
	return &CheckWebsiteHandler{service: service}
}

func (h *CheckWebsiteHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := requireAppAuth(c, h.service); err != nil {
			return err
		}
		id, err := parseWebsiteID(c)
		if err != nil {
			return c.String(http.StatusBadRequest, "invalid website id")
		}

		_, err = h.service.CheckWebsite(id)
		if err != nil {
			return c.String(http.StatusNotFound, err.Error())
		}

		return c.Redirect(http.StatusSeeOther, "/")
	}
}

type UpdateWebsiteSettingsHandler struct {
	service *monitor.Service
}

func NewUpdateWebsiteSettingsHandler(service *monitor.Service) *UpdateWebsiteSettingsHandler {
	return &UpdateWebsiteSettingsHandler{service: service}
}

func (h *UpdateWebsiteSettingsHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := requireAppAuth(c, h.service); err != nil {
			return err
		}
		id, err := parseWebsiteID(c)
		if err != nil {
			return c.String(http.StatusBadRequest, "invalid website id")
		}

		timeoutMS, _ := strconv.Atoi(c.FormValue("timeout_ms"))
		interval, _ := strconv.Atoi(c.FormValue("check_interval_seconds"))
		enabled := c.FormValue("enabled") == "on"
		slackAlertEnabled := c.FormValue("slack_alert_enabled") == "on"

		_, err = h.service.UpdateWebsiteSettings(id, monitor.UpdateWebsiteSettingsInput{
			Name:                 c.FormValue("name"),
			Route:                c.FormValue("route"),
			Enabled:              enabled,
			SlackAlertEnabled:    slackAlertEnabled,
			CheckIntervalSeconds: interval,
			TimeoutMS:            timeoutMS,
		})
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		return c.Redirect(http.StatusSeeOther, "/")
	}
}

type DeleteWebsiteHandler struct {
	service *monitor.Service
}

func NewDeleteWebsiteHandler(service *monitor.Service) *DeleteWebsiteHandler {
	return &DeleteWebsiteHandler{service: service}
}

func (h *DeleteWebsiteHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := requireAppAuth(c, h.service); err != nil {
			return err
		}
		id, err := parseWebsiteID(c)
		if err != nil {
			return c.String(http.StatusBadRequest, "invalid website id")
		}

		if err := h.service.DeleteWebsite(id); err != nil {
			return c.String(http.StatusNotFound, err.Error())
		}

		return c.Redirect(http.StatusSeeOther, "/")
	}
}

type RunChecksHandler struct {
	service *monitor.Service
}

func NewRunChecksHandler(service *monitor.Service) *RunChecksHandler {
	return &RunChecksHandler{service: service}
}

func (h *RunChecksHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := requireAppAuth(c, h.service); err != nil {
			return err
		}
		h.service.CheckAll()
		return c.Redirect(http.StatusSeeOther, "/")
	}
}

type WebsitesAPIHandler struct {
	service *monitor.Service
}

func NewWebsitesAPIHandler(service *monitor.Service) *WebsitesAPIHandler {
	return &WebsitesAPIHandler{service: service}
}

func (h *WebsitesAPIHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := requireAppAuth(c, h.service); err != nil {
			return err
		}
		return c.JSON(http.StatusOK, h.service.ListWebsites())
	}
}

type SlackConfigGetHandler struct {
	service *monitor.Service
}

func NewSlackConfigGetHandler(service *monitor.Service) *SlackConfigGetHandler {
	return &SlackConfigGetHandler{service: service}
}

func (h *SlackConfigGetHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := requireAppAuth(c, h.service); err != nil {
			return err
		}
		cfg, err := h.service.GetSlackConfig()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load slack config"})
		}

		return c.JSON(http.StatusOK, cfg)
	}
}

type SlackConfigPostHandler struct {
	service *monitor.Service
}

func NewSlackConfigPostHandler(service *monitor.Service) *SlackConfigPostHandler {
	return &SlackConfigPostHandler{service: service}
}

func (h *SlackConfigPostHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := requireAppAuth(c, h.service); err != nil {
			return err
		}
		enabled := c.FormValue("enabled") == "on" || strings.EqualFold(c.FormValue("enabled"), "true")

		cfg, err := h.service.SaveSlackConfig(monitor.SaveSlackConfigInput{
			Enabled:  enabled,
			Channel:  c.FormValue("channel"),
			Username: c.FormValue("username"),
		})
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save slack config"})
		}
		if cfg.Enabled && !cfg.HasWebhook {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "set ZELEMETRY_SLACK_WEBHOOK_URL in environment before enabling slack"})
		}

		return c.JSON(http.StatusOK, cfg)
	}
}

type SlackTestHandler struct {
	service *monitor.Service
}

func NewSlackTestHandler(service *monitor.Service) *SlackTestHandler {
	return &SlackTestHandler{service: service}
}

func (h *SlackTestHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := requireAppAuth(c, h.service); err != nil {
			return err
		}
		err := h.service.SendSlackTestMessage()
		switch {
		case err == nil:
			return c.JSON(http.StatusOK, map[string]any{"sent": true})
		case errors.Is(err, monitor.ErrSlackNotConfigured):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "slack is not configured"})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to send slack test message"})
		}
	}
}

func parseWebsiteID(c echo.Context) (int64, error) {
	return strconv.ParseInt(c.Param("id"), 10, 64)
}
