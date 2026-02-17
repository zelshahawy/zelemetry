package handler

import (
	"net/http"
	"strconv"

	"github.com/zelshahawy/zelemetry/internal/handler/view"
	"github.com/zelshahawy/zelemetry/internal/monitor"
	"github.com/labstack/echo/v4"
)

type DashboardHandler struct {
	service *monitor.Service
}

func NewDashboardHandler(service *monitor.Service) *DashboardHandler {
	return &DashboardHandler{service: service}
}

func (h *DashboardHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		_ = h.service
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
		timeoutMS, _ := strconv.Atoi(c.FormValue("timeout_ms"))
		interval, _ := strconv.Atoi(c.FormValue("check_interval_seconds"))
		enabled := c.FormValue("enabled") == "on"

		_, err := h.service.AddWebsite(monitor.AddWebsiteInput{
			Name:                 c.FormValue("name"),
			BaseURL:              c.FormValue("base_url"),
			Route:                c.FormValue("route"),
			Enabled:              enabled,
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
		id, err := parseWebsiteID(c)
		if err != nil {
			return c.String(http.StatusBadRequest, "invalid website id")
		}

		timeoutMS, _ := strconv.Atoi(c.FormValue("timeout_ms"))
		interval, _ := strconv.Atoi(c.FormValue("check_interval_seconds"))
		enabled := c.FormValue("enabled") == "on"

		_, err = h.service.UpdateWebsiteSettings(id, monitor.UpdateWebsiteSettingsInput{
			Name:                 c.FormValue("name"),
			Route:                c.FormValue("route"),
			Enabled:              enabled,
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

// Handle handles delete website requests.
func (h *DeleteWebsiteHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
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

// RunChecksHandler checks every website.
type RunChecksHandler struct {
	service *monitor.Service
}

// NewRunChecksHandler returns a new run checks handler.
func NewRunChecksHandler(service *monitor.Service) *RunChecksHandler {
	return &RunChecksHandler{service: service}
}

// Handle handles full checks execution.
func (h *RunChecksHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		h.service.CheckAll()
		return c.Redirect(http.StatusSeeOther, "/")
	}
}

// WebsitesAPIHandler exposes websites state as JSON.
type WebsitesAPIHandler struct {
	service *monitor.Service
}

// NewWebsitesAPIHandler returns a websites API handler.
func NewWebsitesAPIHandler(service *monitor.Service) *WebsitesAPIHandler {
	return &WebsitesAPIHandler{service: service}
}

// Handle handles API website list requests.
func (h *WebsitesAPIHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.JSON(http.StatusOK, h.service.ListWebsites())
	}
}

func parseWebsiteID(c echo.Context) (int64, error) {
	return strconv.ParseInt(c.Param("id"), 10, 64)
}
