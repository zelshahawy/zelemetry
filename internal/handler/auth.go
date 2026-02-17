package handler

import (
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/zelshahawy/zelemetry/internal/monitor"
)

const sessionCookieName = "zelemetry_session"

type SetupGetHandler struct {
	service *monitor.Service
}

func NewSetupGetHandler(service *monitor.Service) *SetupGetHandler {
	return &SetupGetHandler{service: service}
}

func (h *SetupGetHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		hasUser, err := h.service.HasUser()
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to read users")
		}
		if hasUser {
			return c.Redirect(http.StatusSeeOther, "/login")
		}
		return c.HTML(http.StatusOK, authPage("Create Admin User", "/setup", "", "Create Account", ""))
	}
}

type SetupPostHandler struct {
	service *monitor.Service
}

func NewSetupPostHandler(service *monitor.Service) *SetupPostHandler {
	return &SetupPostHandler{service: service}
}

func (h *SetupPostHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := h.service.CreateInitialUser(c.FormValue("username"), c.FormValue("password")); err != nil {
			return c.HTML(http.StatusBadRequest, authPage("Create Admin User", "/setup", c.FormValue("username"), "Create Account", err.Error()))
		}
		token, err := h.service.Login(c.FormValue("username"), c.FormValue("password"))
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to create session")
		}
		writeSessionCookie(c, token)
		return c.Redirect(http.StatusSeeOther, "/")
	}
}

type LoginGetHandler struct {
	service *monitor.Service
}

func NewLoginGetHandler(service *monitor.Service) *LoginGetHandler {
	return &LoginGetHandler{service: service}
}

func (h *LoginGetHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		hasUser, err := h.service.HasUser()
		if err != nil {
			return c.String(http.StatusInternalServerError, "failed to read users")
		}
		if !hasUser {
			return c.Redirect(http.StatusSeeOther, "/setup")
		}
		if currentSessionToken(c) != "" && h.service.IsSessionValid(currentSessionToken(c)) {
			return c.Redirect(http.StatusSeeOther, "/")
		}
		return c.HTML(http.StatusOK, authPage("Sign In", "/login", "", "Sign In", ""))
	}
}

type LoginPostHandler struct {
	service *monitor.Service
}

func NewLoginPostHandler(service *monitor.Service) *LoginPostHandler {
	return &LoginPostHandler{service: service}
}

func (h *LoginPostHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		token, err := h.service.Login(c.FormValue("username"), c.FormValue("password"))
		if err != nil {
			return c.HTML(http.StatusUnauthorized, authPage("Sign In", "/login", c.FormValue("username"), "Sign In", "invalid username or password"))
		}
		writeSessionCookie(c, token)
		return c.Redirect(http.StatusSeeOther, "/")
	}
}

type LogoutHandler struct {
	service *monitor.Service
}

func NewLogoutHandler(service *monitor.Service) *LogoutHandler {
	return &LogoutHandler{service: service}
}

func (h *LogoutHandler) Handle() echo.HandlerFunc {
	return func(c echo.Context) error {
		h.service.Logout(currentSessionToken(c))
		clearSessionCookie(c)
		return c.Redirect(http.StatusSeeOther, "/login")
	}
}

func requireAppAuth(c echo.Context, service *monitor.Service) error {
	hasUser, err := service.HasUser()
	if err != nil {
		return c.String(http.StatusInternalServerError, "failed to read users")
	}
	if !hasUser {
		if isAPIRequest(c) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "setup required"})
		}
		return c.Redirect(http.StatusSeeOther, "/setup")
	}

	token := currentSessionToken(c)
	if token == "" || !service.IsSessionValid(token) {
		clearSessionCookie(c)
		if isAPIRequest(c) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		}
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	return nil
}

func isAPIRequest(c echo.Context) bool {
	return strings.HasPrefix(c.Request().URL.Path, "/api/")
}

func currentSessionToken(c echo.Context) string {
	cookie, err := c.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func writeSessionCookie(c echo.Context, token string) {
	c.SetCookie(&http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((24 * time.Hour).Seconds()),
	})
}

func clearSessionCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func authPage(title, action, username, cta, errMsg string) string {
	safeUser := html.EscapeString(username)
	safeErr := html.EscapeString(errMsg)
	errorBlock := ""
	if strings.TrimSpace(safeErr) != "" {
		errorBlock = `<p style="color:#ff8e96;margin:0 0 8px;">` + safeErr + `</p>`
	}
	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Zelemetry - ` + title + `</title>
  <style>
    body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#020c24;color:#e8eefb;display:grid;place-items:center;min-height:100vh}
    .card{width:min(420px,92vw);padding:20px;border:1px solid #1a2f56;border-radius:12px;background:#07142e;display:grid;gap:10px}
    input{height:42px;padding:0 12px;border-radius:8px;border:1px solid #294269;background:#041028;color:#e8eefb}
    button{height:42px;border-radius:8px;border:1px solid #2f5ab1;background:#123479;color:#fff;font-weight:600;cursor:pointer}
    h1{margin:0 0 8px;font-size:1.3rem}
    p{margin:0;color:#8ea2c9}
  </style>
</head>
<body>
  <form class="card" method="post" action="` + action + `">
    <h1>` + title + `</h1>
    <p>Zelemetry access is protected.</p>
    ` + errorBlock + `
    <input name="username" placeholder="Username" value="` + safeUser + `" required>
    <input name="password" type="password" placeholder="Password" required>
    <button type="submit">` + cta + `</button>
  </form>
</body>
</html>`
}
