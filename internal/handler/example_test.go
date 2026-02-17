package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zelshahawy/zelemetry/internal"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"go.uber.org/fx"
)

type monitoredWebsite struct {
	ID                   int64      `json:"id"`
	Name                 string     `json:"name"`
	BaseURL              string     `json:"base_url"`
	Route                string     `json:"route"`
	TargetURL            string     `json:"target_url"`
	Enabled              bool       `json:"enabled"`
	CheckIntervalSeconds int        `json:"check_interval_seconds"`
	TimeoutMS            int        `json:"timeout_ms"`
	LastStatus           string     `json:"last_status"`
	LastHTTPStatus       int        `json:"last_http_status"`
	LastCheckedAt        *time.Time `json:"last_checked_at"`
}

func TestDashboardFlow_AddSettingsAndCheckWebsite(t *testing.T) {
	t.Setenv("ZELEMETRY_DB_PATH", ":memory:")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	var httpServer *echo.Echo
	internal.RunTest(t, fx.Populate(&httpServer))

	addForm := url.Values{}
	addForm.Set("name", "Core")
	addForm.Set("base_url", upstream.URL)
	addForm.Set("route", "/health")
	addForm.Set("check_interval_seconds", "60")
	addForm.Set("timeout_ms", "3000")
	addForm.Set("enabled", "on")

	postReq := httptest.NewRequest(http.MethodPost, "/websites", strings.NewReader(addForm.Encode()))
	postReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	postRec := httptest.NewRecorder()
	httpServer.ServeHTTP(postRec, postReq)
	assert.Equalf(t, http.StatusSeeOther, postRec.Code, "add response: %s", postRec.Body.String())

	settingsForm := url.Values{}
	settingsForm.Set("name", "Core API")
	settingsForm.Set("route", "/health")
	settingsForm.Set("check_interval_seconds", "45")
	settingsForm.Set("timeout_ms", "2200")
	settingsForm.Set("enabled", "on")

	setReq := httptest.NewRequest(http.MethodPost, "/websites/1/settings", strings.NewReader(settingsForm.Encode()))
	setReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	setRec := httptest.NewRecorder()
	httpServer.ServeHTTP(setRec, setReq)
	assert.Equalf(t, http.StatusSeeOther, setRec.Code, "settings response: %s", setRec.Body.String())

	runReq := httptest.NewRequest(http.MethodPost, "/checks/run", nil)
	runRec := httptest.NewRecorder()
	httpServer.ServeHTTP(runRec, runReq)
	assert.Equal(t, http.StatusSeeOther, runRec.Code)

	apiReq := httptest.NewRequest(http.MethodGet, "/api/websites", nil)
	apiRec := httptest.NewRecorder()
	httpServer.ServeHTTP(apiRec, apiReq)
	assert.Equal(t, http.StatusOK, apiRec.Code)

	websites := []monitoredWebsite{}
	err := json.Unmarshal(apiRec.Body.Bytes(), &websites)
	assert.NoError(t, err)
	if assert.Len(t, websites, 1) {
		assert.Equal(t, "Core API", websites[0].Name)
		assert.Equal(t, 45, websites[0].CheckIntervalSeconds)
		assert.Equal(t, 2200, websites[0].TimeoutMS)
		assert.True(t, websites[0].Enabled)
		assert.Equal(t, "UP", websites[0].LastStatus)
		assert.Equal(t, http.StatusOK, websites[0].LastHTTPStatus)
		assert.NotNil(t, websites[0].LastCheckedAt)
	}
}

func TestAddWebsiteValidation(t *testing.T) {
	t.Setenv("ZELEMETRY_DB_PATH", ":memory:")

	var httpServer *echo.Echo
	internal.RunTest(t, fx.Populate(&httpServer))

	form := url.Values{}
	form.Set("name", "Broken")
	form.Set("base_url", "not-a-url")
	form.Set("check_interval_seconds", "60")
	form.Set("timeout_ms", "1000")
	form.Set("enabled", "on")

	req := httptest.NewRequest(http.MethodPost, "/websites", strings.NewReader(form.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	httpServer.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "base_url")
}
