package monitor

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeoutMS  = 5000
	defaultIntervalS  = 200
	schedulerTickRate = 5 * time.Second
	slackAlertDelay   = 5 * time.Minute
)

type Website struct {
	ID                   int64      `json:"id"`
	Name                 string     `json:"name"`
	BaseURL              string     `json:"base_url"`
	Route                string     `json:"route"`
	TargetURL            string     `json:"target_url"`
	Enabled              bool       `json:"enabled"`
	SlackAlertEnabled    bool       `json:"slack_alert_enabled"`
	CheckIntervalSeconds int        `json:"check_interval_seconds"`
	TimeoutMS            int        `json:"timeout_ms"`
	LastStatus           string     `json:"last_status"`
	LastHTTPStatus       int        `json:"last_http_status"`
	LastResponseMS       int64      `json:"last_response_ms"`
	LastError            string     `json:"last_error"`
	LastCheckedAt        *time.Time `json:"last_checked_at"`
	DownSinceAt          *time.Time `json:"down_since_at,omitempty"`
	SlackLastAlertAt     *time.Time `json:"slack_last_alert_at,omitempty"`
}

type AddWebsiteInput struct {
	Name                 string
	BaseURL              string
	Route                string
	Enabled              bool
	SlackAlertEnabled    bool
	CheckIntervalSeconds int
	TimeoutMS            int
}

type UpdateWebsiteSettingsInput struct {
	Name                 string
	Route                string
	Enabled              bool
	SlackAlertEnabled    bool
	CheckIntervalSeconds int
	TimeoutMS            int
}

type SlackConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
	Username   string `json:"username"`
}

type SaveSlackConfigInput struct {
	Enabled    bool
	WebhookURL string
	Channel    string
	Username   string
}

type Service struct {
	db     *sql.DB
	client *http.Client
}

func NewHTTPClient() *http.Client {
	return &http.Client{}
}

func NewService(db *sql.DB, client *http.Client) *Service {
	return &Service{db: db, client: client}
}

func (s *Service) AddWebsite(input AddWebsiteInput) (Website, error) {
	baseURL := strings.TrimSpace(input.BaseURL)
	name := strings.TrimSpace(input.Name)
	route := strings.TrimSpace(input.Route)

	if baseURL == "" {
		return Website{}, errors.New("base_url is required")
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return Website{}, errors.New("base_url must be a valid absolute URL")
	}

	if name == "" {
		name = parsedURL.Host
	}

	interval := input.CheckIntervalSeconds
	if interval <= 0 {
		interval = defaultIntervalS
	}

	timeoutMS := input.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = defaultTimeoutMS
	}

	targetURL := buildTargetURL(parsedURL.String(), route)
	enabled := input.Enabled

	res, err := s.db.Exec(
		`INSERT INTO websites (name, base_url, route, target_url, enabled, slack_alert_enabled, check_interval_seconds, timeout_ms, last_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'UNKNOWN')`,
		name,
		parsedURL.String(),
		route,
		targetURL,
		boolToInt(enabled),
		boolToInt(input.SlackAlertEnabled),
		interval,
		timeoutMS,
	)
	if err != nil {
		return Website{}, fmt.Errorf("insert website: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return Website{}, fmt.Errorf("last insert id: %w", err)
	}

	return s.GetWebsite(id)
}

func (s *Service) UpdateWebsiteSettings(id int64, input UpdateWebsiteSettingsInput) (Website, error) {
	current, err := s.GetWebsite(id)
	if err != nil {
		return Website{}, err
	}

	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = current.Name
	}

	route := strings.TrimSpace(input.Route)
	targetURL := buildTargetURL(current.BaseURL, route)

	interval := input.CheckIntervalSeconds
	if interval <= 0 {
		interval = current.CheckIntervalSeconds
		if interval <= 0 {
			interval = defaultIntervalS
		}
	}

	timeoutMS := input.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = current.TimeoutMS
		if timeoutMS <= 0 {
			timeoutMS = defaultTimeoutMS
		}
	}

	_, err = s.db.Exec(
		`UPDATE websites SET name = ?, route = ?, target_url = ?, enabled = ?, slack_alert_enabled = ?, check_interval_seconds = ?, timeout_ms = ? WHERE id = ?`,
		name,
		route,
		targetURL,
		boolToInt(input.Enabled),
		boolToInt(input.SlackAlertEnabled),
		interval,
		timeoutMS,
		id,
	)
	if err != nil {
		return Website{}, fmt.Errorf("update website: %w", err)
	}

	return s.GetWebsite(id)
}

func (s *Service) DeleteWebsite(id int64) error {
	res, err := s.db.Exec(`DELETE FROM websites WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete website: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("website %d not found", id)
	}

	return nil
}

func (s *Service) ListWebsites() []Website {
	rows, err := s.db.Query(`SELECT id, name, base_url, route, target_url, enabled, slack_alert_enabled, check_interval_seconds, timeout_ms, last_status, last_http_status, last_response_ms, last_error, last_checked_at, down_since_at, slack_last_alert_at FROM websites ORDER BY id ASC`)
	if err != nil {
		return []Website{}
	}
	defer rows.Close()

	websites := []Website{}
	for rows.Next() {
		website, scanErr := scanWebsite(rows)
		if scanErr == nil {
			websites = append(websites, website)
		}
	}

	return websites
}

func (s *Service) GetWebsite(id int64) (Website, error) {
	row := s.db.QueryRow(`SELECT id, name, base_url, route, target_url, enabled, slack_alert_enabled, check_interval_seconds, timeout_ms, last_status, last_http_status, last_response_ms, last_error, last_checked_at, down_since_at, slack_last_alert_at FROM websites WHERE id = ?`, id)
	website, err := scanWebsite(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Website{}, fmt.Errorf("website %d not found", id)
		}
		return Website{}, fmt.Errorf("get website: %w", err)
	}
	return website, nil
}

func (s *Service) CheckWebsite(id int64) (Website, error) {
	site, err := s.GetWebsite(id)
	if err != nil {
		return Website{}, err
	}

	checked := s.performCheck(site)
	if checked.LastStatus == "DOWN" {
		if checked.DownSinceAt == nil {
			if checked.LastCheckedAt != nil {
				downSince := checked.LastCheckedAt.UTC()
				checked.DownSinceAt = &downSince
			} else {
				now := time.Now().UTC()
				checked.DownSinceAt = &now
			}
		}
	} else {
		checked.DownSinceAt = nil
		checked.SlackLastAlertAt = nil
	}

	_, err = s.db.Exec(
		`UPDATE websites SET last_status = ?, last_http_status = ?, last_response_ms = ?, last_error = ?, last_checked_at = ?, down_since_at = ?, slack_last_alert_at = ? WHERE id = ?`,
		checked.LastStatus,
		checked.LastHTTPStatus,
		checked.LastResponseMS,
		checked.LastError,
		toNullableTimeString(checked.LastCheckedAt),
		toNullableTimeString(checked.DownSinceAt),
		toNullableTimeString(checked.SlackLastAlertAt),
		checked.ID,
	)
	if err != nil {
		return Website{}, fmt.Errorf("update check result: %w", err)
	}
	if shouldSendSlackDownAlert(checked) {
		if notifyErr := s.notifySlackDown(checked); notifyErr == nil {
			now := time.Now().UTC()
			checked.SlackLastAlertAt = &now
			_, _ = s.db.Exec(
				`UPDATE websites SET slack_last_alert_at = ? WHERE id = ?`,
				toNullableTimeString(checked.SlackLastAlertAt),
				checked.ID,
			)
		}
	}

	return checked, nil
}

func (s *Service) GetSlackConfig() (SlackConfig, error) {
	row := s.db.QueryRow(`SELECT enabled, webhook_url, channel, username FROM slack_config WHERE id = 1`)

	var (
		cfg        SlackConfig
		enabledInt int
	)

	err := row.Scan(&enabledInt, &cfg.WebhookURL, &cfg.Channel, &cfg.Username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SlackConfig{}, nil
		}
		return SlackConfig{}, fmt.Errorf("get slack config: %w", err)
	}

	cfg.Enabled = intToBool(enabledInt)
	return cfg, nil
}

func (s *Service) SaveSlackConfig(input SaveSlackConfigInput) (SlackConfig, error) {
	cfg := SlackConfig{
		Enabled:    input.Enabled,
		WebhookURL: strings.TrimSpace(input.WebhookURL),
		Channel:    strings.TrimSpace(input.Channel),
		Username:   strings.TrimSpace(input.Username),
	}

	_, err := s.db.Exec(
		`INSERT INTO slack_config (id, enabled, webhook_url, channel, username) VALUES (1, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled, webhook_url = excluded.webhook_url, channel = excluded.channel, username = excluded.username`,
		boolToInt(cfg.Enabled),
		cfg.WebhookURL,
		cfg.Channel,
		cfg.Username,
	)
	if err != nil {
		return SlackConfig{}, fmt.Errorf("save slack config: %w", err)
	}

	return cfg, nil
}

func (s *Service) CheckAll() []Website {
	websites := s.ListWebsites()
	for _, site := range websites {
		_, _ = s.CheckWebsite(site.ID)
	}
	return s.ListWebsites()
}

func (s *Service) CheckDue(now time.Time) {
	websites := s.ListWebsites()
	for _, site := range websites {
		if !site.Enabled {
			continue
		}
		if shouldCheckNow(site, now) {
			_, _ = s.CheckWebsite(site.ID)
		}
	}
}

func (s *Service) performCheck(site Website) Website {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(site.TimeoutMS)*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, site.TargetURL, nil)
	if err != nil {
		return checkedDown(site, 0, time.Since(start), err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return checkedDown(site, 0, time.Since(start), err)
	}
	defer resp.Body.Close()

	now := time.Now().UTC()
	site.LastCheckedAt = &now
	site.LastHTTPStatus = resp.StatusCode
	site.LastResponseMS = time.Since(start).Milliseconds()
	site.LastError = ""

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		site.LastStatus = "UP"
	} else {
		site.LastStatus = "DOWN"
		site.LastError = "unexpected status code " + strconv.Itoa(resp.StatusCode)
	}

	return site
}

func checkedDown(site Website, code int, duration time.Duration, err error) Website {
	now := time.Now().UTC()
	site.LastCheckedAt = &now
	site.LastStatus = "DOWN"
	site.LastHTTPStatus = code
	site.LastResponseMS = duration.Milliseconds()
	site.LastError = err.Error()

	return site
}

func shouldCheckNow(site Website, now time.Time) bool {
	if site.LastCheckedAt == nil {
		return true
	}
	interval := site.CheckIntervalSeconds
	if interval <= 0 {
		interval = defaultIntervalS
	}
	nextCheck := site.LastCheckedAt.Add(time.Duration(interval) * time.Second)
	return now.After(nextCheck) || now.Equal(nextCheck)
}

func shouldSendSlackDownAlert(site Website) bool {
	if site.LastStatus != "DOWN" || !site.SlackAlertEnabled {
		return false
	}
	if site.SlackLastAlertAt != nil {
		return false
	}
	if site.DownSinceAt == nil {
		return false
	}
	return time.Since(site.DownSinceAt.UTC()) >= slackAlertDelay
}

func buildTargetURL(baseURL string, route string) string {
	trimmedBase := strings.TrimRight(baseURL, "/")
	trimmedRoute := strings.TrimSpace(route)
	if trimmedRoute == "" {
		return trimmedBase
	}

	if strings.HasPrefix(trimmedRoute, "http://") || strings.HasPrefix(trimmedRoute, "https://") {
		return trimmedRoute
	}

	if strings.HasPrefix(trimmedRoute, "/") {
		return trimmedBase + trimmedRoute
	}

	return trimmedBase + "/" + trimmedRoute
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func intToBool(v int) bool {
	return v != 0
}

func toNullableTimeString(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

type websiteScanner interface {
	Scan(dest ...interface{}) error
}

var ErrSlackNotConfigured = errors.New("slack is not configured")

func scanWebsite(scanner websiteScanner) (Website, error) {
	var (
		site        Website
		enabledInt  int
		slackInt    int
		lastChecked sql.NullString
		downSince   sql.NullString
		lastAlert   sql.NullString
	)

	err := scanner.Scan(
		&site.ID,
		&site.Name,
		&site.BaseURL,
		&site.Route,
		&site.TargetURL,
		&enabledInt,
		&slackInt,
		&site.CheckIntervalSeconds,
		&site.TimeoutMS,
		&site.LastStatus,
		&site.LastHTTPStatus,
		&site.LastResponseMS,
		&site.LastError,
		&lastChecked,
		&downSince,
		&lastAlert,
	)
	if err != nil {
		return Website{}, err
	}

	site.Enabled = intToBool(enabledInt)
	site.SlackAlertEnabled = intToBool(slackInt)
	if lastChecked.Valid {
		parsed, parseErr := time.Parse(time.RFC3339Nano, lastChecked.String)
		if parseErr == nil {
			site.LastCheckedAt = &parsed
		}
	}
	if downSince.Valid {
		parsed, parseErr := time.Parse(time.RFC3339Nano, downSince.String)
		if parseErr == nil {
			site.DownSinceAt = &parsed
		}
	}
	if lastAlert.Valid {
		parsed, parseErr := time.Parse(time.RFC3339Nano, lastAlert.String)
		if parseErr == nil {
			site.SlackLastAlertAt = &parsed
		}
	}

	return site, nil
}

func (s *Service) notifySlackDown(site Website) error {
	cfg, err := s.GetSlackConfig()
	if err != nil {
		return err
	}
	if !cfg.Enabled || cfg.WebhookURL == "" {
		return ErrSlackNotConfigured
	}

	text := fmt.Sprintf(":rotating_light: %s is DOWN (%s) status=%d error=%s", site.Name, site.TargetURL, site.LastHTTPStatus, site.LastError)
	return s.sendSlackMessage(cfg, text)
}

// SendSlackTestMessage sends a test slack alert using the configured webhook.
func (s *Service) SendSlackTestMessage() error {
	cfg, err := s.GetSlackConfig()
	if err != nil {
		return err
	}
	if !cfg.Enabled || cfg.WebhookURL == "" {
		return ErrSlackNotConfigured
	}
	return s.sendSlackMessage(cfg, ":warning: Zelemetry test alert")
}

func (s *Service) sendSlackMessage(cfg SlackConfig, text string) error {
	payload := map[string]string{"text": text}
	if cfg.Channel != "" {
		payload["channel"] = cfg.Channel
	}
	if cfg.Username != "" {
		payload["username"] = cfg.Username
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}
