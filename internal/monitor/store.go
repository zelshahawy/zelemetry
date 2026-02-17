package monitor

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const (
	defaultDBPath = "build/zelemetry.db"
)

// OpenDatabase opens and initializes the SQLite database.
func OpenDatabase() (*sql.DB, error) {
	path := strings.TrimSpace(os.Getenv("ZELEMETRY_DB_PATH"))
	if path == "" {
		path = defaultDBPath
	}

	if path != ":memory:" {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create db directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS websites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  route TEXT NOT NULL,
  target_url TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  check_interval_seconds INTEGER NOT NULL DEFAULT 200,
  timeout_ms INTEGER NOT NULL DEFAULT 5000,
  slack_alert_enabled INTEGER NOT NULL DEFAULT 0,
  last_status TEXT NOT NULL DEFAULT 'UNKNOWN',
  last_http_status INTEGER NOT NULL DEFAULT 0,
  last_response_ms INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  last_checked_at TEXT,
  down_since_at TEXT,
  slack_last_alert_at TEXT
);
`)
	if err != nil {
		return fmt.Errorf("create websites table: %w", err)
	}

	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS slack_config (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  enabled INTEGER NOT NULL DEFAULT 0,
  webhook_url TEXT NOT NULL DEFAULT '',
  channel TEXT NOT NULL DEFAULT '',
  username TEXT NOT NULL DEFAULT ''
);
`)
	if err != nil {
		return fmt.Errorf("create slack_config table: %w", err)
	}

	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS app_users (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`)
	if err != nil {
		return fmt.Errorf("create app_users table: %w", err)
	}

	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS auth_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
`)
	if err != nil {
		return fmt.Errorf("create auth_sessions table: %w", err)
	}

	if err := addColumnIfMissing(db, `ALTER TABLE websites ADD COLUMN slack_alert_enabled INTEGER NOT NULL DEFAULT 0`); err != nil {
		return fmt.Errorf("alter websites table: %w", err)
	}
	if err := addColumnIfMissing(db, `ALTER TABLE websites ADD COLUMN down_since_at TEXT`); err != nil {
		return fmt.Errorf("alter websites table: %w", err)
	}
	if err := addColumnIfMissing(db, `ALTER TABLE websites ADD COLUMN slack_last_alert_at TEXT`); err != nil {
		return fmt.Errorf("alter websites table: %w", err)
	}

	return nil
}

func addColumnIfMissing(db *sql.DB, query string) error {
	_, err := db.Exec(query)
	if err != nil {
		lowerErr := strings.ToLower(err.Error())
		if strings.Contains(lowerErr, "duplicate column name") {
			return nil
		}
		return err
	}

	return nil
}
