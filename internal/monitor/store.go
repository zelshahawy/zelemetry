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
  check_interval_seconds INTEGER NOT NULL DEFAULT 60,
  timeout_ms INTEGER NOT NULL DEFAULT 5000,
  last_status TEXT NOT NULL DEFAULT 'UNKNOWN',
  last_http_status INTEGER NOT NULL DEFAULT 0,
  last_response_ms INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  last_checked_at TEXT
);
`)
	if err != nil {
		return fmt.Errorf("create websites table: %w", err)
	}

	return nil
}
