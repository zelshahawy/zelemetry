# Zelemetry

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Go version](https://img.shields.io/badge/Go-1.24-blue)](https://go.dev/)

A website health monitoring dashboard built on [Yokai](https://github.com/ankorstore/yokai).

Zelemetry lets you monitor websites/endpoints, run checks manually or on a schedule, and manage settings per website from a live dashboard.

## Features

- Website monitoring with status (`UP`, `DOWN`, `UNKNOWN`)
- Per-website settings:
  - route/path
  - check interval
  - timeout
  - enabled/disabled state
- Manual checks:
  - check one website
  - check all websites
- Scheduled checks in background worker
- Persistent storage with SQLite
- Live dashboard UI (async actions, no full-page reload)
- JSON API for monitored websites

## Architecture

- Framework: Yokai + Echo
- Backend: Go
- UI rendering: [templ](https://github.com/a-h/templ)
- Database: SQLite (`modernc.org/sqlite`)
- Runtime persistence path: `build/zelemetry.db`

## Project Layout

- `cmd/`: CLI entrypoints
- `configs/`: app configuration files
- `internal/`:
  - `handler/`: HTTP handlers
  - `handler/view/`: templ UI component(s)
  - `monitor/`: monitoring service, storage, scheduler
  - `bootstrap.go`: app bootstrap
  - `register.go`: dependency registration
  - `router.go`: route registration

## HTTP Endpoints

- `GET /` dashboard
- `GET /api/websites` list monitored websites (JSON)
- `POST /websites` add website
- `POST /websites/:id/check` run check for website
- `POST /websites/:id/settings` update settings
- `POST /websites/:id/delete` delete website
- `POST /checks/run` run checks for all websites

## Running Locally

### With Docker (recommended for dev)

```bash
make up
```

Open:

- `http://localhost:8080` app dashboard
- `http://localhost:8081` Yokai core dashboard

Stop:

```bash
make down
```

Refresh (rebuild + restart):

```bash
make fresh
```

### Without Docker

```bash
go run . run
```

## Data Persistence

SQLite is embedded in the app, so no separate DB container is required.

In Docker Compose, data persists via named volume mounted to `/app/build`.

Optional override for DB path:

- env var: `ZELEMETRY_DB_PATH`

Example:

```bash
ZELEMETRY_DB_PATH=:memory: go test ./...
```

## Development Commands

```bash
make up     # start docker compose stack
make down   # stop docker compose stack
make logs   # stream stack logs
make fresh  # rebuild and restart
make test   # run tests
make lint   # run linter
```

## Templ Notes

UI is defined in:

- `internal/handler/view/dashboard.templ`

Generated file:

- `internal/handler/view/dashboard_templ.go`

Regenerate after changing `.templ` files:

```bash
go run github.com/a-h/templ/cmd/templ@v0.3.977 generate
```

## License

MIT
