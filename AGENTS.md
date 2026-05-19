# Agent conventions

Short reference for coding agents (and humans) working in this repo. The
canonical descriptions live in linked documents — this file is the
"don't drift" checklist.

## Logging

- All application logging goes through `log/slog`. Use the package
  logger in [`log/`](log/) via `log.Default()`, `log.With(...)`, or the
  package-level `log.Info / Warn / Error / Debug / Fatal` helpers.
- Prefer **named fields** over format strings:
  `log.Info("token issued", "grant_type", gt, "client_id", c.Key)`,
  not `log.Info(fmt.Sprintf("token issued for %s", gt))`.
- Inside HTTP handler chains (and anywhere `r *http.Request` or a
  `ctx context.Context` is in scope), call `log.FromContext(ctx)` —
  the per-request logger automatically inherits `trace_id` / `span_id`
  via the log handler chain configured in [`log/handlers.go`](log/handlers.go).
- Do **not** import `RichardKnop/logging` or the `INFO` / `WARNING`
  channel API — both are removed.

## Telemetry

- The `telemetry:` config block (see
  [`telemetry/config.go`](telemetry/config.go)) is wired through
  `config.Config.Telemetry` and is parsed once by `telemetry.Init` at
  startup. Read it from there; don't introduce a parallel config path.
- New HTTP integrations should sit **inside the mux chain via
  `router.Use(...)`** so the existing `httptelem.Middleware` and
  `URLLoggerMiddleware` see them. Do not register routes that bypass
  the mux router.
- New database integrations should open through
  [`telemetry/dbtelem`](telemetry/dbtelem) so every SQL call flows
  through the otelsql wrapper. Do not call `sql.Open` directly.
- New OAuth grant types or endpoints should follow the existing
  pattern: open a domain span via `s.telem.Start*`, defer
  `span.End()`, call `s.telem.FinishWithError` on the error path,
  and emit the appropriate counter via `s.telem.Record*`. See
  [`oauth/handlers.go`](oauth/handlers.go) and
  [`telemetry/oauthtelem`](telemetry/oauthtelem) for examples.
- `/v1/health` is excluded from HTTP telemetry by default.
  **`/test/*` is deliberately not** — load tests against the test-mode
  control plane need that visibility. Don't add `/test/*` to
  `HTTP.ExcludedPaths`.
- Telemetry must remain **default-off** with **zero overhead when
  disabled**. New instrumentation should short-circuit cleanly when
  `cfg.Enabled == false` (the existing packages all model this).

For the full surface area — every span name, every metric and its
dimensions, all attributes recorded, sampling behavior, the local
Grafana stack — see [`docs/telemetry.md`](docs/telemetry.md).

## Configuration

- Production config loads from etcd or consul as **JSON** (not YAML);
  struct tags use `json:"..."`. Add `omitempty` for optional blocks so
  upgrading deployments don't see unexpected zero-valued fields.
- The in-process test-mode config (`testmode.NewConfig`) sets only the
  fields tests need. Telemetry is off there by default; tests that
  want telemetry enabled construct their own `cnf.Telemetry`.

## OAuth domain

- Internal sentinel errors map to RFC 6749 / 7009 / 7662 codes via
  [`oauth/telemetry_codes.go`](oauth/telemetry_codes.go). When adding
  a new sentinel, add it to that map so it surfaces as a stable
  `oauth.error_code` in dashboards rather than collapsing to
  `server_error`.
- Token values, refresh tokens, and client secrets must **never**
  appear in span attributes, metric labels, or log fields. The
  oauthtelem helpers enforce this for spans/metrics; review log call
  sites yourself.

## Testing

- `go test ./...` is expected to pass on changes you submit.
- The `oauth/` suite is a pre-existing exception — it hardcodes
  `dial tcp: lookup postgres: no such host`. It only passes inside the
  docker-compose harness. Don't try to "fix" it as a side effect; if
  your change has a test impact there, gate it on the Postgres host
  being reachable.
- Integration tests under `integration/` exercise the real handler
  chain via `httptest.NewServer` on top of an in-memory SQLite DB.
  Add new scenarios there when they cross-cut multiple packages.

## When in doubt

- Configuration: [`config/config.go`](config/config.go),
  [`telemetry/config.go`](telemetry/config.go)
- HTTP middleware: [`telemetry/httptelem/middleware.go`](telemetry/httptelem/middleware.go),
  [`util/response/logging.go`](util/response/logging.go)
- DB instrumentation: [`telemetry/dbtelem/dbtelem.go`](telemetry/dbtelem/dbtelem.go)
- OAuth telemetry: [`telemetry/oauthtelem/oauthtelem.go`](telemetry/oauthtelem/oauthtelem.go),
  [`oauth/handlers.go`](oauth/handlers.go)
- Test mode: [`docs/test_mode_api.md`](docs/test_mode_api.md),
  [`testmode/app.go`](testmode/app.go)
- All telemetry behavior: [`docs/telemetry.md`](docs/telemetry.md)
