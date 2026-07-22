# Telemetry

`go-oauth2-server` ships with first-class OpenTelemetry support across
the three signal families:

- **Traces** — inbound HTTP requests, OAuth2 lifecycle (token issuance,
  grant-type dispatch, introspection, revocation, userinfo), and every
  SQL operation.
- **Metrics** — HTTP RED, OAuth domain counters / histograms, and
  `database/sql` connection-pool gauges.
- **Logs** — application logs structured via `log/slog`, optionally
  shipped over OTLP and stamped with `trace_id` / `span_id`.

Telemetry is **default-off**. With no `telemetry:` config block (or
`enabled: false`), the binary behaves exactly as it did before any of
the OpenTelemetry work landed — no exporter goroutines, no network
connections, no measurable overhead beyond a handful of no-op
interface calls per request.

This document is the canonical source of truth for what the application
emits, how to turn it on, and how to verify it locally.

---

## Table of contents

- [Configuration](#configuration)
- [Environment variables](#environment-variables)
- [Sampling](#sampling)
- [Path exclusion](#path-exclusion)
- [HTTP instrumentation](#http-instrumentation)
- [Database instrumentation](#database-instrumentation)
- [OAuth2 lifecycle telemetry](#oauth2-lifecycle-telemetry)
- [Logging and trace/log correlation](#logging-and-tracelog-correlation)
- [Error and panic capture](#error-and-panic-capture)
- [Local observability stack](#local-observability-stack)
- [Zero-cost guarantee](#zero-cost-guarantee)

---

## Configuration

The full `telemetry:` block lives inside the application config (loaded
from etcd, consul, or the in-process test-mode config). The schema is
defined in `telemetry/config.go`.

`runserver` can also overlay the most common fields from CLI flags or
matching `GO_OAUTH2_*` environment variables:

```sh
go-oauth2-server runserver \
  --telemetry \
  --otel-endpoint http://otel-collector:4317 \
  --otel-protocol grpc \
  --otel-service-name go-oauth2-server \
  --otel-insecure
```

These overrides apply to both regular and `--test-mode` servers.

```json
{
  "Telemetry": {
    "Enabled": true,
    "Exporter": {
      "Protocol": "grpc",
      "Endpoint": "http://otel-collector:4317",
      "Headers": { "X-Tenant": "auth" },
      "Insecure": false
    },
    "Resource": {
      "ServiceName": "go-oauth2-server",
      "Attributes": {
        "deployment.environment": "staging",
        "region": "us-east-1"
      }
    },
    "Sampling": { "Ratio": 0.1 },
    "Signals": {
      "Traces": true,
      "Metrics": true,
      "Logs": true
    },
    "HTTP": {
      "ExcludedPaths": ["/v1/health"]
    },
    "Database": {
      "DisableStatement": false
    },
    "OAuth": {
      "IncludeClientID": true
    },
    "Shutdown": { "Timeout": "5s" }
  }
}
```

Field-by-field:

| Field | Type | Meaning |
| --- | --- | --- |
| `Enabled` | bool | Master switch. When false, every other field is ignored and providers fall back to OTel no-ops. |
| `Exporter.Protocol` | `"grpc"` \| `"http/protobuf"` | Wire protocol for all three signals. |
| `Exporter.Endpoint` | string | OTLP Collector endpoint. Default `http://localhost:4317` for gRPC, `http://localhost:4318` for HTTP. |
| `Exporter.Headers` | map[string]string | Static headers attached to every export request (auth tokens, tenant IDs, etc.). |
| `Exporter.Insecure` | bool | Disables TLS verification for gRPC / HTTP transports. |
| `Resource.ServiceName` | string | Required when enabled. Defaults to `go-oauth2-server`. |
| `Resource.Attributes` | map[string]string | Additional `service.*` / deployment attributes merged into the resource. |
| `Sampling.Ratio` | float64 in `[0.0, 1.0]` | Parent-based head sampling ratio. `nil` ⇒ `1.0` (sample everything). |
| `Signals.Traces` / `Metrics` / `Logs` | *bool | Per-signal opt-out. `nil` ⇒ enabled. |
| `HTTP.ExcludedPaths` | []string | Paths that emit neither HTTP spans nor metrics. See [Path exclusion](#path-exclusion). |
| `Database.DisableStatement` | bool | Suppresses `db.statement` on emitted SQL spans. Bind values are never captured regardless. |
| `OAuth.IncludeClientID` | *bool | Drops `oauth.client_id` from counter dimensions when false. `nil` ⇒ true. |
| `Shutdown.Timeout` | duration | Bound on the flush-and-stop window. Default 5s. |

## Environment variables

The binary honors the `runserver`-specific `GO_OAUTH2_*` variables and
the standard `OTEL_*` environment variables. Precedence runs
**CLI / `GO_OAUTH2_*` → config → `OTEL_*` → defaults**: explicit
runserver overrides win, loaded config wins over standard OTel env,
standard OTel env fills unset fields, and defaults fill what remains.

| Variable | Maps to |
| --- | --- |
| `GO_OAUTH2_TELEMETRY_ENABLED` | enable telemetry export |
| `GO_OAUTH2_OTEL_ENDPOINT` | `Exporter.Endpoint` |
| `GO_OAUTH2_OTEL_PROTOCOL` | `Exporter.Protocol` |
| `GO_OAUTH2_OTEL_SERVICE_NAME` | `Resource.ServiceName` |
| `GO_OAUTH2_OTEL_INSECURE` | `Exporter.Insecure` |

Standard OTel environment variables:

| Variable | Maps to |
| --- | --- |
| `OTEL_SERVICE_NAME` | `Resource.ServiceName` |
| `OTEL_RESOURCE_ATTRIBUTES` | merged into `Resource.Attributes` (comma-separated `k=v` pairs) |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `Exporter.Protocol` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `Exporter.Endpoint` |
| `OTEL_EXPORTER_OTLP_HEADERS` | merged into `Exporter.Headers` |

## Sampling

Sampling is **parent-based, head-sampled** with the configured ratio.
Inbound requests that arrive with a valid W3C `traceparent` header
inherit the parent's sampling decision; otherwise the
`TraceIDRatioBased(ratio)` policy applies.

`Ratio: 1.0` (the default) samples every trace. Set lower values in
production to bound trace volume; the Collector can do tail-based
sampling on top of that if needed.

## Path exclusion

By default `/v1/health` is excluded from HTTP telemetry — both spans and
RED metrics. Add additional paths via `HTTP.ExcludedPaths`. Patterns
support exact match or a trailing `/*` for a prefix match:

```json
{ "HTTP": { "ExcludedPaths": ["/v1/health", "/internal/*"] } }
```

`/test/*` is **deliberately not** excluded. The test-mode control plane
sits behind `/test/` and is exercised by load tests; their performance
characteristics are part of what operators want to see.

## HTTP instrumentation

A `mux.MiddlewareFunc` in `telemetry/httptelem` opens one server span
per non-excluded request and emits HTTP RED metrics. Because it runs
inside the mux chain (via `router.Use(...)`), `mux.CurrentRoute(r)` is
available — the matched route template becomes the span name and the
`http.route` metric dimension. Path parameters never blow out
cardinality.

**Spans** (semconv 1.40 attributes):

| Span | Notes |
| --- | --- |
| `<route template>` | e.g. `/v1/oauth/tokens`. Kind = Server. Attributes: `http.request.method`, `http.route`, `url.path`, `url.scheme`, `http.response.status_code`. 5xx → status = Error. |

**Metrics:**

| Name | Type | Unit | Dimensions |
| --- | --- | --- | --- |
| `http.server.request.duration` | histogram | ms | `http.request.method`, `http.route`, `http.response.status_code` |
| `http.server.requests` | counter | 1 | `http.request.method`, `http.route`, `http.response.status_code` |
| `http.server.active_requests` | up/down counter | 1 | `http.request.method`, `http.route` |

Panics inside a handler are recorded as `exception` events on the
span (with the status set to Error) and re-raised so the existing
negroni Recovery middleware still emits a 500 response.

Incoming `traceparent` headers are honored — server spans inherit the
inbound trace ID and parent span ID.

## Database instrumentation

`database.NewDatabase` opens connections through `telemetry/dbtelem`,
which wraps `database/sql` via
[`github.com/XSAM/otelsql`](https://github.com/XSAM/otelsql) when
telemetry is enabled and falls back to a plain `sql.Open` when it's
not. GORM v1.9.16 accepts a `*sql.DB` directly, so the dialect-specific
SQL generator sits unchanged on top of the instrumented driver. Both
Postgres and SQLite are supported.

**Spans:** one per SQL operation. Attributes include `db.system.name`
(`postgresql` or `sqlite`), `db.statement` (parameterized SQL — never
bind values; opt out via `Database.DisableStatement`), and per-method
attributes derived by otelsql. Failed queries set the span status to
Error.

**Metrics:** connection-pool gauges via `otelsql.RegisterDBStatsMetrics`,
emitted under names like `db.sql.connection.open`,
`db.sql.connection.max_open`, `db.sql.connection.wait`,
`db.sql.connection.wait_duration`, plus a `db.sql.latency` histogram.

## OAuth2 lifecycle telemetry

The OAuth handlers wrap their request bodies in domain spans (child of
the HTTP server span) and emit OAuth-domain counters. Token values,
refresh tokens, and client secrets are **never** recorded.

**Spans:**

| Span | Where |
| --- | --- |
| `oauth.tokens` | `tokensHandler` (POST /v1/oauth/tokens) |
| `oauth.grant.authorization_code` | `authorizationCodeGrant` |
| `oauth.grant.password` | `passwordGrant` |
| `oauth.grant.client_credentials` | `clientCredentialsGrant` |
| `oauth.grant.refresh_token` | `refreshTokenGrant` |
| `oauth.introspect` | `introspectHandler` (RFC 7662) |
| `oauth.revoke` | `revokeHandler` (RFC 7009) |
| `oauth.userinfo` | `userinfoHandler` |

Span attributes: `oauth.grant_type`, `oauth.client_id` (when
`OAuth.IncludeClientID` is true), `oauth.scope`, `oauth.token_type`,
plus `oauth.error_code` on the error path. Errors are mapped to RFC
6749 / 7009 / 7662 codes (`invalid_grant`, `invalid_client`,
`invalid_scope`, `unsupported_grant_type`, `invalid_request`,
`unsupported_token_type`, ...). Unknown errors collapse to
`server_error`.

**Metrics:**

| Name | Type | Dimensions |
| --- | --- | --- |
| `oauth.token.issued` | counter | `oauth.grant_type`, `outcome`, `oauth.client_id`, `oauth.error_code` (on error) |
| `oauth.token.refreshed` | counter | `oauth.grant_type` (= `refresh_token`), `outcome`, `oauth.client_id`, `oauth.error_code` (on error) |
| `oauth.token.revoked` | counter | `oauth.token_type_hint`, `oauth.client_id` |
| `oauth.introspect.requests` | counter | `active`, `outcome`, `oauth.client_id`, `oauth.error_code` (on error) |
| `oauth.userinfo.requests` | counter | `outcome`, `oauth.error_code` (on error) |
| `oauth.grant.duration` | histogram (ms) | `oauth.grant_type`, `outcome` |

Set `OAuth.IncludeClientID` to `false` in deployments with very high
client cardinality to drop the `oauth.client_id` label from counters.

## Logging and trace/log correlation

Application logging is structured via `log/slog`. The package logger
in `log/` is set up by `log.Init(Options)` from the binary entry
point. Options resolve in this priority order:

1. Explicit fields (`Level`, `Format`, `Output`, `OTelProvider`, ...)
2. `LOG_LEVEL` / `LOG_FORMAT` environment variables
3. Dev / prod defaults: text + debug when `IsDevelopment` is true,
   JSON + info otherwise.

When telemetry is enabled and `Signals.Logs` is true, the binary
passes `providers.LoggerProvider` to `log.Init`. The package then
attaches:

- A **tee** handler that fans every record out to both the console
  encoder (text or JSON) and an OTLP bridge via
  `go.opentelemetry.io/contrib/bridges/otelslog`. Operators still see
  records on stdout for `docker logs` purposes.
- A **trace-correlation** handler that reads
  `trace.SpanContextFromContext(ctx)` for each record and stamps
  `trace_id` and `span_id` as attributes when the span context is
  valid. Records outside a traced context pass through unchanged.

The negroni URL access logger has moved into the mux chain (via
`util/response.URLLoggerMiddleware`), positioned after the telemetry
middleware so the request's context already carries the HTTP server
span. Each `request started` / `request finished` record inherits the
matching `trace_id`.

## Error and panic capture

- **5xx responses** mark the HTTP server span as `Error` with the
  status code on the span.
- **Panics** inside handlers record an `exception` event on the span
  (with status `Error`) and are re-raised so negroni Recovery emits
  the 500. Panic metrics flow into `http.server.requests` with status
  500.
- **Failed SQL queries** set the database span status to `Error` via
  otelsql.
- **OAuth error responses** record the resolved `oauth.error_code`
  on both the span and the corresponding counter.

## Local observability stack

`docker-compose.yml` ships an opt-in `observability` profile that
brings up [`grafana/otel-lgtm`](https://github.com/grafana/docker-otel-lgtm)
— a single container bundling Grafana, Tempo (traces), Loki (logs),
Prometheus (metrics), and a pre-wired OTel Collector. Default
`docker compose up -d` is unchanged.

```sh
docker compose --profile observability up -d otel_lgtm
```

- Grafana UI: <http://localhost:3001> (login `admin` / `admin`).
- OTLP gRPC: `localhost:4317`
- OTLP HTTP: `localhost:4318`

A pre-provisioned **go-oauth2-server overview** dashboard surfaces
HTTP RED, OAuth token issuance, Tempo trace search, and Loki logs.

Point the app at the stack with env vars on a local `go run`:

```sh
OTEL_SERVICE_NAME=go-oauth2-server \
OTEL_EXPORTER_OTLP_PROTOCOL=grpc \
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 \
  go run . runserver --test-mode
```

The equivalent etcd / consul JSON block is at the top of this document.

Useful queries:

| Backend | Query |
| --- | --- |
| Prometheus | `sum(rate(http_server_requests_total[5m])) by (http_route)` |
| Prometheus | `histogram_quantile(0.95, sum(rate(http_server_request_duration_milliseconds_bucket[5m])) by (le, http_route))` |
| Prometheus | `sum(rate(oauth_token_issued_total[5m])) by (oauth_grant_type, outcome)` |
| Tempo (TraceQL) | `{ resource.service.name = "go-oauth2-server" && name =~ "oauth.*" }` |
| Loki (LogQL) | `{service_name="go-oauth2-server"} \| json` |

## Zero-cost guarantee

When telemetry is disabled (`Enabled: false`, or the block is absent):

- `telemetry.Init` returns no-op providers and never touches the OTel
  globals or opens a network connection.
- `httptelem.Middleware` returns the next handler unchanged — a true
  pass-through, not a wrapped no-op.
- `dbtelem.Open` returns a plain `*sql.DB` from `sql.Open` — the
  otelsql wrapper is not in the call chain.
- `oauthtelem.Recorder` short-circuits every method without touching
  OTel; `Start*` returns a no-op `trace.Span` that's safe to `End()`.
- The log package omits the OTLP bridge and (by default) the
  trace-correlation handler. Console behavior is identical to a
  pre-telemetry baseline.

Upgrading to a build that includes telemetry support is therefore safe
for any existing deployment: behavior is bit-for-bit unchanged until
you opt in.
