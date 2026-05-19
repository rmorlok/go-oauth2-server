# Documentation

Operational and developer-facing documentation for `go-oauth2-server`.
The top-level [`README.md`](../README.md) covers the OAuth 2.0 surface,
setup, and deployment basics; the documents below dig deeper into
specific areas.

| Document | What it covers |
| --- | --- |
| [`telemetry.md`](telemetry.md) | OpenTelemetry: traces, metrics, logs, config schema, env vars, sampling, OAuth lifecycle telemetry catalog, the bundled Grafana + Tempo + Loki + Prometheus dev stack. |
| [`test_mode_api.md`](test_mode_api.md) | The `/test/*` control plane that ships with `runserver --test-mode`: client / user / script registration, recorder snapshots, scope policy. |
| [`integration_test_gaps.md`](integration_test_gaps.md) | Spec-to-test mapping for the integration suite and open coverage gaps. |

For contributor-facing conventions (how to add instrumentation, how to
log, which paths are excluded from telemetry by default), see
[`../AGENTS.md`](../AGENTS.md).
