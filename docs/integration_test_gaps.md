# Integration test gaps

Tracks scenarios where the `--test-mode` server cannot fully simulate
the AuthProxy integration test requirements, with priority and
proposed change. Format mirrors the AuthProxy spec's required-changes
table.

After the gap-closure series in [#2] and the integration test suite in
[#26], the server supports almost every scenario directly. The
remaining entries are mostly proxy-side responsibilities documented
for visibility, with a small number of server-side conveniences that
would tighten edge-case tests.

The 30 scenario tests under `integration/` link back to the rows
below where their assertions stop at the server / proxy boundary.

[#2]: https://github.com/rmorlok/go-oauth2-server/issues/2
[#26]: https://github.com/rmorlok/go-oauth2-server/issues/26

## Server-side conveniences (would tighten existing tests)

| Priority | Missing capability | Required behavior | Affected scenarios | Proposed change |
|---|---|---|---|---|
| <a id="per-request-lifetime"></a>P2 | Per-request access-token lifetime | Issue a token with a custom `expires_in` without mutating server config | [Scenario 30](#scenario-30) (clock skew) — currently mutates `Oauth.AccessTokenLifetime` on the in-memory config | Accept `access_token_lifetime` on `/test/clients` registration, or as an override on `/test/authorize`. Default to the server-wide setting when absent. |
| <a id="fresh-rt-per-auth"></a>P2 | Fresh-RT-per-authorization mode | Each new authorization for the same `(client, user)` pair mints an independent refresh-token chain instead of reusing the existing one | [Scenario 25](#scenario-25) (incremental authorization) — currently the second flow's RT is the first flow's RT | Add `Oauth.AlwaysMintRefreshToken` server flag (default `false` to preserve current behavior). When `true`, `GetOrCreateRefreshToken` always creates a new chain. |
| <a id="stdout-log-redaction"></a>P2 | Stdout log redaction audit | Ensure secrets are never echoed in the negroni request logger or gorm SQL log | [Scenario 12](#scenario-12) covers the recorder; stdout logs are not asserted | Replace negroni's default logger with one that respects the same redaction rules as the recorder (`redactedFormFields`); confirm gorm log mode is off in production. |

## Proxy-side responsibilities (out of scope for this server)

These rows describe places where the spec's verification depends on
proxy logic that lives in AuthProxy's own test harness. The server
provides the hooks; the proxy provides the policy. The corresponding
scenario tests verify the server contribution and link here.

<a id="scenario-15"></a>
### Row scenario-15 — callback contains both code and error

| | |
|---|---|
| **Server contribution** | `/test/authorize` can produce a `code+state` redirect (approve) or an `error=access_denied+state` redirect (deny) |
| **Proxy responsibility** | Detect and reject a malicious callback URL that contains both fields |
| **Scenario test** | `integration/scenario_15_test.go` |

<a id="scenario-16"></a>
### Row scenario-16 — missing authorization code

| | |
|---|---|
| **Server contribution** | Exchange requests without `code` are rejected at `/v1/oauth/tokens` |
| **Proxy responsibility** | Detect "callback had valid state but no code" before attempting an exchange |
| **Scenario test** | `integration/scenario_16_test.go` |

<a id="scenario-29"></a>
### Row scenario-29 — open redirect protection

| | |
|---|---|
| **Server contribution** | `/test/authorize` rejects `redirect_uri` mismatches; missing `redirect_uri` falls back to the client's registered URI |
| **Proxy responsibility** | Validate any post-auth return URL the proxy itself redirects users to (open-redirect prevention on the proxy's side) |
| **Scenario test** | `integration/scenario_29_test.go` |

<a id="scenario-30"></a>
### Row scenario-30 — clock skew

| | |
|---|---|
| **Server contribution** | Tokens can be issued with a custom lifetime (via in-memory config mutation today; see [per-request-lifetime](#per-request-lifetime)) and back-dated for expiry assertions |
| **Proxy responsibility** | Apply expiry buffer / skew tolerance; refresh before nominal expiry |
| **Scenario test** | `integration/scenario_30_test.go` |

## Status

| Phase | Issue | Status |
|---|---|---|
| 1 — Scaffolding | #27 | merged |
| 2 — P0 happy paths (1, 6, 9, 19) | #28 | merged |
| 3 — P0 negatives (2, 4, 5, 11) | #29 | merged |
| 4 — P0 scripting + scope + concurrency + redaction (3, 7, 8, 10, 12) | #30 | merged |
| 5 — P1 robustness (13, 14, 15, 16, 17, 18) | #31 | merged |
| 6 — P1 resource & proxied API responses (20, 21, 22, 23, 24) | #32 | merged |
| 7 — P2 advanced (25, 26, 27, 28, 29, 30) | #33 | merged |
| 8 — Gaps doc + cross-link pass | #34 | this PR |

## Anchors used by scenario tests

For convenience, scenario tests reference rows by these short ids:

- `per-request-lifetime` — server-side; touched by scenario 30
- `fresh-rt-per-auth` — server-side; touched by scenario 25
- `stdout-log-redaction` — server-side; reference for scenario 12
- `scenario-15` — proxy-side; scenario 15
- `scenario-16` — proxy-side; scenario 16
- `scenario-29` — proxy-side; scenario 29
- `scenario-30` — proxy-side; scenario 30

[Scenario 12]: https://github.com/rmorlok/go-oauth2-server/blob/master/integration/scenario_12_test.go
[Scenario 25]: https://github.com/rmorlok/go-oauth2-server/blob/master/integration/scenario_25_test.go
[Scenario 30]: https://github.com/rmorlok/go-oauth2-server/blob/master/integration/scenario_30_test.go
