# Test Mode API Reference

This document describes every endpoint exposed when `go-oauth2-server`
is run with `--test-mode`. The aim of test mode is to provide a fully
controllable third-party OAuth provider for integration tests:
arbitrary clients and users can be registered at runtime, the
authorize step can be driven programmatically, every recordable
endpoint can have responses scripted, and identity attributes can be
mutated mid-session.

The standard production OAuth endpoints (`/v1/oauth/tokens`,
`/v1/oauth/introspect`, `/v1/oauth/revoke`, `/v1/oauth/userinfo`) are
documented in the project [README](../README.md). This file covers
only the `/test/*` control plane and the small set of test-mode
behavior toggles.

## Table of contents

- [Starting test mode](#starting-test-mode)
- [Endpoint summary](#endpoint-summary)
- [Bootstrap](#bootstrap)
  - [`GET /test/health`](#get-testhealth)
- [Clients](#clients)
  - [`POST /test/clients`](#post-testclients)
- [Users](#users)
  - [`POST /test/users`](#post-testusers)
  - [`POST /test/users/{id}/identity`](#post-testusersididentity)
  - [`POST /test/users/{id}/swap-subject`](#post-testusersidswap-subject)
- [Authorization](#authorization)
  - [`POST /test/authorize`](#post-testauthorize)
- [Scripted responses](#scripted-responses)
  - [`POST /test/scripts`](#post-testscripts)
  - [`GET /test/scripts`](#get-testscripts)
  - [`DELETE /test/scripts`](#delete-testscripts)
  - [Action shape](#action-shape)
  - [Body templates](#body-templates)
  - [Endpoint labels](#endpoint-labels)
- [Provider-side revocation](#provider-side-revocation)
  - [`POST /test/revoke`](#post-testrevoke)
- [Refresh-token rotation policy](#refresh-token-rotation-policy)
  - [`POST /test/refresh-tokens/rotate-policy`](#post-testrefresh-tokensrotate-policy)
- [Resource server](#resource-server)
  - [`ANY /test/resource/{path}`](#any-testresourcepath)
  - [`POST /test/resource-policy`](#post-testresource-policy)
- [Request inspection](#request-inspection)
  - [`GET /test/requests`](#get-testrequests)
- [Sanitization](#sanitization)
- [Differences from production](#differences-from-production)

## Starting test mode

Test mode is a flag on the existing `runserver` command:

```sh
go-oauth2-server runserver --test-mode \
  [--test-port 8080] \
  [--test-db-path :memory:]
```

When `--test-mode` is on:

- The remote-config backend (etcd / consul) is bypassed; the server
  uses sensible in-memory defaults from
  [`testmode.NewConfig`](../testmode/config.go).
- The database is embedded SQLite. Default `:memory:` for an
  ephemeral DB; pass `--test-db-path /tmp/oauth.db` for a persistent
  file.
- All `/test/*` routes below are mounted. They are not present when
  `--test-mode` is off.
- Refresh-token rotation defaults to **on**. Toggle at runtime via
  [`POST /test/refresh-tokens/rotate-policy`](#post-testrefresh-tokensrotate-policy).
- The `profile` and `email` scopes are seeded alongside the production
  defaults (`read`, `read_write`).

The standard `/v1/oauth/*` and `/web/*` endpoints continue to work
exactly as in production. `/test/resource/{path}` is *also* mounted
when `--test-mode` is off (production binary) so an operator can
manually validate an OAuth flow against a real protected resource;
see [Sample resource](#sample-resource).

## Endpoint summary

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/test/health` | Liveness check |
| `POST` | `/test/clients` | Register an OAuth client |
| `POST` | `/test/users` | Register a user |
| `POST` | `/test/users/{id}/identity` | Partial identity update |
| `POST` | `/test/users/{id}/swap-subject` | Override `sub` for userinfo |
| `POST` | `/test/authorize` | Drive the authorize step programmatically |
| `POST` | `/test/scripts` | Enqueue scripted responses |
| `GET` | `/test/scripts` | List queued actions |
| `DELETE` | `/test/scripts` | Clear queued actions |
| `POST` | `/test/revoke` | Provider-side revocation (no client auth) |
| `POST` | `/test/refresh-tokens/rotate-policy` | Toggle refresh-token rotation |
| `ANY` | `/test/resource/{path}` | Sample protected resource (bearer-required) |
| `POST` | `/test/resource-policy` | Register scope policy for a resource path |
| `GET` | `/test/requests` | Inspect recorded requests to recordable endpoints |

All request and response bodies are JSON unless noted. Errors return
`{"error": "<message>"}` with the appropriate HTTP status.

## Bootstrap

### `GET /test/health`

Liveness check. No auth.

**Response 200**

```json
{"status": "ok", "mode": "test"}
```

## Clients

### `POST /test/clients`

Register an OAuth client. Test-mode only.

**Request body**

```json
{
  "key": "string",                              // required, becomes the client_id
  "secret": "string",                           // optional; ignored for token_endpoint_auth_method=none
  "redirect_uri": "string",                     // optional; required for auth-code flows
  "token_endpoint_auth_method": "string",       // optional; one of:
                                                //   "client_secret_basic" (default)
                                                //   "client_secret_post"
                                                //   "none"
  "require_pkce": false,                        // optional; auto-set true for `none`
  "scope": "string"                             // optional; accepted but currently unused
}
```

`token_endpoint_auth_method` semantics (RFC 7591 §2):

- `client_secret_basic` (default) — token endpoint requires HTTP Basic.
- `client_secret_post` — token endpoint requires `client_id`+`client_secret` in the form body.
- `none` — public client. Token endpoint accepts `client_id` only; PKCE is required at authorize.

`require_pkce: true` extends the strict-PKCE behavior to confidential
clients: a missing `code_challenge` at authorize is rejected, and a
spurious `code_verifier` at the token endpoint (against a code with
no stored challenge) is rejected. RFC 7636 §4.5 lax behavior is the
default for confidential clients.

**Response 201**

```json
{
  "id": "uuid",
  "key": "string",
  "redirect_uri": "string",
  "token_endpoint_auth_method": "string",
  "require_pkce": false
}
```

**Errors**

- `400` — missing `key`, unknown `token_endpoint_auth_method`, or other validation failure.

**Example**

```sh
curl -s -X POST http://127.0.0.1:8080/test/clients \
  -H 'Content-Type: application/json' \
  -d '{"key":"acme","secret":"s3cret","redirect_uri":"https://app.example.com/cb"}'
```

## Users

### `POST /test/users`

Register a user. Test-mode only.

**Request body**

```json
{
  "username": "string",      // required
  "password": "string",      // optional; required if you plan to use password grant
  "role": "string",          // optional; defaults to "user". "superuser" or "user"
  "email": "string",         // optional; surfaced via /v1/oauth/userinfo
  "display_name": "string",  // optional; surfaced as `name` in userinfo
  "sub": "string"            // optional; overrides the user's UUID as the userinfo `sub`
}
```

**Response 201**

```json
{
  "id": "uuid",
  "username": "string",
  "role": "string",
  "email": "string",
  "display_name": "string",
  "sub": "string"
}
```

Empty optional fields are omitted from the response.

### `POST /test/users/{id}/identity`

Partial-update a user's identity. Only the fields present in the
request are changed; missing fields are left alone. Pass an explicit
empty string to clear a field.

**Request body**

```json
{
  "sub": "string|null",          // optional; updates sub_override
  "email": "string|null",
  "display_name": "string|null"
}
```

**Response 200**

The full identity record (same shape as the create response).

**Errors**

- `404` — unknown user id.

### `POST /test/users/{id}/swap-subject`

Stronger variant of identity update that only touches the subject
override. Useful for "same proxy account, different IdP identity"
scenarios.

**Request body**

```json
{"new_sub": "string"}     // required; empty string clears the override
```

**Response 200**

The updated identity record.

## Authorization

### `POST /test/authorize`

Drive the authorize step programmatically without going through the
HTML/session flow. Returns the redirect URL the proxy would have
followed.

**Request body**

```json
{
  "client_id": "string",                  // required; client's public key (not the UUID)
  "user_id": "uuid",                      // user_id OR username (one required, except for deny)
  "username": "string",
  "redirect_uri": "string",               // optional; falls back to client's registered URI
  "scope": "string",                      // optional; defaults to default scope
  "state": "string",                      // optional; echoed verbatim in the redirect
  "decision": "approve" | "deny",         // required
  "granted_scope": "string",              // optional; narrower-than-requested scope to actually grant
  "code_challenge": "string",             // optional, RFC 7636
  "code_challenge_method": "S256"|"plain" // optional, RFC 7636
}
```

For `decision: "deny"` only `client_id`, `decision`, and (optionally)
`state` and `redirect_uri` matter; user lookup is skipped.

**Response 200**

```json
{"redirect_url": "https://..."}
```

For `decision: "approve"` the URL contains `code` + `state`. For
`decision: "deny"` it contains `error=access_denied` + `state`.

**Errors**

- `400` — bad payload, redirect_uri mismatch, invalid scope, PKCE input invalid (`code_challenge_method` without `code_challenge`, unknown method, or `require_pkce` client missing `code_challenge`).
- `404` — unknown client or user.

**Example**

```sh
curl -s -X POST http://127.0.0.1:8080/test/authorize \
  -H 'Content-Type: application/json' \
  -d '{
    "client_id": "acme",
    "user_id": "ace3...",
    "redirect_uri": "https://app.example.com/cb",
    "scope": "read",
    "state": "csrf-x",
    "decision": "approve",
    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    "code_challenge_method": "S256"
  }'
```

## Scripted responses

The script queue intercepts requests to recordable endpoints (see
[Endpoint labels](#endpoint-labels)) before they reach the real
handler. Actions are popped FIFO; once queued, an action fires on the
next matching request. After all actions are exhausted, requests fall
through to the real handler.

### `POST /test/scripts`

Enqueue actions for `(client_id, endpoint)`.

**Request body**

```json
{
  "client_id": "string",       // optional; "" means wildcard, matches any caller
  "endpoint": "string",        // required; see Endpoint labels
  "actions": [Action, ...]     // required, non-empty; see Action shape
}
```

**Response**

`204 No Content`.

**Errors**

- `400` — missing endpoint, unknown endpoint, empty actions, unknown body_template.

### `GET /test/scripts`

List remaining actions across all queues.

**Response 200**

```json
[
  {
    "client_id": "string",
    "endpoint": "string",
    "actions": [Action, ...]
  }
]
```

### `DELETE /test/scripts`

Clear queues by filter. Empty fields match anything.

**Query parameters**

- `client_id` (optional)
- `endpoint` (optional)

**Response**

`204 No Content`.

### Action shape

```json
{
  "status": 0,                        // HTTP status. 0 = pass-through (run the real handler).
                                      // Non-zero = full replacement.
  "headers": {"H": "v"},              // optional; written before the body
  "body": "string",                   // raw response body (sent verbatim)
  "body_template": "string",          // see Body templates. Fills in defaults.
  "delay_ms": 0,                      // sleep before responding
  "drop_connection": false,           // hijack the conn and close
  "fail_count": 0,                    // 0 → apply once. N>0 → apply N times then drop.
  "scope_override": "string|null",    // pass-through only: rewrite the JSON `scope` field.
                                      //   "" → omit scope from response
                                      //   "x" → set scope to "x"
                                      //   null/absent → no rewrite
  "skip_pkce_check": false            // pass-through only: bypass code_verifier check
                                      // for one /v1/oauth/tokens call (RFC 7636 §4.5)
}
```

**Mutually exclusive paths**

- `status > 0` ⇒ full replacement. The `body` (or template) is sent
  verbatim with the supplied status and headers; the real handler
  does not run. `scope_override` and `skip_pkce_check` are ignored.
- `status == 0` and a non-empty `body` ⇒ a 200 with that body.
- `status == 0`, empty `body`, `scope_override` set ⇒ pass-through
  with JSON `scope` field rewritten on the way out.
- `status == 0`, empty `body`, `skip_pkce_check: true` ⇒ pass-through
  with the `authorization_code` PKCE check skipped for this call.
- `status == 0`, no overrides ⇒ pass-through (action consumed but no
  visible effect — useful as a sentinel).
- `drop_connection: true` ⇒ hijack the connection and close it
  (after `delay_ms` if set). The client sees a connection reset.

**Match preference**

When a request arrives, the queue lookup checks the specific
`client_id+endpoint` queue first; if empty, the wildcard
(`""+endpoint`) queue. Whichever has actions popped first; the other
remains untouched.

### Body templates

Convenience presets for common shapes. If `body_template` is set, its
defaults fill in `Status`, `Headers`, and `Body` only where the
explicit action did not specify them.

| Name | Status | Body |
|---|---|---|
| `access_token_success` | 200 | `{"access_token":"00000000-0000-4000-8000-000000000000","expires_in":3600,"token_type":"Bearer","scope":"read"}` |
| `access_token_no_scope` | 200 | `{"access_token":"00000000-0000-4000-8000-000000000000","expires_in":3600,"token_type":"Bearer"}` |
| `invalid_grant` | 400 | `{"error":"invalid_grant"}` |
| `temporarily_unavailable_503` | 503 | `{"error":"temporarily_unavailable"}` |
| `malformed_json` | 200 | `{not valid json` |

All templates set `Content-Type: application/json` unless overridden.

### Endpoint labels

The script queue and request recorder use the same set of labels.
A request is classified by path (and form fields for `/v1/oauth/tokens`):

| Label | Path | Notes |
|---|---|---|
| `token` | `POST /v1/oauth/tokens` | grant_type other than `refresh_token` |
| `refresh` | `POST /v1/oauth/tokens` | grant_type=`refresh_token` |
| `introspect` | `POST /v1/oauth/introspect` | |
| `revoke` | `POST /v1/oauth/revoke` | |
| `userinfo` | `GET\|POST /v1/oauth/userinfo` | |
| `resource` | `ANY /test/resource/<path>` | strict prefix `/test/resource/` |

Other paths (including `/test/*` control-plane endpoints other than
`/test/resource/*`) are not classified, so they are never recorded
or scriptable.

## Provider-side revocation

### `POST /test/revoke`

Admin-style revocation — bypasses ownership checks and client auth.
Useful for simulating "the user revoked at the IdP" without going
through the proxy. Exactly one of `token`, `user_id`, or `client_id`
must be set.

The standard RFC 7009 endpoint at `POST /v1/oauth/revoke` is also
available; it requires basic-auth client credentials and applies the
ownership rules per spec.

**Request body**

```json
{"token": "string"}      // revoke a single token (access or refresh; refresh cascades to access)
```

```json
{"user_id": "uuid"}      // revoke all unrevoked tokens for that user
```

```json
{"client_id": "string"}  // revoke all unrevoked tokens for that client.
                         // accepts either the client's public key or the database UUID.
```

**Response 200**

For token mode:

```json
{"found": true}
```

For bulk modes:

```json
{
  "refresh_tokens_revoked": 0,
  "access_tokens_revoked": 0
}
```

**Errors**

- `400` — none or more than one of the three modes specified.

## Refresh-token rotation policy

### `POST /test/refresh-tokens/rotate-policy`

Toggle the in-memory refresh-token rotation flag. Test mode defaults
to **on**; production servers default to **off** (legacy reuse).

**Request body**

```json
{"rotation": true}
```

**Response 200**

```json
{"rotation": true}
```

When rotation is on, every `grant_type=refresh_token` exchange:

- issues a new access AND refresh token;
- atomically marks the old refresh token revoked
  (CAS: `WHERE id = ? AND revoked_at IS NULL`) so concurrent
  refreshes deterministically race — exactly one wins;
- links the new RT to the old via `parent_id`.

Replaying the old RT after rotation fails with HTTP 400 and the body
`{"error":"Refresh token revoked"}`.

## Resource server

### `ANY /test/resource/{path}`

A sample protected resource. **Mounted in both test mode AND
production** so an operator can manually validate an OAuth flow
end-to-end.

**Headers**

- `Authorization: Bearer <access_token>` — required.

**Behavior**

1. Bearer token must validate (unexpired, unrevoked).
2. If a scope policy is registered for `r.URL.Path` (see below), the
   token must include all required scopes.
3. Default 200 body:

   ```json
   {
     "sub": "<user UUID>",
     "client_id": "<client UUID>",
     "scope": "<granted scope>",
     "path": "<request path>",
     "method": "<HTTP method, omitted for GET>"
   }
   ```

In test mode, requests are recorded by the recorder and may be
intercepted by the script queue (label `resource`). In production
neither is active; the handler runs unmodified.

**Errors**

- `401 invalid_token` — missing/invalid bearer. Header
  `WWW-Authenticate: Bearer realm="<realm>", error="invalid_token", ...`.
- `403 insufficient_scope` — token lacks a required scope. Header
  `... scope="<required>"`.

### `POST /test/resource-policy`

Register a scope requirement for a resource path. Test-mode only.

**Request body**

```json
{
  "path": "/test/resource/admin",     // required; must start with /test/resource/
  "required_scope": "read_write"      // required; space-separated for multi-scope
}
```

Multi-scope is AND-semantics: every required scope must be present in
the token.

**Response**

`204 No Content`.

**Errors**

- `400` — missing or malformed path.

## Request inspection

### `GET /test/requests`

Return a sanitized snapshot of recent requests to recordable endpoints.

**Query parameters**

- `endpoint` (optional) — filter by [endpoint label](#endpoint-labels).
- `client_id` (optional) — filter by inferred client_id (Basic auth username, or form `client_id`).
- `since` (optional) — RFC 3339 timestamp; only entries at-or-after this time are returned.

**Response 200**

```json
[
  {
    "timestamp": "2026-04-30T11:11:11.123Z",
    "method": "POST",
    "path": "/v1/oauth/tokens",
    "endpoint": "token",
    "client_id": "acme",
    "headers": {
      "Authorization": "Basic <redacted>",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    "query": {},
    "form": {
      "grant_type": ["client_credentials"],
      "scope": ["read"]
    }
  }
]
```

The recorder is a bounded ring buffer of 1000 entries (oldest dropped
first when the buffer is full).

## Sanitization

The recorder strips or masks values that would otherwise leak
secrets:

| Field | Treatment |
|---|---|
| `Authorization` header | Scheme preserved, value masked: `Basic <redacted>`, `Bearer <redacted>` |
| `Cookie`, `Set-Cookie` | Dropped from recorded headers entirely |
| Form `client_secret` | `<redacted>` |
| Form `password` | `<redacted>` |
| Form `code_verifier` | `<redacted>` |
| Form `refresh_token` | `<redacted>` |

These rules apply to every request that hits a recordable endpoint;
they cannot be disabled in test mode.

## Differences from production

| Behavior | Production (`runserver`) | Test mode (`runserver --test-mode`) |
|---|---|---|
| Config backend | etcd or consul | in-memory defaults |
| Database | postgres | embedded SQLite (`:memory:` by default) |
| Refresh-token rotation | off (legacy reuse) | on by default; toggleable via [`/test/refresh-tokens/rotate-policy`](#post-testrefresh-tokensrotate-policy) |
| Default scopes | `read`, `read_write` | `read`, `read_write`, `profile`, `email` |
| `/test/*` control plane | not mounted | mounted |
| `/test/resource/{path}` | **mounted** (sample resource) | mounted (with policy + recorder + scriptable) |
| Request recorder | not active | active for recordable endpoints |
| Script queue | not active | active for recordable endpoints |
| gzip middleware | enabled | disabled (would break script queue's pass-through actions) |

## Related documentation

- Production OAuth flows and grant types: [README](../README.md)
- Integration test gaps doc (proxy-side responsibilities): [integration_test_gaps.md](./integration_test_gaps.md)
- Live integration suite that exercises every endpoint here:
  [`integration/`](../integration)
