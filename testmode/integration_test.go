package testmode_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RichardKnop/go-oauth2-server/database"
	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth"
	"github.com/RichardKnop/go-oauth2-server/testmode"
	"github.com/RichardKnop/go-oauth2-server/util/migrations"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
)

type testApp struct {
	server   *httptest.Server
	recorder *testmode.Recorder
}

func newTestApp(t *testing.T, withTestMode bool) *testApp {
	t.Helper()

	cnf := testmode.NewConfig(":memory:")
	db, err := database.NewDatabase(cnf)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := migrations.Bootstrap(db); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := models.MigrateAll(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := testmode.Seed(db); err != nil {
		t.Fatalf("seed: %v", err)
	}

	router := mux.NewRouter()
	oauthService := oauth.NewService(cnf, db)
	oauthService.RegisterRoutes(router, "/v1/oauth")

	app := negroni.New()
	var rec *testmode.Recorder
	if withTestMode {
		ts := testmode.NewService(cnf, db, oauthService)
		app.Use(ts.Middleware())
		app.Use(ts.ScriptMiddleware())
		ts.RegisterRoutes(router, "/test")
		rec = ts.Recorder()
	}
	app.UseHandler(router)

	srv := httptest.NewServer(app)
	t.Cleanup(srv.Close)
	return &testApp{server: srv, recorder: rec}
}

func TestTestModeBootstrap(t *testing.T) {
	app := newTestApp(t, true)
	srv := app.server

	t.Run("health", func(t *testing.T) {
		resp := mustGet(t, srv.URL+"/test/health")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var body map[string]string
		json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if body["status"] != "ok" || body["mode"] != "test" {
			t.Fatalf("unexpected health body: %v", body)
		}
	})

	t.Run("register client and obtain client_credentials token", func(t *testing.T) {
		// Register client.
		body := mustPostJSON(t, srv.URL+"/test/clients", map[string]string{
			"key":          "acme",
			"secret":       "s3cret",
			"redirect_uri": "https://example.com/cb",
		})
		var clientResp struct {
			ID, Key, RedirectURI string `json:""`
		}
		if err := json.Unmarshal(body, &clientResp); err != nil {
			t.Fatalf("decode client: %v body=%s", err, body)
		}
		if clientResp.Key != "acme" {
			t.Fatalf("expected key=acme got %q", clientResp.Key)
		}

		// Exchange via client_credentials.
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("scope", "read")
		req, _ := http.NewRequest("POST", srv.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("acme", "s3cret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("token request: %v", err)
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 got %d body=%s", resp.StatusCode, respBody)
		}
		var tok struct {
			AccessToken string `json:"access_token"`
			Scope       string `json:"scope"`
			TokenType   string `json:"token_type"`
		}
		if err := json.Unmarshal(respBody, &tok); err != nil {
			t.Fatalf("decode token: %v", err)
		}
		if tok.AccessToken == "" || tok.Scope != "read" || tok.TokenType != "Bearer" {
			t.Fatalf("unexpected token response: %+v", tok)
		}
	})

	t.Run("register user with explicit role", func(t *testing.T) {
		body := mustPostJSON(t, srv.URL+"/test/users", map[string]string{
			"username": "alice@example.com",
			"password": "hunter22",
			"role":     "user",
		})
		var userResp struct {
			ID, Username, Role string
		}
		if err := json.Unmarshal(body, &userResp); err != nil {
			t.Fatalf("decode user: %v body=%s", err, body)
		}
		if userResp.Username != "alice@example.com" || userResp.Role != "user" {
			t.Fatalf("unexpected user response: %+v", userResp)
		}
	})

	t.Run("client missing key returns 400", func(t *testing.T) {
		buf, _ := json.Marshal(map[string]string{"redirect_uri": "https://x"})
		resp, err := http.Post(srv.URL+"/test/clients", "application/json", bytes.NewReader(buf))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 got %d", resp.StatusCode)
		}
	})
}

func TestProductionModeOmitsTestRoutes(t *testing.T) {
	app := newTestApp(t, false)
	resp := mustGet(t, app.server.URL+"/test/health")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 when test-mode is off, got %d", resp.StatusCode)
	}
}

func TestProgrammaticAuthorize(t *testing.T) {
	app := newTestApp(t, true)
	srv := app.server

	// Setup: register client and user.
	clientBody := mustPostJSON(t, srv.URL+"/test/clients", map[string]string{
		"key":          "auth-client",
		"secret":       "topsecret",
		"redirect_uri": "https://app.example.com/cb",
	})
	var client struct{ ID, Key, RedirectURI string }
	json.Unmarshal(clientBody, &client)

	userBody := mustPostJSON(t, srv.URL+"/test/users", map[string]string{
		"username": "bob@example.com",
		"password": "hunter22",
	})
	var user struct{ ID, Username, Role string }
	json.Unmarshal(userBody, &user)

	t.Run("approve returns redirect with code and round-trips through tokens endpoint", func(t *testing.T) {
		body := mustPostJSON(t, srv.URL+"/test/authorize", map[string]string{
			"client_id":    "auth-client",
			"user_id":      user.ID,
			"redirect_uri": "https://app.example.com/cb",
			"scope":        "read",
			"state":        "xyzzy",
			"decision":     "approve",
		})
		var resp struct{ RedirectURL string `json:"redirect_url"` }
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("decode authorize body: %v", err)
		}
		u, err := url.Parse(resp.RedirectURL)
		if err != nil {
			t.Fatalf("parse redirect: %v", err)
		}
		if u.Host != "app.example.com" || u.Path != "/cb" {
			t.Fatalf("unexpected redirect host/path: %s", resp.RedirectURL)
		}
		code := u.Query().Get("code")
		if code == "" {
			t.Fatalf("expected code in redirect: %s", resp.RedirectURL)
		}
		if got := u.Query().Get("state"); got != "xyzzy" {
			t.Fatalf("expected state=xyzzy got %q", got)
		}

		// Exchange the code for tokens.
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", "https://app.example.com/cb")
		req, _ := http.NewRequest("POST", srv.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("auth-client", "topsecret")
		tokenResp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("token request: %v", err)
		}
		body2, _ := io.ReadAll(tokenResp.Body)
		tokenResp.Body.Close()
		if tokenResp.StatusCode != http.StatusOK {
			t.Fatalf("expected token 200, got %d body=%s", tokenResp.StatusCode, body2)
		}
		var tok struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		json.Unmarshal(body2, &tok)
		if tok.AccessToken == "" {
			t.Fatalf("expected access_token in response, got %s", body2)
		}
	})

	t.Run("deny returns redirect with error=access_denied", func(t *testing.T) {
		body := mustPostJSON(t, srv.URL+"/test/authorize", map[string]string{
			"client_id":    "auth-client",
			"user_id":      user.ID,
			"redirect_uri": "https://app.example.com/cb",
			"scope":        "read",
			"state":        "denied-state",
			"decision":     "deny",
		})
		var resp struct{ RedirectURL string `json:"redirect_url"` }
		json.Unmarshal(body, &resp)
		u, _ := url.Parse(resp.RedirectURL)
		if got := u.Query().Get("error"); got != "access_denied" {
			t.Fatalf("expected error=access_denied got %q", got)
		}
		if got := u.Query().Get("state"); got != "denied-state" {
			t.Fatalf("expected state denied-state got %q", got)
		}
		if got := u.Query().Get("code"); got != "" {
			t.Fatalf("deny should not include code, got %q", got)
		}
	})

	t.Run("redirect_uri mismatch returns 400", func(t *testing.T) {
		buf, _ := json.Marshal(map[string]string{
			"client_id":    "auth-client",
			"user_id":      user.ID,
			"redirect_uri": "https://evil.example.com/cb",
			"scope":        "read",
			"decision":     "approve",
		})
		resp, err := http.Post(srv.URL+"/test/authorize", "application/json", bytes.NewReader(buf))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 got %d", resp.StatusCode)
		}
	})

	t.Run("granted_scope narrows the granted scope", func(t *testing.T) {
		// scope=read_write requested, granted_scope=read narrows it.
		body := mustPostJSON(t, srv.URL+"/test/authorize", map[string]string{
			"client_id":     "auth-client",
			"user_id":       user.ID,
			"redirect_uri":  "https://app.example.com/cb",
			"scope":         "read_write",
			"granted_scope": "read",
			"decision":      "approve",
		})
		var resp struct{ RedirectURL string `json:"redirect_url"` }
		json.Unmarshal(body, &resp)
		u, _ := url.Parse(resp.RedirectURL)
		code := u.Query().Get("code")

		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", "https://app.example.com/cb")
		req, _ := http.NewRequest("POST", srv.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("auth-client", "topsecret")
		tokenResp, _ := http.DefaultClient.Do(req)
		body2, _ := io.ReadAll(tokenResp.Body)
		tokenResp.Body.Close()
		var tok struct{ Scope string }
		json.Unmarshal(body2, &tok)
		if tok.Scope != "read" {
			t.Fatalf("expected granted scope=read, got %q (full: %s)", tok.Scope, body2)
		}
	})
}

func TestRequestRecording(t *testing.T) {
	app := newTestApp(t, true)
	srv := app.server

	mustPostJSON(t, srv.URL+"/test/clients", map[string]string{
		"key":          "rec-client",
		"secret":       "rec-secret",
		"redirect_uri": "https://x.example.com/cb",
	})

	// Issue a token request — should be recorded.
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "read")
	req, _ := http.NewRequest("POST", srv.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("rec-client", "rec-secret")
	tokenResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	tokenResp.Body.Close()

	t.Run("GET /test/requests returns the token call with sanitized headers", func(t *testing.T) {
		resp := mustGet(t, srv.URL+"/test/requests?endpoint=token")
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var entries []testmode.RecordedRequest
		if err := json.Unmarshal(body, &entries); err != nil {
			t.Fatalf("decode: %v body=%s", err, body)
		}
		if len(entries) != 1 {
			t.Fatalf("expected 1 entry got %d: %s", len(entries), body)
		}
		e := entries[0]
		if e.Path != "/v1/oauth/tokens" || e.Method != "POST" || e.Endpoint != "token" {
			t.Fatalf("unexpected entry: %+v", e)
		}
		if e.ClientID != "rec-client" {
			t.Fatalf("expected client_id rec-client, got %q", e.ClientID)
		}
		if got := e.Headers["Authorization"]; got != "Basic <redacted>" {
			t.Fatalf("expected Authorization redacted, got %q", got)
		}
		if e.Form["grant_type"] == nil || e.Form["grant_type"][0] != "client_credentials" {
			t.Fatalf("expected grant_type recorded, got %v", e.Form)
		}
	})

	t.Run("password grant redacts password form field", func(t *testing.T) {
		// Create user.
		mustPostJSON(t, srv.URL+"/test/users", map[string]string{
			"username": "carol@example.com",
			"password": "hunter22",
		})
		form := url.Values{}
		form.Set("grant_type", "password")
		form.Set("username", "carol@example.com")
		form.Set("password", "hunter22")
		form.Set("scope", "read")
		req, _ := http.NewRequest("POST", srv.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("rec-client", "rec-secret")
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()

		// Snapshot all token-endpoint records and assert the latest password
		// grant has the password redacted.
		entries := app.recorder.Snapshot(testmode.SnapshotFilter{Endpoint: "token"})
		var pwdEntry *testmode.RecordedRequest
		for i := range entries {
			if entries[i].Form["grant_type"] != nil && entries[i].Form["grant_type"][0] == "password" {
				pwdEntry = &entries[i]
			}
		}
		if pwdEntry == nil {
			t.Fatalf("no password-grant entry found")
		}
		if got := pwdEntry.Form["password"]; len(got) != 1 || got[0] != "<redacted>" {
			t.Fatalf("password should be redacted, got %v", got)
		}
		if got := pwdEntry.Form["client_secret"]; got != nil {
			// client_secret is in Basic auth here, not form, so it should be
			// absent from the form. But if form contained it, it should be redacted.
			if got[0] != "<redacted>" {
				t.Fatalf("client_secret in form should be redacted, got %v", got)
			}
		}
	})

	t.Run("since filter works", func(t *testing.T) {
		future := time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339)
		resp := mustGet(t, srv.URL+"/test/requests?since="+url.QueryEscape(future))
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var entries []testmode.RecordedRequest
		json.Unmarshal(body, &entries)
		if len(entries) != 0 {
			t.Fatalf("expected 0 entries from future since, got %d", len(entries))
		}
	})

	t.Run("/test/* control endpoints are not recorded", func(t *testing.T) {
		entries := app.recorder.Snapshot(testmode.SnapshotFilter{})
		for _, e := range entries {
			if strings.HasPrefix(e.Path, "/test/") {
				t.Fatalf("control-plane path should not be recorded: %s", e.Path)
			}
		}
	})
}

func TestScriptQueue(t *testing.T) {
	app := newTestApp(t, true)
	srv := app.server

	mustPostJSON(t, srv.URL+"/test/clients", map[string]string{
		"key":          "scr-client",
		"secret":       "scr-secret",
		"redirect_uri": "https://x.example.com/cb",
	})

	tokenCall := func(t *testing.T) *http.Response {
		t.Helper()
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("scope", "read")
		req, _ := http.NewRequest("POST", srv.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("scr-client", "scr-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		return resp
	}

	t.Run("queued 503 then real handler success", func(t *testing.T) {
		// Enqueue one 503 action. Next call should be 503; the call after
		// that should fall through to the real handler.
		buf, _ := json.Marshal(map[string]any{
			"client_id": "scr-client",
			"endpoint":  "token",
			"actions": []map[string]any{
				{"body_template": "temporarily_unavailable_503"},
			},
		})
		resp, _ := http.Post(srv.URL+"/test/scripts", "application/json", bytes.NewReader(buf))
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("expected 204 from /test/scripts, got %d", resp.StatusCode)
		}
		resp.Body.Close()

		first := tokenCall(t)
		if first.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", first.StatusCode)
		}
		first.Body.Close()

		second := tokenCall(t)
		body, _ := io.ReadAll(second.Body)
		second.Body.Close()
		if second.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 fall-through, got %d body=%s", second.StatusCode, body)
		}
	})

	t.Run("scope_override empty string omits scope from response", func(t *testing.T) {
		emptyScope := ""
		buf, _ := json.Marshal(map[string]any{
			"client_id": "scr-client",
			"endpoint":  "token",
			"actions": []map[string]any{
				{"scope_override": &emptyScope},
			},
		})
		http.Post(srv.URL+"/test/scripts", "application/json", bytes.NewReader(buf))

		resp := tokenCall(t)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var generic map[string]any
		json.Unmarshal(body, &generic)
		if _, has := generic["scope"]; has {
			t.Fatalf("expected scope omitted, got %s", body)
		}
		if _, has := generic["access_token"]; !has {
			t.Fatalf("expected access_token still present, got %s", body)
		}
	})

	t.Run("scope_override non-empty replaces scope", func(t *testing.T) {
		newScope := "narrowed"
		buf, _ := json.Marshal(map[string]any{
			"client_id": "scr-client",
			"endpoint":  "token",
			"actions": []map[string]any{
				{"scope_override": &newScope},
			},
		})
		http.Post(srv.URL+"/test/scripts", "application/json", bytes.NewReader(buf))

		resp := tokenCall(t)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var generic map[string]any
		json.Unmarshal(body, &generic)
		if generic["scope"] != "narrowed" {
			t.Fatalf("expected scope=narrowed, got %v (body=%s)", generic["scope"], body)
		}
	})

	t.Run("fail_count repeats then drops", func(t *testing.T) {
		buf, _ := json.Marshal(map[string]any{
			"client_id": "scr-client",
			"endpoint":  "token",
			"actions": []map[string]any{
				{"status": 418, "body": `{"e":"teapot"}`, "fail_count": 2},
			},
		})
		http.Post(srv.URL+"/test/scripts", "application/json", bytes.NewReader(buf))

		first := tokenCall(t)
		first.Body.Close()
		second := tokenCall(t)
		second.Body.Close()
		third := tokenCall(t)
		third.Body.Close()

		if first.StatusCode != 418 || second.StatusCode != 418 {
			t.Fatalf("expected 418,418 got %d,%d", first.StatusCode, second.StatusCode)
		}
		if third.StatusCode != http.StatusOK {
			t.Fatalf("third call should fall through to 200, got %d", third.StatusCode)
		}
	})

	t.Run("wildcard client_id matches any caller", func(t *testing.T) {
		buf, _ := json.Marshal(map[string]any{
			// no client_id
			"endpoint": "token",
			"actions":  []map[string]any{{"status": 599, "body": `{}`}},
		})
		http.Post(srv.URL+"/test/scripts", "application/json", bytes.NewReader(buf))

		resp := tokenCall(t)
		resp.Body.Close()
		if resp.StatusCode != 599 {
			t.Fatalf("expected wildcard to match, got %d", resp.StatusCode)
		}
	})

	t.Run("DELETE clears queues", func(t *testing.T) {
		buf, _ := json.Marshal(map[string]any{
			"client_id": "scr-client",
			"endpoint":  "token",
			"actions":   []map[string]any{{"status": 599, "body": `{}`}},
		})
		http.Post(srv.URL+"/test/scripts", "application/json", bytes.NewReader(buf))

		req, _ := http.NewRequest("DELETE", srv.URL+"/test/scripts", nil)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()

		listResp := mustGet(t, srv.URL+"/test/scripts")
		body, _ := io.ReadAll(listResp.Body)
		listResp.Body.Close()
		var snap []testmode.QueueSnapshot
		json.Unmarshal(body, &snap)
		if len(snap) != 0 {
			t.Fatalf("expected empty snapshot, got %v", snap)
		}

		// Token call should fall through.
		fall := tokenCall(t)
		fall.Body.Close()
		if fall.StatusCode != http.StatusOK {
			t.Fatalf("expected fall-through 200 after clear, got %d", fall.StatusCode)
		}
	})

	t.Run("drop_connection causes client read error", func(t *testing.T) {
		buf, _ := json.Marshal(map[string]any{
			"client_id": "scr-client",
			"endpoint":  "token",
			"actions":   []map[string]any{{"drop_connection": true}},
		})
		http.Post(srv.URL+"/test/scripts", "application/json", bytes.NewReader(buf))

		// Use a non-keepalive client so we see the close cleanly.
		client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("scope", "read")
		req, _ := http.NewRequest("POST", srv.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("scr-client", "scr-secret")
		_, err := client.Do(req)
		if err == nil {
			t.Fatalf("expected connection error from drop_connection, got nil")
		}
	})
}

func TestRefreshTokenRotation(t *testing.T) {
	app := newTestApp(t, true)
	srv := app.server

	// Setup: client + user.
	mustPostJSON(t, srv.URL+"/test/clients", map[string]string{
		"key":          "rot-client",
		"secret":       "rot-secret",
		"redirect_uri": "https://x.example.com/cb",
	})
	mustPostJSON(t, srv.URL+"/test/users", map[string]string{
		"username": "dave@example.com",
		"password": "hunter22",
	})

	// Get an initial refresh token via password grant.
	initialRefreshToken := func(t *testing.T) string {
		t.Helper()
		form := url.Values{}
		form.Set("grant_type", "password")
		form.Set("username", "dave@example.com")
		form.Set("password", "hunter22")
		form.Set("scope", "read")
		req, _ := http.NewRequest("POST", srv.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("rot-client", "rot-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("password grant: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var tok struct {
			RefreshToken string `json:"refresh_token"`
		}
		json.Unmarshal(body, &tok)
		if tok.RefreshToken == "" {
			t.Fatalf("expected refresh_token in response, got %s", body)
		}
		return tok.RefreshToken
	}

	doRefresh := func(t *testing.T, rt string) (status int, body []byte) {
		t.Helper()
		form := url.Values{}
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", rt)
		req, _ := http.NewRequest("POST", srv.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("rot-client", "rot-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, body
	}

	t.Run("rotation issues a new refresh token and revokes the old", func(t *testing.T) {
		rt := initialRefreshToken(t)

		status, body := doRefresh(t, rt)
		if status != http.StatusOK {
			t.Fatalf("first refresh expected 200 got %d body=%s", status, body)
		}
		var refreshResp struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		json.Unmarshal(body, &refreshResp)
		if refreshResp.RefreshToken == "" || refreshResp.RefreshToken == rt {
			t.Fatalf("expected a new refresh token, got %q (was %q)", refreshResp.RefreshToken, rt)
		}

		// Replay the OLD refresh token: must fail (revoked).
		status2, body2 := doRefresh(t, rt)
		if status2 == http.StatusOK {
			t.Fatalf("expected reuse of old refresh token to fail, got 200 body=%s", body2)
		}
		if status2 != http.StatusBadRequest {
			t.Fatalf("expected 400 on revoked-token reuse, got %d body=%s", status2, body2)
		}

		// New refresh token still works.
		status3, body3 := doRefresh(t, refreshResp.RefreshToken)
		if status3 != http.StatusOK {
			t.Fatalf("new refresh token should work, got %d body=%s", status3, body3)
		}
	})

	t.Run("concurrent refresh: exactly one wins", func(t *testing.T) {
		rt := initialRefreshToken(t)

		const N = 8
		var wg sync.WaitGroup
		results := make([]int, N)
		for i := 0; i < N; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				status, _ := doRefresh(t, rt)
				results[i] = status
			}(i)
		}
		wg.Wait()

		ok, fail := 0, 0
		for _, s := range results {
			switch s {
			case http.StatusOK:
				ok++
			case http.StatusBadRequest:
				fail++
			default:
				t.Fatalf("unexpected status from concurrent refresh: %d", s)
			}
		}
		if ok != 1 {
			t.Fatalf("expected exactly 1 success across %d concurrent refreshes, got %d (results=%v)", N, ok, results)
		}
		if fail != N-1 {
			t.Fatalf("expected %d failures, got %d (results=%v)", N-1, fail, results)
		}
	})

	t.Run("rotate-policy off: legacy reuse behavior", func(t *testing.T) {
		// Toggle rotation off.
		buf, _ := json.Marshal(map[string]bool{"rotation": false})
		resp, _ := http.Post(srv.URL+"/test/refresh-tokens/rotate-policy", "application/json", bytes.NewReader(buf))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 from rotate-policy, got %d", resp.StatusCode)
		}
		resp.Body.Close()
		t.Cleanup(func() {
			// Restore default for subsequent subtests.
			b, _ := json.Marshal(map[string]bool{"rotation": true})
			r, _ := http.Post(srv.URL+"/test/refresh-tokens/rotate-policy", "application/json", bytes.NewReader(b))
			r.Body.Close()
		})

		rt := initialRefreshToken(t)
		status, body := doRefresh(t, rt)
		if status != http.StatusOK {
			t.Fatalf("first refresh expected 200, got %d body=%s", status, body)
		}
		var refreshResp struct {
			RefreshToken string `json:"refresh_token"`
		}
		json.Unmarshal(body, &refreshResp)
		if refreshResp.RefreshToken != rt {
			t.Fatalf("with rotation off, refresh token should be reused; got %q expected %q", refreshResp.RefreshToken, rt)
		}

		// Replay the same refresh token: must still succeed.
		status2, body2 := doRefresh(t, rt)
		if status2 != http.StatusOK {
			t.Fatalf("with rotation off, reuse should succeed; got %d body=%s", status2, body2)
		}
	})
}

func mustGet(t *testing.T, u string) *http.Response {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	return resp
}

func mustPostJSON(t *testing.T, u string, payload any) []byte {
	t.Helper()
	buf, _ := json.Marshal(payload)
	resp, err := http.Post(u, "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("POST %s: %v", u, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Fatalf("POST %s: status %d body %s", u, resp.StatusCode, body)
	}
	return body
}
