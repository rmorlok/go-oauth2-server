package testmode_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/database"
	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth"
	"github.com/RichardKnop/go-oauth2-server/testmode"
	"github.com/RichardKnop/go-oauth2-server/util/migrations"
	"github.com/gorilla/mux"
)

func newTestApp(t *testing.T, withTestMode bool) *httptest.Server {
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

	if withTestMode {
		ts := testmode.NewService(cnf, db, oauthService)
		ts.RegisterRoutes(router, "/test")
	}

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

func TestTestModeBootstrap(t *testing.T) {
	srv := newTestApp(t, true)

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
	srv := newTestApp(t, false)
	resp := mustGet(t, srv.URL+"/test/health")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 when test-mode is off, got %d", resp.StatusCode)
	}
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
