package integration_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/oauth"
	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// registeredClient captures the bits a scenario test needs to drive an
// OAuth flow against a particular client (key, secret, redirect URI,
// auth method).
type registeredClient struct {
	ID                      string `json:"id"`
	Key                     string `json:"key"`
	Secret                  string `json:"-"` // not serialized; held by the test
	RedirectURI             string `json:"redirect_uri"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
	RequirePKCE             bool   `json:"require_pkce"`
}

type registeredUser struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Role        string `json:"role"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Sub         string `json:"sub,omitempty"`
}

// tokenResponse is the typed view of a /v1/oauth/tokens response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	UserID       string `json:"user_id,omitempty"`
}

// clientOpts are optional knobs for registerClient.
type clientOpts struct {
	AuthMethod  string
	RequirePKCE bool
}

func registerClient(t *testing.T, ts *testServer, key, secret, redirectURI string, opts ...clientOpts) *registeredClient {
	t.Helper()
	body := map[string]any{
		"key":          key,
		"redirect_uri": redirectURI,
	}
	if secret != "" {
		body["secret"] = secret
	}
	if len(opts) > 0 {
		o := opts[0]
		if o.AuthMethod != "" {
			body["token_endpoint_auth_method"] = o.AuthMethod
		}
		if o.RequirePKCE {
			body["require_pkce"] = true
		}
	}
	respBytes := postJSON(t, ts.URL+"/test/clients", body, http.StatusCreated)
	var c registeredClient
	if err := json.Unmarshal(respBytes, &c); err != nil {
		t.Fatalf("decode client: %v body=%s", err, respBytes)
	}
	c.Secret = secret
	return &c
}

type userOpts struct {
	Role        string
	Email       string
	DisplayName string
	Sub         string
}

func registerUser(t *testing.T, ts *testServer, username, password string, opts ...userOpts) *registeredUser {
	t.Helper()
	body := map[string]any{
		"username": username,
		"password": password,
	}
	if len(opts) > 0 {
		o := opts[0]
		if o.Role != "" {
			body["role"] = o.Role
		}
		if o.Email != "" {
			body["email"] = o.Email
		}
		if o.DisplayName != "" {
			body["display_name"] = o.DisplayName
		}
		if o.Sub != "" {
			body["sub"] = o.Sub
		}
	}
	respBytes := postJSON(t, ts.URL+"/test/users", body, http.StatusCreated)
	var u registeredUser
	if err := json.Unmarshal(respBytes, &u); err != nil {
		t.Fatalf("decode user: %v body=%s", err, respBytes)
	}
	return &u
}

// authorizeParams are the inputs to /test/authorize. Mirrors the request
// shape of the endpoint.
type authorizeParams struct {
	Client              *registeredClient
	User                *registeredUser // user_id is taken from User.ID; ignored for client_credentials flows
	Username            string          // alternative to User.ID for ergonomics
	RedirectURI         string          // defaults to Client.RedirectURI
	Scope               string
	State               string
	GrantedScope        string
	CodeChallenge       string
	CodeChallengeMethod string
}

// authorize calls /test/authorize with the given decision and returns
// the redirect URL the proxy would have followed.
func authorize(t *testing.T, ts *testServer, decision string, p authorizeParams) string {
	t.Helper()
	body := map[string]any{
		"client_id": p.Client.Key,
		"decision":  decision,
	}
	redirectURI := p.RedirectURI
	if redirectURI == "" {
		redirectURI = p.Client.RedirectURI
	}
	if redirectURI != "" {
		body["redirect_uri"] = redirectURI
	}
	if p.User != nil {
		body["user_id"] = p.User.ID
	} else if p.Username != "" {
		body["username"] = p.Username
	}
	if p.Scope != "" {
		body["scope"] = p.Scope
	}
	if p.State != "" {
		body["state"] = p.State
	}
	if p.GrantedScope != "" {
		body["granted_scope"] = p.GrantedScope
	}
	if p.CodeChallenge != "" {
		body["code_challenge"] = p.CodeChallenge
	}
	if p.CodeChallengeMethod != "" {
		body["code_challenge_method"] = p.CodeChallengeMethod
	}
	respBytes := postJSON(t, ts.URL+"/test/authorize", body, http.StatusOK)
	var resp struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("decode authorize: %v body=%s", err, respBytes)
	}
	return resp.RedirectURL
}

// extractCode pulls the `code` query parameter from a redirect URL.
// Fails the test if absent.
func extractCode(t *testing.T, redirectURL string) string {
	t.Helper()
	u, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", redirectURL, err)
	}
	c := u.Query().Get("code")
	if c == "" {
		t.Fatalf("no code in redirect %q", redirectURL)
	}
	return c
}

// exchangeOpts tunes the token-exchange request beyond the basic
// (grant_type, code, redirect_uri) trio.
type exchangeOpts struct {
	CodeVerifier string // for PKCE
}

func exchangeCode(t *testing.T, ts *testServer, c *registeredClient, code string, opts ...exchangeOpts) (int, *tokenResponse, []byte) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.RedirectURI)
	if len(opts) > 0 && opts[0].CodeVerifier != "" {
		form.Set("code_verifier", opts[0].CodeVerifier)
	}
	return doTokenRequest(t, ts, c, form)
}

// passwordGrant exchanges username/password for tokens.
func passwordGrant(t *testing.T, ts *testServer, c *registeredClient, username, password, scope string) (int, *tokenResponse, []byte) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", username)
	form.Set("password", password)
	if scope != "" {
		form.Set("scope", scope)
	}
	return doTokenRequest(t, ts, c, form)
}

// clientCredentialsGrant gets an app-only access token.
func clientCredentialsGrant(t *testing.T, ts *testServer, c *registeredClient, scope string) (int, *tokenResponse, []byte) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if scope != "" {
		form.Set("scope", scope)
	}
	return doTokenRequest(t, ts, c, form)
}

// refresh runs grant_type=refresh_token.
func refresh(t *testing.T, ts *testServer, c *registeredClient, refreshToken string) (int, *tokenResponse, []byte) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	return doTokenRequest(t, ts, c, form)
}

// doTokenRequest drives /v1/oauth/tokens with the client's configured
// auth method (basic / form / none).
func doTokenRequest(t *testing.T, ts *testServer, c *registeredClient, form url.Values) (int, *tokenResponse, []byte) {
	t.Helper()
	switch c.TokenEndpointAuthMethod {
	case oauth.AuthMethodSecretPost:
		form.Set("client_id", c.Key)
		form.Set("client_secret", c.Secret)
	case oauth.AuthMethodNone:
		form.Set("client_id", c.Key)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/v1/oauth/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.TokenEndpointAuthMethod == "" || c.TokenEndpointAuthMethod == oauth.AuthMethodSecretBasic {
		req.SetBasicAuth(c.Key, c.Secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var tr tokenResponse
	_ = json.Unmarshal(body, &tr) // ok if it fails (e.g. error response)
	return resp.StatusCode, &tr, body
}

// revokeToken hits /v1/oauth/revoke (RFC 7009 path).
func revokeToken(t *testing.T, ts *testServer, c *registeredClient, token, hint string) int {
	t.Helper()
	form := url.Values{}
	form.Set("token", token)
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/v1/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.Key, c.Secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// adminRevoke hits /test/revoke (admin path, no client auth).
func adminRevoke(t *testing.T, ts *testServer, body map[string]string) {
	t.Helper()
	postJSON(t, ts.URL+"/test/revoke", body, http.StatusOK)
}

// callResource hits /test/resource/<path> with a bearer token.
func callResource(t *testing.T, ts *testServer, accessToken, path string) (int, http.Header, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get resource: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, resp.Header, body
}

// userinfo hits /v1/oauth/userinfo.
func userinfo(t *testing.T, ts *testServer, accessToken string) (int, http.Header, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+"/v1/oauth/userinfo", nil)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, resp.Header, body
}

// enqueueScript registers script actions for a given client+endpoint.
// Empty clientID enqueues onto the wildcard queue.
func enqueueScript(t *testing.T, ts *testServer, clientID, endpoint string, actions ...testmode.Action) {
	t.Helper()
	postJSON(t, ts.URL+"/test/scripts", map[string]any{
		"client_id": clientID,
		"endpoint":  endpoint,
		"actions":   actions,
	}, http.StatusNoContent)
}

// pkcePair returns a (verifier, S256-challenge) pair suitable for
// scenario tests. The values are RFC 7636 §4 examples.
func pkcePair() (verifier, challenge string) {
	v := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(v))
	return v, base64.RawURLEncoding.EncodeToString(h[:])
}

// ----- low-level HTTP helpers -----

func postJSON(t *testing.T, u string, payload any, expectStatus int) []byte {
	t.Helper()
	buf, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(u, "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("POST %s: %v", u, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != expectStatus {
		t.Fatalf("POST %s: expected %d got %d body=%s", u, expectStatus, resp.StatusCode, body)
	}
	return body
}
