package integration_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/testmode"
)

// TestScenario20_ProxyAPICallWithValidToken covers the spec's "Proxy
// API Call With Valid Token": real OAuth flow → access token → hit
// /test/resource/<path> with Authorization: Bearer <token>. The
// default body carries sub/client_id/scope/path and the recorder
// captures the request with the bearer redacted.
//
// Spec: P1 scenario 20.
func TestScenario20_ProxyAPICallWithValidToken(t *testing.T) {
	ts := newTestServer(t)
	c := registerClient(t, ts, "scn20", "scn20-secret", "https://app.example.com/cb")
	registerUser(t, ts, "scn20@example.com", "hunter22")

	_, tok, _ := passwordGrant(t, ts, c, "scn20@example.com", "hunter22", "read")
	if tok.AccessToken == "" {
		t.Fatalf("setup: missing access token")
	}

	const path = "/test/resource/some/sub/path"
	status, _, body := callResource(t, ts, tok.AccessToken, path)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", status, body)
	}

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode body: %v body=%s", err, body)
	}
	if doc["path"] != path {
		t.Fatalf("expected path=%s, got %v", path, doc["path"])
	}
	if doc["scope"] != "read" {
		t.Fatalf("expected scope=read, got %v", doc["scope"])
	}
	if doc["client_id"] == nil || doc["client_id"] == "" {
		t.Fatalf("expected client_id in body, got %v", doc["client_id"])
	}
	if doc["sub"] == nil || doc["sub"] == "" {
		t.Fatalf("expected sub in body, got %v", doc["sub"])
	}

	// Recorder captures the request with bearer redacted.
	entries := ts.Recorder.Snapshot(testmode.SnapshotFilter{Endpoint: "resource"})
	if len(entries) != 1 {
		t.Fatalf("expected 1 recorded resource entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Path != path {
		t.Fatalf("expected recorded path=%s, got %q", path, e.Path)
	}
	if got := e.Headers["Authorization"]; got != "Bearer <redacted>" {
		t.Fatalf("expected Bearer <redacted>, got %q", got)
	}
}
