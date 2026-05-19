package log_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/log"
)

func TestDefaultLogger_NotNil(t *testing.T) {
	if log.Default() == nil {
		t.Fatalf("Default() returned nil")
	}
	// Should not panic.
	log.Info("hello", "k", "v")
	log.Warn("hello", "k", "v")
	log.Error("hello", "k", "v")
	log.Debug("hello", "k", "v")
}

func TestInit_JSONFormatEmitsJSONRecords(t *testing.T) {
	var buf bytes.Buffer
	log.Init(log.Options{Level: "debug", Format: log.FormatJSON, Output: &buf})
	t.Cleanup(func() { log.Init(log.Options{}) })

	log.Info("hello world", "client_id", "abc")

	out := strings.TrimSpace(buf.String())
	var rec map[string]any
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatalf("output is not JSON: %q (%v)", out, err)
	}
	if rec["msg"] != "hello world" {
		t.Errorf("msg = %v, want hello world", rec["msg"])
	}
	if rec["client_id"] != "abc" {
		t.Errorf("client_id = %v, want abc", rec["client_id"])
	}
	if rec["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", rec["level"])
	}
}

func TestInit_TextFormatHonorsLevel(t *testing.T) {
	var buf bytes.Buffer
	log.Init(log.Options{Level: "warn", Format: log.FormatText, Output: &buf})
	t.Cleanup(func() { log.Init(log.Options{}) })

	log.Info("should be filtered")
	log.Warn("should appear", "k", "v")

	out := buf.String()
	if strings.Contains(out, "should be filtered") {
		t.Errorf("info record leaked through warn threshold: %s", out)
	}
	if !strings.Contains(out, "should appear") {
		t.Errorf("warn record missing: %s", out)
	}
}

func TestContextWithFromContext(t *testing.T) {
	var buf bytes.Buffer
	log.Init(log.Options{Level: "debug", Format: log.FormatJSON, Output: &buf})
	t.Cleanup(func() { log.Init(log.Options{}) })

	enriched := log.With("request_id", "req-1")
	ctx := log.ContextWith(context.Background(), enriched)
	log.FromContext(ctx).Info("hello")

	out := strings.TrimSpace(buf.String())
	var rec map[string]any
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatalf("output not JSON: %q (%v)", out, err)
	}
	if rec["request_id"] != "req-1" {
		t.Errorf("request_id missing/wrong: %v", rec)
	}
}

func TestFromContext_NoLoggerReturnsDefault(t *testing.T) {
	if l := log.FromContext(context.Background()); l == nil {
		t.Fatalf("FromContext on bare context returned nil")
	}
}
