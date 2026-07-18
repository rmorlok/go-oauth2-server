package testmode

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/RichardKnop/go-oauth2-server/util/response"
)

const (
	defaultLoadResourceStatus   = http.StatusOK
	maxLoadResourceResponseSize = 16 << 20 // 16 MiB keeps accidental requests bounded.
	loadResourceChunkSize       = 32 << 10
)

var loadResourceChunk = bytes.Repeat([]byte("x"), loadResourceChunkSize)

// loadResourceHandler implements ANY /test/load/resource/{path}. It is a
// fast, non-recorded sink for high-QPS proxy load tests where the provider
// should not become a DB/script-recorder bottleneck.
func (s *Service) loadResourceHandler(w http.ResponseWriter, r *http.Request) {
	status, err := loadResourceStatus(r)
	if err != nil {
		response.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	responseSize, err := loadResourceResponseSize(r)
	if err != nil {
		response.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if ok := loadResourceBearerPrefixAuthorized(r); !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="test-load", error="invalid_token"`)
		response.Error(w, "invalid or missing bearer token", http.StatusUnauthorized)
		return
	}

	delay, err := loadResourceDelay(r)
	if err != nil {
		response.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			return
		}
	}

	w.Header().Set("X-Test-Load-Path", r.URL.Path)
	w.Header().Set("X-Test-Load-Response-Bytes", strconv.Itoa(responseSize))
	if responseSize > 0 {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.WriteHeader(status)
	if responseBodyAllowed(status) && responseSize > 0 {
		writeLoadResourceBody(w, responseSize)
	}
}

func loadResourceStatus(r *http.Request) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("status"))
	if raw == "" {
		return defaultLoadResourceStatus, nil
	}
	status, err := strconv.Atoi(raw)
	if err != nil || status < 100 || status > 599 {
		return 0, fmt.Errorf("status must be an integer between 100 and 599")
	}
	return status, nil
}

func loadResourceResponseSize(r *http.Request) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("bytes"))
	if raw == "" {
		raw = strings.TrimSpace(r.URL.Query().Get("response_size"))
	}
	if raw == "" {
		return 0, nil
	}
	size, err := strconv.Atoi(raw)
	if err != nil || size < 0 {
		return 0, fmt.Errorf("bytes must be a non-negative integer")
	}
	if size > maxLoadResourceResponseSize {
		return 0, fmt.Errorf("bytes must be <= %d", maxLoadResourceResponseSize)
	}
	return size, nil
}

func loadResourceBearerPrefixAuthorized(r *http.Request) bool {
	prefix := r.URL.Query().Get("bearer_prefix")
	if prefix == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	return token != "" && strings.HasPrefix(token, prefix)
}

func loadResourceDelay(r *http.Request) (time.Duration, error) {
	delay, err := durationQueryParam(r, "delay", "delay_ms")
	if err != nil {
		return 0, err
	}
	jitter, err := durationQueryParam(r, "jitter", "jitter_ms")
	if err != nil {
		return 0, err
	}
	if jitter > 0 {
		delay += time.Duration(rand.Int63n(int64(jitter)))
	}
	return delay, nil
}

func durationQueryParam(r *http.Request, durationName, millisName string) (time.Duration, error) {
	values := r.URL.Query()
	if raw := strings.TrimSpace(values.Get(durationName)); raw != "" {
		duration, err := time.ParseDuration(raw)
		if err != nil || duration < 0 {
			return 0, fmt.Errorf("%s must be a non-negative Go duration", durationName)
		}
		return duration, nil
	}
	if raw := strings.TrimSpace(values.Get(millisName)); raw != "" {
		ms, err := strconv.Atoi(raw)
		if err != nil || ms < 0 {
			return 0, fmt.Errorf("%s must be a non-negative integer", millisName)
		}
		return time.Duration(ms) * time.Millisecond, nil
	}
	return 0, nil
}

func responseBodyAllowed(status int) bool {
	return status != http.StatusNoContent && status != http.StatusNotModified
}

func writeLoadResourceBody(w http.ResponseWriter, size int) {
	for size > 0 {
		chunk := loadResourceChunk
		if size < len(chunk) {
			chunk = chunk[:size]
		}
		if _, err := w.Write(chunk); err != nil {
			return
		}
		size -= len(chunk)
	}
}
