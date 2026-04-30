package integration_test

import (
	"net/http"
	"sync"
	"testing"
)

// TestScenario10_ConcurrentRefresh hammers the same refresh token with
// N parallel goroutines and asserts the CAS guarantee end-to-end:
// exactly one wins (200 with new tokens), the rest fail (400). This is
// the HTTP-layer counterpart to the unit-level TestRefreshTokenRotation
// in testmode/integration_test.go — same invariant but driven through
// the BuildTestApp middleware chain.
//
// Spec: P0 scenario 10.
func TestScenario10_ConcurrentRefresh(t *testing.T) {
	ts := newTestServer(t)

	c := registerClient(t, ts, "scn10", "scn10-secret", "https://app.example.com/cb")
	registerUser(t, ts, "scn10@example.com", "hunter22")

	_, tok, body := passwordGrant(t, ts, c, "scn10@example.com", "hunter22", "read")
	if tok.RefreshToken == "" {
		t.Fatalf("expected refresh_token, body=%s", body)
	}
	originalRT := tok.RefreshToken

	const N = 8
	var wg sync.WaitGroup
	statuses := make([]int, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, _, _ := refresh(t, ts, c, originalRT)
			statuses[i] = s
		}(i)
	}
	wg.Wait()

	winners, losers := 0, 0
	for _, s := range statuses {
		switch s {
		case http.StatusOK:
			winners++
		case http.StatusBadRequest:
			losers++
		default:
			t.Fatalf("unexpected status from concurrent refresh: %d (full: %v)", s, statuses)
		}
	}
	if winners != 1 {
		t.Fatalf("expected exactly 1 winner across %d concurrent refreshes, got %d (statuses: %v)", N, winners, statuses)
	}
	if losers != N-1 {
		t.Fatalf("expected %d losers, got %d (statuses: %v)", N-1, losers, statuses)
	}
}
