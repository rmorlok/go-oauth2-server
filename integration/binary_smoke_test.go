package integration_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestBinarySmoke proves the runserver --test-mode CLI path works
// end-to-end: builds the binary, starts it on a free port, polls
// /test/health until 200, then tears down. The in-process harness used
// by the rest of this suite goes through testmode.BuildTestApp directly
// — this test is the only one that exercises cmd.RunTestServer + its
// graceful.Server wrapper + the actual `runserver --test-mode` CLI
// argument plumbing.
//
// Slow test (~5–15s for the build) so it lives at the package boundary
// and runs once per `go test ./integration/...` invocation.
func TestBinarySmoke(t *testing.T) {
	bin := buildBinary(t)
	port := freePort(t)

	cmd := exec.Command(bin, "runserver", "--test-mode", "--test-port", strconv.Itoa(port))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	if !waitForHealth(t, port, 20*time.Second) {
		t.Fatalf("server didn't become healthy in time. stdout/stderr:\n%s", out.String())
	}
}

// buildBinary compiles the project's main package into a temp file and
// returns the path. Reuses the test's TempDir so cleanup is automatic.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "go-oauth2-server-binary-smoke")
	cmd := exec.Command("go", "build", "-o", bin, "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// freePort asks the OS for a free TCP port, closes the listener, and
// returns the port number. There is a small race window between close
// and the binary calling net.Listen, but for a single test in a single
// process it is reliable.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// waitForHealth polls GET /test/health until 200 or the deadline.
func waitForHealth(t *testing.T, port int, timeout time.Duration) bool {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d/test/health", port)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}
