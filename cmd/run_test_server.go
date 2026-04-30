package cmd

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/RichardKnop/go-oauth2-server/database"
	"github.com/RichardKnop/go-oauth2-server/log"
	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/services"
	"github.com/RichardKnop/go-oauth2-server/testmode"
	"github.com/RichardKnop/go-oauth2-server/util/migrations"
	"gopkg.in/tylerb/graceful.v1"
)

// RunTestServer boots the server in headless test-provider mode: no remote
// config, embedded SQLite, control-plane routes mounted under /test.
//
// The handler assembly itself lives in testmode.BuildTestApp so the same
// middleware chain is used by integration tests, ensuring the binary and
// the test harness can't drift.
func RunTestServer(dbPath string, port int) error {
	cnf := testmode.NewConfig(dbPath)

	db, err := database.NewDatabase(cnf)
	if err != nil {
		return fmt.Errorf("opening sqlite database at %q: %w", dbPath, err)
	}
	defer db.Close()

	if err := migrations.Bootstrap(db); err != nil {
		return fmt.Errorf("bootstrap migrations: %w", err)
	}
	if err := models.MigrateAll(db); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	if err := testmode.Seed(db); err != nil {
		return fmt.Errorf("seeding default roles/scopes: %w", err)
	}

	if err := services.Init(cnf, db); err != nil {
		return fmt.Errorf("initialising services: %w", err)
	}
	defer services.Close()

	testService := testmode.NewService(cnf, db, services.OauthService)
	handler := testmode.BuildTestApp(
		services.HealthService,
		services.OauthService,
		services.WebService,
		testService,
	)

	addr := fmt.Sprintf(":%d", port)

	// Pre-bind the listener so we can surface a clean error if the port is
	// in use. graceful otherwise log.Fatals from a goroutine.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("test-mode: cannot bind %s: %w (try --test-port=<n>)", addr, err)
	}

	log.INFO.Printf("test-mode: listening on %s (sqlite=%s)", addr, dbPath)

	srv := &graceful.Server{
		Timeout: 5 * time.Second,
		Server:  &http.Server{Addr: addr, Handler: handler},
	}
	if err := srv.Serve(ln); err != nil {
		return fmt.Errorf("test-mode: server stopped: %w", err)
	}
	return nil
}
