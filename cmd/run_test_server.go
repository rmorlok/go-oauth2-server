package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/RichardKnop/go-oauth2-server/database"
	"github.com/RichardKnop/go-oauth2-server/log"
	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/services"
	"github.com/RichardKnop/go-oauth2-server/telemetry"
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
func RunTestServer(dbPath string, port int, opts ...testmode.ConfigOptions) error {
	var configOpts testmode.ConfigOptions
	if len(opts) > 0 {
		configOpts = opts[0]
	}
	cnf := testmode.NewConfigWithOptions(dbPath, configOpts)

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

	providers, err := telemetry.Init(context.Background(), cnf.Telemetry)
	if err != nil {
		return fmt.Errorf("initialising telemetry: %w", err)
	}
	defer func() {
		if err := providers.Shutdown(context.Background()); err != nil {
			log.Error("telemetry shutdown failed", "err", err)
		}
	}()

	logOpts := log.Options{
		Level:         cnf.Logging.Level,
		Format:        log.Format(cnf.Logging.Format),
		IsDevelopment: cnf.IsDevelopment,
	}
	if cnf.Telemetry.Enabled && (cnf.Telemetry.Signals.Logs == nil || *cnf.Telemetry.Signals.Logs) {
		logOpts.OTelProvider = providers.LoggerProvider
	}
	log.Init(logOpts)

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
		cnf.Telemetry,
	)

	addr := fmt.Sprintf(":%d", port)

	// Pre-bind the listener so we can surface a clean error if the port is
	// in use. graceful otherwise log.Fatals from a goroutine.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("test-mode: cannot bind %s: %w (try --test-port=<n>)", addr, err)
	}

	log.Info("test-mode: listening", "addr", addr, "sqlite", dbPath)

	srv := &graceful.Server{
		Timeout: 5 * time.Second,
		Server:  &http.Server{Addr: addr, Handler: handler},
	}
	if err := srv.Serve(ln); err != nil {
		return fmt.Errorf("test-mode: server stopped: %w", err)
	}
	return nil
}
