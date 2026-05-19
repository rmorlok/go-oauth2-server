package cmd

import (
	"context"
	"net/http"
	"time"

	"github.com/RichardKnop/go-oauth2-server/log"
	"github.com/RichardKnop/go-oauth2-server/services"
	"github.com/RichardKnop/go-oauth2-server/telemetry"
	"github.com/RichardKnop/go-oauth2-server/telemetry/httptelem"
	"github.com/RichardKnop/go-oauth2-server/util/response"
	"github.com/gorilla/mux"
	"github.com/phyber/negroni-gzip/gzip"
	"github.com/urfave/negroni"
	"gopkg.in/tylerb/graceful.v1"
)

// RunServer runs the app
func RunServer(configBackend string) error {
	cnf, db, err := initConfigDB(true, true, configBackend)
	if err != nil {
		return err
	}
	defer db.Close()

	providers, err := telemetry.Init(context.Background(), cnf.Telemetry)
	if err != nil {
		return err
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
	if cnf.Telemetry.Enabled && cnf.Telemetry.Signals.Logs != nil && *cnf.Telemetry.Signals.Logs {
		logOpts.OTelProvider = providers.LoggerProvider
	}
	log.Init(logOpts)

	// start the services
	if err := services.Init(cnf, db); err != nil {
		return err
	}
	defer services.Close()

	// Start a classic negroni app. The URL access logger has moved into
	// the mux chain (below) so each record can pick up the OTel span
	// from r.Context() and inherit trace_id / span_id.
	app := negroni.New()
	app.Use(negroni.NewRecovery())
	app.Use(gzip.Gzip(gzip.DefaultCompression))
	app.Use(negroni.NewStatic(http.Dir("public")))

	// Create a router instance
	router := mux.NewRouter()

	// Telemetry middleware runs first inside the mux chain so the matched
	// route template is available for span naming, metric labels, and
	// downstream log records.
	router.Use(httptelem.Middleware(cnf.Telemetry))
	router.Use(response.URLLoggerMiddleware())

	// Add routes
	services.HealthService.RegisterRoutes(router, "/v1")
	services.OauthService.RegisterRoutes(router, "/v1/oauth")
	services.WebService.RegisterRoutes(router, "/web")

	// /test/resource/{path} is a sample protected resource intended for
	// manual OAuth-flow validation against this server: register a client,
	// get a token, hit it with `Authorization: Bearer <token>`. No script
	// queue, no recorder, no scope policy — those live in --test-mode.
	services.OauthService.RegisterSampleResource(router, "/test/resource")

	// Set the router
	app.UseHandler(router)

	// Run the server on port 8080, gracefully stop on SIGTERM signal
	graceful.Run(":8080", 5*time.Second, app)

	return nil
}
