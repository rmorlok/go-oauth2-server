package testmode

import (
	"net/http"

	"github.com/RichardKnop/go-oauth2-server/health"
	"github.com/RichardKnop/go-oauth2-server/oauth"
	"github.com/RichardKnop/go-oauth2-server/web"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
)

// BuildTestApp assembles the test-mode HTTP handler with the same
// middleware chain and route layout used by the binary's runserver
// --test-mode. Both cmd.RunTestServer and the integration test harness
// build their handlers through this function so the two can't drift.
//
// Middleware order:
//
//	recovery → logger → recorder → script → static → router
//
// gzip is intentionally absent: it would wrap the response writer
// downstream of the script middleware, breaking pass-through actions
// (e.g. scope_override) that need to parse the handler's JSON body
// and breaking drop_connection (gzip's writer doesn't implement
// http.Hijacker). Test mode is a controllable test provider, not a
// perf-sensitive endpoint, so the gzip overhead doesn't earn its
// keep here. Production runserver keeps gzip in cmd/run_server.go.
//
// Routes:
//
//	/v1/...     health
//	/v1/oauth/* oauth (tokens, introspect, revoke, userinfo)
//	/web/*      web (login, register, logout, authorize)
//	/test/*     test-mode control plane (clients, users, scripts, etc.)
func BuildTestApp(
	healthService health.ServiceInterface,
	oauthService oauth.ServiceInterface,
	webService web.ServiceInterface,
	testService *Service,
) http.Handler {
	app := negroni.New()
	app.Use(negroni.NewRecovery())
	app.Use(negroni.NewLogger())
	app.Use(testService.Middleware())
	app.Use(testService.ScriptMiddleware())
	app.Use(negroni.NewStatic(http.Dir("public")))

	router := mux.NewRouter()
	healthService.RegisterRoutes(router, "/v1")
	oauthService.RegisterRoutes(router, "/v1/oauth")
	webService.RegisterRoutes(router, "/web")
	testService.RegisterRoutes(router, "/test")

	app.UseHandler(router)
	return app
}
