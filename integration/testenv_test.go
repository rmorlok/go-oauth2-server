// Package integration_test holds end-to-end scenario tests that exercise
// the test-mode server through real HTTP. Test names map 1:1 to the
// scenario numbers in AuthProxy's integration test requirements doc; see
// issue #26 for the spec mapping.
package integration_test

import (
	"net/http/httptest"
	"testing"

	"github.com/RichardKnop/go-oauth2-server/database"
	"github.com/RichardKnop/go-oauth2-server/health"
	"github.com/RichardKnop/go-oauth2-server/models"
	"github.com/RichardKnop/go-oauth2-server/oauth"
	"github.com/RichardKnop/go-oauth2-server/session"
	"github.com/RichardKnop/go-oauth2-server/testmode"
	"github.com/RichardKnop/go-oauth2-server/util/migrations"
	"github.com/RichardKnop/go-oauth2-server/web"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
)

// testServer is the handle a scenario test gets from newTestServer.
// Boots an in-process --test-mode server backed by an in-memory SQLite
// database. The Recorder, Queue, and DB are exposed so scenarios can
// inspect / mutate state without going through HTTP when they need to.
type testServer struct {
	URL          string
	Recorder     *testmode.Recorder
	Queue        *testmode.ScriptQueue
	DB           *gorm.DB
	OauthService *oauth.Service
	TestService  *testmode.Service

	server *httptest.Server
}

// newTestServer brings up an in-process test-mode server using
// testmode.BuildTestApp — same middleware chain and route layout as the
// runserver --test-mode binary. Each call gets its own fresh in-memory
// database.
func newTestServer(t *testing.T) *testServer {
	t.Helper()

	cnf := testmode.NewConfig(":memory:")

	db, err := database.NewDatabase(cnf)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	if err := migrations.Bootstrap(db); err != nil {
		t.Fatalf("bootstrap migrations: %v", err)
	}
	if err := models.MigrateAll(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := testmode.Seed(db); err != nil {
		t.Fatalf("seed: %v", err)
	}

	healthService := health.NewService(db)
	oauthService := oauth.NewService(cnf, db)
	sessionService := session.NewService(cnf, sessions.NewCookieStore([]byte(cnf.Session.Secret)))
	webService := web.NewService(cnf, oauthService, sessionService)
	testService := testmode.NewService(cnf, db, oauthService)

	handler := testmode.BuildTestApp(healthService, oauthService, webService, testService)
	httpSrv := httptest.NewServer(handler)

	ts := &testServer{
		URL:          httpSrv.URL,
		Recorder:     testService.Recorder(),
		Queue:        testService.Queue(),
		DB:           db,
		OauthService: oauthService,
		TestService:  testService,
		server:       httpSrv,
	}

	t.Cleanup(func() {
		httpSrv.Close()
		db.Close()
	})

	return ts
}
