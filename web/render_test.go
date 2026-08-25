package web

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRenderTemplates(t *testing.T) {
	tests := []struct {
		name       string
		template   string
		data       map[string]interface{}
		contains   []string
		notContain []string
	}{
		{
			name:     "login error",
			template: "login.html",
			data: map[string]interface{}{
				"error":       "invalid credentials",
				"queryString": "?client_id=demo&amp;scope=read",
			},
			contains: []string{
				`<h1 id="sign-in-heading">Welcome back</h1>`,
				`autocomplete="current-password"`,
				`role="alert"`,
				"invalid credentials",
			},
		},
		{
			name:     "registration",
			template: "register.html",
			data: map[string]interface{}{
				"queryString": "?client_id=demo",
			},
			contains: []string{
				`<h1 id="register-heading">Create an account</h1>`,
				`autocomplete="new-password"`,
				`name="email"`,
				`name="password"`,
			},
		},
		{
			name:     "authorization code",
			template: "authorize.html",
			data: map[string]interface{}{
				"clientID":      "demo-client",
				"clientInitial": "D",
				"queryString":   "?client_id=demo-client",
				"scopes":        []string{"read", "profile"},
				"showLogout":    true,
				"token":         false,
			},
			contains: []string{
				`<h1 id="authorize-heading">Review access</h1>`,
				"demo-client",
				"<code>read</code>",
				"<code>profile</code>",
				`name="allow" value="Allow"`,
				`name="deny" value="Deny"`,
				`class="header-link"`,
			},
			notContain: []string{`name="lifetime"`},
		},
		{
			name:     "implicit token lifetime",
			template: "authorize.html",
			data: map[string]interface{}{
				"clientID":      "demo-client",
				"clientInitial": "D",
				"scopes":        []string{"read"},
				"showLogout":    true,
				"token":         true,
			},
			contains: []string{
				`name="lifetime" value="3600"`,
				`name="lifetime" value="86400"`,
				`name="lifetime" value="604800" checked`,
			},
		},
		{
			name:     "authorization error",
			template: "authorize.html",
			data: map[string]interface{}{
				"error":      "authorization failed",
				"showLogout": true,
			},
			contains: []string{
				`role="alert"`,
				"Authorization couldn't continue.",
				"authorization failed",
			},
			notContain: []string{"{{", "}}div&gt;"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			if err := renderTemplate(recorder, tt.template, tt.data); err != nil {
				t.Fatalf("renderTemplate() error = %v", err)
			}

			if got := recorder.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Errorf("Content-Type = %q", got)
			}
			if got := recorder.Header().Get("X-Frame-Options"); got != "deny" {
				t.Errorf("X-Frame-Options = %q", got)
			}

			body := recorder.Body.String()
			for _, want := range tt.contains {
				if !strings.Contains(body, want) {
					t.Errorf("rendered body does not contain %q", want)
				}
			}
			for _, unwanted := range tt.notContain {
				if strings.Contains(body, unwanted) {
					t.Errorf("rendered body unexpectedly contains %q", unwanted)
				}
			}
			for _, external := range []string{"maxcdn.bootstrapcdn.com", "ajax.googleapis.com", "jquery", "bootstrap"} {
				if strings.Contains(strings.ToLower(body), external) {
					t.Errorf("rendered body contains external dependency %q", external)
				}
			}
		})
	}
}

func TestAuthorizeTemplateEscapesUntrustedValues(t *testing.T) {
	recorder := httptest.NewRecorder()
	err := renderTemplate(recorder, "authorize.html", map[string]interface{}{
		"clientID":      `<script>alert("client")</script>`,
		"clientInitial": "<",
		"scopes":        []string{`read<script>alert("scope")</script>`},
		"showLogout":    true,
	})
	if err != nil {
		t.Fatalf("renderTemplate() error = %v", err)
	}

	body := recorder.Body.String()
	if strings.Contains(body, "<script>") {
		t.Fatal("rendered body contains an unescaped script element")
	}
	for _, escaped := range []string{"&lt;script&gt;", "&lt;"} {
		if !strings.Contains(body, escaped) {
			t.Errorf("rendered body does not contain escaped value %q", escaped)
		}
	}
}

func TestWebCSSFollowsSystemPreferences(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate test source")
	}
	cssPath := filepath.Join(filepath.Dir(sourceFile), "..", "public", "css", "web.css")
	contents, err := os.ReadFile(cssPath)
	if err != nil {
		t.Fatalf("reading web CSS: %v", err)
	}
	css := string(contents)

	for _, want := range []string{
		"color-scheme: light dark",
		"@media (prefers-color-scheme: dark)",
		"@media (prefers-contrast: more)",
		"@media (prefers-reduced-motion: reduce)",
		"@media (forced-colors: active)",
		"@media (max-width: 680px)",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("web.css does not contain %q", want)
		}
	}
}

func TestRenderTemplateRejectsUnknownName(t *testing.T) {
	if err := renderTemplate(httptest.NewRecorder(), "missing.html", nil); err == nil {
		t.Fatal("renderTemplate() returned nil for an unknown template")
	}
}
