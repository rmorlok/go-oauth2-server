package web

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/RichardKnop/go-oauth2-server/log"
	"github.com/oxtoacart/bpool"
)

var (
	templates     map[string]*template.Template
	bufpool       *bpool.BufferPool
	templatesOnce sync.Once
	templatesErr  error
)

// renderTemplate is a wrapper around template.ExecuteTemplate.
// It writes into a bytes.Buffer before writing to the http.ResponseWriter to catch
// any errors resulting from populating the template.
func renderTemplate(w http.ResponseWriter, name string, data map[string]interface{}) error {
	if err := loadTemplates(); err != nil {
		return err
	}

	// Ensure the template exists in the map.
	tmpl, ok := templates[name]
	if !ok {
		return fmt.Errorf("template %q does not exist", name)
	}

	// Create a buffer to temporarily write to and check if any errors were encountered.
	buf := bufpool.Get()
	defer bufpool.Put(buf)

	err := tmpl.ExecuteTemplate(buf, "base", data)
	if err != nil {
		return err
	}

	// The X-Frame-Options HTTP response header can be used to indicate whether
	// or not a browser should be allowed to render a page in a <frame>,
	// <iframe> or <object> . Sites can use this to avoid clickjacking attacks,
	// by ensuring that their content is not embedded into other sites.
	w.Header().Set("X-Frame-Options", "deny")
	// Set the header and write the buffer to the http.ResponseWriter
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err = buf.WriteTo(w)
	return err
}

// renderPage logs template failures with request context and returns a safe
// HTTP error rather than silently sending an incomplete page.
func renderPage(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
	if err := renderTemplate(w, name, data); err != nil {
		log.FromContext(r.Context()).Error(
			"rendering web template failed",
			"template", name,
			"err", err,
		)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func loadTemplates() error {
	templatesOnce.Do(func() {
		templates = make(map[string]*template.Template)
		bufpool = bpool.NewBufferPool(64)

		webDir, err := templateDirectory()
		if err != nil {
			templatesErr = err
			return
		}
		layout := filepath.Join(webDir, "layouts", "base.html")

		includes := []string{"register.html", "login.html", "authorize.html"}
		for _, includeName := range includes {
			include := filepath.Join(webDir, "includes", includeName)
			tmpl, err := template.ParseFiles(include, layout)
			if err != nil {
				templatesErr = fmt.Errorf("parsing template %q: %w", includeName, err)
				return
			}
			templates[includeName] = tmpl
		}
	})

	return templatesErr
}

// templateDirectory resolves the supported execution contexts: the server
// runs from the repository/application root, package tests run from the web
// directory, and cross-package integration tests run one directory below it.
func templateDirectory() (string, error) {
	for _, candidate := range []string{"web", ".", filepath.Join("..", "web")} {
		layout := filepath.Join(candidate, "layouts", "base.html")
		if info, err := os.Stat(layout); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("locating web templates")
}
