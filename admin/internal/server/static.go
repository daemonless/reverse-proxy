package server

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/daemonless/reverse-proxy/admin/ui"
)

// uiHandler serves the embedded Svelte app. Hashed assets are immutable;
// everything that is not a file is the app shell, so the client router owns
// the URL space outside /api.
func uiHandler() http.Handler {
	dist, err := fs.Sub(ui.Files, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The UI is first-party only. The trust check fetches the proxy's
		// own name over both schemes, which connect-src must allow.
		csp := "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self' https: http:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Never HSTS on the admin: it is the way back in when a certificate
		// changes, and HSTS would turn that warning into a wall. max-age=0
		// also clears the year earlier versions sent.
		w.Header().Set("Strict-Transport-Security", "max-age=0")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/internal/") {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such endpoint"})
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if f, err := dist.Open(p); err == nil {
			f.Close()
			if strings.HasPrefix(p, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			files.ServeHTTP(w, r)
			return
		}
		// A client-side route: hand over the shell.
		w.Header().Set("Cache-Control", "no-cache")
		r.URL.Path = "/"
		files.ServeHTTP(w, r)
	})
}
