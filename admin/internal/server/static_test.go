package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUIShellAndRoutes(t *testing.T) {
	s, _ := newTestServer(t)
	for _, p := range []string{"/", "/hosts", "/hosts/abc", "/settings", "/setup"} {
		req := httptest.NewRequest("GET", "https://proxy.test"+p, nil)
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), `<div id="app">`) {
			t.Fatalf("%s: %d %q", p, rr.Code, rr.Body.String()[:min(60, rr.Body.Len())])
		}
		if cc := rr.Header().Get("Cache-Control"); cc != "no-cache" {
			t.Fatalf("%s: Cache-Control %q", p, cc)
		}
		if csp := rr.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Fatalf("%s: CSP %q", p, csp)
		}
	}
	req := httptest.NewRequest("GET", "https://proxy.test/favicon.svg", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Header().Get("Content-Type"), "svg") {
		t.Fatalf("favicon: %d %s", rr.Code, rr.Header().Get("Content-Type"))
	}
	// API paths never fall through to the shell.
	req = httptest.NewRequest("GET", "https://proxy.test/api/v1/nope", nil)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if strings.Contains(rr.Body.String(), `<div id="app">`) {
		t.Fatal("unknown API path served the UI shell")
	}
}
