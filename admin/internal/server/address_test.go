package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The admin learns where it is reached from the account's setup and
// sign-ins, so the commands can print a link that works.
func TestAdminAddressFollowsTheAccount(t *testing.T) {
	s, c, _ := setUp(t) // setUp signs in at proxy.test
	if _, out := c.do("GET", "/api/v1/status", ""); out["adminUrl"] != "https://proxy.test" {
		t.Fatalf("after setup: %v", out["adminUrl"])
	}
	// The public view says nothing about it.
	if _, out := (&client{t: t, s: s}).do("GET", "/api/v1/status", ""); out["adminUrl"] != nil {
		t.Fatalf("public status leaks the address: %v", out)
	}
	login := func(host string) int {
		req := httptest.NewRequest("POST", "https://proxy.test/api/v1/login", strings.NewReader(`{"password":"a long enough password"}`))
		req.Host = host
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "192.168.1.50")
		req.Header.Set("Origin", "https://"+host)
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		return rr.Code
	}
	if code := login("192.168.1.5:8444"); code != 200 {
		t.Fatalf("login: %d", code)
	}
	if got := s.mgr.State().Settings.AdminAddress; got != "192.168.1.5:8444" {
		t.Fatalf("after login: %q", got)
	}
	// A header no browser sends is not kept.
	for _, bad := range []string{"evil host", "a;b", "proxy.test:notaport", strings.Repeat("a", 260)} {
		login(bad)
		if got := s.mgr.State().Settings.AdminAddress; got != "192.168.1.5:8444" {
			t.Fatalf("%q was kept: %q", bad, got)
		}
	}
	// reset-password gets the same address to print.
	req := httptest.NewRequest("POST", "http://admin/internal/reset", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	var res map[string]any
	json.Unmarshal(rr.Body.Bytes(), &res)
	if rr.Code != 200 || res["adminUrl"] != "https://192.168.1.5:8444" {
		t.Fatalf("reset: %d %s", rr.Code, rr.Body.String())
	}
	// The operator's RP_ADMIN_URL wins over anything learned.
	t.Setenv("RP_ADMIN_URL", "https://proxy.home.example:8443/")
	if got := AdminURL(s.mgr.State()); got != "https://proxy.home.example:8443" {
		t.Fatalf("RP_ADMIN_URL: %q", got)
	}
}

func TestBrowserAddress(t *testing.T) {
	cases := map[string]string{
		"proxy.test":       "proxy.test",
		"Proxy.Test:8443":  "proxy.test:8443",
		"192.168.1.5:8444": "192.168.1.5:8444",
		"[fd00::1]:8443":   "[fd00::1]:8443",
		"admin":            "admin",
		"evil host":        "",
		"a_b.test":         "",
		"proxy.test:99999": "",
		"proxy.test:":      "",
		"":                 "",
		"-leading.test":    "-leading.test", // a label the resolver would refuse, but harmless in print
	}
	for host, want := range cases {
		req := httptest.NewRequest("GET", "https://x/", nil)
		req.Host = host
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		if got := browserAddress(req); got != want {
			t.Errorf("%q: got %q, want %q", host, got, want)
		}
	}
	// Straight over the socket there is no browser.
	req := httptest.NewRequest("GET", "http://admin/", nil)
	req.Host = "admin"
	if got := browserAddress(req); got != "" {
		t.Errorf("socket request kept: %q", got)
	}
	_ = http.StatusOK
}
