package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// setUp runs first-run setup and returns a signed-in client and a key.
func setUp(t *testing.T) (*Server, *client, string) {
	s, tok := newTestServer(t)
	c := &client{t: t, s: s, origin: true}
	c.do("POST", "/api/v1/setup/token", `{"token":"`+tok+`"}`)
	if rr, _ := c.do("POST", "/api/v1/setup/password", `{"password":"a long enough password"}`); rr.Code != 200 {
		t.Fatalf("set password: %d", rr.Code)
	}
	if rr, _ := c.do("PUT", "/api/v1/settings", `{"domain":"apps.test","trustedNetworks":[]}`); rr.Code != 200 {
		t.Fatalf("domain: %d", rr.Code)
	}
	_, out := c.do("POST", "/api/v1/tokens", `{"label":"script"}`)
	key, _ := out["token"].(string)
	if key == "" {
		t.Fatalf("token: %v", out)
	}
	return s, c, key
}

// A connected app's key manages hosts only; the proxy's own settings,
// certificates, backup, password and keys need the account.
func TestKeyScope(t *testing.T) {
	s, _, key := setUp(t)
	api := &client{t: t, s: s, bearer: key}
	allowed := []struct{ method, path string }{
		{"GET", "/api/v1/status"}, {"GET", "/api/v1/hosts"}, {"GET", "/api/v1/hosts/health"},
		{"GET", "/api/v1/hosts/uptime"}, {"GET", "/api/v1/probe?address=127.0.0.1&port=1"},
	}
	for _, a := range allowed {
		if rr, out := api.do(a.method, a.path, ""); rr.Code != 200 {
			t.Errorf("%s %s with a key: %d %v", a.method, a.path, rr.Code, out)
		}
	}
	denied := []struct{ method, path, body string }{
		{"GET", "/api/v1/settings", ""}, {"PUT", "/api/v1/settings", `{"domain":"x.test"}`},
		{"GET", "/api/v1/certificates", ""}, {"GET", "/api/v1/tokens", ""},
		{"POST", "/api/v1/tokens", `{"label":"more"}`}, {"PUT", "/api/v1/password", `{"current":"a","password":"b"}`},
		{"POST", "/api/v1/backup", `{"passphrase":"12345678"}`}, {"GET", "/api/v1/dns-check", ""},
		{"GET", "/api/v1/sources/fjord", ""}, {"GET", "/api/v1/alerts", ""},
		{"PUT", "/api/v1/alerts", `{"kind":"ntfy","url":"https://ntfy.example/t"}`}, {"POST", "/api/v1/alerts/test", `{}`}, {"PUT", "/api/v1/uptime/enabled", `{"enabled":false}`},
	}
	for _, d := range denied {
		if rr, _ := api.do(d.method, d.path, d.body); rr.Code != 403 {
			t.Errorf("%s %s with a key: %d, want 403", d.method, d.path, rr.Code)
		}
	}
	if _, out := api.do("GET", "/api/v1/status", ""); out["product"] != "reverse-proxy" || out["apiVersion"] != float64(1) || out["domain"] != "apps.test" {
		t.Fatalf("status: %v", out)
	}
}

// A request straight over the unix socket (no X-Forwarded-For: it did not
// come through Caddy) is the command line and acts as the account.
func TestLocalSocket(t *testing.T) {
	s, _, _ := setUp(t)
	do := func(method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
		req := httptest.NewRequest(method, "http://admin"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		out := map[string]any{}
		json.Unmarshal(rr.Body.Bytes(), &out)
		return rr, out
	}
	if rr, out := do("POST", "/api/v1/hosts", `{"name":"cli","target":{"address":"1.2.3.4","port":80},"access":"home"}`); rr.Code != 201 {
		t.Fatalf("local add: %d %v", rr.Code, out)
	}
	if rr, out := do("GET", "/api/v1/settings", ""); rr.Code != 200 || out["domain"] != "apps.test" {
		t.Fatalf("local settings: %d %v", rr.Code, out)
	}
	// Removed hosts are listed only when asked for, so a restore can find them.
	_, made := do("GET", "/api/v1/hosts", "")
	id := made["hosts"].([]any)[0].(map[string]any)["id"].(string)
	do("DELETE", "/api/v1/hosts/"+id, "")
	if _, out := do("GET", "/api/v1/hosts", ""); len(out["hosts"].([]any)) != 0 {
		t.Fatalf("removed host still listed: %v", out)
	}
	_, out := do("GET", "/api/v1/hosts?include=removed", "")
	if l := out["hosts"].([]any); len(l) != 1 || l[0].(map[string]any)["deletedAt"] == nil {
		t.Fatalf("removed host not listed with include=removed: %v", out)
	}
	// Through Caddy the same request without a session or key is refused.
	c := &client{t: t, s: s}
	if rr, _ := c.do("GET", "/api/v1/settings", ""); rr.Code != 401 {
		t.Fatalf("network without auth: %d", rr.Code)
	}
}

// Every path and method the OpenAPI document lists is routed, and the
// document itself is served.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	s, c, key := setUp(t)
	rr, _ := c.do("GET", "/api/v1/openapi.json", "")
	if rr.Code != 200 {
		t.Fatalf("openapi.json: %d", rr.Code)
	}
	var doc struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	_, made := c.do("POST", "/api/v1/hosts", `{"name":"doc","target":{"address":"1.2.3.4","port":80},"access":"home"}`)
	id, _ := made["id"].(string)
	api := &client{t: t, s: s, bearer: key}
	// Map order is random: the delete of the host made above has to come
	// after its get and put, or those answer 404 for the right reason.
	type op struct{ path, method string }
	var ops []op
	for path, methods := range doc.Paths {
		for method := range methods {
			if method != "parameters" {
				ops = append(ops, op{path, method})
			}
		}
	}
	sort.Slice(ops, func(i, j int) bool {
		if (ops[i].method == "delete") != (ops[j].method == "delete") {
			return ops[j].method == "delete"
		}
		return ops[i].path+ops[i].method < ops[j].path+ops[j].method
	})
	for _, o := range ops {
		path, method := o.path, o.method
		{
			p := strings.ReplaceAll(path, "{id}", id)
			if strings.Contains(p, "probe") {
				p += "?address=127.0.0.1&port=1"
			}
			body := ""
			if method == "post" || method == "put" {
				body = `{"name":"doc","target":{"address":"1.2.3.4","port":80},"access":"home"}`
			}
			rr, _ := api.do(strings.ToUpper(method), p, body)
			if rr.Code == http.StatusNotFound && !strings.Contains(path, "restore") && !strings.Contains(path, "root.crt") && !strings.HasSuffix(path, "/icon") || rr.Code == http.StatusMethodNotAllowed {
				t.Errorf("%s %s is in openapi.json but answers %d", method, path, rr.Code)
			}
		}
	}
}
