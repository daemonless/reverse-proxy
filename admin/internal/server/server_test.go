package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/app"
	"github.com/daemonless/reverse-proxy/admin/internal/certs"
	"github.com/daemonless/reverse-proxy/admin/internal/dns"
	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

type okLoader struct{}

func (okLoader) Load(any) error { return nil }

type upRunner struct{}

func (upRunner) Running() bool { return true }

func newTestServer(t *testing.T) (*Server, string) {
	// Same layout as the container: state.json beside a secrets/ directory.
	dir := t.TempDir()
	mgr, err := app.New(state.NewStore(filepath.Join(dir, "state.json")), okLoader{}, func(*state.State) any { return map[string]any{} })
	if err != nil {
		t.Fatal(err)
	}
	tok := "K7RT-9XPM-2WQF-HJ4N"
	return New("test", upRunner{}, mgr, tok, filepath.Join(dir, "secrets")), tok
}

type client struct {
	t       *testing.T
	s       *Server
	cookies []*http.Cookie
	bearer  string
	origin  bool
}

func (c *client) do(method, path, body string, hdr ...string) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest(method, "https://proxy.test"+path, strings.NewReader(body))
	req.Host = "proxy.test"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "192.168.1.50") // as Caddy would
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	if c.origin {
		req.Header.Set("Origin", "https://proxy.test")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rr := httptest.NewRecorder()
	c.s.Handler().ServeHTTP(rr, req)
	for _, ck := range rr.Result().Cookies() {
		kept := c.cookies[:0]
		for _, old := range c.cookies {
			if old.Name != ck.Name {
				kept = append(kept, old)
			}
		}
		c.cookies = kept
		if ck.MaxAge >= 0 && ck.Value != "" {
			c.cookies = append(c.cookies, ck)
		}
	}
	var out map[string]any
	json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

func TestFirstRunThenLogin(t *testing.T) {
	s, tok := newTestServer(t)
	c := &client{t: t, s: s, origin: true}

	if rr, _ := c.do("GET", "/api/v1/hosts", ""); rr.Code != 401 {
		t.Fatalf("hosts without auth: %d", rr.Code)
	}
	if _, out := c.do("GET", "/api/v1/session", ""); out["setupRequired"] != true {
		t.Fatalf("session: %v", out)
	}
	if rr, _ := c.do("POST", "/api/v1/login", `{"password":"anything at all"}`); rr.Code != 409 {
		t.Fatalf("login before setup: %d", rr.Code)
	}
	if rr, _ := c.do("POST", "/api/v1/setup/password", `{"password":"a long enough password"}`); rr.Code != 401 {
		t.Fatalf("password without token: %d", rr.Code)
	}
	if rr, _ := c.do("POST", "/api/v1/setup/token", `{"token":"WRONG-WRONG-WRONG-WRON"}`); rr.Code != 400 {
		t.Fatalf("wrong token: %d", rr.Code)
	}
	// Typed with spaces and lower case, as a person would.
	if rr, out := c.do("POST", "/api/v1/setup/token", `{"token":"`+strings.ToLower(strings.ReplaceAll(tok, "-", " "))+`"}`); rr.Code != 200 {
		t.Fatalf("right token: %d %v", rr.Code, out)
	}
	if rr, _ := c.do("POST", "/api/v1/setup/password", `{"password":""}`); rr.Code != 400 {
		t.Fatalf("weak password: %d", rr.Code)
	}
	if rr, out := c.do("POST", "/api/v1/setup/password", `{"password":"a long enough password"}`); rr.Code != 200 {
		t.Fatalf("set password: %d %v", rr.Code, out)
	}
	if rr, _ := c.do("GET", "/api/v1/hosts", ""); rr.Code != 200 {
		t.Fatalf("hosts after setup: %d", rr.Code)
	}
	if _, out := c.do("GET", "/api/v1/status", ""); out["domain"] == nil {
		t.Fatalf("status for admin lacks details: %v", out)
	}
	if rr, _ := c.do("POST", "/api/v1/setup/token", `{"token":"`+tok+`"}`); rr.Code != 409 {
		t.Fatalf("setup token after setup: %d", rr.Code)
	}

	// Sign out, sign back in.
	c.do("POST", "/api/v1/logout", "")
	if rr, _ := c.do("GET", "/api/v1/hosts", ""); rr.Code != 401 {
		t.Fatalf("hosts after logout: %d", rr.Code)
	}
	if rr, _ := c.do("POST", "/api/v1/login", `{"password":"nope nope nope"}`); rr.Code != 401 {
		t.Fatalf("bad login: %d", rr.Code)
	}
	if rr, _ := c.do("POST", "/api/v1/login", `{"password":"a long enough password"}`); rr.Code != 200 {
		t.Fatalf("good login: %d", rr.Code)
	}
	if rr, _ := c.do("GET", "/api/v1/hosts", ""); rr.Code != 200 {
		t.Fatalf("hosts after login: %d", rr.Code)
	}

	// A cookie session must come from our own page for writes.
	c.origin = false
	if rr, _ := c.do("PUT", "/api/v1/settings", `{"domain":"x.lan"}`); rr.Code != 403 {
		t.Fatalf("cross-site write: %d", rr.Code)
	}
	if rr, _ := c.do("PUT", "/api/v1/settings", `{"domain":"x.lan"}`, "Origin", "https://evil.example"); rr.Code != 403 {
		t.Fatalf("foreign origin write: %d", rr.Code)
	}
	if rr, _ := c.do("PUT", "/api/v1/settings", `{"domain":"x.lan"}`, "Sec-Fetch-Site", "same-origin"); rr.Code != 200 {
		t.Fatalf("same-origin write: %d", rr.Code)
	}
	if rr, _ := c.do("GET", "/api/v1/settings", ""); rr.Code != 200 {
		t.Fatalf("read without origin: %d", rr.Code)
	}
	c.origin = true

	// Connected app tokens.
	_, out := c.do("POST", "/api/v1/tokens", `{"label":"fjord"}`)
	bearer, _ := out["token"].(string)
	if !strings.HasPrefix(bearer, "rp_") {
		t.Fatalf("token: %v", out)
	}
	api := &client{t: t, s: s, bearer: bearer}
	if rr, _ := api.do("POST", "/api/v1/hosts", `{"name":"a","target":{"address":"1.2.3.4","port":80}}`); rr.Code != 201 {
		t.Fatalf("bearer write (no origin needed): %d", rr.Code)
	}
	bad := &client{t: t, s: s, bearer: "rp_" + out["id"].(string) + "_wrongsecret"}
	if rr, _ := bad.do("GET", "/api/v1/hosts", ""); rr.Code != 401 {
		t.Fatalf("bad bearer: %d", rr.Code)
	}
	if rr, _ := c.do("DELETE", "/api/v1/tokens/"+out["id"].(string), ""); rr.Code != 200 {
		t.Fatalf("delete token: %d", rr.Code)
	}
	if rr, _ := api.do("GET", "/api/v1/hosts", ""); rr.Code != 401 {
		t.Fatalf("deleted bearer still works: %d", rr.Code)
	}

	// Password change signs everyone out except the changer.
	other := &client{t: t, s: s, origin: true}
	other.do("POST", "/api/v1/login", `{"password":"a long enough password"}`)
	if rr, _ := c.do("PUT", "/api/v1/password", `{"current":"wrong wrong wrong","new":"another long password"}`); rr.Code != 400 {
		t.Fatalf("change with wrong current: %d", rr.Code)
	}
	if rr, _ := c.do("PUT", "/api/v1/password", `{"current":"a long enough password","new":"another long password"}`); rr.Code != 200 {
		t.Fatalf("change password: %d", rr.Code)
	}
	if rr, _ := other.do("GET", "/api/v1/hosts", ""); rr.Code != 401 {
		t.Fatalf("other session survived password change: %d", rr.Code)
	}
	if rr, _ := c.do("GET", "/api/v1/hosts", ""); rr.Code != 200 {
		t.Fatalf("changer lost session: %d", rr.Code)
	}

	// Reset is socket-only: a request Caddy forwarded is a 404; a direct
	// one clears the password and yields a new token.
	if rr, _ := c.do("POST", "/internal/reset", ""); rr.Code != 404 {
		t.Fatalf("reset via caddy: %d", rr.Code)
	}
	req := httptest.NewRequest("POST", "http://admin/internal/reset", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	var res map[string]any
	json.Unmarshal(rr.Body.Bytes(), &res)
	if rr.Code != 200 || len(res["setupToken"].(string)) != 19 {
		t.Fatalf("direct reset: %d %s", rr.Code, rr.Body.String())
	}
	if _, out := c.do("GET", "/api/v1/session", ""); out["setupRequired"] != true || out["authenticated"] != false {
		t.Fatalf("after reset: %v", out)
	}
}

func TestQRIsOnlyForTheTrustPage(t *testing.T) {
	s, _ := newTestServer(t)
	for u, want := range map[string]int{
		"http://192.168.1.5/trust":         200,
		"https://proxy.x.lan/trust":        200,
		"http://192.168.1.5/trust?x=1":     400,
		"http://evil.example/anything":     400,
		"javascript:alert(1)":              400,
		"http://user:pw@192.168.1.5/trust": 400,
	} {
		req := httptest.NewRequest("GET", "https://proxy.test/trust/qr.png?u="+url.QueryEscape(u), nil)
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != want {
			t.Errorf("%s: %d, want %d", u, rr.Code, want)
		}
		if want == 200 && rr.Header().Get("Content-Type") != "image/png" {
			t.Errorf("%s: content type %s", u, rr.Header().Get("Content-Type"))
		}
	}
}

func TestBackupAndRestore(t *testing.T) {
	a, tok := newTestServer(t)
	c := &client{t: t, s: a, origin: true}
	c.do("POST", "/api/v1/setup/token", `{"token":"`+tok+`"}`)
	c.do("POST", "/api/v1/setup/password", `{"password":"a long enough password"}`)
	c.do("PUT", "/api/v1/settings", `{"domain":"x.lan"}`)
	c.do("POST", "/api/v1/hosts", `{"name":"radarr","target":{"address":"1.2.3.4","port":80}}`)
	if rr, _ := c.do("POST", "/api/v1/backup", `{"passphrase":"short"}`); rr.Code != 400 {
		t.Fatalf("short passphrase: %d", rr.Code)
	}
	rr, _ := c.do("POST", "/api/v1/backup", `{"passphrase":"backup passphrase"}`)
	if rr.Code != 200 || !strings.Contains(rr.Header().Get("Content-Disposition"), "reverse-proxy-x-lan-") {
		t.Fatalf("backup: %d %s", rr.Code, rr.Header().Get("Content-Disposition"))
	}
	blob := rr.Body.Bytes()

	// A fresh server, before setup: restore is open.
	b, _ := newTestServer(t)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField("passphrase", "backup passphrase")
	fw, _ := mw.CreateFormFile("file", "x.rpbk")
	fw.Write(blob)
	mw.Close()
	req := httptest.NewRequest("POST", "https://proxy.test/api/v1/restore", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("restore: %d %s", rec.Code, rec.Body.String())
	}
	if _, out := (&client{t: t, s: b}).do("GET", "/api/v1/session", ""); out["setupRequired"] != false {
		t.Fatalf("after restore: %v", out)
	}
	c2 := &client{t: t, s: b, origin: true}
	if rr, _ := c2.do("POST", "/api/v1/login", `{"password":"a long enough password"}`); rr.Code != 200 {
		t.Fatalf("login with restored password: %d", rr.Code)
	}
	if _, out := c2.do("GET", "/api/v1/hosts", ""); len(out["hosts"].([]any)) != 1 {
		t.Fatalf("hosts after restore: %v", out)
	}
	// Once set up, restore needs a session.
	req = httptest.NewRequest("POST", "https://proxy.test/api/v1/restore", strings.NewReader(""))
	rec = httptest.NewRecorder()
	b.Handler().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("restore after setup without session: %d", rec.Code)
	}
}

func TestLockout(t *testing.T) {
	s, _ := newTestServer(t)
	c := &client{t: t, s: s, origin: true}
	var code int
	for i := 0; i < 6; i++ {
		rr, _ := c.do("POST", "/api/v1/setup/token", `{"token":"AAAA-AAAA-AAAA-AAAA"}`)
		code = rr.Code
	}
	if code != 429 {
		t.Fatalf("after repeated failures: %d", code)
	}
}

func TestCertificatesEndpoints(t *testing.T) {
	s, tok := newTestServer(t)
	c := &client{t: t, s: s, origin: true}
	c.do("POST", "/api/v1/setup/token", `{"token":"`+tok+`"}`)
	c.do("POST", "/api/v1/setup/password", `{"password":"correct horse battery"}`)

	// Private ending: nothing to set up.
	c.do("PUT", "/api/v1/settings", `{"domain":"apps.lan","trustedNetworks":[]}`)
	if rr, _ := c.do("PUT", "/api/v1/certificates", `{"provider":"cloudflare","fields":{"api_token":"t"}}`); rr.Code != 400 {
		t.Fatalf("private ending accepted a provider: %d", rr.Code)
	}
	if _, out := c.do("GET", "/api/v1/trust", ""); out["needed"] != true {
		t.Fatalf("trust needed on a private ending: %v", out)
	}

	c.do("PUT", "/api/v1/settings", `{"domain":"home.example.com","trustedNetworks":[]}`)
	if _, out := c.do("GET", "/api/v1/certificates", ""); out["status"].(map[string]any)["state"] != "manual" || out["provider"] != nil {
		t.Fatalf("before: %v", out)
	}
	if rr, out := c.do("PUT", "/api/v1/certificates", `{"provider":"cloudflare","fields":{"api_token":"  "}}`); rr.Code != 400 || out["field"] != "api_token" {
		t.Fatalf("empty token: %d %v", rr.Code, out)
	}
	rr, out := c.do("PUT", "/api/v1/certificates", `{"provider":"cloudflare","fields":{"api_token":" s3cr3t-xyz "}}`)
	if rr.Code != 200 || out["provider"] != "cloudflare" || out["status"].(map[string]any)["state"] != "trial" {
		t.Fatalf("put: %d %v", rr.Code, out)
	}
	if _, out := c.do("GET", "/api/v1/trust", ""); out["needed"] != false {
		t.Fatalf("trust still needed: %v", out)
	}
	if _, out := c.do("GET", "/api/v1/status", ""); out["certificates"] != "trial" {
		t.Fatalf("status: %v", out)
	}
	saved, err := dns.Load(s.secrets)
	if err != nil || saved.Fields["api_token"] != "s3cr3t-xyz" {
		t.Fatalf("secrets: %v %+v", err, saved)
	}
	if st := s.mgr.State(); st.Settings.Certificates == nil || st.Settings.Certificates.Stage != state.StageTrial {
		t.Fatalf("state: %+v", st.Settings.Certificates)
	}
	// The credentials never come back out.
	if _, out := c.do("GET", "/api/v1/certificates", ""); strings.Contains(fmt.Sprint(out), "s3cr3t") {
		t.Fatalf("token leaked: %v", out)
	}

	if rr, out := c.do("DELETE", "/api/v1/certificates", ""); rr.Code != 200 || out["provider"] != nil {
		t.Fatalf("delete: %d %v", rr.Code, out)
	}
	if _, err := dns.Load(s.secrets); err == nil {
		t.Fatal("secrets kept after delete")
	}
	if s.mgr.State().Settings.Certificates != nil {
		t.Fatal("state kept after delete")
	}
}

type rejectLoader struct{ reject bool }

func (l *rejectLoader) Load(any) error {
	if l.reject {
		return errors.New("400 Bad Request: provision dns.providers.cloudflare: API token 'bad' appears invalid")
	}
	return nil
}

func TestCertificatesRejectedByCaddyIsPlainAndRolledBack(t *testing.T) {
	dir := t.TempDir()
	loader := &rejectLoader{}
	mgr, err := app.New(state.NewStore(filepath.Join(dir, "state.json")), loader, func(*state.State) any { return map[string]any{} })
	if err != nil {
		t.Fatal(err)
	}
	tok := "K7RT-9XPM-2WQF-HJ4N"
	s := New("test", upRunner{}, mgr, tok, filepath.Join(dir, "secrets"))
	c := &client{t: t, s: s, origin: true}
	c.do("POST", "/api/v1/setup/token", `{"token":"`+tok+`"}`)
	c.do("POST", "/api/v1/setup/password", `{"password":"correct horse battery"}`)
	c.do("PUT", "/api/v1/settings", `{"domain":"home.example.com","trustedNetworks":[]}`)
	loader.reject = true
	rr, out := c.do("PUT", "/api/v1/certificates", `{"provider":"cloudflare","fields":{"api_token":"bad"}}`)
	if rr.Code != 400 || !strings.Contains(fmt.Sprint(out["error"]), "rejected by Cloudflare") || out["detail"] == nil {
		t.Fatalf("got %d %v", rr.Code, out)
	}
	if _, err := dns.Load(s.secrets); err == nil {
		t.Fatal("secrets left behind after Caddy refused")
	}
	if s.mgr.State().Settings.Certificates != nil {
		t.Fatal("state changed although Caddy refused")
	}
}

// The daily check: a token that stopped working shows while the
// certificate still does, and a new token clears it.
func TestTokenCheckWarnsEarly(t *testing.T) {
	s, tok := newTestServer(t)
	c := &client{t: t, s: s, origin: true}
	c.do("POST", "/api/v1/setup/token", `{"token":"`+tok+`"}`)
	c.do("POST", "/api/v1/setup/password", `{"password":"correct horse battery"}`)
	c.do("PUT", "/api/v1/settings", `{"domain":"home.example.com","trustedNetworks":[]}`)
	c.do("PUT", "/api/v1/certificates", `{"provider":"cloudflare","fields":{"api_token":"good"}}`)
	s.mgr.Apply(func(st *state.State) error { st.Settings.Certificates.Stage = state.StageLive; return nil })
	s.Observe = func(context.Context, string) certs.Observation {
		return certs.Observation{Issuer: certs.IssuerLetsEncrypt, NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	}
	revoked := false
	asked := 0
	s.CheckProvider = func(_ context.Context, cfg *dns.Config, domain string) error {
		asked++
		if !revoked {
			return nil
		}
		return &dns.Problem{Kind: dns.KindRejected, FieldError: &state.FieldError{Field: "api_token", Msg: "Cloudflare doesn't accept this token."}}
	}
	status := func() map[string]any {
		_, out := c.do("GET", "/api/v1/certificates", "")
		return out["status"].(map[string]any)
	}

	s.checkToken(context.Background())
	if st := status(); st["state"] != "ok" || st["message"] != nil {
		t.Fatalf("token fine: %v", st)
	}
	revoked = true
	s.checkToken(context.Background())
	if st := status(); st["state"] != "ok" || st["fix"] != "token" || !strings.Contains(fmt.Sprint(st["message"]), "stopped accepting your token") {
		t.Fatalf("revoked: %v", st)
	}
	before := asked
	status()
	if asked != before {
		t.Fatal("reading the status asked the provider")
	}
	s.CheckProvider = func(context.Context, *dns.Config, string) error { return nil }
	c.do("PUT", "/api/v1/certificates", `{"provider":"cloudflare","fields":{"api_token":"new"}}`)
	if s.tokenBad != nil {
		t.Fatal("a new token kept the old warning")
	}
}

// Short links: "go" until changed, "" is off, one word only, and saving the
// ending or networks (which do not send it) keeps what was chosen.
func TestShortLinksSetting(t *testing.T) {
	s, tok := newTestServer(t)
	c := &client{t: t, s: s, origin: true}
	c.do("POST", "/api/v1/setup/token", `{"token":"`+tok+`"}`)
	c.do("POST", "/api/v1/setup/password", `{"password":"correct horse battery"}`)
	if _, out := c.do("PUT", "/api/v1/settings", `{"domain":"apps.lan","trustedNetworks":[]}`); out["shortLinks"] != "go" {
		t.Fatalf("default: %v", out)
	}
	if rr, out := c.do("PUT", "/api/v1/settings", `{"domain":"apps.lan","trustedNetworks":[],"shortLinks":"go links"}`); rr.Code != 400 || out["field"] != "shortLinks" {
		t.Fatalf("two words: %d %v", rr.Code, out)
	}
	if _, out := c.do("PUT", "/api/v1/settings", `{"domain":"apps.lan","trustedNetworks":[],"shortLinks":" Home "}`); out["shortLinks"] != "home" {
		t.Fatalf("changed: %v", out)
	}
	if _, out := c.do("PUT", "/api/v1/settings", `{"domain":"apps.lan","trustedNetworks":["10.8.0.0/24"]}`); out["shortLinks"] != "home" {
		t.Fatalf("kept: %v", out)
	}
	if _, out := c.do("PUT", "/api/v1/settings", `{"domain":"apps.lan","trustedNetworks":[],"shortLinks":""}`); out["shortLinks"] != "" {
		t.Fatalf("off: %v", out)
	}
	if _, out := c.do("GET", "/api/v1/settings", ""); out["shortLinks"] != "" {
		t.Fatalf("off after reload: %v", out)
	}
}

func TestLocalDomainSkipsTheEngines(t *testing.T) {
	old := resolvConf
	t.Cleanup(func() { resolvConf = old })
	for content, want := range map[string]string{
		"search dns.podman lan\nnameserver 10.88.0.1\n": "lan",
		"domain Home.\n": "home",
		"search svc.cluster.local cluster.local\n": "",
		"nameserver 1.1.1.1\n":                     "",
	} {
		resolvConf = filepath.Join(t.TempDir(), "resolv.conf")
		os.WriteFile(resolvConf, []byte(content), 0o644)
		if got := localDomain(); got != want {
			t.Errorf("%q: %q, want %q", content, got, want)
		}
	}
}

// Suggested endings come from the network's search domains, never the
// container engine's own (apps.dns.podman was offered, 2026-10-27).
func TestSuggestDomainSkipsTheEngines(t *testing.T) {
	old := resolvConf
	t.Cleanup(func() { resolvConf = old })
	resolvConf = filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(resolvConf, []byte("search dns.podman lan\nnameserver 10.88.0.1\n"), 0o644)
	s, tok := newTestServer(t)
	c := &client{t: t, s: s, origin: true}
	c.do("POST", "/api/v1/setup/token", `{"token":"`+tok+`"}`)
	c.do("POST", "/api/v1/setup/password", `{"password":"correct horse battery"}`)
	_, out := c.do("GET", "/api/v1/suggest-domain", "")
	got := fmt.Sprint(out["suggestions"])
	if strings.Contains(got, "podman") || !strings.Contains(got, "apps.lan") {
		t.Fatalf("suggestions: %s", got)
	}
}
