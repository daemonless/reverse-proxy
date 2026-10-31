package certs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/dns"
	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

func TestLastEventReadsNewestLineForTheWildcard(t *testing.T) {
	p := filepath.Join(t.TempDir(), "issuance.log")
	lines := []string{
		`{"level":"info","ts":1760342400.5,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"*.home.example.com"}`,
		`{"level":"error","ts":1760342460.1,"logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"*.home.example.com","issuer":"acme-staging-v02.api.letsencrypt.org-directory","error":"[*.home.example.com] solving challenges: presenting for challenge: adding temporary record for zone \"example.com.\": got error status: HTTP 403: [{Code:10000 Message:Authentication error}]"}`,
		`{"level":"error","ts":1760342461.0,"logger":"tls","msg":"will retry","error":"...","attempt":1}`,
		`{"level":"info","ts":1760342470.0,"logger":"tls.obtain","msg":"certificate obtained successfully","identifier":"*.other.example.com","issuer":"acme-v02.api.letsencrypt.org-directory"}`,
		`not json at all`,
	}
	os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	ev, ok := LastEvent(p, "*.home.example.com")
	if !ok || ev.OK || !strings.Contains(ev.Error, "Authentication error") || ev.At.Unix() != 1760342460 {
		t.Fatalf("got %+v %v", ev, ok)
	}
	if _, ok := LastEvent(p, "*.nothing.example.com"); ok {
		t.Fatal("unexpected event")
	}
	if _, ok := LastEvent(filepath.Join(t.TempDir(), "missing"), "x"); ok {
		t.Fatal("missing file must be no event")
	}
}

func TestExplain(t *testing.T) {
	cases := []struct{ err, want string }{
		{"HTTP 403: Authentication error", "rejected by Cloudflare"},
		{"provision dns.providers.cloudflare: API token 'x' appears invalid; ensure it's correctly entered", "rejected by Cloudflare"},
		{"InvalidClientTokenId: The security token included in the request is invalid", "rejected by Cloudflare"},
		{"NoSuchHostedZone: No hosted zone found", "can't change records for example.com"},
		{"zone example.com. not found in account", "can't change records"},
		{"timed out waiting for record to fully propagate", "never showed up"},
		{"urn:ietf:params:acme:error:rateLimited: too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-10-14 03:00:00 UTC", "limiting requests"},
		{"urn:ietf:params:acme:error:caa: CAA record for example.com prevents issuance", "CAA record"},
		{"something odd", "tried again automatically"},
		{"DuckDNS request failed, expected (OK) but got (KO), url: [https://www.duckdns.org/update?domains=you&token=x], body: KO", "DuckDNS refused the token or the name"},
	}
	for _, c := range cases {
		msg, detail := Explain(c.err, "example.com", "Cloudflare")
		if !strings.Contains(msg, c.want) || detail != redact(c.err) {
			t.Errorf("%q -> %q", c.err, msg)
		}
	}
	msg, _ := Explain("retry after 2026-10-14 03:00:00 UTC rateLimited", "example.com", "x")
	if !strings.Contains(msg, "after ") || strings.Contains(msg, "in an hour") {
		t.Errorf("retry time not used: %s", msg)
	}
}

func TestCompute(t *testing.T) {
	now := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	started := now.Add(-time.Minute)
	pub := func(stage string) state.Settings {
		return state.Settings{Domain: "home.example.com", Certificates: &state.Certificates{Provider: "cloudflare", Stage: stage, StartedAt: started}}
	}
	oldErr := &Event{At: started.Add(-time.Hour), Error: "HTTP 403"}
	newErr := &Event{At: now, Error: "HTTP 403"}
	if s := Compute(state.Settings{Domain: "apps.lan"}, Observation{}, nil, nil, "", now); s.State != "manual" {
		t.Fatalf("private: %s", s.State)
	}
	if s := Compute(state.Settings{Domain: "home.example.com"}, Observation{}, nil, nil, "", now); s.State != "manual" {
		t.Fatalf("public without provider: %s", s.State)
	}
	if s := Compute(pub(state.StageTrial), Observation{}, oldErr, nil, "", now); s.State != "trial" {
		t.Fatalf("old error must not count: %s", s.State)
	}
	if s := Compute(pub(state.StageTrial), Observation{}, newErr, nil, "example.com", now); s.State != "failed" || !strings.Contains(s.Message, "Cloudflare") {
		t.Fatalf("fresh error: %+v", s)
	}
	if s := Compute(pub(state.StageTrial), Observation{Issuer: IssuerStaging}, newErr, nil, "", now); s.State != "issuing" {
		t.Fatalf("staging served: %s", s.State)
	}
	// A trial with no answer either way stops spinning after TrialPatience,
	// and a staging certificate still moves it on after that.
	stuck := pub(state.StageTrial)
	stuck.Certificates.StartedAt = now.Add(-92 * time.Minute)
	if s := Compute(stuck, Observation{}, nil, nil, "example.org", now); s.State != "failed" || !strings.Contains(s.Message, "92 minutes") {
		t.Fatalf("stuck trial: %+v", s)
	}
	if s := Compute(stuck, Observation{Issuer: IssuerStaging}, nil, nil, "example.org", now); s.State != "issuing" {
		t.Fatalf("stuck, then staging served: %s", s.State)
	}
	if s := Compute(pub(state.StageLive), Observation{Issuer: IssuerStaging}, nil, nil, "", now); s.State != "issuing" {
		t.Fatalf("live, still staging: %s", s.State)
	}
	s := Compute(pub(state.StageLive), Observation{Issuer: IssuerLetsEncrypt, NotAfter: now.Add(80 * 24 * time.Hour)}, nil, nil, "", now)
	if s.State != "ok" || s.DaysLeft != 80 || s.Message != "" {
		t.Fatalf("ok: %+v", s)
	}
	slow := &Event{At: now, Error: "timed out waiting for record to fully propagate"}
	s = Compute(pub(state.StageLive), Observation{Issuer: IssuerLetsEncrypt, NotAfter: now.Add(5 * 24 * time.Hour)}, slow, nil, "", now)
	if s.State != "ok" || !strings.Contains(s.Message, "5 days") || s.Detail == "" || s.Fix != "" {
		t.Fatalf("expiring: %+v", s)
	}
	// A temporary failure with time to spare stays quiet: Caddy retries.
	if s := Compute(pub(state.StageLive), Observation{Issuer: IssuerLetsEncrypt, NotAfter: now.Add(25 * 24 * time.Hour)}, slow, nil, "", now); s.Message != "" {
		t.Fatalf("temporary, 25 days left: %+v", s)
	}
	// A rejected token is said at once, while the certificate still works.
	okUntil := Observation{Issuer: IssuerLetsEncrypt, NotAfter: time.Date(2026, 11, 7, 9, 0, 0, 0, time.Local)}
	s = Compute(pub(state.StageLive), okUntil, newErr, nil, "example.com", now)
	if s.State != "ok" || !strings.Contains(s.Message, "Cloudflare stopped accepting your token") || !strings.Contains(s.Message, "Nov 7") || s.Fix != "token" {
		t.Fatalf("rejected on renewal: %+v", s)
	}
	caa := &Event{At: now, Error: "urn:ietf:params:acme:error:caa: CAA record for example.com prevents issuance"}
	if s := Compute(pub(state.StageLive), okUntil, caa, nil, "example.com", now); !strings.Contains(s.Message, "CAA") || s.Fix != "" {
		t.Fatalf("caa on renewal: %+v", s)
	}
	// The daily check finds it before any renewal is tried.
	check := &dns.Problem{Kind: dns.KindZone, FieldError: &state.FieldError{Field: "api_token", Msg: "can't see example.com"}}
	s = Compute(pub(state.StageLive), okUntil, nil, check, "example.com", now)
	if s.State != "ok" || !strings.Contains(s.Message, "can't change example.com any more") || s.Fix != "token" || s.Detail != check.Msg {
		t.Fatalf("daily check: %+v", s)
	}
	// Failing outright with a rejected token points at the token too.
	if s := Compute(pub(state.StageLive), Observation{Issuer: IssuerInternal}, newErr, nil, "", now); s.Fix != "token" {
		t.Fatalf("failed fix: %+v", s)
	}
	if s := Compute(pub(state.StageLive), Observation{Issuer: IssuerInternal}, newErr, nil, "", now); s.State != "failed" {
		t.Fatalf("live failed: %s", s.State)
	}
}

type fakeMgr struct {
	st      *state.State
	applied int
}

func (f *fakeMgr) State() *state.State { return f.st.Clone() }
func (f *fakeMgr) Apply(fn func(*state.State) error) error {
	f.applied++
	return fn(f.st)
}

func TestWatchMovesTrialToLive(t *testing.T) {
	m := &fakeMgr{st: &state.State{Settings: state.Settings{Domain: "home.example.com", Certificates: &state.Certificates{Provider: "desec", Stage: state.StageTrial}}}}
	// Exercise one tick's worth of logic directly.
	obs := Observation{Issuer: IssuerStaging}
	restarts := 0
	restart := func() error { restarts++; return nil }
	tick(m, func(string) Observation { return Observation{} }, restart)
	if m.applied != 0 || restarts != 0 {
		t.Fatal("no staging certificate yet: nothing may change")
	}
	tick(m, func(string) Observation { return obs }, restart)
	if m.st.Settings.Certificates.Stage != state.StageLive || m.applied != 1 || restarts != 1 {
		t.Fatalf("got %+v", m.st.Settings.Certificates)
	}
	tick(m, func(string) Observation { return obs }, restart)
	if m.applied != 1 || restarts != 1 {
		t.Fatal("live must not be touched again")
	}
}

func TestRedactKeepsTokensOutOfDetails(t *testing.T) {
	tok := "a1b2c3d4-e5f6-7890-abcd-ef0123456789"
	_, detail := Explain("DuckDNS request failed, expected (OK) but got (KO), url: [https://www.duckdns.org/update?domains=you&token="+tok+"&txt=abc], body: KO", "you.duckdns.org", "DuckDNS")
	if strings.Contains(detail, tok) || !strings.Contains(detail, "token=…&txt=abc") {
		t.Fatalf("token in detail: %s", detail)
	}
}

func TestLastLine(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "issuance.log")
	os.WriteFile(log, []byte(`{"ts":1793360000.5,"msg":"obtaining certificate","identifier":"*.example.org"}
{"ts":1793360030.5,"msg":"waiting on internal rate limiter","identifiers":["*.example.org"]}
{"ts":1793360040.5,"msg":"obtaining certificate","identifier":"*.other.nz"}
`), 0o644)
	if got := LastLine(log, "*.example.org"); !strings.HasSuffix(got, " waiting on internal rate limiter") {
		t.Errorf("LastLine = %q", got)
	}
	if got := LastLine(filepath.Join(dir, "none"), "*.example.org"); got != "" {
		t.Errorf("no log: %q", got)
	}
}
