package caddy

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/dns"
	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

var update = flag.Bool("update", false, "rewrite golden files")

func fixedInput(st *state.State) Input {
	return Input{
		AdminSocket: "/var/run/reverse-proxy/caddy.sock",
		UISocket:    "/var/run/reverse-proxy/admin.sock",
		ProbeSocket: "/var/run/reverse-proxy/tls.sock",
		CertPath:    "/config/secrets/setup.crt",
		KeyPath:     "/config/secrets/setup.key",
		LogLevel:    "WARN",
		State:       st,
	}
}

func TestRenderGolden(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	deleted := now.Add(-time.Hour)
	cases := map[string]*state.State{
		"empty": {SchemaVersion: 1},
		"private-two-hosts": {
			SchemaVersion: 1,
			Settings:      state.Settings{Domain: "apps.home.lan", TrustedNetworks: []string{"100.64.0.0/10"}},
			Hosts: []state.Host{
				{ID: "a", Name: "radarr", Target: state.Target{Address: "192.168.1.20", Port: 7878}, Access: state.AccessHome, CreatedAt: now},
				{ID: "b", Name: "unifi", ExtraNames: []string{"network"}, Target: state.Target{Address: "192.168.1.1", Port: 8443, HTTPS: true, AcceptUntrusted: true}, Access: state.AccessInternet, CreatedAt: now},
				{ID: "c", Name: "gone", Target: state.Target{Address: "192.168.1.9", Port: 80}, Access: state.AccessHome, CreatedAt: now, DeletedAt: &deleted},
			},
		},
		"host-trusted-override": {
			SchemaVersion: 1,
			Settings:      state.Settings{Domain: "home.example.com", TrustedNetworks: []string{"100.64.0.0/10"}},
			Hosts: []state.Host{
				{ID: "a", Name: "nas", Target: state.Target{Address: "nas.lan", Port: 5000}, Access: state.AccessHome, TrustedNetworks: []string{"10.9.0.0/24"}, CreatedAt: now},
			},
		},
	}
	cases["public-wildcard-live"] = publicState()
	cases["public-wildcard-live"].Settings.Certificates.Stage = state.StageLive
	for name, st := range cases {
		t.Run(name, func(t *testing.T) {
			in := fixedInput(st)
			if name == "public-wildcard-live" {
				in.DNS = &dns.Config{Provider: "cloudflare", Fields: map[string]string{"api_token": "tok"}}
				in.IssuanceLog = "/config/logs/issuance.log"
			}
			got, err := json.MarshalIndent(Render(in), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			p := filepath.Join("testdata", name+".json")
			if *update {
				if err := os.WriteFile(p, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("%v (run with -update to create)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("rendered config differs from %s:\n%s", p, got)
			}
		})
	}
}

func TestDeletedHostNotServed(t *testing.T) {
	gone := time.Now()
	st := &state.State{Settings: state.Settings{Domain: "x.lan"}, Hosts: []state.Host{
		{ID: "a", Name: "gone", Target: state.Target{Address: "1.2.3.4", Port: 80}, Access: state.AccessHome, DeletedAt: &gone},
	}}
	cfg := Render(fixedInput(st))
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	routes := servers["hosts"].(map[string]any)["routes"].([]any)
	// proxy name check + proxy name + unknown-name page + abort: nothing
	// for the host
	if len(routes) != 4 {
		t.Fatalf("deleted host still routed: %d routes", len(routes))
	}
}

func TestProxyNameServedOn443WithoutHosts(t *testing.T) {
	st := &state.State{Settings: state.Settings{Domain: "x.lan"}}
	servers := Render(fixedInput(st))["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	hs, ok := servers["hosts"].(map[string]any)
	if !ok {
		t.Fatal("no :443 listener with a domain but no hosts")
	}
	first := hs["routes"].([]any)[0].(map[string]any)["match"].([]any)[0].(map[string]any)
	if first["host"].([]string)[0] != "proxy.x.lan" || first["path"].([]string)[0] != "/trust/check" {
		t.Fatalf("first route: %v", first)
	}
	if _, ok := Render(fixedInput(&state.State{}))["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["hosts"]; ok {
		t.Fatal(":443 listener without a domain")
	}
}

func TestHomeOnlyHasRemoteIPMatcher(t *testing.T) {
	st := &state.State{Settings: state.Settings{Domain: "x.lan"}, Hosts: []state.Host{
		{ID: "a", Name: "home", Target: state.Target{Address: "1.2.3.4", Port: 80}, Access: state.AccessHome},
		{ID: "b", Name: "open", Target: state.Target{Address: "1.2.3.5", Port: 80}, Access: state.AccessInternet},
	}}
	srv := Render(fixedInput(st))["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["hosts"].(map[string]any)
	routes := srv["routes"].([]any)
	m0 := routes[2].(map[string]any)["match"].([]any)[0].(map[string]any)
	m1 := routes[3].(map[string]any)["match"].([]any)[0].(map[string]any)
	if _, ok := m0["remote_ip"]; !ok {
		t.Fatal("home-only host lacks remote_ip matcher")
	}
	if _, ok := m1["remote_ip"]; ok {
		t.Fatal("internet host has remote_ip matcher")
	}
	last := routes[len(routes)-1].(map[string]any)["handle"].([]any)[0].(map[string]any)
	if last["abort"] != true {
		t.Fatal("catch-all route does not abort")
	}
}

func TestNamesAreAutomated(t *testing.T) {
	st := &state.State{Settings: state.Settings{Domain: "x.lan"}, Hosts: []state.Host{
		{ID: "a", Name: "one", ExtraNames: []string{"two"}, Target: state.Target{Address: "1.2.3.4", Port: 80}, Access: state.AccessHome},
	}}
	in := fixedInput(st)
	in.RootCert, in.RootKey, in.RootID = "/config/secrets/ca-root.crt", "/config/secrets/ca-root.key", "rp-1441"
	apps := Render(in)["apps"].(map[string]any)
	automate := apps["tls"].(map[string]any)["certificates"].(map[string]any)["automate"].([]string)
	if len(automate) != 3 || automate[0] != "one.x.lan" || automate[1] != "proxy.x.lan" || automate[2] != "two.x.lan" {
		t.Fatalf("automate = %v", automate)
	}
	ca := apps["pki"].(map[string]any)["certificate_authorities"].(map[string]any)["rp-1441"].(map[string]any)
	if ca["install_trust"] != false {
		t.Fatal("install_trust not disabled")
	}
	root := ca["root"].(map[string]any)
	if root["certificate"] != in.RootCert || root["private_key"] != in.RootKey {
		t.Fatalf("root not wired: %v", root)
	}
	issuer := apps["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]any)[0].(map[string]any)["issuers"].([]any)[0].(map[string]any)
	if issuer["ca"] != "rp-1441" {
		t.Fatalf("issuer not bound to the CA: %v", issuer)
	}
	// Without a domain there is no CA at all, even if files exist.
	in.State = &state.State{}
	if _, ok := Render(in)["apps"].(map[string]any)["pki"]; ok {
		t.Fatal("CA configured without a domain")
	}
}

func TestHostsServerHardening(t *testing.T) {
	st := &state.State{Settings: state.Settings{Domain: "x.lan"}, Hosts: []state.Host{
		{ID: "a", Name: "one", Target: state.Target{Address: "1.2.3.4", Port: 80}, Access: state.AccessHome},
	}}
	srv := Render(fixedInput(st))["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["hosts"].(map[string]any)
	if srv["strict_sni_host"] != true {
		t.Fatal("strict_sni_host off")
	}
	pol := srv["tls_connection_policies"].([]any)[0].(map[string]any)
	if pol["protocol_min"] != "tls1.2" {
		t.Fatalf("protocol_min %v", pol["protocol_min"])
	}
	handlers := srv["routes"].([]any)[2].(map[string]any)["handle"].([]any)
	if handlers[0].(map[string]any)["handler"] != "headers" || handlers[1].(map[string]any)["handler"] != "reverse_proxy" {
		t.Fatalf("handler order: %v", handlers)
	}
	set := handlers[0].(map[string]any)["response"].(map[string]any)["set"].(map[string]any)
	if _, ok := set["Strict-Transport-Security"]; !ok {
		t.Fatal("no HSTS")
	}
	errs := srv["errors"].(map[string]any)["routes"].([]any)
	body := errs[0].(map[string]any)["handle"].([]any)[0].(map[string]any)["body"].(string)
	if !strings.Contains(body, "{http.request.host}") || strings.Contains(body, "1.2.3.4") {
		t.Fatal("error page wrong")
	}
}

func TestAdminServesProxyNameWithRealCert(t *testing.T) {
	st := &state.State{Settings: state.Settings{Domain: "x.lan"}}
	srv := Render(fixedInput(st))["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["admin"].(map[string]any)
	pols := srv["tls_connection_policies"].([]any)
	if len(pols) != 2 {
		t.Fatalf("policies: %v", pols)
	}
	sni := pols[0].(map[string]any)["match"].(map[string]any)["sni"].([]string)
	if sni[0] != "proxy.x.lan" {
		t.Fatalf("first policy sni %v", sni)
	}
}

func publicState() *state.State {
	return &state.State{
		SchemaVersion: 1,
		Settings: state.Settings{Domain: "home.example.com",
			Certificates: &state.Certificates{Provider: "cloudflare", Stage: state.StageTrial, StartedAt: time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)}},
		Hosts: []state.Host{{ID: "a", Name: "radarr", Target: state.Target{Address: "192.168.1.20", Port: 7878}, Access: state.AccessHome}},
	}
}

func tlsPolicy(t *testing.T, cfg map[string]any) (subjects []string, issuer map[string]any) {
	t.Helper()
	tlsApp := cfg["apps"].(map[string]any)["tls"].(map[string]any)
	pol := tlsApp["automation"].(map[string]any)["policies"].([]any)[0].(map[string]any)
	return pol["subjects"].([]string), pol["issuers"].([]any)[0].(map[string]any)
}

func TestPublicDomainGetsOneWildcardViaDNS(t *testing.T) {
	in := fixedInput(publicState())
	in.DNS = &dns.Config{Provider: "cloudflare", Fields: map[string]string{"api_token": "tok"}}
	in.IssuanceLog = "/config/logs/issuance.log"
	cfg := Render(in)
	subjects, issuer := tlsPolicy(t, cfg)
	if len(subjects) != 1 || subjects[0] != "*.home.example.com" {
		t.Fatalf("subjects %v", subjects)
	}
	if issuer["module"] != "acme" || issuer["ca"] != Staging {
		t.Fatalf("trial must use the staging CA: %v", issuer)
	}
	prov := issuer["challenges"].(map[string]any)["dns"].(map[string]any)["provider"].(map[string]any)
	if prov["name"] != "cloudflare" || prov["api_token"] != "tok" {
		t.Fatalf("provider %v", prov)
	}
	automate := cfg["apps"].(map[string]any)["tls"].(map[string]any)["certificates"].(map[string]any)["automate"].([]string)
	if len(automate) != 1 || automate[0] != "*.home.example.com" {
		t.Fatalf("automate %v", automate)
	}
	logs := cfg["logging"].(map[string]any)["logs"].(map[string]any)
	if _, ok := logs["issuance"]; !ok {
		t.Fatal("issuance log missing")
	}
	// Live stage: no ca override, so Caddy's default (Let's Encrypt).
	in.State.Settings.Certificates.Stage = state.StageLive
	_, issuer = tlsPolicy(t, Render(in))
	if _, has := issuer["ca"]; has {
		t.Fatalf("live stage must not pin a CA: %v", issuer)
	}
}

func TestPublicDomainWithoutCredentialsStaysInternal(t *testing.T) {
	// Provider chosen in state but no secrets file (or a different one):
	// never ask a public CA with nothing to answer the challenge.
	in := fixedInput(publicState())
	subjects, issuer := tlsPolicy(t, Render(in))
	if issuer["module"] != "internal" || len(subjects) != 2 {
		t.Fatalf("got %v %v", subjects, issuer)
	}
	in.DNS = &dns.Config{Provider: "desec"}
	if _, issuer = tlsPolicy(t, Render(in)); issuer["module"] != "internal" {
		t.Fatalf("mismatched provider must stay internal: %v", issuer)
	}
	// A private ending never goes public, whatever the state says.
	in.State.Settings.Domain = "apps.home.lan"
	in.DNS = &dns.Config{Provider: "cloudflare"}
	if _, issuer = tlsPolicy(t, Render(in)); issuer["module"] != "internal" {
		t.Fatalf("private ending must stay internal: %v", issuer)
	}
}

// The proxy's own name on :443 is the admin itself, no port in the address;
// /internal/ (reset-password over the socket) stays off the network there
// as on :8443.
func TestProxyNameServesTheAdmin(t *testing.T) {
	servers := Render(fixedInput(&state.State{Settings: state.Settings{Domain: "x.lan"}}))["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	routes := servers["hosts"].(map[string]any)["routes"].([]any)
	h := routes[1].(map[string]any)["handle"].([]any)[0].(map[string]any)
	if h["handler"] != "subroute" {
		t.Fatalf("proxy name route: %v", h)
	}
	inner := h["routes"].([]any)
	first := inner[0].(map[string]any)
	if first["match"].([]any)[0].(map[string]any)["path"].([]string)[0] != "/internal/*" || first["handle"].([]any)[0].(map[string]any)["status_code"] != 404 {
		t.Fatalf("/internal/ not refused: %v", first)
	}
	if inner[1].(map[string]any)["handle"].([]any)[0].(map[string]any)["handler"] != "reverse_proxy" {
		t.Fatalf("admin not served: %v", inner[1])
	}
}

// With OwnOrigin on, a request from the name's own pages reaches the app
// with the app's own Origin and Referer (UniFi refused the login, then every
// call); off, which is the default, nothing is rewritten.
func TestProxyHandlerRewritesOwnOrigin(t *testing.T) {
	if h := proxyHandler(state.Host{Target: state.Target{Address: "192.168.86.8", Port: 8443, HTTPS: true}}, []string{"unifi.apps.lan"}); h["headers"] != nil {
		t.Fatalf("off by default: %v", h["headers"])
	}
	h := proxyHandler(state.Host{OwnOrigin: true, Target: state.Target{Address: "192.168.86.8", Port: 8443, HTTPS: true}}, []string{"unifi.apps.lan"})
	rules := h["headers"].(map[string]any)["request"].(map[string]any)["replace"].(map[string]any)["Origin"].([]any)
	r := rules[0].(map[string]any)
	if r["search_regexp"] != `^https://unifi\.apps\.lan$` || r["replace"] != "https://192.168.86.8:8443" {
		t.Fatalf("rule %v", r)
	}
	ref := h["headers"].(map[string]any)["request"].(map[string]any)["replace"].(map[string]any)["Referer"].([]any)[0].(map[string]any)
	if ref["search_regexp"] != `^https://unifi\.apps\.lan(/.*)?$` || ref["replace"] != "https://192.168.86.8:8443${1}" {
		t.Fatalf("referer rule %v", ref)
	}
	h = proxyHandler(state.Host{OwnOrigin: true, Target: state.Target{Address: "10.0.0.5", Port: 80}}, []string{"a.x.lan", "b.x.lan"})
	rules = h["headers"].(map[string]any)["request"].(map[string]any)["replace"].(map[string]any)["Origin"].([]any)
	if len(rules) != 2 || rules[1].(map[string]any)["replace"] != "http://10.0.0.5" {
		t.Fatalf("rules %v", rules)
	}
}

// HSTS turns a changed certificate into a wall, so only names open to the
// internet with a public certificate keep it.
func TestPinHTTPS(t *testing.T) {
	public := state.Settings{Domain: "home.example.com", Certificates: &state.Certificates{Provider: "cloudflare", Stage: state.StageLive}}
	private := state.Settings{Domain: "apps.home.lan"}
	noCerts := state.Settings{Domain: "home.example.com"}
	home, internet := state.Host{Access: state.AccessHome}, state.Host{Access: state.AccessInternet}
	for _, c := range []struct {
		set  state.Settings
		h    state.Host
		want bool
	}{
		{public, internet, true},
		{public, home, false},
		{private, internet, false},
		{noCerts, internet, false},
	} {
		if got := pinHTTPS(c.set, c.h); got != c.want {
			t.Errorf("%s %s: got %v", c.set.Domain, c.h.Access, got)
		}
	}
}

// A name nothing answers to: a page for someone at home, the dropped
// connection for anyone else, so a home-only name looks like none.
func TestUnknownNamePageOnlyAtHome(t *testing.T) {
	st := &state.State{Settings: state.Settings{Domain: "x.lan"}}
	servers := Render(fixedInput(st))["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	routes := servers["hosts"].(map[string]any)["routes"].([]any)
	page := routes[len(routes)-2].(map[string]any)
	ranges := page["match"].([]any)[0].(map[string]any)["remote_ip"].(map[string]any)["ranges"].([]string)
	if len(ranges) == 0 || !slices.Contains(ranges, "192.168.0.0/16") {
		t.Fatalf("page not limited to home: %v", ranges)
	}
	h := page["handle"].([]any)[0].(map[string]any)
	if h["status_code"] != 404 || !strings.Contains(h["body"].(string), "proxy.x.lan") {
		t.Fatalf("page: %v", h["status_code"])
	}
	last := routes[len(routes)-1].(map[string]any)["handle"].([]any)[0].(map[string]any)
	if last["abort"] != true || routes[len(routes)-1].(map[string]any)["match"] != nil {
		t.Fatalf("last route is not the drop for everyone else: %v", last)
	}
}
