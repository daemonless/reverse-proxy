package server

import (
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/daemonless/reverse-proxy/admin/internal/caddy"
	"github.com/daemonless/reverse-proxy/admin/internal/netif"
)

// threeNetworks is jupiter's proxy: lan86 for people, two VLANs it reaches
// apps on.
func threeNetworks() []netif.Network {
	return []netif.Network{
		{Interface: "eth0", Network: "192.168.86.0/24", Address: "192.168.86.11", Addresses: []string{"192.168.86.11"}},
		{Interface: "eth1", Network: "192.168.4.0/24", Address: "192.168.4.204", Addresses: []string{"192.168.4.204"}},
		{Interface: "eth2", Network: "192.168.5.0/24", Address: "192.168.5.145", Addresses: []string{"192.168.5.145"}},
	}
}

func put(listen string) string { return `{"listen":` + listen + `}` }

func TestListenOnSomeNetworks(t *testing.T) {
	s, c, _ := setUp(t)
	s.Networks = threeNetworks
	fromLan := []string{caddy.LocalHeader, "192.168.86.11"}
	saved := func() []string { return s.mgr.State().Settings.Listen }

	rr, out := c.do("GET", "/api/v1/settings", "", fromLan...)
	if rr.Code != 200 || out["here"] != "192.168.86.0/24" || len(out["listen"].([]any)) != 0 || len(out["networks"].([]any)) != 3 {
		t.Fatalf("settings: %d %v", rr.Code, out)
	}
	// Leaving out the network this page came in on would cut it off.
	rr, out = c.do("PUT", "/api/v1/listen", put(`["192.168.5.0/24"]`), fromLan...)
	if rr.Code != 400 || out["field"] != "listen" || !strings.Contains(out["error"].(string), "cut this page off") {
		t.Fatalf("without its own: %d %v", rr.Code, out)
	}
	if rr, out = c.do("PUT", "/api/v1/listen", put(`["192.168.86.0/24","10.9.9.0/24"]`), fromLan...); rr.Code != 400 || out["field"] != "listen" {
		t.Fatalf("a network it is not on: %d %v", rr.Code, out)
	}
	// lan86 and vlan5, by address and by interface: saved as subnets.
	if rr, out = c.do("PUT", "/api/v1/listen", put(`["eth2","192.168.86.11"]`), fromLan...); rr.Code != 200 {
		t.Fatalf("two networks: %d %v", rr.Code, out)
	}
	if want := []string{"192.168.5.0/24", "192.168.86.0/24"}; !slices.Equal(saved(), want) {
		t.Fatalf("saved %v, want %v", saved(), want)
	}
	// Leaving listen out keeps it.
	if rr, _ = c.do("PUT", "/api/v1/settings", `{"domain":"apps.test","trustedNetworks":[]}`, fromLan...); rr.Code != 200 || len(saved()) != 2 {
		t.Fatalf("kept: %d %v", rr.Code, saved())
	}
	// All three one by one is every network.
	if rr, _ = c.do("PUT", "/api/v1/listen", put(`["eth0","eth1","eth2"]`), fromLan...); rr.Code != 200 || saved() != nil {
		t.Fatalf("all three: %d %v", rr.Code, saved())
	}
	if rr, _ = c.do("PUT", "/api/v1/listen", put(`["eth0"]`), fromLan...); rr.Code != 200 || len(saved()) != 1 {
		t.Fatalf("one: %d %v", rr.Code, saved())
	}
	if rr, _ = c.do("PUT", "/api/v1/listen", put(`[]`), fromLan...); rr.Code != 200 || saved() != nil {
		t.Fatalf("every network again: %d %v", rr.Code, saved())
	}
}

func TestListenRefusedFromAnUnlistedAddress(t *testing.T) {
	s, c, _ := setUp(t)
	s.Networks = threeNetworks
	// Came in on an address no listed network has (IPv6-only interface).
	rr, out := c.do("PUT", "/api/v1/listen", put(`["192.168.86.0/24"]`), caddy.LocalHeader, "2001:db8::77")
	if rr.Code != 400 || out["field"] != "listen" {
		t.Fatalf("unlisted arrival: %d %v", rr.Code, out)
	}
}

func TestListenCommandOverTheSocket(t *testing.T) {
	s, _, _ := setUp(t)
	s.Networks = threeNetworks
	post := func(body string, hdr ...string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "http://admin/internal/listen", strings.NewReader(body))
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		return rr
	}
	// From the socket any choice goes: it is the way back in.
	if rr := post(`{"listen":["eth2"]}`); rr.Code != 200 || !slices.Equal(s.mgr.State().Settings.Listen, []string{"192.168.5.0/24"}) {
		t.Fatalf("socket: %d %s", rr.Code, rr.Body)
	}
	if rr := post(`{"listen":[]}`); rr.Code != 200 || s.mgr.State().Settings.Listen != nil {
		t.Fatalf("all: %d %s", rr.Code, rr.Body)
	}
	if rr := post(`{"listen":["eth0"]}`, "X-Forwarded-For", "192.168.1.50"); rr.Code != 404 {
		t.Fatalf("from the network: %d", rr.Code)
	}
}

func TestListenSetByEnvironment(t *testing.T) {
	s, c, _ := setUp(t)
	s.Networks = threeNetworks
	s.ListenEnv = "eth0, 192.168.5.0/24"
	_, out := c.do("GET", "/api/v1/settings", "")
	if got := out["listen"].([]any); out["listenSetBy"] != "RP_LISTEN" || len(got) != 2 || got[0] != "192.168.86.0/24" || got[1] != "192.168.5.0/24" {
		t.Fatalf("settings: %v", out)
	}
	if rr, out := c.do("PUT", "/api/v1/listen", put(`[]`)); rr.Code != 400 || out["field"] != "listen" {
		t.Fatalf("change under RP_LISTEN: %d %v", rr.Code, out)
	}
}

func TestRestoreKeepsOnlyNetworksHere(t *testing.T) {
	s, _, _ := setUp(t)
	s.Networks = threeNetworks
	st := s.mgr.State()
	st.Settings.Listen = []string{"10.20.30.0/24"} // the machine the backup came from
	if !s.fitListen(st) || st.Settings.Listen != nil {
		t.Fatalf("foreign network kept: %v", st.Settings.Listen)
	}
	st.Settings.Listen = []string{"10.20.30.0/24", "192.168.86.0/24"}
	if !s.fitListen(st) || !slices.Equal(st.Settings.Listen, []string{"192.168.86.0/24"}) {
		t.Fatalf("partly here: %v", st.Settings.Listen)
	}
	if s.fitListen(st) {
		t.Fatal("changed a choice that fits")
	}
}

func TestListenChosenDuringSetupBeforeAnEnding(t *testing.T) {
	s, tok := newTestServer(t)
	s.Networks = threeNetworks
	c := &client{t: t, s: s, origin: true}
	c.do("POST", "/api/v1/setup/token", `{"token":"`+tok+`"}`)
	c.do("POST", "/api/v1/setup/password", `{"password":"a long enough password"}`)
	rr, out := c.do("PUT", "/api/v1/listen", put(`["eth0","eth2"]`), caddy.LocalHeader, "192.168.86.11")
	if rr.Code != 200 || out["domain"] != "" || len(out["listen"].([]any)) != 2 {
		t.Fatalf("setup step: %d %v", rr.Code, out)
	}
}
