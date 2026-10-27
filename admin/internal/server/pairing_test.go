package server

import (
	"strings"
	"testing"

	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

func TestPairingKey(t *testing.T) {
	s, _ := newTestServer(t)
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	if _, err := RegisterPairingKey(s.mgr, "short", "fjord", "", ""); err == nil {
		t.Fatal("a short key was accepted")
	}
	added, err := RegisterPairingKey(s.mgr, key, "fjord on nas", "http://nas:3567/", "k7f3a9")
	if err != nil || !added {
		t.Fatalf("first registration: added=%v err=%v", added, err)
	}
	if added, _ := RegisterPairingKey(s.mgr, key, "", "javascript:alert(1)", "bad id!"); added {
		t.Fatal("the same key was added twice")
	}
	// The app's address rides along, cleaned: a link, trailing slash off;
	// anything that is not http(s) is dropped rather than put in a link.
	if tk := s.mgr.State().Tokens[0]; tk.URL != "http://nas:3567" || tk.ClientID != "k7f3a9" || tk.Label != "fjord on nas" {
		t.Fatalf("pairing token: %+v", tk)
	}

	c := &client{t: t, s: s, bearer: key}
	if rr, _ := c.do("GET", "/api/v1/hosts", ""); rr.Code != 200 {
		t.Fatalf("paired key as bearer: %d", rr.Code)
	}
	// Using the key is what makes it "connected" on the Settings page.
	if tk := s.mgr.State().Tokens[0]; tk.LastUsedAt == nil {
		t.Fatal("a key that was just used has no last use")
	}
	// Sent in the rp_<id>_<secret> shape it must not match.
	id := s.mgr.State().Tokens[0].ID
	c.bearer = "rp_" + id + "_" + key
	if rr, _ := c.do("GET", "/api/v1/hosts", ""); rr.Code != 401 {
		t.Fatalf("paired key in rp_ form: %d, want 401", rr.Code)
	}

	// Removed by the person: the variable is still set, it stays removed.
	if err := s.mgr.Apply(func(st *state.State) error { st.Tokens = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if added, _ := RegisterPairingKey(s.mgr, key, "", "javascript:alert(1)", "bad id!"); added {
		t.Fatal("a removed key came back")
	}
	c.bearer = key
	if rr, _ := c.do("GET", "/api/v1/hosts", ""); rr.Code != 401 {
		t.Fatalf("removed key still works: %d", rr.Code)
	}
}

func TestCreateHostRefTaken(t *testing.T) {
	s, _ := newTestServer(t)
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := RegisterPairingKey(s.mgr, key, "fjord", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.mgr.Apply(func(st *state.State) error { st.Settings.Domain = "apps.lan"; return nil }); err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, s: s, bearer: key}
	body := `{"name":"radarr","target":{"address":"192.168.1.5","port":7878},"ref":"fjord:nas:radarr"}`
	rr, first := c.do("POST", "/api/v1/hosts", body)
	if rr.Code != 201 {
		t.Fatalf("create: %d", rr.Code)
	}
	rr, again := c.do("POST", "/api/v1/hosts", `{"name":"radarr2","target":{"address":"192.168.1.5","port":7878},"ref":"fjord:nas:radarr"}`)
	if rr.Code != 409 || again["id"] != first["id"] {
		t.Fatalf("same ref: %d %v, want 409 with id %v", rr.Code, again["id"], first["id"])
	}
}

func TestDisconnectAndReconnect(t *testing.T) {
	s, _ := newTestServer(t)
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := RegisterPairingKey(s.mgr, key, "fjord", "", ""); err != nil {
		t.Fatal(err)
	}
	id := s.mgr.State().Tokens[0].ID
	c := &client{t: t, s: s, bearer: key}

	// A key cannot touch keys, its own included.
	if rr, _ := c.do("PUT", "/api/v1/tokens/"+id, `{"disabled":true}`); rr.Code != 403 {
		t.Fatalf("key disabling a key: %d, want 403", rr.Code)
	}
	// Disconnect (the admin, in the UI): the key is refused, and status
	// says so (401, not the public view), but it is kept.
	if err := s.mgr.Apply(func(st *state.State) error { st.Tokens[0].Disabled = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if rr, _ := c.do("GET", "/api/v1/status", ""); rr.Code != 401 {
		t.Fatalf("status with a disconnected key: %d, want 401", rr.Code)
	}
	if len(s.mgr.State().Tokens) != 1 || !s.mgr.State().Tokens[0].Disabled {
		t.Fatal("the key was not kept, turned off")
	}
	// Reconnect (the admin's session in the UI): accepted again.
	if err := s.mgr.Apply(func(st *state.State) error { st.Tokens[0].Disabled = false; return nil }); err != nil {
		t.Fatal(err)
	}
	if rr, _ := c.do("GET", "/api/v1/status", ""); rr.Code != 200 {
		t.Fatalf("status after reconnect: %d", rr.Code)
	}
}

// The Settings page says how many names each connected app made: a fjord
// by its id in the refs; an installer from before ids by what is left.
func TestNamesFromCountsByClientID(t *testing.T) {
	st := &state.State{}
	st.Tokens = []state.ApiToken{
		{ID: "inst", Label: "fjord", Paired: true},
		{ID: "link", Label: "fjord on server-2", ClientID: "9941c5bf65b2"},
		{ID: "key", Label: "script"},
	}
	st.Hosts = []state.Host{
		{ID: "1", Name: "zensical", Ref: "fjord:nas:zensical"},
		{ID: "2", Name: "spike-web", Ref: "fjord:9941c5bf65b2:spike-web"},
		{ID: "3", Name: "router", Ref: ""},
	}
	got := namesFrom(st)
	if got["inst"] != 1 || got["link"] != 1 || got["key"] != 0 {
		t.Fatalf("names from each app: %v", got)
	}
	// The installer learned its id later: its old refs are still its own.
	st.Tokens[0].ClientID = "4cc0fb41d2a0"
	if got := namesFrom(st); got["inst"] != 1 {
		t.Fatalf("installer with an id: %v", got)
	}
}

// An app tells the proxy who it is with its key; the account cannot.
func TestMeUpdatesTheCaller(t *testing.T) {
	s, admin, _ := setUp(t)
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := RegisterPairingKey(s.mgr, key, "fjord", "", ""); err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, s: s, bearer: key}
	rr, out := c.do("PUT", "/api/v1/me", `{"id":"4cc0fb41d2a0","name":"fjord on nas","url":"http://nas:3567/"}`)
	if rr.Code != 200 || out["changed"] != true {
		t.Fatalf("me: %d %v", rr.Code, out)
	}
	find := func() state.ApiToken {
		for _, tk := range s.mgr.State().Tokens {
			if tk.Paired {
				return tk
			}
		}
		t.Fatal("no paired token")
		return state.ApiToken{}
	}
	if tk := find(); tk.ClientID != "4cc0fb41d2a0" || tk.Label != "fjord on nas" || tk.URL != "http://nas:3567" {
		t.Fatalf("token after me: %+v", tk)
	}
	// Said again, nothing new: nothing written.
	if rr, out := c.do("PUT", "/api/v1/me", `{"id":"4cc0fb41d2a0","name":"fjord on nas"}`); rr.Code != 200 || out["changed"] != false {
		t.Fatalf("me again: %d %v", rr.Code, out)
	}
	// A bad id or an overlong name changes nothing of that field.
	c.do("PUT", "/api/v1/me", `{"id":"not valid!","name":"`+strings.Repeat("x", 80)+`"}`)
	if tk := find(); tk.ClientID != "4cc0fb41d2a0" || tk.Label != "fjord on nas" {
		t.Fatalf("token after bad me: %+v", tk)
	}
	if rr, _ := admin.do("PUT", "/api/v1/me", `{"name":"x"}`); rr.Code != 403 {
		t.Fatalf("the account: %d, want 403", rr.Code)
	}
}

// Before setup the public status names the app that installed the proxy,
// so Verify can send people back to it (its Finish setup opens setup
// verified); after setup it is gone, and the key never shows.
func TestStatusNamesInstallerBeforeSetup(t *testing.T) {
	s, _ := newTestServer(t)
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := RegisterPairingKey(s.mgr, key, "fjord on server", "http://server:3567", "e815d9"); err != nil {
		t.Fatal(err)
	}
	s.mgr.Note(func(st *state.State) { st.Settings.AdminPasswordHash = "" })
	rr, out := (&client{t: t, s: s}).do("GET", "/api/v1/status", "")
	by, _ := out["installedBy"].(map[string]any)
	if rr.Code != 200 || by["name"] != "fjord on server" || by["url"] != "http://server:3567" {
		t.Fatalf("before setup: %d %v", rr.Code, out["installedBy"])
	}
	if strings.Contains(rr.Body.String(), key) {
		t.Fatal("the key is in the public status")
	}
	s.mgr.Note(func(st *state.State) { st.Settings.AdminPasswordHash = "x" })
	if _, out := (&client{t: t, s: s}).do("GET", "/api/v1/status", ""); out["installedBy"] != nil {
		t.Fatalf("after setup: %v", out["installedBy"])
	}
}
