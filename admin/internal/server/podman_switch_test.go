package server

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// Turning container labels off removes their names at once, held past the
// undo window; turning them on and naming the container again brings the
// same host back with what the UI set on it.
func TestPodmanSwitchHoldsAndRevives(t *testing.T) {
	s, _ := newTestServer(t)
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := RegisterPairingKey(s.mgr, key, "fjord", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.mgr.Apply(func(st *state.State) error { st.Settings.Domain = "apps.lan"; return nil }); err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, s: s, bearer: key}
	body := `{"name":"radarr","ref":"podman:radarr","trustedNetworks":[],"target":{"address":"10.88.0.5","port":7878}}`
	rr, h := c.do("POST", "/api/v1/hosts", body)
	if rr.Code != 201 {
		t.Fatalf("create: %d %v", rr.Code, h)
	}
	id, _ := h["id"].(string)
	hand := `{"name":"paperless","target":{"address":"10.88.0.9","port":8000}}`
	if rr, _ := c.do("POST", "/api/v1/hosts", hand); rr.Code != 201 {
		t.Fatalf("hand-made: %d", rr.Code)
	}
	s.mgr.Apply(func(st *state.State) error {
		i := st.Find(id)
		st.Hosts[i].Icon, st.Hosts[i].TrustedNetworks, st.Hosts[i].Unwatched = "radarr.svg", []string{"100.64.0.0/10"}, true
		return nil
	})

	flip := func(on bool) {
		t.Helper()
		v := "false"
		if on {
			v = "true"
		}
		rr := httptest.NewRecorder()
		s.putPodmanEnabled(rr, httptest.NewRequest("PUT", "/api/v1/sources/podman/enabled", strings.NewReader(`{"enabled":`+v+`}`)))
		if rr.Code != 200 {
			t.Fatalf("switch %v: %d %s", on, rr.Code, rr.Body)
		}
	}

	flip(false)
	st := s.mgr.State()
	if i := st.Find(id); st.Hosts[i].DeletedAt == nil || !st.Hosts[i].Held {
		t.Fatalf("off removes and holds: %+v", st.Hosts[i])
	}
	for _, o := range st.Hosts {
		if o.Name == "paperless" && o.DeletedAt != nil {
			t.Fatal("off touched a name not made from a label")
		}
	}
	if rr, out := c.do("POST", "/api/v1/hosts", body); rr.Code < 400 {
		t.Fatalf("a label name while off is refused: %d %v", rr.Code, out)
	}
	if rr, _ := c.do("POST", "/api/v1/hosts/"+id+"/restore", ""); rr.Code < 400 {
		t.Fatalf("restore while off is refused: %d", rr.Code)
	}
	if _, out := c.do("GET", "/api/v1/hosts?include=removed", ""); strings.Contains(fmt.Sprint(out), "radarr") {
		t.Fatalf("a held name is not listed as removed: %v", out)
	}
	if rr, _ := c.do("PUT", "/api/v1/sources/podman", `{"socket":true}`); rr.Code != 403 {
		t.Fatalf("an app's key cannot write the unit's report: %d", rr.Code)
	}
	s.mgr.Apply(func(st *state.State) error { st.Purge(time.Now().Add(72 * time.Hour)); return nil })
	if s.mgr.State().Find(id) < 0 {
		t.Fatal("a held name outlives the undo window")
	}

	flip(true)
	if rr, h = c.do("POST", "/api/v1/hosts", body); rr.Code != 201 || h["id"] != id {
		t.Fatalf("revive: %d %v", rr.Code, h)
	}
	st = s.mgr.State()
	got := st.Hosts[st.Find(id)]
	if got.DeletedAt != nil || got.Held || got.Icon != "radarr.svg" || !got.Unwatched || strings.Join(got.TrustedNetworks, ",") != "100.64.0.0/10" {
		t.Fatalf("revive keeps what the UI set: %+v", got)
	}
}

// A name removed and added again by hand is a new name: nothing the old one
// had (trusted networks, icon) is carried over to what may be another machine.
func TestReaddByHandStartsFresh(t *testing.T) {
	s, _ := newTestServer(t)
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := RegisterPairingKey(s.mgr, key, "fjord", "", ""); err != nil {
		t.Fatal(err)
	}
	s.mgr.Apply(func(st *state.State) error { st.Settings.Domain = "apps.lan"; return nil })
	c := &client{t: t, s: s, bearer: key}
	_, h := c.do("POST", "/api/v1/hosts", `{"name":"nas","trustedNetworks":["10.8.0.0/24"],"target":{"address":"192.168.1.9","port":5000}}`)
	id, _ := h["id"].(string)
	c.do("DELETE", "/api/v1/hosts/"+id, "")
	rr, h := c.do("POST", "/api/v1/hosts", `{"name":"nas","target":{"address":"192.168.1.10","port":5000}}`)
	if rr.Code != 201 || h["trustedNetworks"] != nil {
		t.Fatalf("re-added by hand keeps nothing: %d %v", rr.Code, h["trustedNetworks"])
	}
}
