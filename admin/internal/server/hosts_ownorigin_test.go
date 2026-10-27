package server

import (
	"testing"

	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// ownOrigin is set on create, changed only when a PUT names it: fjord's
// port follow PUTs a host without it and must not switch UniFi's off.
func TestOwnOriginKeptWhenAbsent(t *testing.T) {
	s, _ := newTestServer(t)
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := RegisterPairingKey(s.mgr, key, "fjord", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.mgr.Apply(func(st *state.State) error { st.Settings.Domain = "apps.lan"; return nil }); err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, s: s, bearer: key}
	rr, h := c.do("POST", "/api/v1/hosts", `{"name":"unifi","target":{"address":"192.168.1.8","port":8443,"https":true},"ownOrigin":true}`)
	if rr.Code != 201 || h["ownOrigin"] != true {
		t.Fatalf("create: %d %v", rr.Code, h["ownOrigin"])
	}
	id, _ := h["id"].(string)
	if rr, h = c.do("PUT", "/api/v1/hosts/"+id, `{"name":"unifi","extraNames":[],"target":{"address":"192.168.1.8","port":8444,"https":true},"access":"home","trustedNetworks":[],"ref":""}`); rr.Code != 200 || h["ownOrigin"] != true {
		t.Fatalf("PUT without it: %d %v", rr.Code, h["ownOrigin"])
	}
	if rr, h = c.do("PUT", "/api/v1/hosts/"+id, `{"name":"unifi","target":{"address":"192.168.1.8","port":8444,"https":true},"access":"home","ownOrigin":false}`); rr.Code != 200 || h["ownOrigin"] != nil {
		t.Fatalf("PUT turning it off: %d %v", rr.Code, h["ownOrigin"])
	}
	if rr, h = c.do("POST", "/api/v1/hosts", `{"name":"paperless","target":{"address":"192.168.1.9","port":8000}}`); rr.Code != 201 || h["ownOrigin"] != nil {
		t.Fatalf("a name made without it is off: %d %v", rr.Code, h["ownOrigin"])
	}
}
