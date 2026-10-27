package server

import (
	"encoding/json"
	"strings"
	"testing"
)

// A code from the admin, redeemed once by a fjord elsewhere, gives it a key
// that works on the hosts API; the code is dead after that, and a wrong one
// is refused.
func TestPairCodeGivesAKeyOnce(t *testing.T) {
	s, c, _ := setUp(t)
	rr, made := c.do("POST", "/api/v1/pair/code", "")
	if rr.Code != 201 {
		t.Fatalf("code: %d %s", rr.Code, rr.Body.String())
	}
	code, _ := made["code"].(string)
	link, _ := made["link"].(string)
	if code == "" || !strings.Contains(link, "/link#code="+code) {
		t.Fatalf("code/link: %v", made)
	}
	body := `{"code":"` + strings.ToLower(code) + `","client":{"id":"k7f3a9","name":"fjord on venus","url":"http://venus:3567/"}}`
	anon := &client{t: t, s: s}
	rr, got := anon.do("POST", "/api/v1/pair", body)
	if rr.Code != 201 {
		t.Fatalf("pair: %d %s", rr.Code, rr.Body.String())
	}
	key, _ := got["key"].(string)
	if !strings.HasPrefix(key, "rp_") || got["proxyName"] != "proxy.apps.test" {
		t.Fatalf("pair answer: %v", got)
	}
	api := &client{t: t, s: s, bearer: key}
	if rr, _ := api.do("GET", "/api/v1/hosts", ""); rr.Code != 200 {
		t.Fatalf("new key on hosts: %d", rr.Code)
	}
	var tk map[string]any
	for _, x := range s.mgr.State().Tokens {
		if x.ClientID == "k7f3a9" {
			b, _ := json.Marshal(x)
			json.Unmarshal(b, &tk)
		}
	}
	if tk == nil || tk["label"] != "fjord on venus" || tk["url"] != "http://venus:3567" {
		t.Fatalf("token: %v", tk)
	}
	if rr, _ := anon.do("POST", "/api/v1/pair", body); rr.Code != 400 {
		t.Fatalf("code reused: %d", rr.Code)
	}
	if rr, _ := anon.do("POST", "/api/v1/pair", `{"code":"NOPE-NOPE","client":{}}`); rr.Code != 400 {
		t.Fatalf("wrong code: %d", rr.Code)
	}
}
