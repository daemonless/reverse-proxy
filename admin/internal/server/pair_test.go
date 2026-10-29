package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/state"
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

// The installer, disconnected and then linked again with a code (same fjord
// id): its new key replaces the old one and keeps "installed this proxy",
// so it is not shown as disconnected, or twice.
func TestRelinkReplacesTheOldKey(t *testing.T) {
	s, c, _ := setUp(t)
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := RegisterPairingKey(s.mgr, key, "fjord on jupiter", "http://jupiter:3567", "e815d9467dce"); err != nil {
		t.Fatal(err)
	}
	old := s.mgr.State().Tokens[1].ID
	if rr, _ := c.do("PUT", "/api/v1/tokens/"+old, `{"disabled":true}`); rr.Code != 200 {
		t.Fatalf("disconnect: %d", rr.Code)
	}
	_, made := c.do("POST", "/api/v1/pair/code", "")
	anon := &client{t: t, s: s}
	_, got := anon.do("POST", "/api/v1/pair", `{"code":"`+made["code"].(string)+`","client":{"id":"e815d9467dce","name":"fjord on jupiter"}}`)
	newKey, _ := got["key"].(string)
	var mine []state.ApiToken
	for _, x := range s.mgr.State().Tokens {
		if x.ClientID == "e815d9467dce" {
			mine = append(mine, x)
		}
	}
	if len(mine) != 1 || !mine[0].Paired || mine[0].Disabled || mine[0].URL != "http://jupiter:3567" {
		t.Fatalf("tokens after relink: %+v", mine)
	}
	if rr, _ := (&client{t: t, s: s, bearer: newKey}).do("GET", "/api/v1/hosts", ""); rr.Code != 200 {
		t.Fatalf("new key: %d", rr.Code)
	}
	if rr, _ := (&client{t: t, s: s, bearer: key}).do("GET", "/api/v1/hosts", ""); rr.Code != 401 {
		t.Fatalf("old key still works: %d", rr.Code)
	}
}

// State from before the fix: the disconnected installer key beside the key
// the same fjord relinked with. The one it uses stays, as the installer.
func TestFitTokensKeepsTheKeyInUse(t *testing.T) {
	at := func(h int) *time.Time { x := time.Date(2026, 10, 28, h, 0, 0, 0, time.UTC); return &x }
	st := &state.State{Tokens: []state.ApiToken{
		{ID: "script", Label: "script"},
		{ID: "old", ClientID: "e815d9467dce", Paired: true, Disabled: true, URL: "http://jupiter:3567", LastUsedAt: at(20)},
		{ID: "new", ClientID: "e815d9467dce", LastUsedAt: at(23)},
	}}
	if !fitTokens(st) {
		t.Fatal("nothing changed")
	}
	if len(st.Tokens) != 2 || st.Tokens[1].ID != "new" || !st.Tokens[1].Paired || st.Tokens[1].Disabled || st.Tokens[1].URL != "http://jupiter:3567" {
		t.Fatalf("tokens: %+v", st.Tokens)
	}
	if fitTokens(st) {
		t.Fatal("changed again")
	}
}
