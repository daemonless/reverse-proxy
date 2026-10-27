package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestFjordServicesFromRealSample(t *testing.T) {
	sample, err := os.ReadFile("testdata/fjord-stacks.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/stacks" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(401)
			return
		}
		w.Write(sample)
	}))
	defer srv.Close()

	if _, err := (Fjord{URL: srv.URL, Key: "wrong"}).Services(context.Background()); err == nil {
		t.Fatal("wrong key accepted")
	}
	svcs, err := (Fjord{URL: srv.URL, Key: "k"}).Services(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Service{}
	for _, s := range svcs {
		by[s.Stack] = s
	}
	host := HostOf(srv.URL)
	cases := map[string]struct {
		addr  string
		port  int
		webUI bool
	}{
		"hugo":        {host, 1313, false},           // catalog app without web_port: port guessed, no web UI
		"t-vikns":     {host, 3458, true},            // ${WEB_PORT}=3458, published
		"t-wiz-imm":   {host, 2283, true},            // literal web_port, no published ports in sample
		"uptime-kuma": {"192.168.4.106", 3001, true}, // own address: linkHost + ${WEB_PORT}
		"ubooquity":   {host, 2202, true},
	}
	for stack, want := range cases {
		got, ok := by[stack]
		if !ok {
			t.Fatalf("%s missing", stack)
		}
		if got.Address != want.addr || got.Port != want.port || got.WebUI != want.webUI {
			t.Errorf("%s: got %s:%d webUI=%v, want %s:%d webUI=%v", stack, got.Address, got.Port, got.WebUI, want.addr, want.port, want.webUI)
		}
		if got.Ref != "fjord:"+host+":"+stack {
			t.Errorf("%s: ref %s", stack, got.Ref)
		}
	}
	if Label("My Cool App_2") != "my-cool-app-2" || Label("--x--") != "x" {
		t.Fatal("label rule")
	}
}

func TestFjordBadURL(t *testing.T) {
	if _, err := (Fjord{URL: "nas:3567"}).Services(context.Background()); err == nil {
		t.Fatal("scheme-less URL accepted")
	}
}
