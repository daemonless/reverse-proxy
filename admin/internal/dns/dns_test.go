package dns

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

func TestDetectWalksUpToTheZone(t *testing.T) {
	lookup := func(_ context.Context, name string) ([]*net.NS, error) {
		if name == "example.com" {
			return []*net.NS{{Host: "Ada.ns.cloudflare.com."}, {Host: "bob.ns.cloudflare.com."}}, nil
		}
		return nil, errors.New("no NS")
	}
	g := detect(context.Background(), "Home.Example.com.", lookup)
	if g.Zone != "example.com" || g.Provider != "cloudflare" || len(g.Nameservers) != 2 || g.Nameservers[0] != "ada.ns.cloudflare.com" {
		t.Fatalf("got %+v", g)
	}
}

func TestDetectUnknownProvider(t *testing.T) {
	lookup := func(_ context.Context, name string) ([]*net.NS, error) {
		return []*net.NS{{Host: "ns1.example.net."}}, nil
	}
	g := detect(context.Background(), "home.example.com", lookup)
	if g.Zone != "home.example.com" || g.Provider != "" {
		t.Fatalf("got %+v", g)
	}
	if g := detect(context.Background(), "com", lookup); g.Zone != "" {
		t.Fatalf("single label must not be looked up: %+v", g)
	}
}

func TestValidateTrimsAndRequires(t *testing.T) {
	c := &Config{Provider: "cloudflare", Fields: map[string]string{"api_token": "  abc ", "junk": "x"}}
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	if c.Fields["api_token"] != "abc" || len(c.Fields) != 1 {
		t.Fatalf("fields %v", c.Fields)
	}
	if err := Validate(&Config{Provider: "route53", Fields: map[string]string{"access_key_id": "A"}}); err == nil {
		t.Fatal("missing secret must fail")
	}
	if err := Validate(&Config{Provider: "route53", Fields: map[string]string{"access_key_id": "A", "secret_access_key": "S"}}); err != nil {
		t.Fatalf("optional region: %v", err)
	}
	if err := Validate(&Config{Provider: "nope"}); err == nil {
		t.Fatal("unknown provider must fail")
	}
}

func TestSaveLoadRemove(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Fatal("expected not exist")
	}
	if err := Save(dir, &Config{Provider: "desec", Fields: map[string]string{"token": "t"}}); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir)
	if err != nil || c.Provider != "desec" || c.Fields["token"] != "t" {
		t.Fatalf("%v %+v", err, c)
	}
	if err := Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := Remove(dir); err != nil {
		t.Fatalf("second remove: %v", err)
	}
	if _, err := Load(filepath.Join(dir)); err == nil {
		t.Fatal("still there")
	}
}

func TestEveryProviderIsCompiledIntoCaddy(t *testing.T) {
	// The xcaddy --with list in Containerfile.j2.
	raw, err := os.ReadFile("../../../Containerfile.j2")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, m := range regexp.MustCompile(`--with github\.com/caddy-dns/([a-z0-9]+)`).FindAllStringSubmatch(string(raw), -1) {
		want[m[1]] = true
	}
	if len(want) < 9 {
		t.Fatalf("read only %d modules from Containerfile.j2", len(want))
	}
	for _, p := range Providers {
		if !want[p.ID] {
			t.Errorf("%s is not built into Caddy", p.ID)
		}
		delete(want, p.ID)
		if len(p.Fields) == 0 || p.Help == "" {
			t.Errorf("%s needs fields and help", p.ID)
		}
	}
	for id := range want {
		t.Errorf("%s is built into Caddy but not offered", id)
	}
}

// A free name is its own zone and needs no DNS lookup: you.duckdns.org has
// no NS records, and duckdns.org is not the person's zone.
func TestDetectFreeNames(t *testing.T) {
	noLookup := func(context.Context, string) ([]*net.NS, error) {
		t.Fatal("a free name must not need a lookup")
		return nil, nil
	}
	for domain, want := range map[string]Guess{
		"you.duckdns.org":      {Zone: "you.duckdns.org", Provider: "duckdns"},
		"home.you.duckdns.org": {Zone: "you.duckdns.org", Provider: "duckdns"},
	} {
		g := detect(context.Background(), domain, noLookup)
		if g.Zone != want.Zone || g.Provider != want.Provider || g.Nameservers == nil {
			t.Errorf("%s: %+v", domain, g)
		}
	}
	// The shared domain itself is not a free name.
	g := detect(context.Background(), "duckdns.org", func(context.Context, string) ([]*net.NS, error) { return nil, errors.New("none") })
	if g.Provider != "" {
		t.Errorf("duckdns.org: %+v", g)
	}
}

func TestValidateTokenShape(t *testing.T) {
	bad := &Config{Provider: "duckdns", Fields: map[string]string{"api_token": "my-password"}}
	var fe *state.FieldError
	if err := Validate(bad); !errors.As(err, &fe) || fe.Field != "api_token" || fe.Msg == "" {
		t.Fatalf("bad shape: %v", err)
	}
	good := &Config{Provider: "duckdns", Fields: map[string]string{"api_token": " a1b2c3d4-e5f6-7890-abcd-ef0123456789 "}}
	if err := Validate(good); err != nil || good.Fields["api_token"] != "a1b2c3d4-e5f6-7890-abcd-ef0123456789" {
		t.Fatalf("good: %v %+v", err, good.Fields)
	}
}
