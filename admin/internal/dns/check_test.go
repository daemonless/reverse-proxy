package dns

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// A fake Cloudflare: "good" sees ahze.net and its records, "blind" sees no
// zone, "readonly" sees the zone but not its records, anything else is
// refused.
func fakeCloudflare(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch {
		case tok != "good" && tok != "blind" && tok != "readonly":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"success":false,"errors":[{"code":6003,"message":"Invalid request headers"}]}`))
		case r.URL.Path == "/zones" && tok == "blind":
			w.Write([]byte(`{"success":true,"result":[]}`))
		case r.URL.Path == "/zones":
			if r.URL.Query().Get("name") != "ahze.net" {
				t.Errorf("asked about %q", r.URL.Query().Get("name"))
			}
			w.Write([]byte(`{"success":true,"result":[{"id":"z1","name":"ahze.net"}]}`))
		case r.URL.Path == "/zones/z1/dns_records" && tok == "readonly":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"success":false}`))
		default:
			w.Write([]byte(`{"success":true,"result":[]}`))
		}
	}))
	t.Cleanup(srv.Close)
	old := cloudflareAPI
	cloudflareAPI = srv.URL
	t.Cleanup(func() { cloudflareAPI = old })
}

func TestCheckCloudflare(t *testing.T) {
	fakeCloudflare(t)
	for tok, want := range map[string]string{
		"good":     "",
		"wrong":    "doesn't accept this token",
		"blind":    "can't see ahze.net",
		"readonly": "not its DNS records",
	} {
		kind := map[string]string{"wrong": KindRejected, "blind": KindZone, "readonly": KindPermission}[tok]
		err := Check(context.Background(), &Config{Provider: "cloudflare", Fields: map[string]string{"api_token": tok}}, "ahze.net")
		if want == "" {
			if err != nil {
				t.Errorf("%s: %v", tok, err)
			}
			continue
		}
		var fe *state.FieldError
		if !errors.As(err, &fe) || fe.Field != "api_token" || !strings.Contains(fe.Msg, want) {
			t.Errorf("%s: got %v, want %q", tok, err, want)
		}
		var p *Problem
		if !errors.As(err, &p) || p.Kind != kind {
			t.Errorf("%s: kind %v, want %s", tok, p, kind)
		}
	}
}

// No answer from Cloudflare must not block: the trial still tells.
func TestCheckCloudflareUnreachable(t *testing.T) {
	old := cloudflareAPI
	cloudflareAPI = "http://127.0.0.1:1"
	defer func() { cloudflareAPI = old }()
	if err := Check(context.Background(), &Config{Provider: "cloudflare", Fields: map[string]string{"api_token": "x"}}, "ahze.net"); err != nil {
		t.Fatal(err)
	}
}
