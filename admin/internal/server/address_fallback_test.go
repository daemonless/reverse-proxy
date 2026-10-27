package server

import (
	"context"
	"testing"

	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// A sign-in by name keeps the last IP address as the way back in.
func TestFallbackKeepsLastIPAddress(t *testing.T) {
	var set state.Settings
	noteAddress(&set, "192.168.86.10:8443")
	noteAddress(&set, "proxy.home.example.com")
	if set.AdminAddress != "proxy.home.example.com" || set.AdminIPAddress != "192.168.86.10:8443" {
		t.Fatalf("%+v", set)
	}
	if got := FallbackURL(context.Background(), set); got != "https://192.168.86.10:8443" {
		t.Fatalf("got %q", got)
	}
	if got := FallbackURL(context.Background(), state.Settings{}); got != "" {
		t.Fatalf("nothing known: got %q", got)
	}
}
