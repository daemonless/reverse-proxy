package server

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/caddy"
	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// browserAddress is the host[:port] the browser reached the admin at, or ""
// when the request did not come through Caddy or the header is not one a
// browser would send. The value is printed later, so it is checked here.
func browserAddress(r *http.Request) string {
	if r.Header.Get("X-Forwarded-For") == "" {
		return ""
	}
	h := strings.ToLower(strings.TrimSpace(r.Host))
	if h == "" || len(h) > 253 {
		return ""
	}
	host, port := h, ""
	if hp, p, err := net.SplitHostPort(h); err == nil {
		host, port = hp, p
		if _, err := net.LookupPort("tcp", port); err != nil || port == "" {
			return ""
		}
	}
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(host, ".") {
			if label == "" || strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
				return ""
			}
		}
	}
	return h
}

// rememberAddress records where the account reached the admin from, when
// that changed. A sign-in is the one moment the address is known to be a
// person's, so this is the only write the sign-in path does.
func (s *Server) rememberAddress(r *http.Request) {
	a := browserAddress(r)
	set := s.mgr.State().Settings
	if a == "" || (set.AdminAddress == a && (!isIPAddress(a) || set.AdminIPAddress == a)) {
		return
	}
	s.mgr.Apply(func(st *state.State) error { noteAddress(&st.Settings, a); return nil })
}

// noteAddress records a browser address; an IP one is also the way back in.
func noteAddress(set *state.Settings, a string) {
	set.AdminAddress = a
	if isIPAddress(a) {
		set.AdminIPAddress = a
	}
}

func isIPAddress(hostport string) bool {
	h := hostport
	if hp, _, err := net.SplitHostPort(hostport); err == nil {
		h = hp
	}
	return net.ParseIP(strings.Trim(h, "[]")) != nil
}

// FallbackURL is an address the admin opens at whatever happens to names
// and certificates: the last IP address someone signed in from, else the
// address the proxy's own name leads to now. "" when neither is known.
func FallbackURL(ctx context.Context, set state.Settings) string {
	if set.AdminIPAddress != "" {
		return "https://" + set.AdminIPAddress
	}
	if set.Domain == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, caddy.ProxyName(set))
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return "https://" + net.JoinHostPort(a, caddy.AdminPort(set))
		}
	}
	return ""
}

// AdminURL is where a person opens the admin: RP_ADMIN_URL when the
// operator set it, else the address the account last used, else "" (the
// caller words the unknown case).
func AdminURL(st *state.State) string {
	if u := strings.TrimRight(strings.TrimSpace(os.Getenv("RP_ADMIN_URL")), "/"); u != "" {
		return u
	}
	if st.Settings.AdminAddress != "" {
		return "https://" + st.Settings.AdminAddress
	}
	return ""
}
