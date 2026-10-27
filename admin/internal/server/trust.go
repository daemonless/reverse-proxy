package server

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/daemonless/reverse-proxy/admin/internal/auth"
	"github.com/daemonless/reverse-proxy/admin/internal/ca"
	"github.com/daemonless/reverse-proxy/admin/internal/caddy"
	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// rootCert hands out the root certificate. It is public by design: trust
// is established by the fingerprint shown beside it, not by secrecy.
func (s *Server) rootCert(w http.ResponseWriter, r *http.Request) {
	root, err := ca.Load(s.secrets)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no certificate yet; finish setup first"})
		return
	}
	pem, err := os.ReadFile(root.CertPath)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(root.Domain, ".", "-")+`-proxy-root.crt"`)
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(pem)
}

// rootDER is the same root in binary form: its file hash equals the
// fingerprint, which is what Windows tooling can check.
func (s *Server) rootDER(w http.ResponseWriter, r *http.Request) {
	root, err := ca.Load(s.secrets)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no certificate yet; finish setup first"})
		return
	}
	raw, err := os.ReadFile(root.CertPath)
	if err != nil {
		writeError(w, err)
		return
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(root.Domain, ".", "-")+`-proxy-root.der"`)
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(block.Bytes)
}

// qr draws the trust page's address for a phone camera. Only our own trust
// page may be encoded, so this is not a QR service for anything else.
func (s *Server) qr(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.Query().Get("u"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Path != "/trust" || u.RawQuery != "" || u.User != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "only the trust page can be encoded"})
		return
	}
	png, err := qrcode.Encode(u.String(), qrcode.Medium, 320)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(png)
}

// trustCheck is the tiny HTTPS resource the trust page loads to learn
// whether this device trusts the proxy. Over plain HTTP it says so.
func (s *Server) trustCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "secure": r.Header.Get("X-Forwarded-Proto") == "https", "instance": s.instance})
}

// trustInfo is what the trust page shows: the domain, the proxy's name,
// the fingerprint and where to download the root.
func (s *Server) trustInfo(w http.ResponseWriter, _ *http.Request) {
	st := s.mgr.State()
	out := map[string]any{"domain": st.Settings.Domain, "mode": st.Settings.Mode(), "httpPort": s.TrustPort, "instance": s.instance}
	// With public certificates on the way there is nothing to trust by hand.
	out["needed"] = !(st.Settings.Mode() == state.ModePublic && st.Settings.Certificates != nil)
	if st.Settings.Domain != "" {
		out["proxyName"] = caddy.ProxyName(st.Settings)
	}
	if root, err := ca.Load(s.secrets); err == nil && root.Domain == st.Settings.Domain {
		out["fingerprint"] = root.Fingerprint
		out["rootUrl"] = "/trust/root.crt"
		out["notAfter"] = root.NotAfter
	}
	writeJSON(w, http.StatusOK, out)
}

// dnsCheck resolves a never-before-seen name under the domain from inside
// the container, which uses the same resolver the person's devices do on a
// typical network, and reports what came back so the UI can compare it
// with the address the person reached the proxy on.
func (s *Server) dnsCheck(w http.ResponseWriter, r *http.Request) {
	st := s.mgr.State()
	if st.Settings.Domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "set the address first"})
		return
	}
	name := "check-" + auth.NewSecret(5) + "." + st.Settings.Domain
	// Each lookup has its own limit: one slow answer (a resolver that
	// forwards AAAA questions nobody answers) used to eat the whole budget
	// and leave the go/ check with none (2026-10-27).
	lookup := func(host string) ([]string, error) {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		return net.DefaultResolver.LookupHost(ctx, host)
	}
	addrs, err := lookup(name)
	out := map[string]any{"name": name, "addresses": []string{}, "proxyAddresses": []string{}}
	// The browser may have opened the UI by name; this tells it which
	// address that name stands for. Before the record exists the proxy's
	// own name does not resolve, so the name the page was opened by
	// (netlab, from fjord's Finish setup) comes first: the record's
	// address is what it shows (2026-10-27, "the proxy's IP address").
	var here []string
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	if net.ParseIP(host) != nil {
		here = []string{host}
	} else if a, err := lookup(host); host != "" && err == nil {
		here = a
	}
	if pa, perr := lookup(caddy.ProxyName(st.Settings)); perr == nil {
		here = append(here, pa...)
	}
	if here != nil {
		out["proxyAddresses"] = here
	}
	if err == nil {
		out["addresses"] = addrs
	} else if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
		out["notFound"] = true
	} else {
		out["error"] = err.Error()
	}
	// The short-link word as devices ask for it: under the network's own
	// domain (go.lan), which is what the router answers for "go".
	if word, local := st.Settings.ShortName(), localDomain(); word != "" && local != "" {
		short := map[string]any{"name": word + "." + local, "addresses": []string{}}
		if a, err := lookup(word + "." + local); err == nil {
			short["addresses"] = a
		} else if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			short["notFound"] = true
		}
		out["short"] = short
	}
	writeJSON(w, http.StatusOK, out)
}

// suggestDomain offers endings for the setup screen: the resolver's search
// domains (the container inherits the host's), the domain of the address
// the person opened the UI on, and home.arpa as the always-safe fallback.
func (s *Server) suggestDomain(w http.ResponseWriter, r *http.Request) {
	var bases []string
	seen := map[string]bool{}
	add := func(d string) {
		d = strings.Trim(strings.ToLower(d), ".")
		if d == "" || d == "local" || d == "localdomain" || engineDomain(d) || seen[d] {
			return
		}
		seen[d] = true
		bases = append(bases, d)
	}
	if raw, err := os.ReadFile(resolvConf); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) > 1 && (f[0] == "search" || f[0] == "domain") {
				for _, d := range f[1:] {
					add(d)
				}
			}
		}
	}
	if host := strings.TrimSpace(r.URL.Query().Get("host")); host != "" {
		if net.ParseIP(host) != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if names, err := net.DefaultResolver.LookupAddr(ctx, host); err == nil {
				for _, n := range names {
					if i := strings.Index(n, "."); i > 0 {
						add(n[i+1:])
					}
				}
			}
		} else if i := strings.Index(host, "."); i > 0 {
			add(host[i+1:])
		}
	}
	var out []string
	for _, b := range bases {
		out = append(out, "apps."+b, "home."+b)
	}
	out = append(out, "apps.home.arpa")
	if len(out) > 5 {
		out = out[:5]
	}
	writeJSON(w, http.StatusOK, map[string]any{"suggestions": out})
}
