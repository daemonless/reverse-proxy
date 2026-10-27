package caddy

import (
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/daemonless/reverse-proxy/admin/internal/dns"
	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// Input is everything the renderer needs.
type Input struct {
	AdminSocket string // Caddy's admin socket; kept identical to the bootstrap
	UISocket    string // the admin's own unix socket, fronted on :8443
	// ProbeSocket serves the hosts' certificates over a unix socket so the
	// admin can check them without a network path to Caddy (they run in
	// separate containers). Empty leaves it out.
	ProbeSocket string
	CertPath    string // setup certificate served on :8443 until setup finishes
	KeyPath     string
	// RootCert/RootKey are the admin-made, domain-restricted root for the
	// internal CA. Empty until a domain is set.
	RootCert string
	RootKey  string
	// RootID names the CA inside Caddy. It changes with the root, so Caddy
	// never reuses an intermediate or a leaf issued under an older root
	// (its storage is keyed by CA id).
	RootID string
	// LogLevel is Caddy's default log level ("WARN" normally, "INFO" with
	// RP_DEBUG=1).
	LogLevel string
	// DNS is the provider Caddy may edit records at, for the wildcard's DNS
	// challenge. Used only when the state's Certificates names the same
	// provider; nil keeps everything under the internal CA.
	DNS *dns.Config
	// IssuanceLog is a file Caddy writes certificate events to, which the
	// admin reads to report progress and failures. Empty disables it.
	IssuanceLog string
	State       *state.State
}

// Staging is the Let's Encrypt staging directory: real issuance flow,
// untrusted certificates, generous limits.
const Staging = "https://acme-staging-v02.api.letsencrypt.org/directory"

// Resolvers are public resolvers for the DNS challenge's propagation
// check. The container's own resolver often answers for the domain itself
// (that is the point of the local wildcard record) and would never see the
// _acme-challenge record at the real nameservers.
var Resolvers = []string{"1.1.1.1", "8.8.8.8"}

// Public reports whether the wildcard is obtained from a public CA: a
// public domain, a provider chosen, and its credentials present.
func Public(in Input) bool {
	st := in.State
	return st != nil && st.Settings.Mode() == state.ModePublic && st.Settings.Certificates != nil &&
		in.DNS != nil && in.DNS.Provider == st.Settings.Certificates.Provider
}

// setupSNI is the name the setup certificate carries; Caddy assumes it when a
// client sends no SNI (an IP address), so the UI answers on any address.
const setupSNI = "reverse-proxy.setup"

// homeRanges are the addresses that count as the home network before the
// user adds any trusted networks.
var homeRanges = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
	"fc00::/7", "fe80::/10", "::1/128",
}

// Render produces the complete Caddy JSON configuration. Everything Caddy
// runs comes from here; there is no other input path.
func Render(in Input) map[string]any {
	st := in.State
	if st == nil {
		st = &state.State{}
	}
	hosts := st.Live()
	if st.Settings.Mode() == state.ModeUnset {
		hosts = nil // no domain yet: nothing to serve
	}

	// proxy.<domain> is the proxy's own name: the admin UI and the trust
	// check are reached through it once DNS points at the proxy.
	var allNames []string
	proxyName := ""
	if st.Settings.Mode() != state.ModeUnset {
		proxyName = ProxyName(st.Settings)
		allNames = append(allNames, proxyName)
	}
	for _, h := range hosts {
		allNames = append(allNames, h.Names(st.Settings)...)
	}
	sort.Strings(allNames)

	var hostNames []string
	for _, h := range hosts {
		hostNames = append(hostNames, h.Names(st.Settings)...)
	}
	sort.Strings(hostNames)

	servers := map[string]any{
		"admin": adminServer(in, proxyName),
		"trust": trustServer(in, hostNames),
	}
	if proxyName != "" {
		servers["hosts"] = hostsServer(in, st, hosts, proxyName)
		if in.ProbeSocket != "" {
			servers["probe"] = probeServer(in)
		}
	}

	tlsApp := map[string]any{
		"certificates": map[string]any{
			"load_files": []any{map[string]any{
				"certificate": in.CertPath,
				"key":         in.KeyPath,
				"tags":        []string{"setup"},
			}},
		},
	}
	if len(allNames) > 0 {
		// Automatic HTTPS is off on every server (we own the redirects and
		// the matching), so the names Caddy must obtain certificates for are
		// listed here explicitly; a policy alone only says how, not which.
		// A public domain gets one wildcard: names stay out of the
		// transparency logs and one issuance covers every host.
		subjects := allNames
		if Public(in) {
			subjects = []string{"*." + st.Settings.Domain}
		}
		tlsApp["certificates"].(map[string]any)["automate"] = subjects
		tlsApp["automation"] = map[string]any{
			"policies": []any{map[string]any{
				"subjects": subjects,
				"issuers":  issuers(in),
			}},
		}
	}

	apps := map[string]any{
		"http": map[string]any{"servers": servers},
		"tls":  tlsApp,
	}
	// The CA exists only once the admin has made a domain-restricted root,
	// so nothing is ever issued under a Caddy-generated root. Its root
	// must never be installed into the container's own trust store; the
	// trust page hands it out.
	if in.RootCert != "" && st.Settings.Mode() != state.ModeUnset {
		apps["pki"] = map[string]any{
			"certificate_authorities": map[string]any{
				in.RootID: map[string]any{
					"name":          st.Settings.Domain + " proxy",
					"install_trust": false,
					"root":          map[string]any{"format": "pem_file", "certificate": in.RootCert, "private_key": in.RootKey},
				},
			},
		}
	}

	logs := map[string]any{
		// "admin" is excluded too: its one message is a warning that the
		// unix-socket endpoint skips host checks (by design here), and a
		// rejected config reaches us as the API response anyway.
		"default": map[string]any{"level": in.LogLevel, "exclude": []string{"admin", "admin.api"}},
	}
	if in.IssuanceLog != "" {
		// Caddy runs as root; the admin (bsd) must be able to read this.
		logs["issuance"] = map[string]any{
			"writer":  map[string]any{"output": "file", "filename": in.IssuanceLog, "mode": "0644", "roll_size_mb": 1, "roll_keep": 1},
			"encoder": map[string]any{"format": "json"},
			"level":   "INFO",
			"include": []string{"tls.obtain", "tls.renew", "tls.issuance"},
		}
	}
	return map[string]any{
		"admin": map[string]any{
			"listen":  "unix/" + in.AdminSocket + "|0660",
			"origins": []string{"caddy"}, // what our client sends as Host
			"config":  map[string]any{"persist": false},
		},
		// Caddy's default log is chatty JSON at info level, which buries the
		// setup link in `podman logs`. Warnings and errors only, and never
		// the health check's polls of the admin API. RP_DEBUG=1 turns the
		// detail back on.
		"logging": map[string]any{"logs": logs},
		"apps":    apps,
	}
}

// ProxyName is the proxy's own hostname under the user's domain.
func ProxyName(s state.Settings) string { return "proxy." + s.Domain }

// adminUpstream is the admin's unix socket as a reverse_proxy handler.
func adminUpstream(in Input) map[string]any {
	return map[string]any{
		"handler":   "reverse_proxy",
		"upstreams": []any{map[string]any{"dial": "unix/" + in.UISocket}},
	}
}

// issuers picks how certificates are obtained: the internal CA under the
// admin's root, or ACME with the DNS challenge for a public wildcard. The
// trial stage points at the staging CA.
func issuers(in Input) []any {
	if !Public(in) {
		return []any{map[string]any{"module": "internal", "ca": in.RootID}}
	}
	provider := map[string]any{"name": in.DNS.Provider}
	for k, v := range in.DNS.Fields {
		provider[k] = v
	}
	acme := map[string]any{
		"module": "acme",
		"challenges": map[string]any{
			"dns": map[string]any{
				"provider":  provider,
				"resolvers": Resolvers,
			},
		},
	}
	if in.State.Settings.Certificates.Stage == state.StageTrial {
		acme["ca"] = Staging
	}
	return []any{acme}
}

func adminServer(in Input, proxyName string) map[string]any {
	// proxy.<domain> gets its real certificate; any other name or an IP
	// gets the setup certificate, so the UI answers on every address.
	var policies []any
	if proxyName != "" {
		policies = append(policies, map[string]any{"match": map[string]any{"sni": []string{proxyName}}})
	}
	policies = append(policies, map[string]any{
		"default_sni":           setupSNI,
		"certificate_selection": map[string]any{"any_tag": []string{"setup"}},
	})
	for _, p := range policies {
		p.(map[string]any)["protocol_min"] = "tls1.2"
	}
	return map[string]any{
		"listen":          []string{":8443"},
		"automatic_https": map[string]any{"disable": true},
		"routes": []any{
			// /internal/ is for the reset-password command over the unix
			// socket only; it never exists from the network.
			map[string]any{
				"match":    []any{map[string]any{"path": []string{"/internal/*"}}},
				"handle":   []any{map[string]any{"handler": "static_response", "status_code": 404}},
				"terminal": true,
			},
			map[string]any{"handle": []any{adminUpstream(in)}},
		},
		"tls_connection_policies": policies,
	}
}

// trustServer is :80. Host names redirect to HTTPS; the proxy's own name
// and its bare IP serve the trust page from the admin (plain HTTP, because
// a device that does not trust the CA yet cannot load it over HTTPS).
func trustServer(in Input, hostNames []string) map[string]any {
	routes := []any{
		map[string]any{
			"match": []any{map[string]any{"path": []string{"/healthz"}}},
			"handle": []any{map[string]any{
				"handler":     "static_response",
				"status_code": 200,
				"body":        "ok\n",
			}},
		},
	}
	routes = append(routes, shortLinkRoutes(in.State)...)
	if len(hostNames) > 0 {
		routes = append(routes, map[string]any{
			"match": []any{map[string]any{"host": hostNames}},
			"handle": []any{map[string]any{
				"handler":     "static_response",
				"status_code": 308,
				"headers":     map[string]any{"Location": []string{"https://{http.request.host}{http.request.uri}"}},
			}},
		})
	}
	// Only the trust page and what it needs; the admin refuses the rest
	// without a session anyway, but there is no reason to expose it here.
	routes = append(routes,
		map[string]any{
			"match":  []any{map[string]any{"path": []string{"/trust", "/trust/*", "/assets/*", "/favicon.svg", "/api/v1/trust", "/api/v1/trust/*"}}},
			"handle": []any{adminUpstream(in)},
		},
		map[string]any{
			"handle": []any{map[string]any{
				"handler":     "static_response",
				"status_code": 302,
				"headers":     map[string]any{"Location": []string{"/trust"}},
			}},
		})
	return map[string]any{
		"listen":          []string{":80"},
		"automatic_https": map[string]any{"disable": true},
		"protocols":       []string{"h1"}, // plain port: no h2/h3, and no warning about it
		"routes":          routes,
	}
}

// shortLinkRoutes answer http://go/radarr/x?y with radarr.<domain>/x?y, the
// way go links work at work. Plain HTTP only: no certificate can name a
// host without a dot. A redirect, not permanent, so a changed name is not
// remembered wrong; one nobody has lands on the unknown-name page. Bare go/
// opens the proxy's own page, the list of names.
func shortLinkRoutes(st *state.State) []any {
	short := st.Settings.ShortName()
	if short == "" || st.Settings.Domain == "" {
		return nil
	}
	domain := st.Settings.Domain
	to := func(loc string) map[string]any {
		return map[string]any{"handler": "static_response", "status_code": 302, "headers": map[string]any{"Location": []string{loc}}}
	}
	name := map[string]any{"name": "short", "pattern": `^/([A-Za-z0-9][A-Za-z0-9-]*)(/.*)?$`}
	on := func(m map[string]any) []any {
		m["host"] = state.ShortHosts(short)
		return []any{m}
	}
	app := "https://{http.regexp.short.1}." + domain + "{http.regexp.short.2}"
	return []any{
		map[string]any{"match": on(map[string]any{"path_regexp": name, "expression": "{http.request.uri.query} != ''"}), "handle": []any{to(app + "?{http.request.uri.query}")}},
		map[string]any{"match": on(map[string]any{"path_regexp": name}), "handle": []any{to(app)}},
		map[string]any{"match": on(map[string]any{}), "handle": []any{to("https://" + ProxyName(st.Settings) + "/")}},
	}
}

// adminPort is the port a browser reaches the admin's :8443 at: the one in
// the address the account last signed in from (8444 when the compose
// published 8444:8443), else 8443 itself.
// AdminPort is adminPort for the server's links.
func AdminPort(set state.Settings) string { return adminPort(set) }

func adminPort(set state.Settings) string {
	if _, port, err := net.SplitHostPort(set.AdminAddress); err == nil && port != "" {
		return port
	}
	return "8443"
}

// hostsServer is :443. One route per host; a home-only host also needs a
// home address, otherwise the request falls through to the same connection
// close an unknown name gets, so outsiders cannot tell the two apart.
func hostsServer(in Input, st *state.State, hosts []state.Host, proxyName string) map[string]any {
	// The proxy's own name: the trust check lives here so a device can
	// prove it trusts the certificate; anything else goes to the admin UI.
	routes := []any{
		map[string]any{
			"match":    []any{map[string]any{"host": []string{proxyName}, "path": []string{"/trust/check"}}},
			"handle":   []any{adminUpstream(in)},
			"terminal": true,
		},
		// https://proxy.<ending> is the admin, with no port in the address;
		// it used to redirect to :8443, which put the port into every link
		// to the proxy. /internal/ stays off the network, as on :8443. One
		// route (a subroute), so the hosts keep their places after it.
		map[string]any{
			"match": []any{map[string]any{"host": []string{proxyName}}},
			"handle": []any{map[string]any{
				"handler": "subroute",
				"routes": []any{
					map[string]any{
						"match":  []any{map[string]any{"path": []string{"/internal/*"}}},
						"handle": []any{map[string]any{"handler": "static_response", "status_code": 404}},
					},
					map[string]any{"handle": []any{adminUpstream(in)}},
				},
			}},
			"terminal": true,
		},
	}
	for _, h := range hosts {
		match := map[string]any{"host": h.Names(st.Settings)}
		if h.Access == state.AccessHome {
			match["remote_ip"] = map[string]any{"ranges": homeNetworks(st.Settings, h)}
		}
		routes = append(routes, map[string]any{
			"match":    []any{match},
			"handle":   []any{securityHeaders(pinHTTPS(st.Settings, h)), proxyHandler(h, h.Names(st.Settings))},
			"terminal": true,
		})
	}
	// A name nothing answers to: a page for someone at home, who would
	// otherwise see a dropped connection and blame the proxy; outsiders
	// still get the drop, so a home-only name stays indistinguishable from
	// none. Someone at home matches every home-only name anyway.
	routes = append(routes,
		map[string]any{
			"match":    []any{map[string]any{"remote_ip": map[string]any{"ranges": homeNetworks(st.Settings, state.Host{})}}},
			"handle":   []any{unknownNameResponse(proxyName)},
			"terminal": true,
		},
		map[string]any{
			"handle": []any{map[string]any{"handler": "static_response", "abort": true}},
		})
	return map[string]any{
		"listen":          []string{":443"},
		"automatic_https": map[string]any{"disable": true},
		// The Host header must name the same site the TLS handshake did, so
		// one host's certificate cannot be used to reach another's backend.
		"strict_sni_host": true,
		"routes":          routes,
		"errors":          map[string]any{"routes": []any{targetDownRoute()}},
		"tls_connection_policies": []any{map[string]any{
			"protocol_min": "tls1.2",
		}},
	}
}

// probeServer is TLS and nothing else: the same certificates as :443, picked
// by SNI, and every request aborted. It has no access rules because a unix
// socket has no client address; only the admin (group bsd) can open it.
func probeServer(in Input) map[string]any {
	return map[string]any{
		"listen":          []string{"unix/" + in.ProbeSocket + "|0660"},
		"automatic_https": map[string]any{"disable": true},
		"routes": []any{map[string]any{
			"handle": []any{map[string]any{"handler": "static_response", "abort": true}},
		}},
		"tls_connection_policies": []any{map[string]any{
			"protocol_min": "tls1.2",
		}},
	}
}

// targetDownRoute replaces Caddy's bare 502 with a page a visitor can read:
// the name they asked for, that it is not answering, and an automatic
// retry. Nothing about the target leaks.
func targetDownRoute() map[string]any {
	return map[string]any{
		"match": []any{map[string]any{"expression": "{http.error.status_code} in [502, 503, 504]"}},
		"handle": []any{map[string]any{
			"handler":     "static_response",
			"status_code": 503,
			"headers": map[string]any{
				"Content-Type":  []string{"text/html; charset=utf-8"},
				"Retry-After":   []string{"5"},
				"Cache-Control": []string{"no-store"},
			},
			"body": targetDownHTML,
		}},
	}
}

// targetDownHTML uses Caddy placeholders for the host name; everything else
// is static. Styled to match the admin, inline so it needs no assets.
const targetDownHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="refresh" content="5"><title>Not responding</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f4f2;color:#1d1d1f;font-family:system-ui,sans-serif}main{max-width:32rem;margin:1rem;padding:2.5rem;background:#fff;border:1px solid #d9d9d6;border-radius:1rem}h1{margin:0 0 .5rem;font-size:1.6rem;line-height:1.25}p{margin:0;color:#5c5c62;line-height:1.5}code{font-family:ui-monospace,monospace;color:#1d1d1f}@media(prefers-color-scheme:dark){body{background:#1d1d20;color:#f4f4f2}main{background:#28282c;border-color:#3b3b40}p{color:#a6a6ae}code{color:#f4f4f2}}</style></head><body><main><h1><code>{http.request.host}</code> isn't responding right now</h1><p>The proxy reached out to the service behind this address and got no answer. This page tries again every few seconds; if it keeps happening, check that the service is running.</p></main></body></html>`

// unknownNameResponse says that the name leads nowhere from here, and where
// names are given.
func unknownNameResponse(proxyName string) map[string]any {
	return map[string]any{
		"handler":     "static_response",
		"status_code": 404,
		"headers": map[string]any{
			"Content-Type":  []string{"text/html; charset=utf-8"},
			"Cache-Control": []string{"no-store"},
		},
		"body": strings.ReplaceAll(unknownNameHTML, "PROXYNAME", proxyName),
	}
}

const unknownNameHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>No app here</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f4f2;color:#1d1d1f;font-family:system-ui,sans-serif}main{max-width:32rem;margin:1rem;padding:2.5rem;background:#fff;border:1px solid #d9d9d6;border-radius:1rem}h1{margin:0 0 .5rem;font-size:1.6rem;line-height:1.25}p{margin:0 0 .75rem;color:#5c5c62;line-height:1.5}a{color:#2563eb}code{font-family:ui-monospace,monospace;color:#1d1d1f}@media(prefers-color-scheme:dark){body{background:#1d1d20;color:#f4f4f2}main{background:#28282c;border-color:#3b3b40}p{color:#a6a6ae}a{color:#60a5fa}code{color:#f4f4f2}}</style></head><body><main><h1>No app is called <code>{http.request.host}</code></h1><p>Nothing on this proxy answers to that name from here. Check how it is spelled, or that the app still has this name.</p><p>Every name is listed at <a href="https://PROXYNAME/">PROXYNAME</a>.</p></main></body></html>`

// pinHTTPS: HSTS only where it cannot lock anyone out. A browser that has
// seen HSTS refuses the name outright, with no way past the warning, once
// the certificate changes: a new ending, a restored backup, going back to
// the proxy's own root, an old DNS record leading to another proxy. So
// only names open to the internet with a public certificate get it.
func pinHTTPS(set state.Settings, h state.Host) bool {
	return h.Access == state.AccessInternet && set.Mode() == state.ModePublic && set.Certificates != nil
}

// hstsOff clears what earlier versions told browsers (a year of HSTS on
// every name) as soon as a browser opens the name with a good certificate.
const hstsOff = "max-age=0"

// securityHeaders are added to every proxied response. Only headers that
// never break an application: no frame or content-security policy, which
// the applications themselves own.
func securityHeaders(pin bool) map[string]any {
	hsts := hstsOff
	if pin {
		hsts = "max-age=31536000"
	}
	return map[string]any{
		"handler": "headers",
		"response": map[string]any{
			"set": map[string]any{
				"Strict-Transport-Security": []string{hsts},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Referrer-Policy":           []string{"strict-origin-when-cross-origin"},
			},
			"deferred": true,
		},
	}
}

func homeNetworks(s state.Settings, h state.Host) []string {
	extra := s.TrustedNetworks
	if len(h.TrustedNetworks) > 0 {
		extra = h.TrustedNetworks
	}
	out := append([]string(nil), homeRanges...)
	out = append(out, extra...)
	return out
}

func proxyHandler(host state.Host, names []string) map[string]any {
	t := host.Target
	addr := t.Address + ":" + itoa(t.Port)
	h := map[string]any{
		"handler":   "reverse_proxy",
		"upstreams": []any{map[string]any{"dial": addr}},
	}
	// OwnOrigin (per name, off by default): an app that checks Origin or
	// Referer against its own address (UniFi: 403 on login, then 401 on
	// every call, 2026-10-26) sees the name instead. Only a request from the
	// name's own pages is rewritten, to the app's address: one from any
	// other site keeps its headers, so the app's CSRF check still holds.
	// Not the default: most apps compare Origin with Host, which the
	// rewrite would break.
	if host.OwnOrigin && len(names) > 0 {
		scheme, defPort := "http", 80
		if t.HTTPS {
			scheme, defPort = "https", 443
		}
		own := scheme + "://" + t.Address
		if t.Port != defPort {
			own += ":" + itoa(t.Port)
		}
		// Referer the same way, path kept: UniFi's API answered 401 to a
		// Referer naming the name, after a login that went through.
		var origin, referer []any
		for _, n := range names {
			q := regexp.QuoteMeta(n)
			origin = append(origin, map[string]any{"search_regexp": "^https://" + q + "$", "replace": own})
			referer = append(referer, map[string]any{"search_regexp": "^https://" + q + "(/.*)?$", "replace": own + "${1}"})
		}
		h["headers"] = map[string]any{"request": map[string]any{"replace": map[string]any{"Origin": origin, "Referer": referer}}}
	}
	if t.HTTPS {
		tlsCfg := map[string]any{}
		if t.AcceptUntrusted {
			tlsCfg["insecure_skip_verify"] = true
		}
		h["transport"] = map[string]any{"protocol": "http", "tls": tlsCfg}
	}
	return h
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
