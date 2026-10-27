// Package probe looks at a target so Add Host can say "found a service" and
// pick http or https for the user.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Result is what we learned about address:port.
type Result struct {
	Reachable     bool   `json:"reachable"`
	HTTPS         bool   `json:"https"`
	UntrustedCert bool   `json:"untrustedCert"`
	Status        int    `json:"status,omitempty"`
	Server        string `json:"server,omitempty"`
	// Self: the target is this proxy's own 80 or 443, usually an old DNS
	// record for the name. Saving it makes the name a loop.
	Self bool `json:"self,omitempty"`
}

// sitePorts are the ports Caddy serves names on inside the container. Other
// ports on the proxy's own address are other services (host networking).
var sitePorts = map[int]bool{80: true, 443: true}

// isSelf reports whether address resolves to one of this container's own
// addresses.
func isSelf(ctx context.Context, address string, port int) bool {
	if !sitePorts[port] {
		return false
	}
	ips := []net.IP{net.ParseIP(address)}
	if ips[0] == nil {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, address)
		if err != nil {
			return false
		}
		ips = ips[:0]
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	own, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IsLoopback() {
			return true
		}
		for _, a := range own {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

const timeout = 3 * time.Second

// Probe runs from inside the container, where the proxy itself will connect
// from, so what it sees is what Caddy will see.
func Probe(ctx context.Context, address string, port int) Result {
	var r Result
	addr := net.JoinHostPort(address, strconv.Itoa(port))
	d := net.Dialer{Timeout: timeout}

	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return r
	}
	conn.Close()
	r.Reachable = true
	if isSelf(ctx, address, port) {
		r.Self = true
		return r
	}

	// Is it TLS? A plain HTTP server answers the ClientHello with something
	// that is not a TLS record; a certificate we cannot verify, or an alert
	// (the server wants an SNI we don't know), still means TLS. Anything
	// else -- the server hung up on the ClientHello, as nginx on a plain
	// port does -- is settled by asking in plain HTTP: an answer there is
	// an http app (apprise behind nginx read as https, and the proxy then
	// spoke TLS to it: 503 behind its name).
	tconn, err := tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: address, MinVersion: tls.VersionTLS12})
	switch {
	case err == nil:
		tconn.Close()
		r.HTTPS = true
	case errors.As(err, new(tls.RecordHeaderError)):
		// not TLS
	case errors.As(err, new(x509.UnknownAuthorityError)), errors.As(err, new(x509.HostnameError)),
		errors.As(err, new(x509.CertificateInvalidError)), errors.As(err, new(tls.AlertError)):
		r.HTTPS, r.UntrustedCert = true, true
	default:
		if !answersPlain(ctx, addr) {
			r.HTTPS, r.UntrustedCert = true, true
		}
	}

	scheme := "http"
	if r.HTTPS {
		scheme = "https"
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: r.UntrustedCert, MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+addr+"/", nil)
	resp, err := client.Do(req)
	if err != nil {
		return r
	}
	resp.Body.Close()
	r.Status = resp.StatusCode
	r.Server = resp.Header.Get("Server")
	return r
}

// answersPlain reports whether a plain HTTP request gets any HTTP answer.
func answersPlain(ctx context.Context, addr string) bool {
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/", nil)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}
