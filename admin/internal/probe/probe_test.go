package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func split(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return host, n
}

func TestProbePlainAndTLS(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Server", "x"); w.WriteHeader(200) }))
	defer plain.Close()
	h, p := split(t, plain.Listener.Addr().String())
	if r := Probe(context.Background(), h, p); !r.Reachable || r.HTTPS || r.Status != 200 {
		t.Fatalf("plain: %+v", r)
	}
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer secure.Close()
	h, p = split(t, secure.Listener.Addr().String())
	if r := Probe(context.Background(), h, p); !r.Reachable || !r.HTTPS || !r.UntrustedCert || r.Status != 204 {
		t.Fatalf("self-signed https: %+v", r)
	}
}

// nginx on a plain port hangs up on a ClientHello instead of answering it
// with HTTP; that is still a plain http app (apprise-api, 2026-10-26).
func TestProbePlainServerThatHangsUpOnTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1)
				if _, err := c.Read(buf); err != nil || buf[0] == 0x16 { // a TLS record: hang up
					return
				}
				rest := make([]byte, 4096)
				c.Read(rest)
				c.Write([]byte("HTTP/1.0 200 OK\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n"))
			}(c)
		}
	}()
	h, p := split(t, ln.Addr().String())
	r := Probe(context.Background(), h, p)
	if !r.Reachable || r.HTTPS || r.UntrustedCert || r.Status != 200 {
		t.Fatalf("plain behind a hang-up: %+v", r)
	}
}

// An old DNS record that still points at the proxy makes the name a loop
// (radarr.apps.lan at the proxy's own address, jupiter 2026-10-26).
func TestProbeSeesItself(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	h, p := split(t, srv.Listener.Addr().String())
	if r := Probe(context.Background(), h, p); r.Self {
		t.Fatalf("another port on our own address is another service: %+v", r)
	}
	sitePorts[p] = true
	defer delete(sitePorts, p)
	if r := Probe(context.Background(), h, p); !r.Reachable || !r.Self {
		t.Fatalf("our own site port: %+v", r)
	}
}
