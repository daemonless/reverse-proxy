// Package server is the admin's HTTP surface: UI and API, served on a unix
// socket behind Caddy.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/app"
	"github.com/daemonless/reverse-proxy/admin/internal/auth"
	"github.com/daemonless/reverse-proxy/admin/internal/caddy"
	"github.com/daemonless/reverse-proxy/admin/internal/certs"
	"github.com/daemonless/reverse-proxy/admin/internal/dns"
	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// Runner answers whether Caddy is up.
type Runner interface{ Running() bool }

// Server serves the UI and API.
type Server struct {
	// instance tells this proxy apart from another one answering for the
	// same name (a second proxy with the same ending, an old DNS record).
	instance string
	// CheckProvider asks the DNS provider whether new credentials work
	// before the trial starts; nil skips it (tests stay offline).
	CheckProvider func(ctx context.Context, c *dns.Config, domain string) error
	version       string
	caddy         Runner
	mgr           *app.Manager
	mux           *http.ServeMux
	sessions      *auth.Sessions
	limiter       *auth.Limiter

	secrets string // directory holding the root CA files
	// TrustPort is the host port that reaches the plain-HTTP trust listener
	// (RP_TRUST_PORT). The container cannot see its own port mappings, so
	// the trust page is told what to put in its commands and QR code.
	TrustPort int
	// CaddyVersion is what `caddy version` printed at startup (About page).
	CaddyVersion string
	// IssuanceLog is Caddy's certificate log (see caddy.Input); Observe
	// does a TLS handshake with the proxy by name. Both are nil/empty in
	// tests, which then see "no certificate yet".
	IssuanceLog string
	Observe     func(ctx context.Context, serverName string) certs.Observation
	// DNSRefused is Caddy's error when it refused the saved credentials at
	// startup and the proxy runs without them; "" (or nil) otherwise.
	DNSRefused func() string

	mu       sync.Mutex
	tokenBad *dns.Problem         // the last daily token check, when it failed
	tokenAt  time.Time            // when tokenBad was found
	setupTok string               // one-time token from the log; empty once setup is done
	touched  map[string]time.Time // key id -> last time its use was written
	// pairCodes are one-time codes (Connected apps, "Connect a fjord…")
	// with their expiry: a fjord elsewhere redeems one for a key.
	pairCodes map[string]time.Time
}

// New wires the routes. setupToken is the first-run token, or "" when a
// password already exists; secrets is where the root CA lives.
func New(version string, caddy Runner, mgr *app.Manager, setupToken, secrets string) *Server {
	s := &Server{instance: newInstance(), version: version, caddy: caddy, mgr: mgr, mux: http.NewServeMux(),
		sessions: auth.NewPersistentSessions(filepath.Join(secrets, "sessions.json")), limiter: auth.NewLimiter(), setupTok: setupToken, secrets: secrets, TrustPort: 80}
	// Public: health, where-am-I, first run, sign in, the UI shell.
	s.mux.HandleFunc("GET /healthz", s.healthz)
	s.mux.HandleFunc("GET /api/v1/status", s.status)
	s.mux.HandleFunc("GET /api/v1/session", s.session)
	s.mux.HandleFunc("POST /api/v1/setup/token", s.setupToken)
	s.mux.HandleFunc("POST /api/v1/setup/password", s.setupPassword)
	s.mux.HandleFunc("POST /api/v1/login", s.login)
	// Linking a fjord elsewhere: the admin mints a code, the fjord redeems
	// it for a key. Public like login, and limited like it.
	s.mux.HandleFunc("POST /api/v1/pair/code", s.requireAdmin(s.newPairCode))
	s.mux.HandleFunc("POST /api/v1/pair", s.pair)
	s.mux.HandleFunc("PUT /api/v1/me", s.requireAuth(s.me))
	s.mux.HandleFunc("POST /api/v1/logout", s.logout)
	s.mux.HandleFunc("POST /api/v1/restore", s.restoreBackup) // guards itself: open only before setup
	// The trust page and what it needs are public: a device that does not
	// trust the proxy yet is exactly who needs them.
	s.mux.HandleFunc("GET /trust/root.crt", s.rootCert)
	s.mux.HandleFunc("GET /trust/root.der", s.rootDER)
	s.mux.HandleFunc("GET /trust/qr.png", s.qr)
	s.mux.HandleFunc("GET /trust/check", s.trustCheck)
	s.mux.HandleFunc("GET /api/v1/trust", s.trustInfo)
	s.mux.Handle("GET /", uiHandler())
	// Socket-only: the reset-password command.
	s.mux.HandleFunc("POST /internal/reset", s.reset)
	s.mux.HandleFunc("GET /api/v1/openapi.json", openAPI)
	// The hosts API (v1, see openapi.json): the account, the command line
	// over the socket, or a connected app's key.
	s.mux.HandleFunc("GET /api/v1/hosts", s.requireAuth(s.listHosts))
	s.mux.HandleFunc("GET /api/v1/hosts/health", s.requireAuth(s.hostsHealth))
	s.mux.HandleFunc("POST /api/v1/hosts", s.requireAuth(s.createHost))
	s.mux.HandleFunc("GET /api/v1/hosts/{id}", s.requireAuth(s.getHost))
	s.mux.HandleFunc("PUT /api/v1/hosts/{id}", s.requireAuth(s.updateHost))
	s.mux.HandleFunc("DELETE /api/v1/hosts/{id}", s.requireAuth(s.deleteHost))
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/restore", s.requireAuth(s.restoreHost))
	s.mux.HandleFunc("GET /api/v1/probe", s.requireAuth(s.probe))
	// The proxy's own settings: the account only (and the command line).
	s.mux.HandleFunc("GET /api/v1/settings", s.requireAdmin(s.getSettings))
	s.mux.HandleFunc("PUT /api/v1/settings", s.requireAdmin(s.putSettings))
	s.mux.HandleFunc("GET /api/v1/dns-check", s.requireAdmin(s.dnsCheck))
	s.mux.HandleFunc("GET /api/v1/suggest-domain", s.requireAdmin(s.suggestDomain))
	s.mux.HandleFunc("GET /api/v1/certificates", s.requireAdmin(s.getCertificates))
	s.mux.HandleFunc("GET /api/v1/certificates/detect", s.requireAdmin(s.detectProvider))
	s.mux.HandleFunc("PUT /api/v1/certificates", s.requireAdmin(s.putCertificates))
	s.mux.HandleFunc("DELETE /api/v1/certificates", s.requireAdmin(s.deleteCertificates))
	s.mux.HandleFunc("GET /api/v1/sources/fjord", s.requireAdmin(s.getFjordSource))
	s.mux.HandleFunc("PUT /api/v1/sources/fjord", s.requireAdmin(s.putFjordSource))
	s.mux.HandleFunc("GET /api/v1/sources/fjord/services", s.requireAdmin(s.fjordServices))
	s.mux.HandleFunc("PUT /api/v1/password", s.requireAdmin(s.changePassword))
	s.mux.HandleFunc("POST /api/v1/backup", s.requireAdmin(s.createBackup))
	s.mux.HandleFunc("GET /api/v1/tokens", s.requireAdmin(s.listTokens))
	s.mux.HandleFunc("POST /api/v1/tokens", s.requireAdmin(s.createToken))
	s.mux.HandleFunc("DELETE /api/v1/tokens/{id}", s.requireAdmin(s.deleteToken))
	s.mux.HandleFunc("PUT /api/v1/tokens/{id}", s.requireAdmin(s.setTokenDisabled))
	return s
}

// AdminAlive reports whether something answers on the admin socket: a
// running admin. Checked before anything on disk is touched, so a second
// start (the binary typed in a shell) changes nothing.
func AdminAlive(path string) bool {
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// Handler exposes the mux for tests.
func (s *Server) Handler() http.Handler { return s.mux }

// ServeUnix listens on a unix socket until ctx is done. The socket is
// group-accessible so Caddy (root, but any group member too) can reach it.
// A socket that answers belongs to a running admin: `reverse-proxy` typed
// in a shell with no command used to unlink it from under that admin and
// leave the container without one until a restart.
func (s *Server) ServeUnix(ctx context.Context, path string) error {
	if AdminAlive(path) {
		return fmt.Errorf("an admin is already serving %s; for the command line use `reverse-proxy hosts` or `reverse-proxy reset-password`", path)
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return err
	}
	srv := &http.Server{Handler: s.mux, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// writeError maps the error kinds the manager returns to plain responses:
// a field the person must fix, a configuration Caddy refused, or a fault.
func writeError(w http.ResponseWriter, err error) {
	var fe *state.FieldError
	var ce *app.CaddyError
	switch {
	case errors.As(err, &fe):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": fe.Msg, "field": fe.Field})
	case errors.As(err, &ce):
		log.Printf("[admin] %v", err)
		writeJSON(w, http.StatusConflict, map[string]any{"error": "The change was not applied; the previous configuration is still running.", "detail": ce.Err.Error()})
	default:
		log.Printf("[admin] %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Something went wrong on the proxy; see its log."})
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &state.FieldError{Field: "", Msg: fmt.Sprintf("request body: %v", err)}
	}
	return nil
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	if !s.caddy.Running() {
		http.Error(w, "caddy not running", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
}

// status is public but says little; the details need a session.
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	// A key that is sent and refused is an answer the app needs (it was
	// disconnected), not the public view.
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") && s.who(r) == nobody {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "this key is not accepted (disconnected?)"})
		return
	}
	st := s.mgr.State()
	out := map[string]any{
		"product":    "reverse-proxy",
		"apiVersion": 1,
		"version":    s.version,
		"caddy":      map[string]any{"running": s.caddy.Running(), "version": s.CaddyVersion},
		"setup":      map[string]any{"complete": st.Settings.AdminPasswordHash != ""},
	}
	// Until setup is done, the app that installed the proxy (a paired key
	// with a way back): the setup page sends people there to press Finish
	// setup, which opens it verified, instead of into the log for a token.
	// Its label and address only, never the key.
	if st.Settings.AdminPasswordHash == "" {
		for _, t := range st.Tokens {
			if t.Paired && !t.Disabled && t.URL != "" {
				out["installedBy"] = map[string]any{"name": t.Label, "url": t.URL}
				break
			}
		}
	}
	if s.who(r) != nobody {
		out["domain"] = st.Settings.Domain
		if u := AdminURL(st); u != "" {
			out["adminUrl"] = u
		}
		out["mode"] = st.Settings.Mode()
		out["hosts"] = len(st.Live())
		out["certificates"] = s.certStatus(r.Context(), st).State
		if st.Settings.Domain != "" {
			out["proxyName"] = caddy.ProxyName(st.Settings)
			port := ""
			if s.TrustPort != 80 {
				port = ":" + strconv.Itoa(s.TrustPort)
			}
			out["trustUrl"] = "http://" + caddy.ProxyName(st.Settings) + port + "/trust"
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func newInstance() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
