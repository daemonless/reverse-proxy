package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/app"
	"github.com/daemonless/reverse-proxy/admin/internal/certs"
	"github.com/daemonless/reverse-proxy/admin/internal/dns"
	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// certStatus is how the wildcard certificate is doing right now.
func (s *Server) certStatus(ctx context.Context, st *state.State) certs.Status {
	var obs certs.Observation
	if s.Observe != nil && st.Settings.Domain != "" && st.Settings.Certificates != nil {
		obs = s.Observe(ctx, "proxy."+st.Settings.Domain)
	}
	var ev *certs.Event
	if s.IssuanceLog != "" && st.Settings.Domain != "" {
		if e, ok := certs.LastEvent(s.IssuanceLog, "*."+st.Settings.Domain); ok {
			ev = &e
		}
	}
	if s.DNSRefused != nil {
		if msg := s.DNSRefused(); msg != "" {
			ev = &certs.Event{At: time.Now(), Error: msg}
		}
	}
	s.mu.Lock()
	bad := s.tokenBad
	if ev != nil && ev.OK && ev.At.After(s.tokenAt) {
		bad = nil // renewed since: the token works again
	}
	s.mu.Unlock()
	status := certs.Compute(st.Settings, obs, ev, bad, st.Settings.Domain, time.Now())
	if status.State == "failed" && status.Detail == "" && s.IssuanceLog != "" {
		status.Detail = certs.LastLine(s.IssuanceLog, "*."+st.Settings.Domain)
	}
	return status
}

// WatchToken asks the DNS provider once a day whether the saved token
// still works, so a revoked one is said when it happens, not when the
// certificate is about to run out. The first check is a minute after
// start; status reads only the cached answer. A failed token is asked
// again every hour, so mending it at the provider clears the warning.
func (s *Server) WatchToken(ctx context.Context, every time.Duration) {
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.checkToken(ctx)
		s.mu.Lock()
		next := every
		if s.tokenBad != nil {
			next = min(every, time.Hour)
		}
		s.mu.Unlock()
		t.Reset(next)
	}
}

func (s *Server) checkToken(ctx context.Context) {
	st := s.mgr.State()
	c := st.Settings.Certificates
	if s.CheckProvider == nil || c == nil || c.Stage != state.StageLive || st.Settings.Domain == "" {
		return
	}
	cfg, err := dns.Load(s.secrets)
	if err != nil {
		return
	}
	var bad *dns.Problem
	// Anything but a Problem (no answer, an odd one) is not news.
	if !errors.As(s.CheckProvider(ctx, cfg, st.Settings.Domain), &bad) {
		bad = nil
	}
	if bad != nil {
		log.Printf("[admin] certificates: the %s token stopped working (%s): %s", cfg.Provider, bad.Kind, bad.Msg)
	}
	s.mu.Lock()
	s.tokenBad, s.tokenAt = bad, time.Now()
	s.mu.Unlock()
}

// forgetTokenCheck drops the last answer when the token changes.
func (s *Server) forgetTokenCheck() {
	s.mu.Lock()
	s.tokenBad = nil
	s.mu.Unlock()
}

func (s *Server) certView(ctx context.Context, st *state.State) map[string]any {
	out := map[string]any{
		"domain":    st.Settings.Domain,
		"mode":      st.Settings.Mode(),
		"providers": dns.Providers,
		"status":    s.certStatus(ctx, st),
	}
	if c := st.Settings.Certificates; c != nil {
		out["provider"] = c.Provider
	}
	return out
}

func (s *Server) getCertificates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.certView(r.Context(), s.mgr.State()))
}

// detectProvider guesses where the domain's DNS lives from its nameservers.
func (s *Server) detectProvider(w http.ResponseWriter, r *http.Request) {
	st := s.mgr.State()
	if st.Settings.Mode() != state.ModePublic {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "set a public address first"})
		return
	}
	writeJSON(w, http.StatusOK, dns.Detect(r.Context(), st.Settings.Domain))
}

// putCertificates saves the provider's credentials and starts the trial:
// Caddy asks the staging CA for the wildcard; once that works the watcher
// switches to the real CA.
func (s *Server) putCertificates(w http.ResponseWriter, r *http.Request) {
	var in dns.Config
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	if s.mgr.State().Settings.Mode() != state.ModePublic {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "automatic certificates need a public address"})
		return
	}
	if err := dns.Validate(&in); err != nil {
		writeError(w, err)
		return
	}
	if s.CheckProvider != nil {
		if err := s.CheckProvider(r.Context(), &in, s.mgr.State().Settings.Domain); err != nil {
			writeError(w, err)
			return
		}
	}
	// The render reads the secrets file, so it is written first and put
	// back (or removed) if Caddy refuses the result.
	old, err := dns.Load(s.secrets)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		writeError(w, err)
		return
	}
	if err := dns.Save(s.secrets, &in); err != nil {
		writeError(w, err)
		return
	}
	s.forgetTokenCheck()
	err = s.mgr.Apply(func(st *state.State) error {
		st.Settings.Certificates = &state.Certificates{Provider: in.Provider, Stage: state.StageTrial, StartedAt: time.Now()}
		return nil
	})
	if err != nil {
		if old != nil {
			dns.Save(s.secrets, old)
		} else {
			dns.Remove(s.secrets)
		}
		// Some modules check the credential's shape when Caddy loads the
		// config (Cloudflare does); that is the same "token rejected" to
		// the person, said the same way.
		var ce *app.CaddyError
		if errors.As(err, &ce) {
			label := in.Provider
			if p, ok := dns.Find(in.Provider); ok {
				label = p.Label
			}
			msg, detail := certs.Explain(ce.Err.Error(), s.mgr.State().Settings.Domain, label)
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg, "detail": detail})
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.certView(r.Context(), s.mgr.State()))
}

// deleteCertificates goes back to the internal CA and forgets the credentials.
func (s *Server) deleteCertificates(w http.ResponseWriter, r *http.Request) {
	s.forgetTokenCheck()
	err := s.mgr.Apply(func(st *state.State) error {
		st.Settings.Certificates = nil
		return nil
	})
	if err != nil {
		writeError(w, err)
		return
	}
	if err := dns.Remove(s.secrets); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.certView(r.Context(), s.mgr.State()))
}

// CheckProvider is the usual Server.CheckProvider: the domain's zone, then
// the provider's own check.
func CheckProvider(ctx context.Context, c *dns.Config, domain string) error {
	zone := dns.Detect(ctx, domain).Zone
	if zone == "" {
		zone = domain
	}
	return dns.Check(ctx, c, zone)
}
