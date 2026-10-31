package server

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/state"
	"github.com/daemonless/reverse-proxy/admin/internal/uptime"
)

// hostsUptime is the names list's view: each name's state, its percentages
// and the last 24 hours.
func (s *Server) hostsUptime(w http.ResponseWriter, _ *http.Request) {
	out := map[string]uptime.Summary{}
	if s.Uptime != nil {
		out = s.Uptime.Summaries()
	}
	writeJSON(w, http.StatusOK, map[string]any{"uptime": out, "every": int(uptime.Every.Seconds()), "enabled": !s.mgr.State().Settings.UptimeOff})
}

func (s *Server) hostUptime(w http.ResponseWriter, r *http.Request) {
	st := s.mgr.State()
	if i := st.Find(r.PathValue("id")); i < 0 || st.Hosts[i].DeletedAt != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such host"})
		return
	}
	var d uptime.Detail
	if s.Uptime != nil {
		d, _ = s.Uptime.Detail(r.PathValue("id"))
	}
	if d.State == "" {
		d.State = "unknown"
	}
	if d.Hours == nil {
		d.Hours = []uptime.Hour{}
	}
	if d.Outages == nil {
		d.Outages = []uptime.Outage{}
	}
	writeJSON(w, http.StatusOK, d)
}

// alertsView never returns the URL itself: an ntfy topic or a webhook's
// path is as good as a password. Where it goes is enough to recognise it.
func (s *Server) alertsView() map[string]any {
	st := s.mgr.State().Settings
	a := st.Alerts
	out := map[string]any{"kind": "", "to": "", "enabled": !st.UptimeOff}
	if a != nil {
		out["kind"] = a.Kind
		if u, err := url.Parse(a.URL); err == nil {
			out["to"] = u.Host
		}
	}
	s.mu.Lock()
	if s.alertErr != "" {
		out["lastError"], out["lastErrorAt"] = s.alertErr, s.alertErrAt
	}
	s.mu.Unlock()
	return out
}

func (s *Server) getAlerts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.alertsView())
}

type alertsInput struct {
	Kind string `json:"kind"`
	URL  string `json:"url"`
}

func (in alertsInput) check() (*state.Alerts, error) {
	in.URL = strings.TrimSpace(in.URL)
	if in.URL == "" {
		return nil, nil
	}
	if in.Kind != uptime.KindNtfy && in.Kind != uptime.KindWebhook {
		return nil, &state.FieldError{Field: "kind", Msg: "choose ntfy or webhook"}
	}
	u, err := url.Parse(in.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		msg := "enter the address to post to, like https://hooks.example.com/proxy"
		if in.Kind == uptime.KindNtfy {
			msg = "enter the topic's address, like https://ntfy.sh/my-proxy"
		}
		return nil, &state.FieldError{Field: "url", Msg: msg}
	}
	if in.Kind == uptime.KindNtfy && strings.Trim(u.Path, "/") == "" {
		return nil, &state.FieldError{Field: "url", Msg: "add the topic: https://" + u.Host + "/your-topic"}
	}
	return &state.Alerts{Kind: in.Kind, URL: in.URL}, nil
}

// putAlerts saves where alerts go; an empty url turns them off.
func (s *Server) putAlerts(w http.ResponseWriter, r *http.Request) {
	var in alertsInput
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	a, err := in.check()
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.mgr.Note(func(st *state.State) { st.Settings.Alerts = a }); err != nil {
		writeError(w, err)
		return
	}
	s.mu.Lock()
	s.alertErr = ""
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, s.alertsView())
}

// putUptimeEnabled turns the checks on or off for every name.
func (s *Server) putUptimeEnabled(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	if err := s.mgr.Note(func(st *state.State) { st.Settings.UptimeOff = !in.Enabled }); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.alertsView())
}

// testAlert sends a test to the saved place, or to one being typed in
// before it is saved, and says what went wrong.
func (s *Server) testAlert(w http.ResponseWriter, r *http.Request) {
	var in alertsInput
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	a, err := in.check()
	if err != nil {
		writeError(w, err)
		return
	}
	if a == nil {
		a = s.mgr.State().Settings.Alerts
	}
	if a == nil {
		writeError(w, &state.FieldError{Field: "url", Msg: "enter where to send alerts first"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := uptime.Send(ctx, a.Kind, a.URL, uptime.Event{Example: true}); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "The test was not delivered: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": true})
}

// Alert sends e to the saved place, if any, and keeps the last failure for
// Settings to show. Called by the uptime monitor, one goroutine per event.
func (s *Server) Alert(e uptime.Event) {
	a := s.mgr.State().Settings.Alerts
	if a == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	title, _ := e.Text()
	err := uptime.Send(ctx, a.Kind, a.URL, e)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		log.Printf("[admin] alert %q not sent: %v", title, err)
		s.alertErr, s.alertErrAt = err.Error(), time.Now().UTC()
		return
	}
	log.Printf("[admin] alert %q sent", title)
	s.alertErr = ""
}
