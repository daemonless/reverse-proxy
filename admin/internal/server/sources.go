package server

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/sources"
	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

func (s *Server) getFjordSource(w http.ResponseWriter, _ *http.Request) {
	f := s.mgr.State().Settings.Sources.Fjord
	if f == nil {
		writeJSON(w, http.StatusOK, map[string]any{"url": "", "hasKey": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"url": f.URL, "hasKey": f.Key != ""})
}

// putFjordSource saves the connection. The key is write-only: an empty
// key in the request keeps the stored one; "-" clears it.
func (s *Server) putFjordSource(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL string `json:"url"`
		Key string `json:"key"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	in.URL = strings.TrimRight(strings.TrimSpace(in.URL), "/")
	err := s.mgr.Apply(func(st *state.State) error {
		if in.URL == "" {
			st.Settings.Sources.Fjord = nil
			return nil
		}
		u, err := url.Parse(in.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return &state.FieldError{Field: "url", Msg: "enter fjord's address, like http://nas.lan:3567"}
		}
		f := st.Settings.Sources.Fjord
		if f == nil {
			f = &state.FjordSource{}
		}
		f.URL = in.URL
		switch in.Key {
		case "":
		case "-":
			f.Key = ""
		default:
			f.Key = strings.TrimSpace(in.Key)
		}
		st.Settings.Sources.Fjord = f
		return nil
	})
	if err != nil {
		writeError(w, err)
		return
	}
	s.getFjordSource(w, r)
}

// fjordServices lists what fjord runs, marked with the host already made
// for each (by ref), so the picker can say "already added".
func (s *Server) fjordServices(w http.ResponseWriter, r *http.Request) {
	st := s.mgr.State()
	f := st.Settings.Sources.Fjord
	if f == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "connect fjord in Settings first"})
		return
	}
	svcs, err := (sources.Fjord{URL: f.URL, Key: f.Key}).Services(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	byRef := map[string]state.Host{}
	for _, h := range st.Live() {
		if h.Ref != "" {
			byRef[h.Ref] = h
		}
	}
	type row struct {
		sources.Service
		Added     *string `json:"added,omitempty"` // host id when already added
		AddedName string  `json:"addedName,omitempty"`
	}
	out := make([]row, 0, len(svcs))
	for _, sv := range svcs {
		rw := row{Service: sv}
		if h, ok := byRef[sv.Ref]; ok {
			id := h.ID
			rw.Added = &id
			rw.AddedName = h.Names(st.Settings)[0]
		}
		out = append(out, rw)
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": out, "fjord": sources.HostOf(f.URL)})
}

// getPodmanSource is what the podman-labels unit last reported; nil when
// it never did (no socket mounted, or an image without the unit).
func (s *Server) getPodmanSource(w http.ResponseWriter, _ *http.Request) {
	src := s.mgr.State().Settings.Sources
	out := struct {
		state.PodmanSource
		Enabled bool `json:"enabled"`
	}{Enabled: !src.PodmanOff}
	if src.Podman != nil {
		out.PodmanSource = *src.Podman
	}
	writeJSON(w, http.StatusOK, out)
}

// putPodmanEnabled is the Settings switch. Off removes every name made
// from a label at once, held so it comes back as it was; on lets them go
// back to the normal undo window, and the unit names the containers again.
func (s *Server) putPodmanEnabled(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	if in.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "enabled is required"})
		return
	}
	now := time.Now().UTC()
	err := s.mgr.Apply(func(st *state.State) error {
		st.Settings.Sources.PodmanOff = !*in.Enabled
		for i := range st.Hosts {
			h := &st.Hosts[i]
			if !strings.HasPrefix(h.Ref, state.PodmanRefPrefix) {
				continue
			}
			if !*in.Enabled && h.DeletedAt == nil {
				h.DeletedAt, h.Held = &now, true
			} else if *in.Enabled && h.Held {
				h.DeletedAt, h.Held = &now, false
			}
		}
		return nil
	})
	if err != nil {
		writeError(w, err)
		return
	}
	s.getPodmanSource(w, r)
}

// putPodmanSource is the unit's report after each reconcile. Only the unit
// writes it, over the admin's local socket.
func (s *Server) putPodmanSource(w http.ResponseWriter, r *http.Request) {
	if s.who(r) != local {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "only the podman-labels unit reports here"})
		return
	}
	var in state.PodmanSource
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	in.At = time.Now().UTC()
	if len(in.Waiting) > 100 {
		in.Waiting = in.Waiting[:100]
	}
	if len(in.Problems) > 100 {
		in.Problems = in.Problems[:100]
	}
	if len(in.Elsewhere) > 100 {
		in.Elsewhere = in.Elsewhere[:100]
	}
	err := s.mgr.Note(func(st *state.State) {
		st.Settings.Sources.Podman = &in
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, in)
}
