package server

import (
	"net/http"
	"net/url"
	"strings"

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
