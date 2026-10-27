package server

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/probe"
	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// hostInput is what a client may set on a host.
type hostInput struct {
	Name            string       `json:"name"`
	ExtraNames      []string     `json:"extraNames"`
	Target          state.Target `json:"target"`
	Access          state.Access `json:"access"`
	TrustedNetworks []string     `json:"trustedNetworks"`
	Ref             string       `json:"ref"`
	// OwnOrigin is kept as it was when absent: a client that predates it
	// (fjord's port follow PUTs the host back) must not switch it off.
	OwnOrigin *bool `json:"ownOrigin,omitempty"`
}

// hostView is a host as the API presents it, with the names resolved.
type hostView struct {
	state.Host
	Names []string `json:"names"`
	URL   string   `json:"url"`
}

func view(s state.Settings, h state.Host) hostView {
	names := h.Names(s)
	return hostView{Host: h, Names: names, URL: "https://" + names[0]}
}

func newID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (in hostInput) apply(h *state.Host) {
	h.Name = strings.ToLower(strings.TrimSpace(in.Name))
	h.ExtraNames = nil
	for _, n := range in.ExtraNames {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			h.ExtraNames = append(h.ExtraNames, n)
		}
	}
	h.Target = in.Target
	h.Target.Address = strings.TrimSpace(in.Target.Address)
	h.Access = in.Access
	if h.Access == "" {
		h.Access = state.AccessHome
	}
	if r := strings.TrimSpace(in.Ref); r != "" && len(r) <= 200 {
		h.Ref = r
	}
	h.TrustedNetworks = nil
	for _, n := range in.TrustedNetworks {
		if n = strings.TrimSpace(n); n != "" {
			h.TrustedNetworks = append(h.TrustedNetworks, n)
		}
	}
	if in.OwnOrigin != nil {
		h.OwnOrigin = *in.OwnOrigin
	}
}

// listHosts is the live hosts; ?include=removed adds the ones removed in
// the last 24 hours (deletedAt set), for a restore.
func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	st := s.mgr.State()
	hosts := st.Live()
	if r.URL.Query().Get("include") == "removed" {
		hosts = st.Hosts
	}
	out := []hostView{}
	for _, h := range hosts {
		out = append(out, view(st.Settings, h))
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": out})
}

// hostsHealth probes every live host's target at once so the list can show
// a status dot per host without one request each.
func (s *Server) hostsHealth(w http.ResponseWriter, r *http.Request) {
	st := s.mgr.State()
	out := map[string]probe.Result{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range st.Live() {
		wg.Add(1)
		go func(h state.Host) {
			defer wg.Done()
			res := probe.Probe(r.Context(), h.Target.Address, h.Target.Port)
			mu.Lock()
			out[h.ID] = res
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"health": out})
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	st := s.mgr.State()
	i := st.Find(r.PathValue("id"))
	if i < 0 || st.Hosts[i].DeletedAt != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such host"})
		return
	}
	writeJSON(w, http.StatusOK, view(st.Settings, st.Hosts[i]))
}

func (s *Server) createHost(w http.ResponseWriter, r *http.Request) {
	var in hostInput
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	h := state.Host{ID: newID(), CreatedAt: time.Now().UTC()}
	in.apply(&h)
	var existing *state.Host
	err := s.mgr.Apply(func(st *state.State) error {
		if st.Settings.Domain == "" {
			return &state.FieldError{Field: "", Msg: "set the address your services live under first (settings)"}
		}
		// One host per ref: a connected app that retries, or lost track of
		// what it made, gets the host it already has.
		for _, o := range st.Hosts {
			if h.Ref != "" && o.Ref == h.Ref && o.DeletedAt == nil {
				existing = &o
				return errRefTaken
			}
		}
		if err := state.ValidateHost(h, st.Hosts); err != nil {
			return err
		}
		// A removed host with this ref (or, by hand, this name) comes back
		// as this one: Remove and Undo, or remove and add again, used to
		// leave a removed record behind each time.
		for i := range st.Hosts {
			o := &st.Hosts[i]
			if o.DeletedAt == nil || !(h.Ref != "" && o.Ref == h.Ref || h.Ref == "" && o.Ref == "" && o.Name == h.Name) {
				continue
			}
			h.ID, h.CreatedAt = o.ID, o.CreatedAt
			*o = h
			return nil
		}
		st.Hosts = append(st.Hosts, h)
		return nil
	})
	if existing != nil {
		writeJSON(w, http.StatusConflict, view(s.mgr.State().Settings, *existing))
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, view(s.mgr.State().Settings, h))
}

func (s *Server) updateHost(w http.ResponseWriter, r *http.Request) {
	var in hostInput
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	id := r.PathValue("id")
	var out state.Host
	err := s.mgr.Apply(func(st *state.State) error {
		i := st.Find(id)
		if i < 0 || st.Hosts[i].DeletedAt != nil {
			return errNotFound
		}
		h := st.Hosts[i]
		in.apply(&h)
		if err := state.ValidateHost(h, st.Hosts); err != nil {
			return err
		}
		st.Hosts[i] = h
		out = h
		return nil
	})
	if err == errNotFound {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such host"})
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view(s.mgr.State().Settings, out))
}

// deleteHost is a soft delete: the host leaves Caddy at once and can be
// restored for state.UndoWindow.
func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	now := time.Now().UTC()
	err := s.mgr.Apply(func(st *state.State) error {
		i := st.Find(id)
		if i < 0 || st.Hosts[i].DeletedAt != nil {
			return errNotFound
		}
		st.Hosts[i].DeletedAt = &now
		return nil
	})
	if err == errNotFound {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such host"})
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "undoUntil": now.Add(state.UndoWindow)})
}

func (s *Server) restoreHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var out state.Host
	err := s.mgr.Apply(func(st *state.State) error {
		i := st.Find(id)
		if i < 0 || st.Hosts[i].DeletedAt == nil {
			return errNotFound
		}
		h := st.Hosts[i]
		h.DeletedAt = nil
		if err := state.ValidateHost(h, st.Hosts); err != nil {
			return err // its name was reused meanwhile
		}
		st.Hosts[i] = h
		out = h
		return nil
	})
	if err == errNotFound {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "nothing to restore"})
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view(s.mgr.State().Settings, out))
}

type settingsInput struct {
	Domain          string   `json:"domain"`
	TrustedNetworks []string `json:"trustedNetworks"`
	// ShortLinks: left out keeps what is set ("" turns them off).
	ShortLinks *string `json:"shortLinks"`
}

// resolvConf is read for the network's local domain; tests point it elsewhere.
var resolvConf = "/etc/resolv.conf"

// localDomain is the network's own domain (lan, home), as the router hands
// it out: the first search domain that is not the container engine's. The
// short-link record goes under it ("" when unknown).
func localDomain() string {
	raw, err := os.ReadFile(resolvConf)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || (f[0] != "search" && f[0] != "domain") {
			continue
		}
		for _, d := range f[1:] {
			d = strings.ToLower(strings.TrimSuffix(d, "."))
			if engineDomain(d) || d == "localdomain" {
				continue
			}
			return d
		}
	}
	return ""
}

// engineDomain is a search domain the container engine adds for its own
// names (podman's dns.podman, Kubernetes' cluster.local), not the
// network's: never an ending to suggest or a place for a record.
func engineDomain(d string) bool {
	return d == "dns.podman" || strings.HasSuffix(d, ".podman") || d == "cluster.local" || strings.HasSuffix(d, ".cluster.local")
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	st := s.mgr.State()
	out := settingsView(st.Settings)
	out["fallbackUrl"] = FallbackURL(r.Context(), st.Settings)
	writeJSON(w, http.StatusOK, out)
}

func settingsView(s state.Settings) map[string]any {
	nets := s.TrustedNetworks
	if nets == nil {
		nets = []string{}
	}
	return map[string]any{"domain": s.Domain, "mode": s.Mode(), "trustedNetworks": nets, "shortLinks": s.ShortName(), "localDomain": localDomain()}
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	before := s.mgr.State().Settings
	var in settingsInput
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	err := s.mgr.Apply(func(st *state.State) error {
		if err := state.ValidateDomain(in.Domain); err != nil {
			return err
		}
		if err := state.ValidateNetworks("trustedNetworks", in.TrustedNetworks); err != nil {
			return err
		}
		if in.ShortLinks != nil {
			name := strings.ToLower(strings.TrimSpace(*in.ShortLinks))
			if err := state.ValidateShortLinks(name); err != nil {
				return err
			}
			st.Settings.ShortLinks = &name
		}
		st.Settings.Domain = state.NormalizeDomain(in.Domain)
		st.Settings.TrustedNetworks = nil
		for _, n := range in.TrustedNetworks {
			if n = strings.TrimSpace(n); n != "" {
				st.Settings.TrustedNetworks = append(st.Settings.TrustedNetworks, n)
			}
		}
		return nil
	})
	if err != nil {
		writeError(w, err)
		return
	}
	// After a new ending the old name no longer opens; this is where the
	// browser goes on from.
	out := settingsView(s.mgr.State().Settings)
	out["fallbackUrl"] = FallbackURL(r.Context(), before)
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) probe(w http.ResponseWriter, r *http.Request) {
	address := strings.TrimSpace(r.URL.Query().Get("address"))
	port, _ := strconv.Atoi(r.URL.Query().Get("port"))
	if err := state.ValidateTarget(state.Target{Address: address, Port: port}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, probe.Probe(r.Context(), address, port))
}

type sentinel string

func (e sentinel) Error() string { return string(e) }

const errRefTaken sentinel = "a host with this ref exists"

const errNotFound = sentinel("not found")
