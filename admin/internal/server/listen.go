package server

import (
	"log"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/daemonless/reverse-proxy/admin/internal/caddy"
	"github.com/daemonless/reverse-proxy/admin/internal/netif"
	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

func (s *Server) networks() []netif.Network {
	if s.Networks != nil {
		return s.Networks()
	}
	return netif.List()
}

// here is the network the request came in on ("" from the unix socket, or
// from loopback inside the container).
func here(r *http.Request, networks []netif.Network) string {
	local := r.Header.Get(caddy.LocalHeader)
	if ip := net.ParseIP(local); ip == nil || ip.IsLoopback() {
		return ""
	}
	for _, n := range networks {
		if n.Contains(local) {
			return n.Network
		}
	}
	return ""
}

// envNetworks is RP_LISTEN: networks separated by commas or spaces.
func envNetworks(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' })
}

// listenView is the Networks card: the container's networks, the one the
// person is on, and the ones it answers on (none: every network).
func (s *Server) listenView(r *http.Request, set state.Settings) map[string]any {
	networks := s.networks()
	if networks == nil {
		networks = []netif.Network{}
	}
	listen := set.Listen
	setBy := ""
	if s.ListenEnv != "" {
		setBy = "RP_LISTEN"
		listen = nil
		for _, w := range envNetworks(s.ListenEnv) {
			if n, ok := netif.Find(networks, w); ok {
				w = n.Network
			}
			listen = append(listen, w)
		}
	}
	if listen == nil {
		listen = []string{}
	}
	return map[string]any{"networks": networks, "here": here(r, networks), "listen": listen, "listenSetBy": setBy}
}

// checkListen turns a choice into the subnets to save. Each must be a
// network the container is on and, from a browser, the one that browser is
// on must be among them: leaving it out would cut the page off mid-click.
// Every network the container is on, chosen one by one, is saved as none:
// every network, including one added later.
func (s *Server) checkListen(r *http.Request, wants []string) ([]string, error) {
	if s.ListenEnv != "" {
		return nil, &state.FieldError{Field: "listen", Msg: "RP_LISTEN in the container's settings decides this; change it there."}
	}
	networks := s.networks()
	var out []string
	for _, w := range wants {
		if w = strings.TrimSpace(w); w == "" {
			continue
		}
		n, ok := netif.Find(networks, w)
		if !ok {
			return nil, &state.FieldError{Field: "listen", Msg: "The proxy is not on " + w + "."}
		}
		if !slices.Contains(out, n.Network) {
			out = append(out, n.Network)
		}
	}
	if len(out) == 0 || len(out) == len(networks) {
		return nil, nil
	}
	// From a browser (Caddy set the header). An arrival that matches no
	// listed network (IPv6-only, link-local) is refused too; loopback inside
	// the container is not a browser's way in.
	if local := net.ParseIP(r.Header.Get(caddy.LocalHeader)); local != nil && !local.IsLoopback() {
		on := here(r, networks)
		if on == "" {
			return nil, &state.FieldError{Field: "listen", Msg: "This page reached the proxy at " + local.String() + ", which is not on any of its networks. Open it at an address on one of the networks to choose them."}
		}
		if !slices.Contains(out, on) {
			return nil, &state.FieldError{Field: "listen", Msg: "This page reached the proxy on " + on + ". Leaving it out would cut this page off: keep it, or choose from a device on another network."}
		}
	}
	slices.Sort(out)
	return out, nil
}

// putListen is the home-network choice from Settings and from setup
// (before an ending exists, so not part of PUT /settings). It answers with
// the settings, as PUT /settings does.
func (s *Server) putListen(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Listen []string `json:"listen"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	listen, err := s.checkListen(r, in.Listen)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.mgr.Apply(func(st *state.State) error { st.Settings.Listen = listen; return nil }); err != nil {
		writeError(w, err)
		return
	}
	st := s.mgr.State()
	out := settingsView(st.Settings)
	maps.Copy(out, s.listenView(r, st.Settings))
	writeJSON(w, http.StatusOK, out)
}

// internalListen is `reverse-proxy listen`, over the unix socket only (the
// network side never routes /internal/): the way back from a choice that
// locked everyone out.
func (s *Server) internalListen(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Forwarded-For") != "" {
		http.NotFound(w, r)
		return
	}
	var in struct {
		Listen []string `json:"listen"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	listen, err := s.checkListen(r, in.Listen)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.mgr.Apply(func(st *state.State) error { st.Settings.Listen = listen; return nil }); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.listenView(r, s.mgr.State().Settings))
}

// fitListen drops restored networks this machine is not on: a backup moved
// to another host would otherwise answer only inside the container, cutting
// off the page the restore came from.
func (s *Server) fitListen(st *state.State) bool {
	if len(st.Settings.Listen) == 0 {
		return false
	}
	networks := s.networks()
	var kept []string
	for _, w := range st.Settings.Listen {
		if _, ok := netif.Find(networks, w); ok {
			kept = append(kept, w)
		}
	}
	if len(kept) == len(st.Settings.Listen) {
		return false
	}
	if len(kept) == 0 {
		log.Printf("[admin] the backup answered only on %s, which this machine is not on: answering on every network", strings.Join(st.Settings.Listen, ", "))
	} else {
		log.Printf("[admin] the backup answered on %s; this machine is on %s of them only", strings.Join(st.Settings.Listen, ", "), strings.Join(kept, ", "))
	}
	st.Settings.Listen = kept
	return true
}
