package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/auth"
	"github.com/daemonless/reverse-proxy/admin/internal/ca"
	"github.com/daemonless/reverse-proxy/admin/internal/caddy"
	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// pairCodeLife is how long a code from "Connect a fjord…" stays good.
const pairCodeLife = 10 * time.Minute

// newPairCode is POST /api/v1/pair/code: a one-time code and the link that
// carries it (https://proxy.<ending>/link#code=…), for the person to paste
// into the other fjord. Ten minutes, once.
func (s *Server) newPairCode(w http.ResponseWriter, r *http.Request) {
	code := auth.NewSetupToken()
	now := time.Now()
	s.mu.Lock()
	if s.pairCodes == nil {
		s.pairCodes = map[string]time.Time{}
	}
	for c, exp := range s.pairCodes {
		if now.After(exp) {
			delete(s.pairCodes, c)
		}
	}
	s.pairCodes[code] = now.Add(pairCodeLife)
	s.mu.Unlock()
	// The link names this proxy the way the admin reached it (an address,
	// or the name): the other fjord may not resolve proxy.<ending> yet, and
	// an address it can always reach. The proxy's own name comes back when
	// the code is redeemed, for the pin.
	writeJSON(w, http.StatusCreated, map[string]any{
		"code":      code,
		"link":      "https://" + r.Host + "/link#code=" + code,
		"expiresAt": now.Add(pairCodeLife).UTC(),
	})
}

// pair is POST /api/v1/pair {code, client:{id,name,url}}: the other fjord
// redeems a code for a key of its own, and learns what it needs to trust
// this proxy. The code proves the person had the admin page open a moment
// ago; a wrong one counts against the caller like a wrong password.
func (s *Server) pair(w http.ResponseWriter, r *http.Request) {
	if s.tooMany(w, r) {
		return
	}
	var in struct {
		Code   string `json:"code"`
		Client struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"client"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	code := strings.ToUpper(strings.TrimSpace(in.Code))
	s.mu.Lock()
	exp, ok := s.pairCodes[code]
	if ok {
		delete(s.pairCodes, code)
	}
	s.mu.Unlock()
	if !ok || time.Now().After(exp) {
		s.limiter.Fail(clientAddr(r))
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "that code is not right, or it has expired; make a new one under Connected apps", "field": "code"})
		return
	}
	s.limiter.Succeed(clientAddr(r))
	name := strings.TrimSpace(in.Client.Name)
	if name == "" || len(name) > 64 {
		name = "fjord"
	}
	id := newID()
	secret := auth.NewSecret(32)
	t := state.ApiToken{ID: id, Label: name, Hash: auth.HashSecret(secret), CreatedAt: time.Now().UTC(),
		URL: cleanPairingURL(in.Client.URL), ClientID: cleanClientID(in.Client.ID)}
	if err := s.mgr.Apply(func(st *state.State) error { st.Tokens = append(st.Tokens, t); return nil }); err != nil {
		writeError(w, err)
		return
	}
	st := s.mgr.State()
	out := map[string]any{
		"key":    "rp_" + id + "_" + secret,
		"domain": st.Settings.Domain,
		"needed": !(st.Settings.Mode() == state.ModePublic && st.Settings.Certificates != nil),
	}
	if st.Settings.Domain != "" {
		out["proxyName"] = caddy.ProxyName(st.Settings)
	}
	if root, err := ca.Load(s.secrets); err == nil && root.Domain == st.Settings.Domain {
		out["fingerprint"] = root.Fingerprint
		out["rootUrl"] = "/trust/root.crt"
	}
	writeJSON(w, http.StatusCreated, out)
}

// me is PUT /api/v1/me: the app behind the key says who it is (id, name,
// address), so an installer paired before ids existed, or one that was
// renamed, shows up like every other app. Only what is sent changes.
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	id, ok := s.callerToken(r)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "this is for an app's key; the account has nothing to say here"})
		return
	}
	var in struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	clientID, name, u := cleanClientID(in.ID), cleanLabel(in.Name), cleanPairingURL(in.URL)
	changed := false
	for _, t := range s.mgr.State().Tokens {
		if t.ID == id {
			changed = clientID != "" && clientID != t.ClientID || name != "" && name != t.Label || u != "" && u != t.URL
		}
	}
	if changed {
		err := s.mgr.Note(func(st *state.State) {
			for i := range st.Tokens {
				if st.Tokens[i].ID != id {
					continue
				}
				if clientID != "" {
					st.Tokens[i].ClientID = clientID
				}
				if name != "" {
					st.Tokens[i].Label = name
				}
				if u != "" {
					st.Tokens[i].URL = u
				}
			}
		})
		if err != nil {
			writeError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": changed})
}

// callerToken is the id of the key a request carries.
func (s *Server) callerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", false
	}
	return s.tokenValid(strings.TrimPrefix(h, "Bearer "))
}

// cleanLabel is a name fit for the Connected apps list: one line, trimmed,
// at most 64 characters, or nothing.
func cleanLabel(name string) string {
	name = strings.Join(strings.Fields(name), " ")
	if len(name) > 64 {
		return ""
	}
	return name
}
