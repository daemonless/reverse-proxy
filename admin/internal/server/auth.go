package server

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/app"
	"github.com/daemonless/reverse-proxy/admin/internal/auth"
	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

const (
	sessionCookie = "rp_session"
	setupCookie   = "rp_setup"
)

// principal is who is calling: an admin session, a connected app, or nobody.
type principal int

const (
	nobody principal = iota
	adminSession
	apiToken
	// local is a request straight over the admin's unix socket (the
	// reverse-proxy command inside the container): Caddy adds
	// X-Forwarded-For to everything it proxies, so a request without it
	// never came through the network. It acts as the account.
	local
)

// who identifies the caller. Bearer tokens win over cookies so a connected
// app in a browser context is never treated as a cookie session.
func (s *Server) who(r *http.Request) principal {
	if r.Header.Get("X-Forwarded-For") == "" {
		return local
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if id, ok := s.tokenValid(strings.TrimPrefix(h, "Bearer ")); ok {
			s.touchToken(id)
			return apiToken
		}
		return nobody
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if k, ok := s.sessions.Lookup(c.Value); ok && k == auth.KindAdmin {
			return adminSession
		}
	}
	return nobody
}

// tokenValid is the id of the key tok is, if any.
func (s *Server) tokenValid(tok string) (string, bool) {
	// rp_<id>_<secret>, or a paired key sent whole.
	parts := strings.SplitN(tok, "_", 3)
	if len(parts) == 3 && parts[0] == "rp" {
		want := auth.HashSecret(parts[2])
		for _, t := range s.mgr.State().Tokens {
			if t.ID == parts[1] && !t.Paired && !t.Disabled && auth.EqualTokens(t.Hash, want) {
				return t.ID, true
			}
		}
		return "", false
	}
	want := auth.HashSecret(tok)
	for _, t := range s.mgr.State().Tokens {
		if t.Paired && !t.Disabled && auth.EqualTokens(t.Hash, want) {
			return t.ID, true
		}
	}
	return "", false
}

// touchInterval is how often a key's last use is written: fjord calls every
// minute, and the state file need not follow each call.
const touchInterval = 5 * time.Minute

// touchToken records that key id was used now, at most once per
// touchInterval; the Settings page shows it as connected and when.
func (s *Server) touchToken(id string) {
	now := time.Now()
	s.mu.Lock()
	if s.touched == nil {
		s.touched = map[string]time.Time{}
	}
	if last, ok := s.touched[id]; ok && now.Sub(last) < touchInterval {
		s.mu.Unlock()
		return
	}
	s.touched[id] = now
	s.mu.Unlock()
	s.mgr.Note(func(st *state.State) {
		for i := range st.Tokens {
			if st.Tokens[i].ID == id {
				t := now
				st.Tokens[i].LastUsedAt = &t
			}
		}
	})
}

// MinPairingKey is the shortest RP_PAIRING_KEY accepted: it is a bearer
// token, so it must be a random secret, not a word.
const MinPairingKey = 32

// RegisterPairingKey makes key a connected app called label, once: a key
// registered before (and maybe removed since) is never added again.
func RegisterPairingKey(m *app.Manager, key, label, url, clientID string) (bool, error) {
	if len(key) < MinPairingKey {
		return false, fmt.Errorf("the pairing key is %d characters; it needs at least %d", len(key), MinPairingKey)
	}
	url = cleanPairingURL(url)
	clientID = cleanClientID(clientID)
	h := auth.HashSecret(key)
	if slices.Contains(m.State().PairedKeys, h) {
		// Known already; the app's address or name may be new (fjord moved).
		return false, m.Apply(func(st *state.State) error {
			for i := range st.Tokens {
				if st.Tokens[i].Hash != h {
					continue
				}
				if url != "" {
					st.Tokens[i].URL = url
				}
				if clientID != "" {
					st.Tokens[i].ClientID = clientID
				}
				if label != "" {
					st.Tokens[i].Label = label
				}
			}
			return nil
		})
	}
	t := state.ApiToken{ID: newID(), Label: label, Hash: h, CreatedAt: time.Now().UTC(), Paired: true, URL: url, ClientID: clientID}
	err := m.Apply(func(st *state.State) error {
		st.Tokens = append(st.Tokens, t)
		st.PairedKeys = append(st.PairedKeys, h)
		return nil
	})
	return err == nil, err
}

// cleanClientID keeps a short id of letters, digits and dashes.
func cleanClientID(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if len(id) > 64 {
		return ""
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return ""
		}
	}
	return id
}

// cleanPairingURL keeps an http(s) address and nothing else: it is put in
// a link on the page.
func cleanPairingURL(u string) string {
	u = strings.TrimSpace(u)
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return ""
	}
	if strings.ContainsAny(u, " \"'<>\n") {
		return ""
	}
	return strings.TrimRight(u, "/")
}

// requireAuth guards the hosts API: the account, the command line, or a
// connected app's key. Cookie sessions must also pass the same-origin
// check on anything but reads.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch s.who(r) {
		case nobody:
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "sign in first"})
			return
		case adminSession:
			if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "request did not come from this page"})
				return
			}
		}
		next(w, r)
	}
}

// requireAdmin guards the proxy's own settings, certificates, backup,
// password and keys: a connected app manages hosts, not the proxy.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if s.who(r) == apiToken {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "an app's key manages hosts only; this needs the account"})
			return
		}
		next(w, r)
	})
}

// sameOrigin accepts a browser request only when the browser says it came
// from our own page. Caddy passes the Host header through unchanged.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	}
	if o := r.Header.Get("Origin"); o != "" {
		if u, err := url.Parse(o); err == nil && strings.EqualFold(u.Host, r.Host) {
			return true
		}
	}
	return false
}

// setCookie uses the plan's cookie rules: HttpOnly, Secure, SameSite=Strict.
func setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func (s *Server) setupComplete() bool {
	return s.mgr.State().Settings.AdminPasswordHash != ""
}

// clientAddr is the visitor's address as Caddy reports it; "" when the
// request came straight over the unix socket.
func clientAddr(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	return r.RemoteAddr
}

// tooMany answers a locked-out attempt and reports whether it did.
func (s *Server) tooMany(w http.ResponseWriter, r *http.Request) bool {
	wait := s.limiter.Wait(clientAddr(r))
	if wait <= 0 {
		return false
	}
	secs := int(wait.Round(time.Second).Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeJSON(w, http.StatusTooManyRequests, map[string]any{
		"error":      "Too many attempts. Try again in " + strconv.Itoa(secs) + " seconds.",
		"retryAfter": secs,
	})
	return true
}

// session tells the UI where it stands without revealing anything else.
func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	kind := "none"
	switch s.who(r) {
	case adminSession:
		kind = "admin"
	case apiToken:
		kind = "token"
	}
	if kind == "none" {
		if c, err := r.Cookie(setupCookie); err == nil {
			if k, ok := s.sessions.Lookup(c.Value); ok && k == auth.KindSetup {
				kind = "setup"
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": kind == "admin" || kind == "token", "kind": kind, "setupRequired": !s.setupComplete()})
}

// setupToken is step one of first run: the token from the container log.
func (s *Server) setupToken(w http.ResponseWriter, r *http.Request) {
	if s.setupComplete() {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "setup is already done; sign in instead"})
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	if s.tooMany(w, r) {
		return
	}
	s.mu.Lock()
	want := s.setupTok
	s.mu.Unlock()
	if want == "" || !auth.EqualTokens(auth.NormalizeSetupToken(in.Token), auth.NormalizeSetupToken(want)) {
		s.limiter.Fail(clientAddr(r))
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "that's not the token in the log; check for mixed-up letters", "field": "token"})
		return
	}
	s.limiter.Succeed(clientAddr(r))
	setCookie(w, setupCookie, s.sessions.Create(auth.KindSetup), auth.SetupSessionTTL)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// setupPassword is step two: choose the password, then you are signed in.
func (s *Server) setupPassword(w http.ResponseWriter, r *http.Request) {
	if s.setupComplete() {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "setup is already done; sign in instead"})
		return
	}
	c, err := r.Cookie(setupCookie)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "enter the setup token first"})
		return
	}
	if k, ok := s.sessions.Lookup(c.Value); !ok || k != auth.KindSetup {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "the setup token has expired; enter it again"})
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	if err := auth.CheckPasswordStrength(in.Password); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "field": "password"})
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeError(w, err)
		return
	}
	addr := browserAddress(r)
	if err := s.mgr.Apply(func(st *state.State) error {
		st.Settings.AdminPasswordHash = hash
		if addr != "" {
			noteAddress(&st.Settings, addr)
		}
		return nil
	}); err != nil {
		writeError(w, err)
		return
	}
	s.sessions.Delete(c.Value)
	s.mu.Lock()
	s.setupTok = ""
	s.mu.Unlock()
	clearCookie(w, setupCookie)
	setCookie(w, sessionCookie, s.sessions.Create(auth.KindAdmin), auth.SessionAbsolute)
	log.Printf("[admin] setup complete: password set")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.setupComplete() {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "finish setup first", "setupRequired": true})
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	if s.tooMany(w, r) {
		return
	}
	if !auth.VerifyPassword(s.mgr.State().Settings.AdminPasswordHash, in.Password) {
		s.limiter.Fail(clientAddr(r))
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "that password isn't right", "field": "password"})
		return
	}
	s.limiter.Succeed(clientAddr(r))
	s.rememberAddress(r)
	setCookie(w, sessionCookie, s.sessions.Create(auth.KindAdmin), auth.SessionAbsolute)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Delete(c.Value)
	}
	clearCookie(w, sessionCookie)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// changePassword needs the current password and signs every session out.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	if !auth.VerifyPassword(s.mgr.State().Settings.AdminPasswordHash, in.Current) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "the current password isn't right", "field": "current"})
		return
	}
	if err := auth.CheckPasswordStrength(in.New); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "field": "new"})
		return
	}
	hash, err := auth.HashPassword(in.New)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.mgr.Apply(func(st *state.State) error { st.Settings.AdminPasswordHash = hash; return nil }); err != nil {
		writeError(w, err)
		return
	}
	s.sessions.DeleteAll()
	setCookie(w, sessionCookie, s.sessions.Create(auth.KindAdmin), auth.SessionAbsolute)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// reset is reachable only straight over the admin's unix socket (the
// reset-password command inside the container). Caddy adds X-Forwarded-For
// to everything it proxies, and its route for /internal/ answers 404
// before reaching us; a request without the header came from the socket.
func (s *Server) reset(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Forwarded-For") != "" {
		http.NotFound(w, r)
		return
	}
	if err := s.mgr.Apply(func(st *state.State) error { st.Settings.AdminPasswordHash = ""; return nil }); err != nil {
		writeError(w, err)
		return
	}
	s.sessions.DeleteAll()
	tok := auth.NewSetupToken()
	s.mu.Lock()
	s.setupTok = tok
	s.mu.Unlock()
	log.Printf("[admin] password reset; new setup token: %s", tok)
	writeJSON(w, http.StatusOK, map[string]any{"setupToken": tok, "adminUrl": AdminURL(s.mgr.State())})
}

// --- connected apps (API tokens) ---

func (s *Server) listTokens(w http.ResponseWriter, _ *http.Request) {
	st := s.mgr.State()
	counts := namesFrom(st)
	out := []map[string]any{}
	for _, t := range st.Tokens {
		out = append(out, map[string]any{"id": t.ID, "label": t.Label, "createdAt": t.CreatedAt, "lastUsedAt": t.LastUsedAt, "paired": t.Paired, "disabled": t.Disabled, "url": t.URL, "clientId": t.ClientID, "names": counts[t.ID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

// namesFrom counts the live hosts each connected app made, by token id. A
// fjord's refs are fjord:<its id>:<stack>; the installer also gets every
// fjord ref no id claims (fjord:<host>:<stack>, made before ids existed).
func namesFrom(st *state.State) map[string]int {
	out := map[string]int{}
	claimed := map[string]string{} // ref prefix -> token id
	for _, t := range st.Tokens {
		if t.ClientID != "" {
			claimed["fjord:"+t.ClientID+":"] = t.ID
		}
	}
	for _, h := range st.Live() {
		if !strings.HasPrefix(h.Ref, "fjord:") {
			continue
		}
		owner := ""
		for prefix, id := range claimed {
			if strings.HasPrefix(h.Ref, prefix) {
				owner = id
			}
		}
		if owner == "" {
			// fjord:<host>:<stack>, from before ids: the installer's.
			for _, t := range st.Tokens {
				if t.Paired {
					owner = t.ID
				}
			}
		}
		if owner != "" {
			out[owner]++
		}
	}
	return out
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Label string `json:"label"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	label := strings.TrimSpace(in.Label)
	if label == "" || len(label) > 64 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "give the app a short name", "field": "label"})
		return
	}
	id := newID()
	secret := auth.NewSecret(32)
	t := state.ApiToken{ID: id, Label: label, Hash: auth.HashSecret(secret), CreatedAt: time.Now().UTC()}
	if err := s.mgr.Apply(func(st *state.State) error { st.Tokens = append(st.Tokens, t); return nil }); err != nil {
		writeError(w, err)
		return
	}
	// Shown once; only the hash is kept.
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "label": label, "token": "rp_" + id + "_" + secret, "createdAt": t.CreatedAt})
}

// setTokenDisabled is PUT /api/v1/tokens/{id} {"disabled": bool}:
// disconnect a connected app and keep it, or reconnect it.
func (s *Server) setTokenDisabled(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Disabled bool `json:"disabled"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	id := r.PathValue("id")
	found := false
	err := s.mgr.Apply(func(st *state.State) error {
		for i := range st.Tokens {
			if st.Tokens[i].ID == id {
				st.Tokens[i].Disabled = in.Disabled
				found = true
			}
		}
		return nil
	})
	if err != nil {
		writeError(w, err)
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such app"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "disabled": in.Disabled})
}

func (s *Server) deleteToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.mgr.Apply(func(st *state.State) error {
		for i, t := range st.Tokens {
			if t.ID == id {
				st.Tokens = append(st.Tokens[:i], st.Tokens[i+1:]...)
				return nil
			}
		}
		return errNotFound
	})
	if err == errNotFound {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such token"})
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
