package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// An app's icon, sent by the app that made the name (fjord sends the one
// it shows for the app), shown beside the name. Files beside state.json,
// not in it: every save rewrites state.json.

const maxIcon = 256 << 10

// iconMu makes saves one at a time: a tidy between another save's file and
// its record took that file (fjord sends every app's icon at once on start).
var iconMu sync.Mutex

var iconTypes = map[string]string{"svg": "image/svg+xml", "png": "image/png", "webp": "image/webp", "jpg": "image/jpeg"}

// iconKind tells the image by its bytes, never by what the sender says.
func iconKind(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return "png"
	case bytes.HasPrefix(b, []byte{0xff, 0xd8, 0xff}):
		return "jpg"
	case len(b) > 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return "webp"
	}
	head := strings.ToLower(string(b[:min(len(b), 1024)]))
	if strings.HasPrefix(strings.TrimSpace(head), "<") && strings.Contains(head, "<svg") {
		return "svg"
	}
	return ""
}

func (s *Server) iconDir() string { return filepath.Join(filepath.Dir(s.secrets), "icons") }

// iconFile is where a host's icon is kept; its record names the kind.
func (s *Server) iconFile(h state.Host) string {
	_, kind, _ := strings.Cut(h.Icon, ".")
	return filepath.Join(s.iconDir(), h.ID+"."+kind)
}

// putHostIcon takes the icon as the request body. state.Host.Icon becomes
// "<hash>.<kind>", so a sender compares the hash with its own and sends
// again only when its icon changed.
func (s *Server) putHostIcon(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxIcon+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "could not read the icon"})
		return
	}
	if len(b) > maxIcon {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "an icon is at most 256 KB"})
		return
	}
	kind := iconKind(b)
	if kind == "" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "an icon is an SVG, PNG, WebP or JPEG image"})
		return
	}
	sum := sha256.Sum256(b)
	icon := hex.EncodeToString(sum[:8]) + "." + kind
	id := r.PathValue("id")
	iconMu.Lock()
	defer iconMu.Unlock()
	st := s.mgr.State()
	i := st.Find(id)
	if i < 0 || st.Hosts[i].DeletedAt != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such host"})
		return
	}
	h := st.Hosts[i]
	if h.Icon != icon {
		if err := os.MkdirAll(s.iconDir(), 0o755); err != nil {
			writeError(w, err)
			return
		}
		h.Icon = icon
		tmp := s.iconFile(h) + ".new"
		if err := os.WriteFile(tmp, b, 0o644); err != nil {
			writeError(w, err)
			return
		}
		if err := os.Rename(tmp, s.iconFile(h)); err != nil {
			writeError(w, err)
			return
		}
		err = s.mgr.Note(func(st *state.State) {
			if i := st.Find(id); i >= 0 {
				st.Hosts[i].Icon = icon
			}
		})
		if err != nil {
			writeError(w, err)
			return
		}
		s.tidyIcons()
	}
	writeJSON(w, http.StatusOK, view(s.mgr.State().Settings, h))
}

// hostIcon serves it to the Names page. An SVG opened on its own runs on
// this page's origin: the policy keeps its scripts from running.
func (s *Server) hostIcon(w http.ResponseWriter, r *http.Request) {
	st := s.mgr.State()
	i := st.Find(r.PathValue("id"))
	if i < 0 || st.Hosts[i].Icon == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no icon"})
		return
	}
	h := st.Hosts[i]
	b, err := os.ReadFile(s.iconFile(h))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no icon"})
		return
	}
	_, kind, _ := strings.Cut(h.Icon, ".")
	w.Header().Set("Content-Type", iconTypes[kind])
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	// The page asks with ?v=<hash>: a new icon is a new address.
	w.Header().Set("Cache-Control", "private, max-age=604800")
	w.Write(b)
}

// tidyIcons drops the files of hosts that are gone, and of kinds a host
// no longer has. Callers other than putHostIcon hold iconMu.
func (s *Server) tidyIcons() {
	keep := map[string]bool{}
	for _, h := range s.mgr.State().Hosts {
		if h.Icon != "" {
			keep[filepath.Base(s.iconFile(h))] = true
		}
	}
	entries, _ := os.ReadDir(s.iconDir())
	for _, e := range entries {
		if !keep[e.Name()] {
			if err := os.Remove(filepath.Join(s.iconDir(), e.Name())); err != nil {
				log.Printf("[admin] icon %s: %v", e.Name(), err)
			}
		}
	}
}

// fitIcons forgets icons whose file is not there: a restored backup holds
// state.json, not the icons. The app that sent them sends them again when
// it sees no hash.
func (s *Server) fitIcons(st *state.State) bool {
	changed := false
	for i, h := range st.Hosts {
		if h.Icon == "" {
			continue
		}
		if _, err := os.Stat(s.iconFile(h)); err != nil {
			st.Hosts[i].Icon = ""
			changed = true
		}
	}
	return changed
}
