package server

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/backup"
)

// createBackup streams an encrypted backup. The passphrase comes in the
// body so it never appears in a URL.
func (s *Server) createBackup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Passphrase string `json:"passphrase"`
	}
	if err := decode(w, r, &in); err != nil {
		writeError(w, err)
		return
	}
	var buf bytes.Buffer
	if err := backup.Create(&buf, filepath.Dir(s.secrets), in.Passphrase); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "field": "passphrase"})
		return
	}
	domain := strings.ReplaceAll(s.mgr.State().Settings.Domain, ".", "-")
	if domain == "" {
		domain = "unset"
	}
	name := fmt.Sprintf("reverse-proxy-%s-%s.rpbk", domain, time.Now().UTC().Format("2006-01-02"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(buf.Bytes())
}

// restoreBackup takes the file and passphrase as a multipart form. Before
// setup it is open (a fresh install has nothing to protect and no account
// to sign in with); afterwards it needs an admin session.
func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request) {
	if s.setupComplete() && s.who(r) != adminSession {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "sign in first"})
		return
	}
	if s.setupComplete() && !sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "request did not come from this page"})
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "send the backup file and the passphrase"})
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "choose the backup file", "field": "file"})
		return
	}
	defer f.Close()
	files, err := backup.Open(f, r.FormValue("passphrase"))
	switch {
	case errors.Is(err, backup.ErrWrongPassphrase):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "field": "passphrase"})
		return
	case errors.Is(err, backup.ErrNotABackup):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "field": "file"})
		return
	case err != nil:
		writeError(w, err)
		return
	}
	if err := backup.Write(filepath.Dir(s.secrets), files); err != nil {
		writeError(w, err)
		return
	}
	if err := s.mgr.Restore(); err != nil {
		writeError(w, err)
		return
	}
	// Everyone is signed out: the restored password is the one that counts.
	s.sessions.DeleteAll()
	s.mu.Lock()
	s.setupTok = ""
	s.mu.Unlock()
	clearCookie(w, sessionCookie)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domain": s.mgr.State().Settings.Domain})
}
