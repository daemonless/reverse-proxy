package auth

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Session lifetimes from the plan: 12 hours idle, 7 days absolute.
const (
	SessionIdle     = 12 * time.Hour
	SessionAbsolute = 7 * 24 * time.Hour
	// SetupSessionTTL bounds how long a verified setup token stays usable
	// before a password is chosen.
	SetupSessionTTL = 15 * time.Minute
)

// Kind separates a logged-in admin from someone mid-setup.
type Kind int

const (
	KindAdmin Kind = iota + 1
	KindSetup
)

type session struct {
	Kind     Kind      `json:"kind"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"lastSeen"`
}

// Sessions is the session store. Admin sessions are written to a file so
// a restart (every update) does not sign the person out; setup sessions
// are short-lived and stay in memory.
type Sessions struct {
	mu   sync.Mutex
	m    map[string]*session
	now  func() time.Time
	path string // "" = memory only
}

// NewSessions returns an empty store kept in memory.
func NewSessions() *Sessions {
	return &Sessions{m: map[string]*session{}, now: time.Now}
}

// NewPersistentSessions loads admin sessions from path and saves them
// back on every change. A missing or unreadable file is an empty store.
func NewPersistentSessions(path string) *Sessions {
	s := &Sessions{m: map[string]*session{}, now: time.Now, path: path}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &s.m)
		s.sweep(s.now())
	}
	return s
}

// save writes admin sessions (never setup ones). Called with mu held.
func (s *Sessions) save() {
	if s.path == "" {
		return
	}
	keep := map[string]*session{}
	for id, se := range s.m {
		if se.Kind == KindAdmin {
			keep[id] = se
		}
	}
	data, err := json.Marshal(keep)
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

// Create returns a new session id.
func (s *Sessions) Create(kind Kind) string {
	id := NewSecret(32)
	now := s.now()
	s.mu.Lock()
	s.m[id] = &session{Kind: kind, Created: now, LastSeen: now}
	s.sweep(now)
	s.save()
	s.mu.Unlock()
	return id
}

// Lookup returns the session's kind and refreshes its idle timer.
func (s *Sessions) Lookup(id string) (Kind, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	se, ok := s.m[id]
	if !ok {
		return 0, false
	}
	now := s.now()
	if s.expired(se, now) {
		delete(s.m, id)
		return 0, false
	}
	// Refresh the idle timer, and persist it at most once a minute so a
	// busy UI does not rewrite the file on every request.
	if now.Sub(se.LastSeen) > time.Minute {
		se.LastSeen = now
		s.save()
	} else {
		se.LastSeen = now
	}
	return se.Kind, true
}

// Delete ends a session.
func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.save()
	s.mu.Unlock()
}

// DeleteAll ends every session (password change, reset).
func (s *Sessions) DeleteAll() {
	s.mu.Lock()
	s.m = map[string]*session{}
	s.save()
	s.mu.Unlock()
}

func (s *Sessions) expired(se *session, now time.Time) bool {
	if se.Kind == KindSetup {
		return now.Sub(se.Created) > SetupSessionTTL
	}
	return now.Sub(se.LastSeen) > SessionIdle || now.Sub(se.Created) > SessionAbsolute
}

func (s *Sessions) sweep(now time.Time) {
	for id, se := range s.m {
		if s.expired(se, now) {
			delete(s.m, id)
		}
	}
}
