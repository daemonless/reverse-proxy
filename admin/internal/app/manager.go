// Package app holds the admin's one write path: change state, render, load
// into Caddy, and only then persist.
package app

import (
	"fmt"
	"sync"
	"time"

	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

// Loader pushes a complete configuration into Caddy.
type Loader interface {
	Load(cfg any) error
}

// CaddyError is a configuration Caddy refused; the previous one stays live.
type CaddyError struct{ Err error }

func (e *CaddyError) Error() string { return "caddy rejected the configuration: " + e.Err.Error() }
func (e *CaddyError) Unwrap() error { return e.Err }

// Manager serializes every change to state and Caddy.
type Manager struct {
	mu     sync.Mutex
	store  *state.Store
	caddy  Loader
	render func(*state.State) any
	st     *state.State
	now    func() time.Time
	// Prepare, when set, runs before each render with the state about to
	// be applied: the place to make files the config will reference (the
	// root CA). It must be idempotent.
	Prepare func(*state.State) error
}

// New loads the state file. Nothing is pushed to Caddy until Reload.
func New(store *state.Store, caddy Loader, render func(*state.State) any) (*Manager, error) {
	st, err := store.Load()
	if err != nil {
		return nil, err
	}
	return &Manager{store: store, caddy: caddy, render: render, st: st, now: time.Now}, nil
}

// State returns a copy; callers never see the live object.
func (m *Manager) State() *state.State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st.Clone()
}

// Reload renders the current state and loads it (startup, or after Caddy
// restarted underneath us).
func (m *Manager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Prepare != nil {
		if err := m.Prepare(m.st); err != nil {
			return err
		}
	}
	if err := m.caddy.Load(m.render(m.st)); err != nil {
		return &CaddyError{err}
	}
	return nil
}

// Apply runs mutate on a copy of the state, renders it, loads it into Caddy
// and, only if Caddy accepted it, persists and adopts it. A validation error
// from mutate is returned untouched so the API can show the field.
func (m *Manager) Apply(mutate func(*state.State) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.st.Clone()
	next.Purge(m.now())
	if err := mutate(next); err != nil {
		return err
	}
	if m.Prepare != nil {
		if err := m.Prepare(next); err != nil {
			return err
		}
	}
	if err := m.caddy.Load(m.render(next)); err != nil {
		return &CaddyError{err}
	}
	if err := m.store.Save(next); err != nil {
		// Caddy already runs the new config; keep it in memory and report.
		m.st = next
		return fmt.Errorf("saving state: %w", err)
	}
	m.st = next
	return nil
}

// Note records a change that Caddy's config does not depend on (a key's
// last use): saved, never rendered or loaded.
func (m *Manager) Note(mutate func(*state.State)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.st.Clone()
	mutate(next)
	if err := m.store.Save(next); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}
	m.st = next
	return nil
}

// Restore re-reads the state file (after a backup was written to disk),
// renders it and loads it into Caddy. On failure the previous in-memory
// state stays live. adapt, when set, fits the restored state to this
// machine first, and what it changes is saved.
func (m *Manager) Restore(adapt func(*state.State) bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.store.Load()
	if err != nil {
		return err
	}
	if adapt != nil && adapt(st) {
		if err := m.store.Save(st); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}
	}
	if m.Prepare != nil {
		if err := m.Prepare(st); err != nil {
			return err
		}
	}
	if err := m.caddy.Load(m.render(st)); err != nil {
		return &CaddyError{err}
	}
	m.st = st
	return nil
}
