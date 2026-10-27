package dns

import (
	"maps"
	"sync"
)

// Refusal remembers credentials Caddy would not load at startup (a token
// the provider module rejects by its shape, say from a restored backup).
// The proxy then runs on its own certificates instead of not at all, until
// the saved credentials change.
type Refusal struct {
	mu  sync.Mutex
	cfg *Config
	err string
}

// Set records c as refused with Caddy's error.
func (r *Refusal) Set(c *Config, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg, r.err = c, err.Error()
}

// Refused is Caddy's error when c is the refused configuration, else "".
func (r *Refusal) Refused(c *Config) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg == nil || c == nil || c.Provider != r.cfg.Provider || !maps.Equal(c.Fields, r.cfg.Fields) {
		return ""
	}
	return r.err
}
