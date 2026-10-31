// Package uptime checks every name's target in the background and keeps a
// small history: hourly counts for 90 days and the last outages. A very
// small Uptime Kuma: a port that accepts a connection is up.
package uptime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	// Every is how often each target is checked.
	Every = time.Minute
	// DownAfter failed checks in a row make a target down; one success
	// makes it up again. A single dropped connection is not an outage.
	DownAfter = 2
	// Keep is how far back the hourly counts go.
	Keep       = 90 * 24 * time.Hour
	keepOutage = 50
	saveEvery  = 5 * time.Minute
	tick       = 10 * time.Second
	timeout    = 5 * time.Second
	parallel   = 16
)

// Target is one name to watch.
type Target struct {
	ID      string
	Name    string // the full name, radarr.apps.lan
	Address string
	Port    int
	// Skip: not checked now (removed inside its Undo window, or checks
	// turned off); its history stays.
	Skip bool
}

func (t Target) where() string { return net.JoinHostPort(t.Address, strconv.Itoa(t.Port)) }

// Hour is one hour's checks: [start (unix seconds), checks, up, sum of the
// up checks' connect times in ms]. An array, not an object: 2160 per name.
type Hour [4]int64

// Outage is a stretch of down; End is nil while it lasts.
type Outage struct {
	Start time.Time  `json:"start"`
	End   *time.Time `json:"end,omitempty"`
}

type record struct {
	Name    string    `json:"name"`
	Where   string    `json:"where"` // address:port the history is of
	Hours   []Hour    `json:"hours"`
	Outages []Outage  `json:"outages,omitempty"`
	Down    bool      `json:"down,omitempty"`
	Since   time.Time `json:"since"` // when the current state began
	// Seen: it was up at least once. A target the proxy never reached
	// (an address its network cannot see) shows down but sends no alert.
	Seen  bool       `json:"seen,omitempty"`
	Fails int        `json:"fails,omitempty"`
	First *time.Time `json:"firstFail,omitempty"`
	Last  time.Time  `json:"last"`
	// Began is the first check, kept for "watching since".
	Began time.Time `json:"began,omitzero"`
}

// Event is a change worth telling someone about.
type Event struct {
	HostID  string
	Name    string
	Where   string
	Down    bool
	Since   time.Time     // when it went down (the first failed check)
	Lasted  time.Duration // on recovery: how long it was down
	Example bool          // a test sent from Settings
}

// Monitor holds the history and runs the checks.
type Monitor struct {
	path string
	// Check reports whether the target answered and how fast; a TCP
	// connect unless a test replaces it.
	Check func(ctx context.Context, t Target) (bool, time.Duration)
	// Notify is called (in its own goroutine) for each Event; nil sends
	// nothing.
	Notify func(Event)
	now    func() time.Time

	mu    sync.Mutex
	hosts map[string]*record
	dirty bool
	done  chan struct{}
}

type file struct {
	Version int                `json:"version"`
	Hosts   map[string]*record `json:"hosts"`
}

// Open loads the history at path; a missing or unreadable file starts empty
// (it is a history, not configuration).
func Open(path string) *Monitor {
	m := &Monitor{path: path, Check: dial, now: time.Now, hosts: map[string]*record{}, done: make(chan struct{})}
	if raw, err := os.ReadFile(path); err == nil {
		var f file
		if json.Unmarshal(raw, &f) == nil && f.Hosts != nil {
			m.hosts = f.Hosts
		}
	}
	return m
}

func dial(ctx context.Context, t Target) (bool, time.Duration) {
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", t.where())
	if err != nil {
		return false, 0
	}
	c.Close()
	return true, time.Since(start)
}

// Run checks every target once a minute until ctx is done, then saves. A
// target that is new, or now points somewhere else, is checked at once.
func (m *Monitor) Run(ctx context.Context, targets func() []Target) {
	defer close(m.done)
	t := time.NewTicker(tick)
	defer t.Stop()
	saved := m.now()
	for {
		m.Round(ctx, targets())
		if m.now().Sub(saved) >= saveEvery {
			m.save()
			saved = m.now()
		}
		select {
		case <-ctx.Done():
			m.save()
			return
		case <-t.C:
		}
	}
}

// Done is closed once Run has saved for the last time.
func (m *Monitor) Done() <-chan struct{} { return m.done }

// Round checks the targets that are due and forgets names that are gone.
// A skipped name's outage ends there: a Restore later, or checks turned
// back on, is not a recovery.
func (m *Monitor) Round(ctx context.Context, targets []Target) {
	now := m.now()
	known := map[string]bool{}
	var due []Target
	m.mu.Lock()
	for _, t := range targets {
		known[t.ID] = true
		r := m.hosts[t.ID]
		if t.Skip {
			if r != nil && len(r.Outages) > 0 && r.Outages[len(r.Outages)-1].End == nil {
				r.Outages[len(r.Outages)-1].End = &now
				m.dirty = true
			}
			continue
		}
		if r == nil || r.Where != t.where() || now.Sub(r.Last) >= Every-tick/2 {
			due = append(due, t)
		}
	}
	for id := range m.hosts {
		if !known[id] {
			delete(m.hosts, id)
			m.dirty = true
		}
	}
	m.mu.Unlock()

	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for _, t := range due {
		wg.Add(1)
		sem <- struct{}{}
		go func(t Target) {
			defer func() { <-sem; wg.Done() }()
			ok, took := m.Check(ctx, t)
			if ctx.Err() != nil {
				return // shutting down: not an answer from the target
			}
			if e := m.record(t, ok, took, m.now()); e != nil && m.Notify != nil {
				go m.Notify(*e)
			}
		}(t)
	}
	wg.Wait()
}

// record adds one check and returns the change it made, if any.
func (m *Monitor) record(t Target, ok bool, took time.Duration, now time.Time) *Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dirty = true
	r := m.hosts[t.ID]
	if r == nil {
		r = &record{Since: now, Began: now}
		m.hosts[t.ID] = r
	}
	if r.Where != t.where() {
		// The app moved (a recreated container gets a new address and the
		// app that made the name points it there): failures at the old
		// address no longer count, but an outage goes on until the new
		// one answers, so "back" is still said.
		r.Where, r.Fails, r.First = t.where(), 0, nil
	}
	r.Name = t.Name
	r.Last = now
	r.Hours = addCheck(r.Hours, now, ok, took)

	ev := Event{HostID: t.ID, Name: t.Name, Where: t.where()}
	if ok {
		r.Fails, r.First = 0, nil
		was := r.Down
		if was || !r.Seen {
			r.Since = now
		}
		r.Down, r.Seen = false, true
		if was && len(r.Outages) > 0 && r.Outages[len(r.Outages)-1].End == nil {
			o := &r.Outages[len(r.Outages)-1]
			o.End = &now
			ev.Since, ev.Lasted = o.Start, now.Sub(o.Start)
			return &ev
		}
		return nil
	}
	r.Fails++
	if r.First == nil {
		first := now
		r.First = &first
	}
	if r.Fails < DownAfter || r.Down {
		return nil
	}
	r.Down, r.Since = true, *r.First
	if !r.Seen {
		return nil
	}
	r.Outages = append(r.Outages, Outage{Start: *r.First})
	if len(r.Outages) > keepOutage {
		r.Outages = r.Outages[len(r.Outages)-keepOutage:]
	}
	ev.Down, ev.Since = true, *r.First
	return &ev
}

func addCheck(hours []Hour, now time.Time, ok bool, took time.Duration) []Hour {
	h := now.Truncate(time.Hour).Unix()
	if n := len(hours); n == 0 || hours[n-1][0] != h {
		hours = append(hours, Hour{h, 0, 0, 0})
	}
	b := &hours[len(hours)-1]
	b[1]++
	if ok {
		b[2]++
		b[3] += took.Milliseconds()
	}
	cut := now.Add(-Keep).Unix()
	i := 0
	for i < len(hours) && hours[i][0] < cut {
		i++
	}
	return hours[i:]
}

// Summary is what the names list shows for one name.
type Summary struct {
	// State is "up", "down" or "unknown" (not checked yet).
	State string    `json:"state"`
	Since time.Time `json:"since,omitzero"`
	// Never: down, and never seen up since it was added.
	Never bool `json:"never,omitempty"`
	// Percent of the checks that answered; nil where nothing was checked.
	Day   *float64 `json:"day"`
	Week  *float64 `json:"week"`
	Month *float64 `json:"month"`
	// AvgMs is the average connect time over the last day.
	AvgMs *int64 `json:"avgMs,omitempty"`
	// Hours are the last 24 hours' counts, oldest first.
	Hours []Hour `json:"hours"`
	// From is the first check still counted: a name watched for an hour
	// has no 30 days to speak of.
	From time.Time `json:"from,omitzero"`
}

// Detail is one name's whole history.
type Detail struct {
	Summary
	Hours   []Hour   `json:"hours"`
	Outages []Outage `json:"outages"`
}

// Summaries returns one Summary per known name.
func (m *Monitor) Summaries() map[string]Summary {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	out := make(map[string]Summary, len(m.hosts))
	for id, r := range m.hosts {
		out[id] = summarize(r, now)
	}
	return out
}

// Detail returns one name's history; false when it was never checked.
func (m *Monitor) Detail(id string) (Detail, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.hosts[id]
	if r == nil {
		return Detail{}, false
	}
	d := Detail{Summary: summarize(r, m.now()), Hours: append([]Hour{}, r.Hours...), Outages: append([]Outage{}, r.Outages...)}
	return d, true
}

func summarize(r *record, now time.Time) Summary {
	s := Summary{State: "up", Since: r.Since, Hours: since(r.Hours, now.Add(-24*time.Hour))}
	if len(r.Hours) > 0 {
		s.From = time.Unix(r.Hours[0][0], 0).UTC()
		if r.Began.After(s.From) {
			s.From = r.Began
		}
	}
	switch {
	case r.Down:
		s.State, s.Never = "down", !r.Seen
	case !r.Seen:
		s.State, s.Since = "unknown", time.Time{}
	}
	s.Day = percent(r.Hours, now.Add(-24*time.Hour))
	s.Week = percent(r.Hours, now.Add(-7*24*time.Hour))
	s.Month = percent(r.Hours, now.Add(-30*24*time.Hour))
	var up, ms int64
	for _, h := range s.Hours {
		up += h[2]
		ms += h[3]
	}
	if up > 0 {
		avg := ms / up
		s.AvgMs = &avg
	}
	return s
}

// since returns the hours that start at or after from's hour.
func since(hours []Hour, from time.Time) []Hour {
	cut := from.Truncate(time.Hour).Unix()
	i := len(hours)
	for i > 0 && hours[i-1][0] > cut {
		i--
	}
	return append([]Hour{}, hours[i:]...)
}

func percent(hours []Hour, from time.Time) *float64 {
	var checks, up int64
	for _, h := range since(hours, from) {
		checks += h[1]
		up += h[2]
	}
	if checks == 0 {
		return nil
	}
	p := float64(up) * 100 / float64(checks)
	return &p
}

func (m *Monitor) save() {
	m.mu.Lock()
	if !m.dirty {
		m.mu.Unlock()
		return
	}
	data, err := json.Marshal(file{Version: 1, Hosts: m.hosts})
	m.dirty = false
	m.mu.Unlock()
	if err == nil {
		err = writeAtomic(m.path, data)
	}
	if err != nil {
		m.mu.Lock()
		m.dirty = true
		m.mu.Unlock()
	}
}

// Save writes the history now.
func (m *Monitor) Save() error {
	m.save()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dirty {
		return errors.New("uptime: could not write " + m.path)
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".uptime-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
