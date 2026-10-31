package uptime

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

// open starts an empty history whose clock reads t0 plus an hour, so the
// summaries look at the checks the test made.
func open(t *testing.T) *Monitor {
	m := Open(filepath.Join(t.TempDir(), "uptime.json"))
	m.now = func() time.Time { return t0.Add(time.Hour) }
	return m
}

var web = Target{ID: "h1", Name: "web.apps.test", Address: "10.0.0.5", Port: 80}

func TestDownAfterTwoFailuresAndBack(t *testing.T) {
	m := open(t)
	if e := m.record(web, true, 3*time.Millisecond, t0); e != nil {
		t.Fatalf("first up: %+v", e)
	}
	if e := m.record(web, false, 0, t0.Add(time.Minute)); e != nil {
		t.Fatalf("one failure is not an outage: %+v", e)
	}
	e := m.record(web, false, 0, t0.Add(2*time.Minute))
	if e == nil || !e.Down || !e.Since.Equal(t0.Add(time.Minute)) {
		t.Fatalf("down after two, since the first: %+v", e)
	}
	if e := m.record(web, false, 0, t0.Add(3*time.Minute)); e != nil {
		t.Fatalf("still down says nothing: %+v", e)
	}
	s := m.Summaries()["h1"]
	if s.State != "down" || !s.Since.Equal(t0.Add(time.Minute)) || s.Never {
		t.Fatalf("summary while down: %+v", s)
	}
	e = m.record(web, true, 2*time.Millisecond, t0.Add(13*time.Minute))
	if e == nil || e.Down || e.Lasted != 12*time.Minute {
		t.Fatalf("recovery: %+v", e)
	}
	d, _ := m.Detail("h1")
	if len(d.Outages) != 1 || d.Outages[0].End == nil {
		t.Fatalf("outage closed: %+v", d.Outages)
	}
}

// A blip (one failure between successes) is neither an outage nor an alert.
func TestBlip(t *testing.T) {
	m := open(t)
	for i, ok := range []bool{true, false, true, false, true} {
		if e := m.record(web, ok, 0, t0.Add(time.Duration(i)*time.Minute)); e != nil {
			t.Fatalf("check %d: %+v", i, e)
		}
	}
	if s := m.Summaries()["h1"]; s.State != "up" || *s.Day != 60 {
		t.Fatalf("blips: %+v day %v", s, *s.Day)
	}
}

// A target never seen up (an address the proxy cannot reach) shows down
// but never alerts, and has no outage to recover from.
func TestNeverReached(t *testing.T) {
	m := open(t)
	for i := range 5 {
		if e := m.record(web, false, 0, t0.Add(time.Duration(i)*time.Minute)); e != nil {
			t.Fatalf("never reached alerts: %+v", e)
		}
	}
	if s := m.Summaries()["h1"]; s.State != "down" || !s.Never {
		t.Fatalf("never reached: %+v", s)
	}
	if e := m.record(web, true, 0, t0.Add(6*time.Minute)); e != nil {
		t.Fatalf("first answer is not a recovery: %+v", e)
	}
}

// The app moved while down (recreated, new address): the outage goes on
// and the first answer at the new address says it's back.
func TestTargetMovedWhileDown(t *testing.T) {
	m := open(t)
	m.record(web, true, 0, t0)
	m.record(web, false, 0, t0.Add(time.Minute))
	m.record(web, false, 0, t0.Add(2*time.Minute))
	moved := web
	moved.Address = "10.0.0.9"
	if e := m.record(moved, true, 0, t0.Add(3*time.Minute)); e == nil || e.Down || e.Lasted != 2*time.Minute {
		t.Fatalf("back at the new address: %+v", e)
	}
	if d, _ := m.Detail("h1"); d.State != "up" || d.Outages[0].End == nil || d.Hours[0][1] != 4 {
		t.Fatalf("after the move: %+v", d)
	}
}

// Moved before it counted as down: one failure at the old address and one
// at the new one are not two in a row.
func TestTargetMovedBeforeDown(t *testing.T) {
	m := open(t)
	m.record(web, true, 0, t0)
	m.record(web, false, 0, t0.Add(time.Minute))
	moved := web
	moved.Address = "10.0.0.9"
	if e := m.record(moved, false, 0, t0.Add(2*time.Minute)); e != nil {
		t.Fatalf("old and new failures added up: %+v", e)
	}
}

func TestHoursRollAndTrim(t *testing.T) {
	m := open(t)
	m.record(web, true, 4*time.Millisecond, t0)
	m.record(web, true, 6*time.Millisecond, t0.Add(30*time.Minute))
	m.record(web, false, 0, t0.Add(70*time.Minute))
	d, _ := m.Detail("h1")
	if len(d.Hours) != 2 || d.Hours[0] != (Hour{t0.Unix(), 2, 2, 10}) || d.Hours[1] != (Hour{t0.Add(time.Hour).Unix(), 1, 0, 0}) {
		t.Fatalf("hours: %v", d.Hours)
	}
	m.record(web, true, 0, t0.Add(Keep+2*time.Hour))
	if d, _ := m.Detail("h1"); len(d.Hours) != 1 {
		t.Fatalf("older than %v kept: %v", Keep, d.Hours)
	}
}

// Hours with no checks (the proxy was off) count as nothing, not as down.
func TestGapsAreNoData(t *testing.T) {
	m := open(t)
	m.now = func() time.Time { return t0.Add(10 * time.Hour) }
	m.record(web, true, 0, t0)
	m.record(web, true, 0, t0.Add(9*time.Hour))
	s := m.Summaries()["h1"]
	if *s.Day != 100 || len(s.Hours) != 2 || !s.From.Equal(t0) {
		t.Fatalf("gap: day %v hours %v", *s.Day, s.Hours)
	}
}

func TestSaveAndOpen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "uptime.json")
	m := Open(p)
	m.record(web, true, 0, t0)
	m.record(web, false, 0, t0.Add(time.Minute))
	m.record(web, false, 0, t0.Add(2*time.Minute))
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	again := Open(p)
	again.now = func() time.Time { return t0.Add(3 * time.Minute) }
	if s := again.Summaries()["h1"]; s.State != "down" {
		t.Fatalf("after a restart: %+v", s)
	}
	// Still down after the restart: the outage it was in, not a new alert.
	if e := again.record(web, false, 0, t0.Add(3*time.Minute)); e != nil {
		t.Fatalf("restart re-alerted: %+v", e)
	}
	if e := again.record(web, true, 0, t0.Add(4*time.Minute)); e == nil || e.Lasted != 3*time.Minute {
		t.Fatalf("recovery after restart: %+v", e)
	}
}

func TestRoundForgetsRemovedAndChecksNewAtOnce(t *testing.T) {
	m := open(t)
	now := t0
	m.now = func() time.Time { return now }
	checked := 0
	m.Check = func(context.Context, Target) (bool, time.Duration) { checked++; return true, 0 }
	m.Round(context.Background(), []Target{web})
	now = now.Add(20 * time.Second)
	other := Target{ID: "h2", Name: "db.apps.test", Address: "10.0.0.6", Port: 5432}
	m.Round(context.Background(), []Target{web, other})
	if checked != 2 {
		t.Fatalf("checks: %d, want web once and the new one at once", checked)
	}
	m.Round(context.Background(), []Target{other})
	if _, ok := m.Summaries()["h1"]; ok {
		t.Fatal("a purged name's history is kept")
	}
}

// A removed name (Undo window) keeps its history and is not checked; the
// outage it was in ends, so a Restore later is not "back after 3 h".
func TestRemovedKeepsHistory(t *testing.T) {
	m := open(t)
	now := t0
	m.now = func() time.Time { return now }
	var mu sync.Mutex
	up := true
	checked := 0
	m.Check = func(context.Context, Target) (bool, time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		checked++
		return up, 0
	}
	events := make(chan Event, 4)
	m.Notify = func(e Event) { events <- e }
	m.Round(context.Background(), []Target{web})
	mu.Lock()
	up = false
	mu.Unlock()
	for range 2 {
		now = now.Add(time.Minute)
		m.Round(context.Background(), []Target{web})
	}
	gone := web
	gone.Skip = true
	now = now.Add(time.Minute)
	m.Round(context.Background(), []Target{gone})
	mu.Lock()
	defer mu.Unlock()
	if checked != 3 {
		t.Fatalf("a removed name was checked: %d checks", checked)
	}
	d, ok := m.Detail("h1")
	if !ok || d.Outages[0].End == nil {
		t.Fatalf("removed: kept %v, outage %+v", ok, d.Outages)
	}
	up = true
	mu.Unlock()
	now = now.Add(3 * time.Hour)
	m.Round(context.Background(), []Target{web})
	mu.Lock()
	if e := <-events; !e.Down {
		t.Fatalf("first event: %+v, want the down", e)
	}
	select {
	case e := <-events:
		t.Fatalf("restored sent %+v", e)
	case <-time.After(50 * time.Millisecond):
	}
}

// The case seen once live: down, the proxy restarts, the app is re-pointed
// at a new address and answers. The recovery is still sent.
func TestRestartThenMoved(t *testing.T) {
	p := filepath.Join(t.TempDir(), "uptime.json")
	m := Open(p)
	m.record(web, true, 0, t0)
	m.record(web, false, 0, t0.Add(time.Minute))
	m.record(web, false, 0, t0.Add(2*time.Minute))
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	again := Open(p)
	again.record(web, false, 0, t0.Add(4*time.Minute))
	moved := web
	moved.Address = "10.0.0.9"
	if e := again.record(moved, true, 0, t0.Add(5*time.Minute)); e == nil || e.Down || e.Lasted != 4*time.Minute {
		t.Fatalf("recovery after a restart and a move: %+v", e)
	}
}

func TestSend(t *testing.T) {
	var got *http.Request
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		body, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	down := Event{Name: "web.apps.test", Where: "10.0.0.5:80", Down: true, Since: t0}
	if err := Send(context.Background(), KindNtfy, srv.URL, down); err != nil {
		t.Fatal(err)
	}
	if got.Header.Get("Title") != "web.apps.test is down" || got.Header.Get("Priority") != "high" || string(body) != "web.apps.test is not responding at 10.0.0.5:80." {
		t.Fatalf("ntfy: %v %q", got.Header, body)
	}
	back := Event{Name: "web.apps.test", Where: "10.0.0.5:80", Since: t0, Lasted: 12 * time.Minute}
	if err := Send(context.Background(), KindWebhook, srv.URL, back); err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if json.Unmarshal(body, &p) != nil || p["state"] != "up" || p["downSeconds"] != float64(720) || p["message"] != "web.apps.test is responding again, after 12 min." {
		t.Fatalf("webhook: %s", body)
	}
	if err := Send(context.Background(), KindWebhook, srv.URL, Event{Example: true}); err != nil {
		t.Fatal(err)
	}
	p = nil
	if json.Unmarshal(body, &p) != nil || p["state"] != "test" || p["name"] != nil || p["url"] != nil {
		t.Fatalf("a test names no host: %s", body)
	}
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", 403) }))
	defer fail.Close()
	if err := Send(context.Background(), KindNtfy, fail.URL, down); err == nil {
		t.Fatal("a refusal is not an error")
	}
}
