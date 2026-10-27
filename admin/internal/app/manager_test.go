package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daemonless/reverse-proxy/admin/internal/state"
)

type fakeLoader struct {
	fail  error
	loads int
	last  any
}

func (f *fakeLoader) Load(cfg any) error {
	f.loads++
	f.last = cfg
	return f.fail
}

func render(st *state.State) any { return map[string]any{"domain": st.Settings.Domain} }

func newManager(t *testing.T, l Loader) (*Manager, string) {
	p := filepath.Join(t.TempDir(), "state.json")
	m, err := New(state.NewStore(p), l, render)
	if err != nil {
		t.Fatal(err)
	}
	return m, p
}

func TestApplyPersistsAfterCaddyAccepts(t *testing.T) {
	l := &fakeLoader{}
	m, p := newManager(t, l)
	err := m.Apply(func(st *state.State) error { st.Settings.Domain = "x.lan"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if l.loads != 1 || l.last.(map[string]any)["domain"] != "x.lan" {
		t.Fatalf("caddy got %v", l.last)
	}
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), `"domain": "x.lan"`) {
		t.Fatalf("state not persisted: %s", raw)
	}
	if m.State().Settings.Domain != "x.lan" {
		t.Fatal("live state not adopted")
	}
}

func TestApplyRollsBackWhenCaddyRejects(t *testing.T) {
	l := &fakeLoader{fail: errors.New("bad")}
	m, p := newManager(t, l)
	err := m.Apply(func(st *state.State) error { st.Settings.Domain = "x.lan"; return nil })
	var ce *CaddyError
	if !errors.As(err, &ce) {
		t.Fatalf("got %v, want CaddyError", err)
	}
	if m.State().Settings.Domain != "" {
		t.Fatal("rejected change leaked into live state")
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "x.lan") {
		t.Fatal("rejected change was persisted")
	}
}

func TestApplyValidationErrorSkipsCaddy(t *testing.T) {
	l := &fakeLoader{}
	m, _ := newManager(t, l)
	want := &state.FieldError{Field: "name", Msg: "nope"}
	err := m.Apply(func(*state.State) error { return want })
	if err != want || l.loads != 0 {
		t.Fatalf("err=%v loads=%d", err, l.loads)
	}
}

func TestStateIsACopy(t *testing.T) {
	m, _ := newManager(t, &fakeLoader{})
	m.State().Settings.Domain = "leak"
	if m.State().Settings.Domain != "" {
		t.Fatal("State() exposed the live object")
	}
}
