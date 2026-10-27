package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadCreatesEmptyState(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "state.json"))
	st, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.SchemaVersion != SchemaVersion || len(st.Hosts) != 0 {
		t.Fatalf("unexpected state %+v", st)
	}
	if _, err := os.Stat(s.path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "state.json"))
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	in := &State{SchemaVersion: SchemaVersion, Settings: Settings{Domain: "home.example.com"},
		Hosts: []Host{{ID: "a1", Name: "radarr", Target: Target{Address: "192.168.1.20", Port: 7878}, Access: AccessHome, CreatedAt: now}}}
	if err := s.Save(in); err != nil {
		t.Fatal(err)
	}
	out, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if out.Settings.Domain != "home.example.com" || len(out.Hosts) != 1 || out.Hosts[0].Name != "radarr" {
		t.Fatalf("round trip lost data: %+v", out)
	}
	info, _ := os.Stat(s.path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v, want 0600", info.Mode().Perm())
	}
}

func TestMigrationKeepsBackup(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	os.WriteFile(p, []byte(`{"schemaVersion":0,"settings":{"domain":"x.lan"},"hosts":[]}`), 0o600)
	st, err := NewStore(p).Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.SchemaVersion != SchemaVersion {
		t.Fatalf("not migrated: %d", st.SchemaVersion)
	}
	entries, _ := os.ReadDir(dir)
	var backup bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "state.json.v0-") {
			backup = true
		}
	}
	if !backup {
		t.Fatal("no backup of the pre-migration file")
	}
}

func TestNewerSchemaRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(p, []byte(`{"schemaVersion":99}`), 0o600)
	if _, err := NewStore(p).Load(); err == nil {
		t.Fatal("expected an error for a newer schema")
	}
}

func TestPurgeAndLive(t *testing.T) {
	now := time.Now()
	old := now.Add(-25 * time.Hour)
	recent := now.Add(-time.Hour)
	st := &State{Hosts: []Host{{ID: "keep"}, {ID: "old", DeletedAt: &old}, {ID: "recent", DeletedAt: &recent}}}
	st.Purge(now)
	if len(st.Hosts) != 2 || st.Find("old") != -1 {
		t.Fatalf("purge wrong: %+v", st.Hosts)
	}
	if live := st.Live(); len(live) != 1 || live[0].ID != "keep" {
		t.Fatalf("live wrong: %+v", live)
	}
}

// Removed records: one per name (the latest), none for a name a live host
// holds. Remove, add again, remove again used to pile them up.
func TestPurgeKeepsOneRemovedPerName(t *testing.T) {
	now := time.Now()
	t1, t2, t3 := now.Add(-3*time.Hour), now.Add(-2*time.Hour), now.Add(-time.Hour)
	st := &State{Hosts: []Host{
		{ID: "d1", Name: "deckcraft", DeletedAt: &t1},
		{ID: "d2", Name: "deckcraft", DeletedAt: &t3},
		{ID: "d3", Name: "deckcraft", DeletedAt: &t2},
		{ID: "z1", Name: "zensical", DeletedAt: &t1},
		{ID: "z2", Name: "zensical"},
		{ID: "a1", Name: "actual", DeletedAt: &t2},
	}}
	st.Purge(now)
	ids := []string{}
	for _, h := range st.Hosts {
		ids = append(ids, h.ID)
	}
	if got := strings.Join(ids, ","); got != "d2,z2,a1" {
		t.Fatalf("kept %s, want d2,z2,a1", got)
	}
}

func TestCloneIsDeep(t *testing.T) {
	st := &State{Hosts: []Host{{ID: "a", ExtraNames: []string{"x"}}}}
	c := st.Clone()
	c.Hosts[0].ExtraNames[0] = "changed"
	c.Hosts[0].Name = "changed"
	if st.Hosts[0].ExtraNames[0] != "x" || st.Hosts[0].Name != "" {
		t.Fatal("clone shares memory with the original")
	}
}

func TestValidation(t *testing.T) {
	good := Host{ID: "h1", Name: "radarr", Target: Target{Address: "192.168.1.20", Port: 7878}, Access: AccessHome}
	if err := ValidateHost(good, nil); err != nil {
		t.Fatal(err)
	}
	bad := []struct {
		name string
		h    Host
		fld  string
	}{
		{"empty name", Host{Target: good.Target, Access: AccessHome}, "name"},
		{"dot in name", Host{Name: "a.b", Target: good.Target, Access: AccessHome}, "name"},
		{"bad port", Host{Name: "x", Target: Target{Address: "1.2.3.4", Port: 0}, Access: AccessHome}, "target.port"},
		{"bad address", Host{Name: "x", Target: Target{Address: "not valid!", Port: 80}, Access: AccessHome}, "target.address"},
		{"no access", Host{Name: "x", Target: good.Target}, "access"},
		{"bad network", Host{Name: "x", Target: good.Target, Access: AccessHome, TrustedNetworks: []string{"nope"}}, "trustedNetworks"},
		{"taken", Host{ID: "h2", Name: "radarr", Target: good.Target, Access: AccessHome}, "name"},
	}
	for _, tc := range bad {
		err := ValidateHost(tc.h, []Host{good})
		fe, ok := err.(*FieldError)
		if !ok || fe.Field != tc.fld {
			t.Errorf("%s: got %v, want field %s", tc.name, err, tc.fld)
		}
	}
	for _, d := range []string{"home.example.com", "apps.home.lan"} {
		if err := ValidateDomain(d); err != nil {
			t.Errorf("%s rejected: %v", d, err)
		}
	}
	for _, d := range []string{"", "nodots", "bad_char.com", "x.local"} {
		if err := ValidateDomain(d); err == nil {
			t.Errorf("%q accepted", d)
		}
	}
	if (Settings{Domain: "apps.home.lan"}).Mode() != ModePrivate || (Settings{Domain: "home.example.com"}).Mode() != ModePublic || (Settings{}).Mode() != ModeUnset {
		t.Fatal("mode derivation wrong")
	}
}
