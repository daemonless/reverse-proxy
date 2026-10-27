package backup

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "secrets"), 0o700)
	os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"schemaVersion":1}`), 0o600)
	os.WriteFile(filepath.Join(dir, "secrets/ca-root.crt"), []byte("CERT"), 0o644)
	os.WriteFile(filepath.Join(dir, "secrets/ca-root.key"), []byte("KEY"), 0o600)
	os.WriteFile(filepath.Join(dir, "secrets/setup.key"), []byte("NOT INCLUDED"), 0o600)

	var buf bytes.Buffer
	if err := Create(&buf, dir, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("schemaVersion")) || bytes.Contains(buf.Bytes(), []byte("KEY")) {
		t.Fatal("backup is not encrypted")
	}

	if _, err := Open(bytes.NewReader(buf.Bytes()), "wrong"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := Open(strings.NewReader("garbage file"), "x"); !errors.Is(err, ErrNotABackup) {
		t.Fatalf("garbage: %v", err)
	}
	files, err := Open(bytes.NewReader(buf.Bytes()), "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if string(files["secrets/ca-root.key"]) != "KEY" || len(files) != 3 {
		t.Fatalf("files: %v", files)
	}

	out := t.TempDir()
	os.MkdirAll(filepath.Join(out, "secrets"), 0o700)
	os.WriteFile(filepath.Join(out, "state.json"), []byte("old"), 0o600)
	if err := Write(out, files); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(out, "state.json"))
	if string(got) != `{"schemaVersion":1}` {
		t.Fatalf("restored state: %s", got)
	}
	entries, _ := os.ReadDir(out)
	var kept bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "state.json.before-restore-") {
			kept = true
		}
	}
	if !kept {
		t.Fatal("previous state not kept")
	}
	info, _ := os.Stat(filepath.Join(out, "secrets/ca-root.key"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", info.Mode().Perm())
	}
}

func TestShortPassphraseRefused(t *testing.T) {
	if err := Create(&bytes.Buffer{}, t.TempDir(), "short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
}

// No passphrase is a choice: the file opens with none, and not with one.
func TestNoPassphraseRoundTrip(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "secrets"), 0o700)
	os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"schemaVersion":1}`), 0o600)
	os.WriteFile(filepath.Join(dir, "secrets/ca-root.crt"), []byte("CERT"), 0o644)
	os.WriteFile(filepath.Join(dir, "secrets/ca-root.key"), []byte("KEY"), 0o600)
	var buf bytes.Buffer
	if err := Create(&buf, dir, ""); err != nil {
		t.Fatalf("no passphrase: %v", err)
	}
	files, err := Open(bytes.NewReader(buf.Bytes()), "")
	if err != nil || string(files["secrets/ca-root.key"]) != "KEY" {
		t.Fatalf("open with none: %v", err)
	}
	if _, err := Open(bytes.NewReader(buf.Bytes()), "something-else"); err == nil {
		t.Fatal("opened with a passphrase it was not sealed with")
	}
}
