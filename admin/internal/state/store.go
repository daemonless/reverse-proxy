package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Store persists State as one JSON file with atomic replacement.
type Store struct {
	path string
}

// NewStore returns a store for the file at path.
func NewStore(path string) *Store { return &Store{path: path} }

// Load reads the state, creating an empty one when the file is missing and
// migrating an older schema (a copy of the original is kept beside it).
func (s *Store) Load() (*State, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		st := &State{SchemaVersion: SchemaVersion}
		return st, s.Save(st)
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	if st.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("%s is schema %d, this version understands %d", s.path, st.SchemaVersion, SchemaVersion)
	}
	if st.SchemaVersion < SchemaVersion {
		backup := fmt.Sprintf("%s.v%d-%s", s.path, st.SchemaVersion, time.Now().UTC().Format("20060102T150405Z"))
		if err := os.WriteFile(backup, raw, 0o600); err != nil {
			return nil, err
		}
		migrate(&st)
		if err := s.Save(&st); err != nil {
			return nil, err
		}
	}
	return &st, nil
}

// migrate brings an older state forward one version at a time.
func migrate(st *State) {
	for st.SchemaVersion < SchemaVersion {
		switch st.SchemaVersion {
		case 0:
			// Pre-release files carried no version.
		}
		st.SchemaVersion++
	}
}

// Save writes the state atomically: temp file, fsync, rename.
func (s *Store) Save(st *State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
