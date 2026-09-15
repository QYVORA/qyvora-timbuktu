// Package evidence stores the verifiable observations collected during an
// assessment, optionally persisted to a JSON file for reproducibility.
package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

// Store keeps evidence for one assessment run.
type Store struct {
	mu    sync.Mutex
	path  string
	items []models.Evidence
}

// New returns an empty evidence store. When path is non-empty the store is
// written there on Save (owner-only).
func New(path string) *Store { return &Store{path: path} }

// Add records a piece of evidence.
func (s *Store) Add(ev models.Evidence) {
	if ev.ID == "" {
		ev.ID = models.NewID("ev")
	}
	if ev.Hash == "" {
		ev.Hash = models.HashContent(ev.Data)
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = ev.CollectedAt
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, ev)
}

// List returns all evidence in insertion order.
func (s *Store) List() []models.Evidence {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]models.Evidence, len(s.items))
	copy(out, s.items)
	return out
}

// Len returns the number of recorded evidence items.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// Save writes the store to its configured path (0600 in a 0700 directory).
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return nil
	}
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(s.items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}
