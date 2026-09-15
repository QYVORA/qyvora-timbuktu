// Package target manages the targets an assessment runs against. Offline
// targets (snapshot and simulation) never require authorization; provider
// targets would, and live provider collection is refused as unimplemented.
package target

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

// ErrUnauthorizedTarget is returned when a live operation requires an
// authorized target but the current target has not passed the gate.
var ErrUnauthorizedTarget = errors.New("target is not authorized")

// state is the on-disk snapshot of the target manager.
type state struct {
	CurrentID string           `json:"current_id,omitempty"`
	Targets   []*models.Target `json:"targets,omitempty"`
}

// Manager holds the set of known targets and tracks the current one.
type Manager struct {
	mu      sync.RWMutex
	path    string
	current *models.Target
	byID    map[string]*models.Target
}

// NewManager returns an empty target manager. When path is non-empty it is
// loaded from (and saved to) that JSON file (owner-only).
func NewManager(path string) *Manager {
	m := &Manager{path: path, byID: map[string]*models.Target{}}
	if path != "" {
		m.load()
	}
	return m
}

func (m *Manager) load() {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range st.Targets {
		if t == nil || t.ID == "" {
			continue
		}
		m.byID[t.ID] = t
		if t.ID == st.CurrentID {
			m.current = t
		}
	}
}

func (m *Manager) save() error {
	if m.path == "" {
		return nil
	}
	m.mu.RLock()
	st := state{Targets: make([]*models.Target, 0, len(m.byID))}
	if m.current != nil {
		st.CurrentID = m.current.ID
	}
	for _, t := range m.byID {
		st.Targets = append(st.Targets, t)
	}
	m.mu.RUnlock()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(m.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating target state dir: %w", err)
		}
	}
	return os.WriteFile(m.path, data, 0o600)
}

// Clear removes the current target selection while keeping registered targets.
func (m *Manager) Clear() error {
	m.mu.Lock()
	m.current = nil
	m.mu.Unlock()
	return m.save()
}

// Set registers a target and makes it current. Offline targets (snapshot,
// simulation) are always accepted; provider targets must be authorized.
func (m *Manager) Set(t *models.Target) error {
	if t == nil {
		return errors.New("cannot set a nil target")
	}
	if !t.Type.Valid() {
		return fmt.Errorf("invalid target type %q", t.Type)
	}
	if !t.Type.IsProvider() && !t.Authorized() {
		// Offline analysis needs no authorization; record that explicitly.
		t.Auth.Granted = true
		t.Auth.Scope = "offline"
	}
	if !t.Authorized() && t.Type.IsProvider() {
		return fmt.Errorf("%w: %s", ErrUnauthorizedTarget, t.DisplayName())
	}
	if t.ID == "" {
		t.ID = models.NewID("tgt")
	}
	m.mu.Lock()
	m.byID[t.ID] = t
	m.current = t
	m.mu.Unlock()
	if err := m.save(); err != nil {
		return fmt.Errorf("persisting targets: %w", err)
	}
	return nil
}

// Current returns the current target, or nil.
func (m *Manager) Current() *models.Target {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// Get returns a registered target by ID.
func (m *Manager) Get(id string) (*models.Target, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.byID[id]
	return t, ok
}

// List returns all registered targets in insertion order.
func (m *Manager) List() []*models.Target {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*models.Target, 0, len(m.byID))
	for _, t := range m.byID {
		out = append(out, t)
	}
	return out
}
