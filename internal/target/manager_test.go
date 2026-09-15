package target_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/QYVORA/qyvora-timbuktu/internal/target"
	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

func TestSetPersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m := target.NewManager(path)
	t1 := &models.Target{Name: "sim", Type: models.TargetSimulation}
	if err := m.Set(t1); err != nil {
		t.Fatalf("set: %v", err)
	}
	if t1.ID == "" {
		t.Fatal("target id not assigned")
	}

	// State file must be owner-only.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("state perms = %v", info.Mode().Perm())
	}

	m2 := target.NewManager(path)
	if cur := m2.Current(); cur == nil || cur.ID != t1.ID {
		t.Errorf("reloaded current = %+v", cur)
	}
	if _, ok := m2.Get(t1.ID); !ok {
		t.Error("reloaded target missing")
	}
}

func TestOfflineTargetAutoAuthorized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m := target.NewManager(path)
	err := m.Set(&models.Target{Name: "snap", Type: models.TargetSnapshot, Value: "/tmp/x.json"})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if !m.Current().Authorized() {
		t.Error("offline target should be auto-authorized")
	}
}

func TestProviderTargetRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m := target.NewManager(path)
	err := m.Set(&models.Target{Name: "aws", Type: models.TargetAWS})
	if err == nil {
		t.Fatal("provider target should be refused")
	}
}

func TestClear(t *testing.T) {
	m := target.NewManager("")
	if err := m.Set(&models.Target{Name: "sim", Type: models.TargetSimulation}); err != nil {
		t.Fatal(err)
	}
	if err := m.Clear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if m.Current() != nil {
		t.Error("current not nil after clear")
	}
	if len(m.List()) != 1 {
		t.Errorf("registered targets lost: %d", len(m.List()))
	}
}
