package evidence_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/QYVORA/qyvora-timbuktu/internal/evidence"
	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

func TestStoreAddAssignsIDAndHash(t *testing.T) {
	s := evidence.New("")
	s.Add(models.Evidence{Kind: models.EvidenceConfiguration, Source: "snapshot", Data: "value"})
	if s.Len() != 1 {
		t.Fatalf("len = %d", s.Len())
	}
	ev := s.List()[0]
	if ev.ID == "" {
		t.Error("id not assigned")
	}
	if ev.Hash == "" {
		t.Error("hash not assigned")
	}
	if ev.Hash != models.HashContent("value") {
		t.Error("hash mismatch")
	}
}

func TestStoreSaveAndLoadPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ev", "evidence.json")
	s := evidence.New(path)
	s.Add(models.Evidence{Kind: models.EvidenceObservation, Source: "x", Data: "y"})
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perms = %v", info.Mode().Perm())
	}
}

func TestStoreSaveNoPathIsNoop(t *testing.T) {
	s := evidence.New("")
	s.Add(models.Evidence{Source: "x"})
	if err := s.Save(); err != nil {
		t.Fatalf("save with no path: %v", err)
	}
}
