package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/QYVORA/qyvora-timbuktu/internal/config"
)

func TestLoadDefaults(t *testing.T) {
	v, err := config.Load("")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p, err := config.Profile(v)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	if p != config.ProfileStandard {
		t.Errorf("default profile = %q", p)
	}
	if n := config.MaxAssets(v); n != 10000 {
		t.Errorf("default max_assets = %d", n)
	}
	if !config.SecretScanEnabled(v) {
		t.Error("secret scanning should default to enabled")
	}
}

func TestLoadFilePrecedence(t *testing.T) {
	dir := t.TempDir()
	cfg := "profile: deep\nanalysis:\n  max_assets: 500\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := config.Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p, _ := config.Profile(v); p != config.ProfileDeep {
		t.Errorf("profile = %q, want deep", p)
	}
	if n := config.MaxAssets(v); n != 500 {
		t.Errorf("max_assets = %d, want 500", n)
	}
}

func TestEnvNamespace(t *testing.T) {
	t.Setenv("QYVORA_TIMBUKTU_PROFILE", "quick")
	v, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := config.Profile(v); p != config.ProfileQuick {
		t.Errorf("env profile = %q, want quick", p)
	}
}

func TestInvalidProfileRejected(t *testing.T) {
	t.Setenv("QYVORA_TIMBUKTU_PROFILE", "turbo")
	v, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Profile(v); err == nil {
		t.Error("expected error for unknown profile")
	}
}
