package models_test

import (
	"testing"
	"time"

	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

func TestSeverityWeights(t *testing.T) {
	cases := []struct {
		s    models.Severity
		want int
	}{
		{models.SeverityCritical, 4},
		{models.SeverityHigh, 3},
		{models.SeverityMedium, 2},
		{models.SeverityLow, 1},
		{models.SeverityInformational, 0},
	}
	for _, c := range cases {
		if got := c.s.Weights(); got != c.want {
			t.Errorf("%s weight = %d, want %d", c.s, got, c.want)
		}
	}
}

func TestConfidenceRankOrdering(t *testing.T) {
	if models.ConfidenceConfirmed.Rank() <= models.ConfidenceObserved.Rank() {
		t.Error("confirmed must rank above observed")
	}
	if models.ConfidenceUnknown.Rank() >= models.ConfidenceObserved.Rank() {
		t.Error("unknown must rank below observed")
	}
}

func TestFindingFingerprintIsStable(t *testing.T) {
	a := models.Finding{RuleID: "X", Category: "iam", Title: "Wildcard", Objects: []string{"b"}}
	b := models.Finding{RuleID: "X", Category: "iam", Title: "Wildcard", Objects: []string{"b"}}
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("fingerprints differ for identical findings")
	}
	c := models.Finding{RuleID: "X", Category: "iam", Title: "Wildcard", Objects: []string{"a"}}
	if a.Fingerprint() == c.Fingerprint() {
		t.Error("fingerprints must differ for different objects")
	}
}

func TestRedactSecrets(t *testing.T) {
	f := models.Finding{
		Attributes: map[string]string{"token": "supersecret", "region": "us-east-1"},
		Evidence:   []models.Evidence{{Data: "k=v"}, {Data: "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"}},
	}
	f.RedactSecrets()
	if f.Attributes["token"] != "<redacted>" {
		t.Error("token not redacted")
	}
	if f.Attributes["region"] != "us-east-1" {
		t.Error("non-secret attribute must be preserved")
	}
	if f.Evidence[0].Data != "k=v" {
		t.Error("non-secret evidence payload must be preserved")
	}
	if f.Evidence[1].Data != "<redacted>" {
		t.Error("secret-shaped evidence payload must be redacted")
	}
}

func TestRedactSecretData(t *testing.T) {
	list := []models.Evidence{
		{Data: "client_secret=wJalrXUtnFEMI_K7MDENG+bPxRfiCYEXAMPLEKEY"},
		{Data: "line 12: allow inbound from 0.0.0.0/0"},
	}
	models.RedactSecretData(list)
	if list[0].Data != "<redacted>" {
		t.Error("secret value must be redacted from evidence list")
	}
	if list[1].Data == "<redacted>" {
		t.Error("non-secret evidence must survive list redaction")
	}
}

func TestTargetAuthorizedByScope(t *testing.T) {
	off := models.Target{Type: models.TargetSnapshot, Auth: models.Authorization{Granted: true, Scope: "offline"}}
	if !off.Authorized() {
		t.Error("offline target should be authorized")
	}
	live := models.Target{Type: models.TargetAWS, Auth: models.Authorization{Granted: false}}
	if live.Authorized() {
		t.Error("provider target without auth must not be authorized")
	}
	if !live.Type.IsProvider() {
		t.Error("aws should be a provider")
	}
}

func TestResultOffline(t *testing.T) {
	if r := (models.Result{Sim: true}); !r.Offline() {
		t.Error("sim result should be offline")
	}
	if r := (models.Result{Target: &models.Target{Type: models.TargetSnapshot}}); !r.Offline() {
		t.Error("snapshot result should be offline")
	}
	if r := (models.Result{Target: &models.Target{Type: models.TargetAWS}}); r.Offline() {
		t.Error("provider result must not be offline")
	}
}

func TestNewIDUniqueAndPrefixed(t *testing.T) {
	if a, b := models.NewID("x"), models.NewID("x"); a == b {
		t.Error("ids must differ")
	}
	for _, id := range []string{models.NewID("run"), models.NewID("tgt")} {
		if len(id) < 8 {
			t.Errorf("id too short: %q", id)
		}
	}
}

func TestNowIsUTC(t *testing.T) {
	if loc := models.Now().Location(); loc != time.UTC {
		t.Errorf("Now() location = %v", loc)
	}
}
