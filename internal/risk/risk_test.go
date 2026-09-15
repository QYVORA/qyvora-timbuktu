package risk_test

import (
	"context"
	"testing"

	"github.com/QYVORA/qyvora-timbuktu/internal/risk"
	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

func TestScoreForIsTransparentAndBounded(t *testing.T) {
	f := &models.Finding{
		RuleID: "X", Category: "secrets", Severity: models.SeverityCritical,
		Confidence: models.ConfidenceConfirmed,
	}
	r := risk.ScoreFor(f)
	if r.Score <= 0 || r.Score > risk.MaxScore {
		t.Fatalf("score out of range: %d", r.Score)
	}
	if r.Level != "critical" {
		t.Errorf("level = %s", r.Level)
	}
}

func TestSeverityWeights(t *testing.T) {
	if got := models.SeverityCritical.Weights(); got != 4 {
		t.Errorf("critical weight = %d", got)
	}
	if got := models.SeverityLow.Weights(); got <= 0 {
		t.Errorf("low weight = %d", got)
	}
}

func TestAssessSkipsFalsePositivesAndResolved(t *testing.T) {
	var assessor risk.Assessor
	fs := []*models.Finding{
		{RuleID: "a", Category: "iam", Severity: models.SeverityHigh, Confidence: models.ConfidenceConfirmed, Status: models.StatusConfirmed},
		{RuleID: "b", Category: "iam", Severity: models.SeverityCritical, Confidence: models.ConfidenceConfirmed, Status: models.StatusFalsePositive},
		{RuleID: "c", Category: "iam", Severity: models.SeverityCritical, Confidence: models.ConfidenceConfirmed, Status: models.StatusResolved},
	}
	score, level := assessor.Assess(context.Background(), fs)
	if score <= 0 {
		t.Errorf("expected non-zero score, got %d", score)
	}
	if level == "" {
		t.Errorf("level empty")
	}
}

func TestLevelBuckets(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "none"}, {34, "low"}, {35, "medium"}, {59, "medium"},
		{60, "high"}, {79, "high"}, {80, "critical"}, {100, "critical"},
	}
	for _, c := range cases {
		if got := risk.Level(c.score); got != c.want {
			t.Errorf("Level(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}
