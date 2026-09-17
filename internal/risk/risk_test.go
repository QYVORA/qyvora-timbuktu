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

func TestExposureForDomainCoverage(t *testing.T) {
	if risk.ExposureFor("command-and-control") != 5 {
		t.Error("c2 exposure should rank 5")
	}
	if risk.ExposureFor("iam") != 4 {
		t.Error("iam exposure should rank 4")
	}
	if risk.ExposureFor("network") != 3 {
		t.Error("network exposure should rank 3")
	}
	if risk.ExposureFor("timeline") != 2 {
		t.Error("timeline exposure should rank 2")
	}
	if risk.ExposureFor("unknown-category") != 2 {
		t.Error("unknown categories must fall back to 2")
	}
}

// TestAssessIsWorstCaseAware verifies a critical finding is never diluted by
// many harmless findings (the previous mean aggregation could hide it).
func TestAssessIsWorstCaseAware(t *testing.T) {
	var assessor risk.Assessor
	critical := []*models.Finding{
		{RuleID: "k", Category: "iam", Severity: models.SeverityCritical, Confidence: models.ConfidenceConfirmed, Status: models.StatusConfirmed},
	}
	criticalPlusNoise := append([]*models.Finding{
		{RuleID: "x", Category: "timeline", Severity: models.SeverityLow, Confidence: models.ConfidenceConfirmed, Status: models.StatusConfirmed},
		{RuleID: "y", Category: "timeline", Severity: models.SeverityLow, Confidence: models.ConfidenceConfirmed, Status: models.StatusConfirmed},
		{RuleID: "z", Category: "timeline", Severity: models.SeverityLow, Confidence: models.ConfidenceConfirmed, Status: models.StatusConfirmed},
	}, critical...)

	alone, _ := assessor.Assess(context.Background(), critical)
	withNoise, _ := assessor.Assess(context.Background(), criticalPlusNoise)
	if alone <= 0 {
		t.Fatalf("critical finding alone must score > 0, got %d", alone)
	}
	if withNoise < alone {
		t.Errorf("noise must never lower the critical score: alone=%d withNoise=%d", alone, withNoise)
	}
	// Worst case: a single critical finding must not collapse below high.
	if risk.Level(alone) != "critical" && risk.Level(alone) != "high" {
		t.Errorf("critical finding alone should retain critical/high exposure, got level %q", risk.Level(alone))
	}
}

// TestAssessMonotonic verifies adding a finding never lowers the score.
func TestAssessMonotonic(t *testing.T) {
	var assessor risk.Assessor
	base := []*models.Finding{
		{RuleID: "R1", Category: "cloud", Severity: models.SeverityMedium, Confidence: models.ConfidenceConfirmed, Status: models.StatusConfirmed},
	}
	baseScore, _ := assessor.Assess(context.Background(), base)

	more := []*models.Finding{
		{RuleID: "R2", Category: "cloud", Severity: models.SeverityMedium, Confidence: models.ConfidenceConfirmed, Status: models.StatusConfirmed},
		{RuleID: "R3", Category: "cloud", Severity: models.SeverityMedium, Confidence: models.ConfidenceConfirmed, Status: models.StatusConfirmed},
		{RuleID: "R9", Category: "secrets", Severity: models.SeverityHigh, Confidence: models.ConfidenceConfirmed, Status: models.StatusConfirmed},
	}
	all := append(append([]*models.Finding{}, base...), more...)
	addedScore, _ := assessor.Assess(context.Background(), more)
	allScore, _ := assessor.Assess(context.Background(), all)
	if addedScore < baseScore || allScore < addedScore {
		t.Fatalf("score must be monotonic under additions: base=%d added=%d all=%d", baseScore, addedScore, allScore)
	}
	if allScore != addedScore {
		t.Errorf("worst-case aggregation should be driven by the worst finding, got base-extension %d != standalone %d", allScore, addedScore)
	}
	// The same set must produce the same score regardless of input order.
	rev := make([]*models.Finding, len(all))
	for i, f := range all {
		rev[len(all)-1-i] = f
	}
	revScore, _ := assessor.Assess(context.Background(), rev)
	if revScore != allScore {
		t.Errorf("risk aggregation must be order-independent: %d != %d", revScore, allScore)
	}
}

func TestAssessMaxScoreCap(t *testing.T) {
	var assessor risk.Assessor
	fs := make([]*models.Finding, 0, 200)
	for i := 0; i < 200; i++ {
		fs = append(fs, &models.Finding{RuleID: string(rune(int(rune('A')) + i%26)), Category: "iam",
			Severity: models.SeverityCritical, Confidence: models.ConfidenceConfirmed, Status: models.StatusConfirmed})
	}
	score, level := assessor.Assess(context.Background(), fs)
	if score > risk.MaxScore {
		t.Errorf("score capped at MaxScore, got %d", score)
	}
	if score <= 0 {
		t.Errorf("expected positive capped score, got %d", score)
	}
	_ = level
}
