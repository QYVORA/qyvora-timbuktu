// Package risk implements the risk engine. It separates severity, confidence
// and exposure rather than emitting a fake-precision score, and every score is
// explainable: a finding's classification is derived from explicit components.
package risk

import (
	"context"
	"fmt"
	"strings"

	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

// MaxScore is the total attainable target risk score (0..100).
const MaxScore = 100

// Assessor computes per-finding context and overall target risk.
type Assessor struct{}

// Risk summarises the risk components of a single finding transparently.
type Risk struct {
	Severity   models.Severity   `json:"severity"`
	Confidence models.Confidence `json:"confidence"`
	Impact     int               `json:"impact"`   // 0..4
	Exposure   int               `json:"exposure"` // 0..5
	Score      int               `json:"score"`    // 0..100, derived
	Level      string            `json:"level"`
	Rationale  string            `json:"rationale"`
}

// Level maps a 0..100 risk score to a severity label.
func Level(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 35:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

// ExposureFor returns the per-category exposure heuristic (0..5): how much of
// the category's attack surface is reachable and consequential. The default
// (2) applies to informatic-resource issues; categories with direct external
// attack surface or lasting credential/persistence impact score higher. This
// mapping is shared across the QYVORA frameworks and is tuned per discipline.
func ExposureFor(category string) int {
	switch strings.ToLower(category) {
	// Cloud security posture.
	case "iam", "storage", "secrets", "credentials":
		return 4
	case "network", "containers", "misconfig", "infrastructure":
		return 3
	// Identity and credential security.
	case "authentication", "privilege", "attack-path", "lifecycle", "authorization":
		return 4
	// DFIR and malware analysis.
	case "command-and-control", "persistence", "exfiltration":
		return 5
	case "execution", "intrusion", "memory", "payload", "behavior", "armoring":
		return 4
	case "obfuscation", "filesystem", "signing", "authenticode", "transport", "permissions":
		return 3
	case "timeline", "logs", "indicators", "ioc", "integrity", "static", "crypto", "data", "platform":
		return 2
	default:
		return 2
	}
}

// ScoreFor computes the transparent risk of a single finding.
func ScoreFor(f *models.Finding) Risk {
	if f == nil {
		return Risk{}
	}
	sev := f.Severity.Weights()
	conf := confidenceValue(f.Confidence)
	exposure := ExposureFor(f.Category)
	score := int(float64(sev) * conf * (float64(exposure) / 5.0) * 40)
	if score > MaxScore {
		score = MaxScore
	}
	rationale := fmt.Sprintf("impact=%s confidence=%s exposure=%d/5",
		f.Severity, f.Confidence, exposure)
	return Risk{
		Severity:   f.Severity,
		Confidence: f.Confidence,
		Impact:     sev,
		Exposure:   exposure,
		Score:      score,
		Level:      Level(score),
		Rationale:  rationale,
	}
}

// Assess computes the target-level risk from a collection of findings.
func (a *Assessor) Assess(_ context.Context, findings []*models.Finding) (int, string) {
	var total float64
	var maxWeight float64
	for _, f := range findings {
		if f == nil {
			continue
		}
		if f.Status == models.StatusFalsePositive || f.Status == models.StatusResolved {
			continue
		}
		total += float64(ScoreFor(f).Score)
		maxWeight += float64(MaxScore)
	}
	if maxWeight == 0 {
		return 0, Level(0)
	}
	score := int(total / maxWeight * MaxScore)
	if score > MaxScore {
		score = MaxScore
	}
	return score, Level(score)
}

func confidenceValue(c models.Confidence) float64 {
	switch c {
	case models.ConfidenceConfirmed:
		return 1.0
	case models.ConfidenceObserved:
		return 0.9
	case models.ConfidenceProbable:
		return 0.7
	case models.ConfidencePossible:
		return 0.5
	case models.ConfidenceUnknown:
		return 0.3
	case models.ConfidenceNotObserved:
		return 0.1
	default:
		return 0.5
	}
}
