package models

import (
	"strings"
)

// Severity describes the security or business impact of a finding.
type Severity string

const (
	SeverityCritical      Severity = "critical"
	SeverityHigh          Severity = "high"
	SeverityMedium        Severity = "medium"
	SeverityLow           Severity = "low"
	SeverityInformational Severity = "informational"
)

// ParseSeverity converts a case-insensitive string into a Severity, defaulting
// to informational for unknown values.
func ParseSeverity(s string) Severity {
	switch Severity(strings.ToLower(s)) {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return Severity(strings.ToLower(s))
	default:
		return SeverityInformational
	}
}

// Weights maps a Severity to a 0..4 impact weight used by the risk engine.
func (s Severity) Weights() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Confidence expresses how sure the framework is about a finding.
type Confidence string

const (
	ConfidenceConfirmed   Confidence = "confirmed"    // direct authoritative record or independent sources agree
	ConfidenceObserved    Confidence = "observed"     // seen in at least one primary source
	ConfidenceProbable    Confidence = "probable"     // strong but not direct evidence
	ConfidencePossible    Confidence = "possible"     // weak or single-source inference
	ConfidenceUnknown     Confidence = "unknown"      // insufficient information
	ConfidenceNotObserved Confidence = "not_observed" // explicit absence of observation
)

// ParseConfidence converts a case-insensitive string into a Confidence.
func ParseConfidence(s string) Confidence {
	switch Confidence(strings.ToLower(s)) {
	case ConfidenceConfirmed, ConfidenceObserved, ConfidenceProbable,
		ConfidencePossible, ConfidenceUnknown, ConfidenceNotObserved:
		return Confidence(strings.ToLower(s))
	default:
		return ConfidenceUnknown
	}
}

// Rank orders confidence values: confirmed > observed > probable > possible >
// unknown > not_observed. Zero means the value is invalid.
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceConfirmed:
		return 6
	case ConfidenceObserved:
		return 5
	case ConfidenceProbable:
		return 4
	case ConfidencePossible:
		return 3
	case ConfidenceUnknown:
		return 2
	case ConfidenceNotObserved:
		return 1
	default:
		return 0
	}
}

// RiskLevel rates the operational risk of a collection/analysis step.
type RiskLevel string

const (
	RiskS1 RiskLevel = "S1" // read-only, reversible, low impact
	RiskS2 RiskLevel = "S2" // read-only against production systems
	RiskS3 RiskLevel = "S3" // state-changing but bounded and reversible
	RiskS4 RiskLevel = "S4" // destructive / irreversible
)

// Rank orders risk levels.
func (r RiskLevel) Rank() int {
	switch r {
	case RiskS1:
		return 1
	case RiskS2:
		return 2
	case RiskS3:
		return 3
	case RiskS4:
		return 4
	default:
		return 0
	}
}

// RequiresConfirmation reports whether an operation of this risk class demands
// explicit interactive confirmation before it may run.
func (r RiskLevel) RequiresConfirmation() bool { return r == RiskS3 || r == RiskS4 }
