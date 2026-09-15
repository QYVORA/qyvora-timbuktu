package models

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// FindingStatus tracks where a finding sits in the assessment lifecycle.
type FindingStatus string

const (
	StatusDetected      FindingStatus = "detected"
	StatusConfirmed     FindingStatus = "confirmed"
	StatusFalsePositive FindingStatus = "false-positive"
	StatusResolved      FindingStatus = "resolved"
	StatusInformational FindingStatus = "informational"
)

// Finding is the normalized representation of a security condition. Every
// finding carries evidence, confidence, severity and risk context.
type Finding struct {
	ID             string            `json:"id"`
	TargetID       string            `json:"target_id"`
	RuleID         string            `json:"rule_id"`
	Title          string            `json:"title"`
	Category       string            `json:"category"`
	Description    string            `json:"description"`
	Impact         string            `json:"impact,omitempty"`
	Recommendation string            `json:"recommendation,omitempty"`
	Severity       Severity          `json:"severity"`
	Confidence     Confidence        `json:"confidence"`
	Status         FindingStatus     `json:"status"`
	State          State             `json:"state"`
	Objects        []string          `json:"objects,omitempty"` // affected entity identifiers (e.g. bucket ARNs)
	Evidence       []Evidence        `json:"evidence,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
	References     []string          `json:"references,omitempty"`
	Timestamp      time.Time         `json:"timestamp"`
}

// Fingerprint returns a stable identity key for the finding (SHA-256 of
// rule/category/title/objects/attributes). Two findings with the same
// fingerprint describe the same underlying issue.
func (f *Finding) Fingerprint() string {
	var b strings.Builder
	b.WriteString(f.RuleID)
	b.WriteString("\x00")
	b.WriteString(f.Category)
	b.WriteString("\x00")
	b.WriteString(f.Title)

	objs := append([]string(nil), f.Objects...)
	sort.Strings(objs)
	for _, o := range objs {
		b.WriteString("\x00obj=")
		b.WriteString(o)
	}

	keys := make([]string, 0, len(f.Attributes))
	for k := range f.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("\x00")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(f.Attributes[k])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// RedactSecrets strips known secret-shaped attribute values before a finding
// is written to any output surface. Affects data, not structural fields.
func (f *Finding) RedactSecrets() {
	for k, v := range f.Attributes {
		if looksSecret(k) {
			f.Attributes[k] = "<redacted>"
		}
		_ = v
	}
	for i := range f.Evidence {
		f.Evidence[i].Data = "<redacted>"
	}
}

// looksSecret classifies attribute keys that must never be emitted verbatim.
func looksSecret(k string) bool {
	l := strings.ToLower(k)
	for _, prefix := range []string{"secret", "token", "password", "key", "credential", "private"} {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return strings.Contains(l, "secret") || strings.Contains(l, "password")
}
