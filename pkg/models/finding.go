package models

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
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

// RedactSecrets strips secret-shaped values from a finding before it is
// written to any output surface. It is field-scoped, not blanket: structural
// fields (rule, category, description, recommendation, objects, references)
// are preserved verbatim, and only attribute values and evidence payloads that
// look like credential material are replaced. Keeping non-secret evidence
// readable means reports stay useful for triage while values never leak.
func (f *Finding) RedactSecrets() {
	for k, v := range f.Attributes {
		if looksSecret(k) || looksSecretValue(v) {
			f.Attributes[k] = "<redacted>"
		}
	}
	for i := range f.Evidence {
		if looksSecretValue(f.Evidence[i].Data) {
			f.Evidence[i].Data = "<redacted>"
		}
	}
}

// RedactSecretData redacts secret-shaped payloads from an evidence slice in
// place, so result-level evidence lists are also safe to persist.
func RedactSecretData(list []Evidence) {
	for i := range list {
		if looksSecretValue(list[i].Data) {
			list[i].Data = "<redacted>"
		}
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

// looksSecretValue classifies value-shaped credential material: stable secret
// prefixes, standard private-key markers, and inline key=value assignments
// whose value is a known credential class. High-entropy guessing is
// deliberately avoided so evidence quality is not destroyed by false positives.
func looksSecretValue(s string) bool {
	if s == "" || s == "<redacted>" {
		return false
	}
	l := strings.ToLower(strings.TrimSpace(s))
	for _, p := range []string{
		"-----begin", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
		"glpat-", "sk_live_", "pk_live_", "sk_test_", "pk_test_", "xoxb-",
		"xoxp-", "xoxa-", "ya29.", "eyj",
	} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	if secretValueRx.MatchString(s) {
		return true
	}
	return false
}

// secretValueRx detects credential-shaped values wherever they appear in a
// payload: AWS access key ids, GitHub tokens, JWT headers, private key blocks,
// Google API keys, and SECRET=long-value assignments.
var secretValueRx = regexp.MustCompile(`(?is)\bAKIA[0-9A-Z]{16}\b|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----|\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}|\bAIza[0-9A-Za-z_-]{35}|(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*\S+|\b(?:password|passwd|secret|token|client[_-]?secret|api[_-]?key|access[_-]?key)\s*[=:]\s*[\"']?[A-Za-z0-9._\-+/=]{14,}`)
