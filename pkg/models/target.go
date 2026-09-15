package models

import "time"

// TargetType distinguishes the kind of cloud assessment target.
type TargetType string

const (
	// TargetAWS identifies an Amazon Web Services account/scope.
	TargetAWS TargetType = "aws"
	// TargetAzure identifies a Microsoft Azure subscription/tenant scope.
	TargetAzure TargetType = "azure"
	// TargetGCP identifies a Google Cloud project scope.
	TargetGCP TargetType = "gcp"
	// TargetSnapshot identifies an offline cloud snapshot (JSON file) to analyze.
	TargetSnapshot TargetType = "snapshot"
	// TargetSimulation is the built-in deterministic simulation target.
	TargetSimulation TargetType = "simulation"
)

// ParseTargetType converts a case-insensitive type string.
func ParseTargetType(s string) TargetType {
	switch TargetType(s) {
	case TargetAWS, TargetAzure, TargetGCP, TargetSnapshot, TargetSimulation:
		return TargetType(s)
	default:
		return TargetSnapshot
	}
}

// Valid reports whether the target type is a known provider or offline scope.
func (t TargetType) Valid() bool {
	switch t {
	case TargetAWS, TargetAzure, TargetGCP, TargetSnapshot, TargetSimulation:
		return true
	}
	return false
}

// IsProvider reports whether the type names a live cloud provider.
func (t TargetType) IsProvider() bool {
	return t == TargetAWS || t == TargetAzure || t == TargetGCP
}

// Authorization records the explicit consent state of a target. Live provider
// collection requires a granted authorization; offline snapshot and simulation
// analysis never do.
type Authorization struct {
	Granted   bool      `json:"granted"`
	GrantedAt time.Time `json:"granted_at,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	GrantedBy string    `json:"granted_by,omitempty"`
}

// Target is the object an assessment runs against.
type Target struct {
	ID        string        `json:"id"`
	Name      string        `json:"name,omitempty"`
	Type      TargetType    `json:"type"`
	Value     string        `json:"value"` // account/subscription/project id or snapshot path
	Profile   string        `json:"profile,omitempty"`
	Auth      Authorization `json:"authorization"`
	CreatedAt time.Time     `json:"created_at"`
}

// Authorized reports whether the target passed the authorization gate.
func (t *Target) Authorized() bool { return t != nil && t.Auth.Granted }

// DisplayName returns a short human-readable label for the target.
func (t *Target) DisplayName() string {
	if t == nil {
		return "<nil>"
	}
	if t.Name != "" {
		return t.Name
	}
	if t.Value != "" {
		return t.Value
	}
	return "unknown target"
}

// TypedName renders the target with its type prefix, e.g. "aws:acme-root".
func (t *Target) TypedName() string {
	if t == nil {
		return "<nil>"
	}
	if t.Value == "" {
		return string(t.Type)
	}
	return string(t.Type) + ":" + t.Value
}
