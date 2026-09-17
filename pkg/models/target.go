package models

import "time"

// TargetType distinguishes the kind of assessment target. The model is
// domain-neutral: concrete provider naming is domain data carried in Value.
type TargetType string

const (
	// TargetProvider identifies a live data source that requires collection.
	// Concrete provider identity (aws/azure/gcp/device/host) belongs in Value.
	TargetProvider TargetType = "provider"
	// TargetSnapshot identifies an offline analysis file (snapshot, case,
	// directory, app profile or sample document) to analyze.
	TargetSnapshot TargetType = "snapshot"
	// TargetSimulation is the built-in deterministic simulation target.
	TargetSimulation TargetType = "simulation"
)

// ParseTargetType converts a case-insensitive type string.
func ParseTargetType(s string) TargetType {
	switch TargetType(s) {
	case TargetProvider, TargetSnapshot, TargetSimulation:
		return TargetType(s)
	default:
		return TargetSnapshot
	}
}

// Valid reports whether the target type is a known provider or offline scope.
func (t TargetType) Valid() bool {
	switch t {
	case TargetProvider, TargetSnapshot, TargetSimulation:
		return true
	}
	return false
}

// IsProvider reports whether the type names a live collection source.
func (t TargetType) IsProvider() bool {
	return t == TargetProvider
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
	Value     string        `json:"value"` // provider identity or offline file path
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
