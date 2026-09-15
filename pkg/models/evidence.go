package models

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// EvidenceKind classifies how evidence was obtained.
type EvidenceKind string

const (
	EvidenceAttribute     EvidenceKind = "attribute"
	EvidenceConfiguration EvidenceKind = "configuration"
	EvidenceObservation   EvidenceKind = "observation"
	EvidenceArtifact      EvidenceKind = "artifact"
	EvidenceFile          EvidenceKind = "file"
)

// Evidence is one verifiable observation backing a finding. It carries a
// content hash so reports can trace finding → evidence → source deterministically.
type Evidence struct {
	ID          string       `json:"id"`
	Kind        EvidenceKind `json:"kind"`
	Source      string       `json:"source"`              // collection source, e.g. "snapshot:aws"
	SourceID    string       `json:"source_id,omitempty"` // entity id the evidence describes
	Target      string       `json:"target,omitempty"`    // target identifier
	Data        string       `json:"data,omitempty"`      // quoted value (never secrets after redaction)
	Hash        string       `json:"hash"`
	State       State        `json:"state"`
	CollectedAt time.Time    `json:"collected_at,omitempty"`
	Timestamp   time.Time    `json:"timestamp"`
}

// HashContent returns the lowercase hex SHA-256 digest of s.
func HashContent(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
