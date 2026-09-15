// Package models holds the shared, framework-independent data contracts for
// cloud security assessments: targets, findings, evidence, risk, results and
// the common enums used across collections.
package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// State distinguishes how the framework knows a value: directly observed,
// validated, inferred, unknown, or explicitly not seen.
type State string

const (
	StateObserved  State = "observed"
	StateValidated State = "validated"
	StateInferred  State = "inferred"
	StateUnknown   State = "unknown"
	StateNotSeen   State = "not_seen"
)

// NewID returns a random lowercase hex identifier with the given prefix, or a
// timestamp fallback if the CSPRNG is unavailable.
func NewID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return prefix + "-" + time.Now().UTC().Format("20060102T150405.000")
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}

// Now returns the current UTC instant, the standard timestamp for all
// framework records.
func Now() time.Time { return time.Now().UTC() }
