// Package safety implements the architectural safety model of timbuktu.
//
// Every operation carries metadata describing its class, risk, authorization
// requirement, whether it changes remote state, and whether it is reversible.
// Forensic analysis is read-only and offline by default: case-file and
// simulation analysis need no authorization, never run arbitrary binaries and
// never contact a live host. Live acquisition is not implemented and is
// refused with an honest error rather than faked.
package safety

import "github.com/QYVORA/qyvora-timbuktu/pkg/models"

// Class identifies a family of assessment operation.
type Class string

const (
	ClassDiscovery Class = "discovery"
	ClassAnalysis  Class = "analysis"
	ClassLive      Class = "live-acquisition"
)

// OperationMetadata describes one operation's safety contract.
type OperationMetadata struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	Class        Class            `json:"class"`
	Risk         models.RiskLevel `json:"risk"`
	TargetType   string           `json:"target_type"`
	AuthRequired bool             `json:"authorization_required"`
	Confirm      bool             `json:"confirmation_required"`
	ChangesState bool             `json:"changes_state"`
	Reversible   bool             `json:"reversible"`
}

// Known operations.
var (
	// OpCaseParse analyzes an offline forensic case. Read-only, no auth.
	OpCaseParse = OperationMetadata{
		ID: "timbuktu.case.parse", Name: "forensic case analysis",
		Description: "Parse and analyze a read-only forensic case file.",
		Class:       ClassDiscovery, Risk: models.RiskS1, TargetType: "case",
		AuthRequired: false, Confirm: false, ChangesState: false, Reversible: true,
	}
	// OpAnalyze runs the analysis pipeline over collected evidence. Read-only.
	OpAnalyze = OperationMetadata{
		ID: "timbuktu.analyze", Name: "digital forensics analysis",
		Description: "Run artifact, filesystem, memory, timeline, log and indicator analysis.",
		Class:       ClassAnalysis, Risk: models.RiskS1, TargetType: "any",
		AuthRequired: false, Confirm: false, ChangesState: false, Reversible: true,
	}
	// OpLiveAcquisition would contact a live host. Not implemented.
	OpLiveAcquisition = OperationMetadata{
		ID: "timbuktu.live.acquisition", Name: "live host acquisition",
		Description: "Acquire memory/disk directly from a live endpoint (NOT IMPLEMENTED).",
		Class:       ClassLive, Risk: models.RiskS2, TargetType: "live",
		AuthRequired: true, Confirm: true, ChangesState: true, Reversible: false,
	}
)

// Implemented reports whether an operation actually exists in this build.
// Live acquisition is deliberately not implemented; calling it must produce an
// honest error rather than pretend capability.
func (op OperationMetadata) Implemented() bool {
	return op.ID != OpLiveAcquisition.ID
}

// RequiresAuthorization reports whether an operation only runs on an
// authorized target.
func (op OperationMetadata) RequiresAuthorization() bool { return op.AuthRequired }
