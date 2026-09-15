package models

import "time"

// Result captures one full assessment run: its target, findings, evidence,
// computed risk and provenance. Machine-readable output derives from exactly
// this structure — there is no separate presentation model.
type Result struct {
	ID          string     `json:"id"`
	Framework   string     `json:"framework"`
	Target      *Target    `json:"target"`
	Profile     string     `json:"profile"`
	Sim         bool       `json:"sim"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt time.Time  `json:"completed_at"`
	Assets      int        `json:"assets"`
	Findings    []Finding  `json:"findings"`
	Evidence    []Evidence `json:"evidence"`
	Events      int        `json:"events"`
	Score       int        `json:"score,omitempty"` // 0..100
	Level       string     `json:"level,omitempty"` // none|low|medium|high|critical
	Summary     string     `json:"summary,omitempty"`
}

// Offline reports whether the run analyzed a snapshot or simulation rather
// than contacting any live provider.
func (r *Result) Offline() bool {
	return r.Sim || (r.Target != nil && (r.Target.Type == TargetSnapshot || r.Target.Type == TargetSimulation))
}
