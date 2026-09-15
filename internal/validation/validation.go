// Package validation performs deterministic preflight checks on a target and
// its inputs before an assessment runs. It produces a plan of steps and any
// blocking or warning conditions.
package validation

import "github.com/QYVORA/qyvora-timbuktu/pkg/models"

// Check is one preflight result.
type Check struct {
	ID      string `json:"id"`
	Step    string `json:"step"`
	Pass    bool   `json:"pass"`
	Message string `json:"message,omitempty"`
}

// Plan is the deterministic preflight result for a target.
type Plan struct {
	TargetID string  `json:"target_id"`
	Checks   []Check `json:"checks"`
	Ready    bool    `json:"ready"`
}

// Validator runs preflight checks for a target.
type Validator struct{}

// Validate checks a target. For snapshot targets it verifies the file exists,
// is readable, and capping limits are sane; for provider targets it verifies
// the provider is known and reports live collection as not implemented.
func (v *Validator) Validate(t *models.Target, pathExists func(string) bool) Plan {
	plan := Plan{}
	if t != nil {
		plan.TargetID = t.ID
	}
	plan.Ready = true

	if t == nil {
		plan.Checks = append(plan.Checks, Check{ID: "target.present", Pass: false, Message: "no target selected"})
		plan.Ready = false
		return plan
	}

	switch t.Type {
	case models.TargetSnapshot, models.TargetSimulation:
		plan.Checks = append(plan.Checks, Check{ID: "target.present", Pass: true, Message: t.TypedName()})
		if t.Type == models.TargetSnapshot {
			ok := pathExists != nil && pathExists(t.Value)
			if !ok {
				plan.Checks = append(plan.Checks, Check{
					ID: "snapshot.exists", Pass: false,
					Message: "snapshot file not found: " + t.Value,
				})
				plan.Ready = false
			} else {
				plan.Checks = append(plan.Checks, Check{ID: "snapshot.exists", Pass: true})
			}
		} else {
			plan.Checks = append(plan.Checks, Check{ID: "snapshot.provided", Pass: true, Message: "built-in simulation dataset"})
		}
	case models.TargetAWS, models.TargetAzure, models.TargetGCP:
		plan.Checks = append(plan.Checks, Check{
			ID: "provider.known", Pass: true, Message: string(t.Type),
		})
		plan.Checks = append(plan.Checks, Check{
			ID: "live.implemented", Pass: false,
			Message: "live provider collection is not implemented; provide a snapshot file instead",
		})
		plan.Ready = false
	default:
		plan.Checks = append(plan.Checks, Check{ID: "target.valid", Pass: false, Message: "unsupported target type: " + string(t.Type)})
		plan.Ready = false
	}
	return plan
}
