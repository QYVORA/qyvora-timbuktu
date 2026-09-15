// Package pipeline runs a staged assessment. Each stage is a named unit of
// work that receives a shared step context and may emit events, evidence and
// findings. The engine emits stage lifecycle events and aborts on the first
// stage failure.
package pipeline

import (
	"context"
	"fmt"

	"github.com/QYVORA/qyvora-timbuktu/internal/events"
	"github.com/QYVORA/qyvora-timbuktu/internal/evidence"
	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

// Step carries the shared state visible to every stage.
type Step struct {
	Target   *models.Target
	Sim      bool
	Events   *events.Stream
	Evidence *evidence.Store
	Result   *models.Result
}

// Stage is one unit of pipeline work.
type Stage struct {
	ID   string
	Name string
	Run  func(ctx context.Context, step *Step) error
}

// Engine executes a sequence of stages, emitting lifecycle events.
type Engine struct {
	stages []Stage
}

// New returns an engine running the given stages in order.
func New(stages ...Stage) *Engine { return &Engine{stages: stages} }

// Stages returns the registered stage descriptors.
func (e *Engine) Stages() []Stage { return e.stages }

// Run executes all stages. Events for stage start/complete are emitted for
// every stage; the first stage error aborts the run.
func (e *Engine) Run(ctx context.Context, step *Step) error {
	if e == nil {
		return nil
	}
	for _, st := range e.stages {
		if err := ctx.Err(); err != nil {
			return err
		}
		if step.Events != nil {
			step.Events.Info(events.StageStarted, map[string]any{"stage": st.ID, "name": st.Name})
		}
		if err := st.Run(ctx, step); err != nil {
			if step.Events != nil {
				step.Events.Fail(events.Error, map[string]any{"stage": st.ID, "error": err.Error()})
			}
			return fmt.Errorf("stage %s: %w", st.ID, err)
		}
		if step.Events != nil {
			step.Events.Info(events.StageCompleted, map[string]any{"stage": st.ID, "name": st.Name})
		}
	}
	return nil
}
