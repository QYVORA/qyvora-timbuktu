// Package pipeline runs a staged assessment. Each stage is a named unit of
// work that receives a shared step context and may emit events, evidence and
// findings. The engine emits stage lifecycle events and aborts on the first
// stage failure. A per-run cache on the step lets stages and rules share
// parsed models instead of re-reading the same input repeatedly.
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

	cache map[string]any
}

// Cached returns a lazily computed, per-run value shared by all stages and
// rules. The loader runs at most once per step; later callers reuse the value.
func (s *Step) Cached(key string, load func() (any, error)) (any, error) {
	if s == nil {
		return nil, fmt.Errorf("assessment step is nil")
	}
	if s.cache == nil {
		s.cache = map[string]any{}
	}
	if v, ok := s.cache[key]; ok {
		return v, nil
	}
	v, err := load()
	if err != nil {
		return nil, err
	}
	s.cache[key] = v
	return v, nil
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
