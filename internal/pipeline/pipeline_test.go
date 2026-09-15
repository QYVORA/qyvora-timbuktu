package pipeline_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/QYVORA/qyvora-timbuktu/internal/events"
	"github.com/QYVORA/qyvora-timbuktu/internal/evidence"
	"github.com/QYVORA/qyvora-timbuktu/internal/pipeline"
	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

func TestEngineRunsStagesInOrder(t *testing.T) {
	var order []string
	eng := pipeline.New(
		stg("a", func(ctx context.Context, step *pipeline.Step) error {
			order = append(order, "a")
			return nil
		}),
		stg("b", func(ctx context.Context, step *pipeline.Step) error {
			order = append(order, "b")
			return nil
		}),
	)
	step := &pipeline.Step{
		Events:   events.NewStream(&bytes.Buffer{}),
		Evidence: evidence.New(""),
		Result:   &models.Result{},
		Target:   &models.Target{ID: "t", Type: models.TargetSimulation},
		Sim:      true,
	}
	if err := eng.Run(context.Background(), step); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(order) != 2 || order[0] != "a" || order[1] != "b" {
		t.Fatalf("stage order = %v", order)
	}
}

func TestEngineAbortsOnFirstFailure(t *testing.T) {
	boom := errors.New("boom")
	var ran []string
	eng := pipeline.New(
		stg("bad", func(ctx context.Context, step *pipeline.Step) error { return boom }),
		stg("never", func(ctx context.Context, step *pipeline.Step) error {
			ran = append(ran, "never")
			return nil
		}),
	)
	err := eng.Run(context.Background(), &pipeline.Step{
		Events:   events.NewStream(&bytes.Buffer{}),
		Evidence: evidence.New(""),
		Result:   &models.Result{},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if len(ran) != 0 {
		t.Errorf("stage ran after failure: %v", ran)
	}
}

func TestEngineAbortsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	eng := pipeline.New(stg("x", func(ctx context.Context, step *pipeline.Step) error { return nil }))
	err := eng.Run(ctx, &pipeline.Step{
		Events: events.NewStream(&bytes.Buffer{}), Evidence: evidence.New(""), Result: &models.Result{},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func stg(id string, fn func(ctx context.Context, step *pipeline.Step) error) pipeline.Stage {
	return pipeline.Stage{ID: id, Name: id, Run: fn}
}
