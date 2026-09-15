package validation_test

import (
	"testing"

	"github.com/QYVORA/qyvora-timbuktu/internal/validation"
	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

func TestSnapshotTargetValidatesPresence(t *testing.T) {
	var v validation.Validator
	p := v.Validate(&models.Target{
		ID: "t", Type: models.TargetSnapshot, Value: "/does/not/exist.json",
	}, func(path string) bool { return false })
	if p.Ready {
		t.Fatal("expected plan to be not ready for missing snapshot")
	}
	if !anyFailed(p) {
		t.Fatal("expected snapshot.exists failure")
	}
}

func TestPresentSnapshotIsReady(t *testing.T) {
	var v validation.Validator
	p := v.Validate(&models.Target{
		ID: "t", Type: models.TargetSnapshot, Value: "/tmp/x.json",
	}, func(path string) bool { return true })
	if !p.Ready {
		t.Fatalf("expected ready plan: %+v", p)
	}
}

func TestSimulationIsAlwaysReady(t *testing.T) {
	var v validation.Validator
	p := v.Validate(&models.Target{
		ID: "t", Type: models.TargetSimulation,
	}, nil)
	if !p.Ready {
		t.Fatalf("simulation should be ready: %+v", p)
	}
}

func TestProviderTargetRefused(t *testing.T) {
	var v validation.Validator
	p := v.Validate(&models.Target{
		ID: "t", Type: models.TargetAWS,
	}, nil)
	if p.Ready {
		t.Fatal("provider target must not be ready (live collection not implemented)")
	}
	if !anyFailed(p) {
		t.Fatal("expected live.implemented failure")
	}
}

func TestNilTargetRefused(t *testing.T) {
	var v validation.Validator
	p := v.Validate(nil, nil)
	if p.Ready {
		t.Fatal("nil target must not be ready")
	}
}

func anyFailed(p validation.Plan) bool {
	for _, c := range p.Checks {
		if !c.Pass {
			return true
		}
	}
	return false
}
