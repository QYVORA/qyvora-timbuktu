package analysis_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/QYVORA/qyvora-timbuktu/internal/analysis"
	"github.com/QYVORA/qyvora-timbuktu/internal/events"
	"github.com/QYVORA/qyvora-timbuktu/internal/evidence"
	"github.com/QYVORA/qyvora-timbuktu/internal/pipeline"
	"github.com/QYVORA/qyvora-timbuktu/internal/rules"
	"github.com/QYVORA/qyvora-timbuktu/internal/rules/builtin"
	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

// TestSimulationPipelineProducesFindings runs the full analysis pipeline over
// the deterministic simulation and verifies that every known hazard ships a
// finding.
func TestSimulationPipelineProducesFindings(t *testing.T) {
	reg := rules.NewRegistry()
	reg.RegisterAll(builtin.All()...)

	var evBuf bytes.Buffer
	stream := events.NewStream(&evBuf)
	mgr := evidence.New("")
	step := &pipeline.Step{
		Target:   &models.Target{ID: "sim", Type: models.TargetSimulation},
		Sim:      true,
		Events:   stream,
		Evidence: mgr,
		Result: &models.Result{
			ID: "run", Framework: "timbuktu", Target: &models.Target{ID: "sim"}, Sim: true,
		},
	}

	stages := analysis.Stages(reg, map[string]any{}, 1000)
	eng := pipeline.New(stages...)
	if err := eng.Run(context.Background(), step); err != nil {
		t.Fatalf("pipeline run: %v", err)
	}

	found := map[string]bool{}
	for _, f := range step.Result.Findings {
		found[f.RuleID] = true
	}
	expected := []string{"DFI-001", "DFI-002", "DFI-003", "DFI-004", "DFI-005",
		"DFI-006", "DFI-007", "DFI-008", "DFI-009", "DFI-010",
		"DFI-011", "DFI-012", "DFI-013"}
	for _, id := range expected {
		if !found[id] {
			t.Errorf("expected finding %s in simulation", id)
		}
	}
	if mgr.Len() == 0 {
		t.Error("simulation produced no evidence")
	}
	if step.Result.Score <= 0 {
		t.Errorf("expected positive risk score, got %d", step.Result.Score)
	}
	if step.Result.Assets == 0 {
		t.Error("acquisition found no evidence items")
	}

	// Event stream must be valid JSONL with the shared envelope.
	for _, line := range bytes.Split(bytes.TrimSpace(evBuf.Bytes()), []byte("\n")) {
		var ev map[string]any
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("invalid event line %q: %v", line, err)
		}
		if ev["framework"] != "timbuktu" {
			t.Errorf("event framework = %v", ev["framework"])
		}
	}
}

// TestCasePipelineAcceptsFileTarget exercises the file-path path with a raw
// case document and verifies a filesystem finding ships.
func TestCasePipelineAcceptsFileTarget(t *testing.T) {
	reg := rules.NewRegistry()
	reg.RegisterAll(builtin.All()...)

	doc := `{"schema":"qyvora.timbuktu.case.v1","case_id":"INC-T-1","source":"disk",
	  "evidence":[{"id":"ev-1","kind":"disk_image","content":"payload"}],
	  "volumes":[{"id":"vol-c","name":"C:","fs_type":"NTFS",
	    "files":[{"path":"C:\\Users\\qa\\AppData\\Local\\Temp\\drop.exe","name":"drop.exe","extension":"exe"}]}]}`
	path := writeTemp(t, doc)

	step := &pipeline.Step{
		Target:   &models.Target{ID: "case", Type: models.TargetSnapshot, Value: path},
		Events:   events.NewStream(&bytes.Buffer{}),
		Evidence: evidence.New(""),
		Result:   &models.Result{ID: "run", Framework: "timbuktu", Target: &models.Target{ID: "case"}},
	}
	stages := analysis.Stages(reg, map[string]any{}, 1000)
	if err := pipeline.New(stages...).Run(context.Background(), step); err != nil {
		t.Fatalf("case run: %v", err)
	}
	var got bool
	for _, f := range step.Result.Findings {
		if f.RuleID == "DFI-006" {
			got = true
		}
	}
	if !got {
		t.Error("expected DFI-006 for temp executable in case")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/case.json"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
