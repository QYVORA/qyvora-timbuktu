package rules

import (
	"context"
	"sync"
	"testing"

	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

// oracleRule is a deterministic, configurable rule used to exercise the
// registry and sink mechanics.
type oracleRule struct {
	meta   Meta
	emit   func(ctx context.Context, sink *Sink)
	panics bool
}

func (o *oracleRule) Meta() Meta { return o.meta }

func (o *oracleRule) Run(ctx context.Context, _ any, sink *Sink) error {
	if o.panics {
		panic("boom")
	}
	if o.emit != nil {
		o.emit(ctx, sink)
	}
	return nil
}

func oracle(id string, sev models.Severity, emit func(ctx context.Context, sink *Sink), panics bool) *oracleRule {
	return &oracleRule{
		meta:   Meta{ID: id, Name: id, Category: "test", DefaultSeverity: sev, DefaultConfidence: models.ConfidenceObserved},
		emit:   emit,
		panics: panics,
	}
}

func TestRegisterRejectsDuplicateID(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(oracle("DUP", models.SeverityHigh, nil, false)); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := reg.Register(oracle("DUP", models.SeverityCritical, nil, false)); err == nil {
		t.Fatal("duplicate id must be rejected")
	}
	if reg.Len() != 1 {
		t.Fatalf("len = %d, want 1", reg.Len())
	}
}

func TestRegisterAllIsAtomicOnDuplicate(t *testing.T) {
	reg := NewRegistry()
	rules := []Rule{
		oracle("A", models.SeverityHigh, nil, false),
		oracle("A", models.SeverityMedium, nil, false),
		oracle("B", models.SeverityLow, nil, false),
	}
	if err := reg.RegisterAll(rules...); err == nil {
		t.Fatal("RegisterAll must fail on duplicate id")
	}
	if reg.Len() != 0 {
		t.Fatalf("RegisterAll partially registered %d rules, want 0", reg.Len())
	}
}

func TestSinkDedupMergesConfidenceAndEvidence(t *testing.T) {
	sink := NewSink()
	a := &models.Finding{
		RuleID: "T", Category: "test", Title: "same",
		Objects:    []string{"o1"},
		Attributes: map[string]string{"k": "v"},
		Severity:   models.SeverityLow,
		Confidence: models.ConfidenceObserved,
		State:      models.StateObserved,
		Evidence:   []models.Evidence{{Source: "a", Data: "one"}},
	}
	b := &models.Finding{
		RuleID: "T", Category: "test", Title: "same",
		Objects:    []string{"o1"},
		Attributes: map[string]string{"k": "v"},
		Severity:   models.SeverityLow,
		Confidence: models.ConfidenceConfirmed,
		State:      models.StateInferred,
		Evidence:   []models.Evidence{{Source: "b", Data: "two"}},
	}
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("test findings must collide on fingerprint")
	}
	sink.Add(a)
	sink.Add(b)
	if sink.Len() != 1 {
		t.Fatalf("len = %d, want 1 merged finding", sink.Len())
	}
	got := sink.List()[0]
	if got.Confidence != models.ConfidenceConfirmed {
		t.Errorf("confidence not raised to strongest: %s", got.Confidence)
	}
	if len(got.Evidence) != 2 {
		t.Errorf("evidence not merged: %d entries", len(got.Evidence))
	}
	if got.ID == "" || got.ID != stableFindingID(got.Fingerprint()) {
		t.Errorf("finding ID not fingerprint-derived: %q", got.ID)
	}
}

func TestStableFindingIDIsDeterministic(t *testing.T) {
	if stableFindingID("abc") != stableFindingID("abc") {
		t.Error("stable id must be a pure function of the fingerprint")
	}
	if stableFindingID("a") == stableFindingID("b") {
		t.Error("different fingerprints must produce different ids")
	}
}

func TestRunProfileQuickRunsOnlyHighAndCritical(t *testing.T) {
	reg := NewRegistry()
	var mu sync.Mutex
	ran := map[string]bool{}
	mark := func(id string) {
		mu.Lock()
		ran[id] = true
		mu.Unlock()
	}
	reg.RegisterAll(
		oracle("CRIT", models.SeverityCritical, func(_ context.Context, s *Sink) {
			mark("CRIT")
			s.Add(&models.Finding{RuleID: "CRIT", Category: "t", Title: "c", Severity: models.SeverityCritical})
		}, false),
		oracle("HIGH", models.SeverityHigh, func(_ context.Context, s *Sink) {
			mark("HIGH")
			s.Add(&models.Finding{RuleID: "HIGH", Category: "t", Title: "h", Severity: models.SeverityHigh})
		}, false),
		oracle("MED", models.SeverityMedium, func(_ context.Context, s *Sink) {
			mark("MED")
			s.Add(&models.Finding{RuleID: "MED", Category: "t", Title: "m", Severity: models.SeverityMedium})
		}, false),
		oracle("LOW", models.SeverityLow, func(_ context.Context, s *Sink) {
			mark("LOW")
			s.Add(&models.Finding{RuleID: "LOW", Category: "t", Title: "l", Severity: models.SeverityLow})
		}, false),
	)
	sink := NewSink()
	if err := reg.RunProfile(context.Background(), nil, sink, "quick"); err != nil {
		t.Fatalf("RunProfile: %v", err)
	}
	if !ran["CRIT"] || !ran["HIGH"] {
		t.Error("quick profile must run critical and high rules")
	}
	if ran["MED"] || ran["LOW"] {
		t.Error("quick profile must skip medium and low rules")
	}
	if sink.Len() != 2 {
		t.Errorf("sink findings = %d, want 2", sink.Len())
	}
}

func TestRunProfileDeepRunsEverything(t *testing.T) {
	reg := NewRegistry()
	ran := map[string]bool{}
	var mu sync.Mutex
	mark := func(id string) {
		mu.Lock()
		ran[id] = true
		mu.Unlock()
	}
	reg.RegisterAll(
		oracle("CRIT", models.SeverityCritical, func(_ context.Context, _ *Sink) { mark("CRIT") }, false),
		oracle("INFO", models.SeverityInformational, func(_ context.Context, _ *Sink) { mark("INFO") }, false),
	)
	if err := reg.RunProfile(context.Background(), nil, NewSink(), "deep"); err != nil {
		t.Fatalf("RunProfile: %v", err)
	}
	if !ran["CRIT"] || !ran["INFO"] {
		t.Error("deep profile must run every severity")
	}
}

func TestRunIsolatesPanickingRule(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterAll(
		oracle("PANIC", models.SeverityHigh, nil, true),
		oracle("OK", models.SeverityHigh, func(_ context.Context, s *Sink) {
			s.Add(&models.Finding{RuleID: "OK", Category: "t", Title: "ok", Severity: models.SeverityHigh})
		}, false),
	)
	sink := NewSink()
	err := reg.RunProfile(context.Background(), nil, sink, "standard")
	if err == nil {
		t.Fatal("panicked rule must surface an error")
	}
	if sink.Len() == 0 {
		t.Fatal("sink must still contain results from healthy rules")
	}
	foundDiagnostic := false
	foundHealthy := false
	for _, f := range sink.List() {
		if f.RuleID == "PANIC" && f.Category == "internal" {
			foundDiagnostic = true
		}
		if f.RuleID == "OK" {
			foundHealthy = true
		}
	}
	if !foundDiagnostic {
		t.Error("expected a diagnostic finding for the panicked rule")
	}
	if !foundHealthy {
		t.Error("healthy rules must still produce findings")
	}
}

func TestRunFlushOrderIsRegistrationOrder(t *testing.T) {
	reg := NewRegistry()
	ids := []string{"R1", "R2", "R3", "R4"}
	for _, id := range ids {
		id := id
		reg.Register(oracle(id, models.SeverityHigh, func(_ context.Context, s *Sink) {
			s.Add(&models.Finding{RuleID: id, Category: "t", Title: id, Severity: models.SeverityHigh})
		}, false))
	}
	sink := NewSink()
	for i := 0; i < 3; i++ {
		if err := reg.Run(context.Background(), nil, sink); err != nil {
			t.Fatal(err)
		}
	}
	got := sink.List()
	if len(got) != 4 {
		t.Fatalf("len = %d, want 4 (runs must deduplicate)", len(got))
	}
	for i, f := range got {
		if f.RuleID != ids[i] {
			t.Errorf("order[%d] = %s, want %s", i, f.RuleID, ids[i])
		}
	}
}
