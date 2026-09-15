// Package rules provides the shared rule registry. A rule inspects collected
// assessment state and emits findings; the registry deduplicates by finding
// fingerprint, merging corroborating observations into one finding so the same
// underlying issue is reported once and with the strongest available evidence.
package rules

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

// Meta describes a rule for documentation, filtering and capability lists.
type Meta struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Category          string            `json:"category"`
	Description       string            `json:"description"`
	DefaultSeverity   models.Severity   `json:"default_severity"`
	DefaultConfidence models.Confidence `json:"default_confidence"`
	Recommendation    string            `json:"recommendation,omitempty"`
}

// Sink collects findings, deduplicating by fingerprint and merging
// corroborating observations into one finding.
type Sink struct {
	mu       sync.Mutex
	order    []string
	findings map[string]*models.Finding
}

// NewSink returns an empty finding sink.
func NewSink() *Sink { return &Sink{findings: map[string]*models.Finding{}} }

// Add records a finding. A duplicate fingerprint raises confidence to the
// strongest observation seen and merges evidence; it is never silently dropped.
func (s *Sink) Add(f *models.Finding) {
	if f == nil {
		return
	}
	fp := f.Fingerprint()
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.findings[fp]
	if !ok {
		f.ID = stableFindingID(fp)
		s.order = append(s.order, fp)
		s.findings[fp] = f
		return
	}
	mergeInto(existing, f)
}

// List returns the findings in first-seen order (the registration order of the
// rules that produced them; deterministic for a fixed rule set).
func (s *Sink) List() []*models.Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*models.Finding, 0, len(s.order))
	for _, fp := range s.order {
		out = append(out, s.findings[fp])
	}
	return out
}

// Len returns the number of findings recorded.
func (s *Sink) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.order)
}

// stableFindingID derives a deterministic identifier from the fingerprint so
// the same finding yields the same ID across runs and reports are diff-able.
func stableFindingID(fp string) string {
	if len(fp) < 12 {
		return "find-" + fp
	}
	return "find-" + fp[:12]
}

// mergeInto folds a duplicate finding into the kept one, keeping the strongest
// confidence and combining evidence without repeating content hashes.
func mergeInto(dst, src *models.Finding) {
	if src.Confidence.Rank() > dst.Confidence.Rank() {
		dst.Confidence = src.Confidence
	}
	if dst.State == models.StateNotSeen && src.State != models.StateNotSeen {
		dst.State = src.State
	}
	have := make(map[string]bool, len(dst.Evidence)+len(src.Evidence))
	for i := range dst.Evidence {
		have[dst.Evidence[i].Hash] = true
	}
	for _, e := range src.Evidence {
		if e.Hash == "" {
			e.Hash = models.HashContent(e.Data)
		}
		if have[e.Hash] {
			continue
		}
		have[e.Hash] = true
		if e.ID == "" {
			e.ID = models.NewID("ev")
		}
		dst.Evidence = append(dst.Evidence, e)
	}
}

// Rule inspects an assessment environment and emits findings.
type Rule interface {
	Meta() Meta
	Run(ctx context.Context, env any, sink *Sink) error
}

// Registry holds the rules known to one framework build.
type Registry struct {
	mu    sync.RWMutex
	order []Rule
	ids   map[string]bool
}

// NewRegistry returns an empty rule registry.
func NewRegistry() *Registry { return &Registry{ids: map[string]bool{}} }

// Register appends a rule, rejecting duplicate rule IDs.
func (r *Registry) Register(rule Rule) error {
	if rule == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id := rule.Meta().ID
	if r.ids[id] {
		return fmt.Errorf("duplicate rule id %q", id)
	}
	r.ids[id] = true
	r.order = append(r.order, rule)
	return nil
}

// RegisterAll appends many rules in order. It registers nothing when two rules
// declare the same ID, so a defective rule set can never run half-registered.
func (r *Registry) RegisterAll(rules ...Rule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		id := rule.Meta().ID
		if r.ids[id] || seen[id] {
			return fmt.Errorf("duplicate rule id %q", id)
		}
		seen[id] = true
	}
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		id := rule.Meta().ID
		r.ids[id] = true
		r.order = append(r.order, rule)
	}
	return nil
}

// Metas returns the metadata of all registered rules in order.
func (r *Registry) Metas() []Meta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Meta, 0, len(r.order))
	for _, rule := range r.order {
		out = append(out, rule.Meta())
	}
	return out
}

// Len returns the number of registered rules.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.order)
}

// Run executes every registered rule against env in a bounded worker pool,
// flushing results in registration order so output stays deterministic. Rule
// failures and panics are isolated: a diagnostic finding is emitted and the
// remaining rules still run, so one bad rule never voids a report.
func (r *Registry) Run(ctx context.Context, env any, sink *Sink) error {
	return r.RunProfile(ctx, env, sink, "")
}

// RunProfile runs the registry limited to a named analysis profile. Quick runs
// only critical/high rules, standard adds medium, deep runs everything.
func (r *Registry) RunProfile(ctx context.Context, env any, sink *Sink, profile string) error {
	r.mu.RLock()
	rs := append([]Rule(nil), r.order...)
	r.mu.RUnlock()

	selected := make([]Rule, 0, len(rs))
	for _, rule := range rs {
		if severityAllows(profile, rule.Meta().DefaultSeverity) {
			selected = append(selected, rule)
		}
	}

	type outcome struct {
		local *Sink
		err   error
	}
	outcomes := make([]outcome, len(selected))

	workers := runtime.GOMAXPROCS(0)
	if workers > len(selected) || workers <= 0 {
		workers = len(selected)
	}
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, rule := range selected {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, rule Rule) {
			defer wg.Done()
			defer func() { <-sem }()
			local := NewSink()
			var runErr error
			func() {
				defer func() {
					if p := recover(); p != nil {
						runErr = fmt.Errorf("rule %s panicked: %v", rule.Meta().ID, p)
					}
				}()
				runErr = rule.Run(ctx, env, local)
			}()
			outcomes[idx] = outcome{local: local, err: runErr}
		}(i, rule)
	}
	wg.Wait()

	var firstErr error
	for i, o := range outcomes {
		if o.err != nil {
			if firstErr == nil {
				firstErr = o.err
			}
			m := selected[i].Meta()
			sink.Add(&models.Finding{
				RuleID:      m.ID,
				Title:       "Rule evaluation error",
				Category:    "internal",
				Description: fmt.Sprintf("Rule %s failed during evaluation: %v. The remaining rules still ran.", m.ID, o.err),
				Severity:    models.SeverityLow,
				Confidence:  models.ConfidenceNotObserved,
				Status:      models.StatusInformational,
				State:       models.StateUnknown,
				Timestamp:   models.Now(),
			})
			continue
		}
		for _, f := range o.local.List() {
			sink.Add(f)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return firstErr
}

// severityAllows reports whether a rule's default severity belongs to the
// named profile. An empty profile allows everything.
func severityAllows(profile string, sev models.Severity) bool {
	switch profile {
	case "quick":
		return sev == models.SeverityCritical || sev == models.SeverityHigh
	case "standard":
		return sev.Weights() >= 2 // critical, high, medium
	case "deep", "":
		return true
	default:
		return sev.Weights() >= 2
	}
}
