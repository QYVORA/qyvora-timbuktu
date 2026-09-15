// Package rules provides the shared rule registry. A rule inspects collected
// assessment state and emits findings; the registry deduplicates by finding
// fingerprint so the same underlying issue is reported once per assessment.
package rules

import (
	"context"
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

// Sink collects findings and deduplicates by fingerprint.
type Sink struct {
	mu       sync.Mutex
	findings []*models.Finding
	seen     map[string]bool
}

// NewSink returns an empty finding sink.
func NewSink() *Sink { return &Sink{seen: map[string]bool{}} }

// Add records a finding, silently dropping exact duplicates.
func (s *Sink) Add(f *models.Finding) {
	if f == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.ID == "" {
		f.ID = models.NewID("find")
	}
	fp := f.Fingerprint()
	if s.seen[fp] {
		return
	}
	s.seen[fp] = true
	s.findings = append(s.findings, f)
}

// List returns the findings in insertion order.
func (s *Sink) List() []*models.Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*models.Finding, len(s.findings))
	copy(out, s.findings)
	return out
}

// Len returns the number of findings recorded.
func (s *Sink) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.findings)
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
}

// NewRegistry returns an empty rule registry.
func NewRegistry() *Registry { return &Registry{} }

// Register appends a rule.
func (r *Registry) Register(rule Rule) {
	if rule == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order = append(r.order, rule)
}

// RegisterAll appends many rules in order.
func (r *Registry) RegisterAll(rules ...Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order = append(r.order, rules...)
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

// Run executes every registered rule against env, collecting into sink.
func (r *Registry) Run(ctx context.Context, env any, sink *Sink) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, rule := range r.order {
		if err := rule.Run(ctx, env, sink); err != nil {
			return err
		}
	}
	return nil
}
