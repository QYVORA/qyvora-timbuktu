// Package capabilities exposes the machine-readable tool contract so
// automation and humans can read what this framework actually implements,
// without trusting prose.
package capabilities

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/QYVORA/qyvora-timbuktu/internal/events"
	"github.com/QYVORA/qyvora-timbuktu/internal/output"
	"github.com/QYVORA/qyvora-timbuktu/internal/version"
	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

// Command describes one CLI command surface.
type Command struct {
	Name        string   `json:"name"`
	Summary     string   `json:"summary"`
	OutputModes []string `json:"output_modes"`
	Sim         bool     `json:"sim_support"`
}

// Capability lists one implemented capability area.
type Capability struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Implemented bool   `json:"implemented"`
	Live        bool   `json:"live"` // requires a live host connection
	Note        string `json:"note,omitempty"`
}

// Document is the full machine-readable contract of this framework build.
type Document struct {
	Framework      string         `json:"framework"`
	Version        string         `json:"version"`
	ExitCodes      map[string]int `json:"exit_codes"`
	OutputFormats  []string       `json:"output_formats"`
	EventVerbs     []string       `json:"event_verbs"`
	SeverityLevels []string       `json:"severity_levels"`
	Confidence     []string       `json:"confidence_levels"`
	Authorized     string         `json:"authorization_model"`
	Capabilities   []Capability   `json:"capabilities"`
	Commands       []Command      `json:"commands"`
}

// Report is the summary returned to the CLI.
type Report struct {
	Doc     Document
	Printer *output.Printer
}

// Build assembles the capability document for this build.
func Build() Document {
	return Document{
		Framework: version.Framework,
		Version:   version.Version,
		ExitCodes: map[string]int{
			"success": 0, "runtime": 1, "usage": 2, "interrupted": 130,
		},
		OutputFormats: []string{"terminal", "json", "yaml", "markdown", "html"},
		EventVerbs: []string{
			events.ScanStarted, events.ScanCompleted, events.StageStarted,
			events.StageCompleted, events.FindingDiscovered,
			events.EvidenceCollected, events.SourceDetected,
			events.EvidenceRegistered, events.IntegrityVerified,
			events.ArtifactIdentified, events.FileSystemAnalyzed,
			events.MemoryAnalyzed, events.LogAnalyzed,
			events.TimelineBuilt, events.IndicatorExtracted,
			events.RiskCalculated, events.ReportGenerated,
		},
		SeverityLevels: []string{
			"critical", "high", "medium", "low", "informational",
		},
		Confidence: []string{
			"confirmed", "observed", "probable", "possible", "unknown", "not_observed",
		},
		Authorized: "offline case-file/simulation analysis requires no authorization; " +
			"live host acquisition is not implemented and is refused",
		Capabilities: []Capability{
			{ID: "forensics.acquisition", Name: "evidence acquisition", Implemented: true, Live: false},
			{ID: "forensics.integrity", Name: "evidence integrity verification", Implemented: true, Live: false},
			{ID: "forensics.artifacts", Name: "artifact identification", Implemented: true, Live: false},
			{ID: "forensics.filesystem", Name: "filesystem analysis", Implemented: true, Live: false},
			{ID: "forensics.memory", Name: "memory-image analysis", Implemented: true, Live: false},
			{ID: "forensics.timeline", Name: "timeline reconstruction", Implemented: true, Live: false},
			{ID: "forensics.logs", Name: "log analysis", Implemented: true, Live: false},
			{ID: "forensics.indicators", Name: "indicator extraction", Implemented: true, Live: false},
			{ID: "forensics.live", Name: "live host acquisition", Implemented: false, Live: true,
				Note: "case-file analysis only; live collection tooling is not wired up"},
		},
		Commands: []Command{
			{Name: "assess", Summary: "run the full analysis pipeline", OutputModes: []string{"terminal", "json", "yaml", "markdown", "html"}, Sim: true},
			{Name: "case", Summary: "generate a deterministic sample forensic case", OutputModes: []string{"terminal", "json", "yaml", "markdown", "html"}, Sim: true},
			{Name: "report", Summary: "render the latest assessment report", OutputModes: []string{"terminal", "markdown", "json", "yaml", "html"}, Sim: true},
			{Name: "findings", Summary: "inspect the latest assessment findings", OutputModes: []string{"terminal", "json", "yaml", "markdown", "html"}, Sim: true},
			{Name: "evidence", Summary: "inspect the latest assessment evidence", OutputModes: []string{"terminal", "json", "yaml", "markdown", "html"}, Sim: true},
			{Name: "sources", Summary: "list supported evidence sources and their status", OutputModes: []string{"terminal", "json", "yaml", "markdown", "html"}, Sim: true},
			{Name: "target", Summary: "manage assessment targets", OutputModes: []string{"terminal", "json", "yaml", "markdown", "html"}, Sim: true},
			{Name: "capabilities", Summary: "print this machine-readable contract", OutputModes: []string{"terminal", "json", "yaml", "markdown", "html"}, Sim: false},
		},
	}
}

// Render prints the document in the active format.
func Render(p *output.Printer) {
	p.Print(Build())
}

// RenderCapabilities prints capability rows.
func RenderCapabilities(p *output.Printer) {
	doc := Build()
	rows := make([][]string, 0, len(doc.Capabilities))
	for _, c := range doc.Capabilities {
		rows = append(rows, []string{c.ID, boolStr(c.Implemented), boolStr(c.Live)})
	}
	p.PrintTable([]string{"capability", "implemented", "live"}, rows)
}

// RenderSources prints the supported evidence sources and their status.
func RenderSources(p *output.Printer) {
	type source struct {
		Source      string `json:"source"`
		Live        bool   `json:"live"`
		Implemented bool   `json:"implemented"`
		Note        string `json:"note,omitempty"`
	}
	sources := []source{
		{Source: "disk", Live: false, Implemented: true, Note: "image file analysis"},
		{Source: "memory", Live: false, Implemented: true, Note: "memory image analysis"},
		{Source: "logs", Live: false, Implemented: true, Note: "evtx/auth/syslog parsing"},
		{Source: "registry", Live: false, Implemented: true, Note: "hive export analysis"},
		{Source: "browser", Live: false, Implemented: true, Note: "browser profile analysis"},
		{Source: "prefetch", Live: false, Implemented: true, Note: "prefetch analysis"},
		{Source: "live", Live: true, Implemented: false, Note: "live acquisition is not implemented"},
	}
	p.Print(sources)
}

// RenderCommands prints the command table.
func RenderCommands(p *output.Printer) {
	doc := Build()
	rows := make([][]string, 0, len(doc.Commands))
	for _, c := range doc.Commands {
		rows = append(rows, []string{c.Name, c.Summary, strings.Join(c.OutputModes, ","), boolStr(c.Sim)})
	}
	p.PrintTable([]string{"command", "summary", "formats", "sim"}, rows)
}

// RenderJSON is a convenience for tests: it JSON-encodes the document.
func RenderJSON(doc Document) ([]byte, error) {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding capabilities: %w", err)
	}
	return data, nil
}

// SortCapabilities orders capabilities by ID for deterministic output.
func SortCapabilities(doc Document) {
	sort.Slice(doc.Capabilities, func(i, j int) bool { return doc.Capabilities[i].ID < doc.Capabilities[j].ID })
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

var _ = models.StateObserved // keep models import meaningful for future use
