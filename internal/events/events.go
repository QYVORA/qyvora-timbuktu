// Package events implements the shared QYVORA JSONL event envelope. Every
// emitted line is one JSON object:
//
//	{"schema_version":"1.0","timestamp":"...","execution_id":"...",
//	 "framework":"timbuktu","level":"info","event":"stage.completed","data":{}}
//
// Consumers key on event names, never on terminal output.
package events

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/QYVORA/qyvora-timbuktu/internal/version"
)

// SchemaVersion is the event schema version every event carries.
const SchemaVersion = "1.0"

// Shared, ecosystem-wide verbs plus timbuktu's forensics-specific verbs,
// shaped "category.thing.state" so consumers can route on prefix.
const (
	ScanStarted       = "scan.started"
	ScanCompleted     = "scan.completed"
	StageStarted      = "stage.started"
	StageCompleted    = "stage.completed"
	FindingDiscovered = "finding.discovered"
	EvidenceCollected = "evidence.collected"
	Warning           = "warning"
	Error             = "error"
	ReportGenerated   = "report.generated"

	SourceDetected     = "source.detected"
	EvidenceRegistered = "evidence.registered"
	IntegrityVerified  = "integrity.verified"
	ArtifactIdentified = "artifact.identified"
	FileSystemAnalyzed = "filesystem.analyzed"
	MemoryAnalyzed     = "memory.analyzed"
	LogAnalyzed        = "log.analyzed"
	TimelineBuilt      = "timeline.built"
	IndicatorExtracted = "indicator.extracted"
	RiskCalculated     = "risk.calculated"
)

// Level values for the envelope's level field.
const (
	LevelInfo    = "info"
	LevelWarning = "warning"
	LevelError   = "error"
)

// Event is the wire shape of one event line.
type Event struct {
	SchemaVersion string         `json:"schema_version"`
	Timestamp     time.Time      `json:"timestamp"`
	ExecutionID   string         `json:"execution_id"`
	Framework     string         `json:"framework"`
	Level         string         `json:"level"`
	Event         string         `json:"event"`
	Data          map[string]any `json:"data,omitempty"`
}

// Stream writes events as JSONL to w. It is safe for concurrent use.
type Stream struct {
	mu          sync.Mutex
	w           io.Writer
	executionID string
}

// NewStream returns a stream bound to a freshly generated execution id.
func NewStream(w io.Writer) *Stream {
	return &Stream{w: w, executionID: newExecutionID()}
}

// ExecutionID returns the execution id bound to this stream.
func (s *Stream) ExecutionID() string {
	if s == nil {
		return ""
	}
	return s.executionID
}

// Emit writes one event. Data may be nil.
func (s *Stream) Emit(level, name string, data map[string]any) {
	if s == nil || s.w == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ev := Event{
		SchemaVersion: SchemaVersion,
		Timestamp:     time.Now().UTC(),
		ExecutionID:   s.executionID,
		Framework:     version.Framework,
		Level:         level,
		Event:         name,
		Data:          data,
	}
	if err := json.NewEncoder(s.w).Encode(ev); err != nil {
		return
	}
}

// Info emits an informational event.
func (s *Stream) Info(name string, data map[string]any) { s.Emit(LevelInfo, name, data) }

// Warn emits a warning event.
func (s *Stream) Warn(name string, data map[string]any) { s.Emit(LevelWarning, name, data) }

// Fail emits an error event.
func (s *Stream) Fail(name string, data map[string]any) { s.Emit(LevelError, name, data) }

func newExecutionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return version.Framework + "-" + time.Now().UTC().Format("20060102T150405.000000000")
	}
	return hex.EncodeToString(b[:])
}
