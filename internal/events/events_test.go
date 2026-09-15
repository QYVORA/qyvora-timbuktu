package events_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-timbuktu/internal/events"
)

func TestStreamEmitsSchemaConformantJSONL(t *testing.T) {
	var buf bytes.Buffer
	s := events.NewStream(&buf)
	s.Info(events.SourceDetected, map[string]any{"source": "disk"})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 event line, got %d", len(lines))
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("event is not valid JSON: %v", err)
	}
	if ev["schema_version"] != "1.0" {
		t.Errorf("schema_version = %v", ev["schema_version"])
	}
	if ev["framework"] != "timbuktu" {
		t.Errorf("framework = %v", ev["framework"])
	}
	if ev["event"] != events.SourceDetected {
		t.Errorf("event = %v", ev["event"])
	}
	if _, ok := ev["timestamp"].(string); !ok {
		t.Errorf("timestamp missing: %+v", ev)
	}
}

func TestStreamSupportsLevels(t *testing.T) {
	var buf bytes.Buffer
	s := events.NewStream(&buf)
	s.Warn("warning", nil)
	s.Fail("error", map[string]any{"x": 1})
	out := buf.String()
	if !strings.Contains(out, `"level":"warning"`) {
		t.Errorf("missing warning line")
	}
	if !strings.Contains(out, `"level":"error"`) {
		t.Errorf("missing error line")
	}
}

func TestNilStreamIsSafe(t *testing.T) {
	var s *events.Stream
	s.Info("x", nil) // must not panic
	if s.ExecutionID() != "" {
		t.Errorf("nil stream execution id = %q", s.ExecutionID())
	}
}
