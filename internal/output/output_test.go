package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-timbuktu/internal/output"
)

func TestParseFormat(t *testing.T) {
	valid := map[string]output.Format{
		"terminal": output.FormatTerminal, "json": output.FormatJSON,
		"yaml": output.FormatYAML, "markdown": output.FormatMarkdown,
		"html": output.FormatHTML, "md": output.FormatMarkdown, "table": output.FormatTerminal,
		"TEXT": output.FormatTerminal,
	}
	for in, want := range valid {
		got, err := output.ParseFormat(in)
		if err != nil {
			t.Fatalf("ParseFormat(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("ParseFormat(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := output.ParseFormat("notaformat"); err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestJSONOutputIsValid(t *testing.T) {
	var buf bytes.Buffer
	p := output.New()
	p.SetWriter(&buf)
	p.SetFormat(output.FormatJSON)
	p.Print(map[string]any{"a": 1, "b": []string{"x"}})
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("json output invalid: %v", err)
	}
	if m["a"].(float64) != 1 {
		t.Errorf("a = %v", m["a"])
	}
}

func TestMarkdownTable(t *testing.T) {
	var buf bytes.Buffer
	p := output.New()
	p.SetWriter(&buf)
	p.SetFormat(output.FormatMarkdown)
	p.PrintTable([]string{"id", "name"}, [][]string{{"1", "two | pipes"}, {"3", "four"}})
	out := buf.String()
	if !strings.HasPrefix(out, "| id | name |") {
		t.Errorf("missing header: %q", out)
	}
	if !strings.Contains(out, `two \| pipes`) {
		t.Errorf("markdown pipe not escaped: %q", out)
	}
}

func TestTerminalTableIgnoresANSIIfDisabled(t *testing.T) {
	var buf bytes.Buffer
	p := output.New()
	p.SetWriter(&buf)
	p.SetFormat(output.FormatTerminal)
	p.SetColor(false)
	p.PrintTable([]string{"col"}, [][]string{{"value"}})
	if !strings.Contains(buf.String(), "value") {
		t.Errorf("terminal table missing row: %q", buf.String())
	}
}
