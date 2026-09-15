// Package reporting renders an assessment result into an on-disk report file
// (0700 directory, 0600 file). Terminal consumers render live; this package
// is for producing the persistent artifact in any supported format.
package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

// Write writes a result as a report file in format (markdown, json, yaml,
// html) under dir and returns the written path. Reports never contain secret
// values: findings are redacted before serialization.
func Write(dir, format string, res *models.Result) (string, error) {
	target := res.Target
	name := "report"
	if target != nil {
		base := strings.NewReplacer(":", "-", "/", "-", " ", "-").Replace(target.TypedName())
		if base != "" {
			name = strings.ToLower(base) + "-report"
		}
	}
	stamp := time.Now().UTC().Format("20060102T150405")
	fname := fmt.Sprintf("%s-%s.%s", name, stamp, ext(format))
	fpath := filepath.Join(dir, fname)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}

	body, err := render(format, res)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(fpath, body, 0o600); err != nil {
		return "", err
	}
	return fpath, nil
}

func ext(format string) string {
	switch format {
	case "json":
		return "json"
	case "yaml":
		return "yaml"
	case "html":
		return "html"
	default:
		return "md"
	}
}

// render is a small internal renderer; the CLI also renders to terminal via
// the output printer for live display.
func render(format string, res *models.Result) ([]byte, error) {
	redacted := redactResult(res)
	switch format {
	case "json":
		return json.MarshalIndent(redacted, "", "  ")
	case "yaml":
		return yaml.Marshal(redacted)
	case "html":
		data, err := json.MarshalIndent(redacted, "", "  ")
		if err != nil {
			return nil, err
		}
		return []byte("<pre>" + escapeHTML(string(data)) + "</pre>"), nil
	default:
		return renderMarkdown(redacted), nil
	}
}

func renderMarkdown(res *models.Result) []byte {
	var b strings.Builder
	b.WriteString("# Cloud Security Report\n\n")
	if res.Target != nil {
		b.WriteString("- Target: `" + res.Target.TypedName() + "`\n")
	}
	b.WriteString("- Framework: `" + res.Framework + "`\n")
	b.WriteString("- Started: " + res.StartedAt.UTC().Format(time.RFC3339) + "\n")
	b.WriteString("- Completed: " + res.CompletedAt.UTC().Format(time.RFC3339) + "\n")
	b.WriteString("- Mode: ")
	if res.Sim {
		b.WriteString("simulation\n")
	} else {
		b.WriteString("offline snapshot\n")
	}
	b.WriteString("- Assets analyzed: " + itoa(res.Assets) + "\n")
	b.WriteString("- Findings: " + itoa(len(res.Findings)) + "\n")
	b.WriteString("- Evidence: " + itoa(len(res.Evidence)) + "\n")
	b.WriteString("- Risk: " + res.Level + " (" + itoa(res.Score) + "/100)\n")
	b.WriteString("\n")

	b.WriteString("## Findings\n\n")
	if len(res.Findings) == 0 {
		b.WriteString("_No findings._\n")
	}
	for i := range res.Findings {
		f := &res.Findings[i]
		b.WriteString("### " + f.RuleID + " — " + f.Title + "\n\n")
		b.WriteString("- Severity: " + string(f.Severity) + "\n")
		b.WriteString("- Confidence: " + string(f.Confidence) + "\n")
		b.WriteString("- Category: " + f.Category + "\n")
		b.WriteString("- Status: " + string(f.Status) + "\n")
		if len(f.Objects) > 0 {
			b.WriteString("- Affected: " + strings.Join(f.Objects, ", ") + "\n")
		}
		if f.Impact != "" {
			b.WriteString("- Impact: " + f.Impact + "\n")
		}
		b.WriteString("\n" + f.Description + "\n")
		if f.Recommendation != "" {
			b.WriteString("\n**Recommendation:** " + f.Recommendation + "\n")
		}
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// redactResult returns a copy of the result with secret values removed so no
// writer can emit them.
func redactResult(res *models.Result) *models.Result {
	cp := *res
	cp.Findings = make([]models.Finding, len(res.Findings))
	copy(cp.Findings, res.Findings)
	for i := range cp.Findings {
		cp.Findings[i].RedactSecrets()
	}
	cp.Evidence = make([]models.Evidence, len(res.Evidence))
	copy(cp.Evidence, res.Evidence)
	return &cp
}

func escapeHTML(s string) string {
	repl := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return repl.Replace(s)
}

func itoa(v int) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v%10]
		v /= 10
	}
	return string(buf[i:])
}
