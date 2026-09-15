// Package console implements the interactive assessment REPL. It is a thin,
// honest facade over the same pipeline the CLI uses — there is no second,
// degraded assessment path. Machine output still belongs to stdout; prompts
// and errors go to stderr.
package console

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ergochat/readline"

	"github.com/QYVORA/qyvora-timbuktu/internal/capabilities"
	"github.com/QYVORA/qyvora-timbuktu/internal/forensics"
	"github.com/QYVORA/qyvora-timbuktu/internal/output"
	"github.com/QYVORA/qyvora-timbuktu/internal/rules"
	"github.com/QYVORA/qyvora-timbuktu/internal/target"
	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

const prompt = "timbuktu> "

// AssessFunc runs one assessment from parsed console arguments.
type AssessFunc func(ctx context.Context, args []string, printer *output.Printer) error

// App wires the console to framework services.
type App struct {
	Execute  AssessFunc
	Printer  *output.Printer
	Manager  *target.Manager
	Registry *rules.Registry
	Version  string
	Out      io.Writer
	ErrOut   io.Writer
}

// Console is the running REPL.
type Console struct {
	app App
	rl  *readline.Instance
}

// New builds a console with an interactive line reader.
func New(a App) (*Console, error) {
	rl, err := readline.NewFromConfig(&readline.Config{
		Prompt:          prompt,
		HistoryLimit:    200,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete:    completion{App: a},
	})
	if err != nil {
		return nil, fmt.Errorf("initializing console: %w", err)
	}
	return &Console{app: a, rl: rl}, nil
}

// Run executes the REPL loop until exit, EOF or context cancellation.
func (c *Console) Run(ctx context.Context) {
	defer func() { _ = c.rl.Close() }()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line, err := c.rl.Readline()
		if err != nil {
			switch err {
			case readline.ErrInterrupt:
				c.banner()
				continue
			case io.EOF:
				return
			default:
				_, _ = fmt.Fprintln(c.app.ErrOut, err)
				return
			}
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if c.dispatch(ctx, line) {
			return
		}
	}
}

// dispatch handles one command line; returns true when the session should end.
func (c *Console) dispatch(ctx context.Context, line string) bool {
	args := tokenize(line)
	if len(args) == 0 {
		return false
	}
	_ = c.rl.SaveToHistory(line)
	switch args[0] {
	case "exit", "quit":
		return true
	case "help":
		c.help()
	case "version", "ver":
		_, _ = fmt.Fprintf(c.app.Out, "timbuktu %s\n", c.app.Version)
	case "clear":
		c.clr()
	case "assess", "run":
		c.runAssessWrapper(ctx, args[1:])
	case "case":
		c.snapshot(args[1:])
	case "targets":
		c.targets()
	case "findings":
		c.findings()
	case "evidence":
		c.evidence()
	case "sources":
		c.sources()
	case "capabilities", "caps":
		c.capabilities()
	case "rules":
		c.rules()
	default:
		_, _ = fmt.Fprintf(c.app.ErrOut, "unknown command %q (type help)\n", args[0])
	}
	return false
}

// runAssessWrapper adapts console args to the assess driver. Output stays on
// the configured printer; live targets are refused by the driver itself.
func (c *Console) runAssessWrapper(ctx context.Context, args []string) {
	if c.app.Execute == nil {
		_, _ = fmt.Fprintln(c.app.ErrOut, "assess is unavailable in this build")
		return
	}
	if err := c.app.Execute(ctx, args, c.app.Printer); err != nil {
		_, _ = fmt.Fprintln(c.app.ErrOut, err)
	}
}

func (c *Console) help() {
	_, _ = fmt.Fprintln(c.app.Out, `Commands:
  assess [--sim] [--case FILE]      run the analysis pipeline
  case [--out FILE]                  write the deterministic simulation case
  targets                            list registered targets
  findings                           render the latest findings
  evidence                           render the latest evidence
  sources                            list evidence source support
  capabilities                       print the capability contract
  rules                              list analysis rules
  version                            print the version
  clear                              clear the terminal
  help                               this help
  exit | quit                        leave the console`)
}

func (c *Console) clr()    { _, _ = fmt.Fprint(c.app.Out, "\033[2J\033[H") }
func (c *Console) banner() {}

func (c *Console) snapshot(args []string) {
	out := ""
	printer := c.app.Printer
	data, err := caseJSON()
	if err != nil {
		_, _ = fmt.Fprintln(c.app.ErrOut, err)
		return
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--out", "-o":
			if i+1 < len(args) {
				out = args[i+1]
				i++
			}
		}
	}
	if out == "" {
		_, _ = c.app.Out.Write(data)
		_, _ = c.app.Out.Write([]byte("\n"))
		return
	}
	if err := writeFile(out, data); err != nil {
		_, _ = fmt.Fprintln(c.app.ErrOut, err)
		return
	}
	_ = printer
	_, _ = fmt.Fprintf(c.app.ErrOut, "case written to %s\n", out)
}

func (c *Console) targets() {
	rows := make([][]string, 0)
	for _, t := range c.app.Manager.List() {
		mark := ""
		if cur := c.app.Manager.Current(); cur != nil && cur.ID == t.ID {
			mark = "*"
		}
		rows = append(rows, []string{mark, t.ID, string(t.Type), t.TypedName(), t.Auth.Scope})
	}
	c.app.Printer.PrintTable([]string{"cur", "id", "type", "target", "auth"}, rows)
}

func (c *Console) findings() {
	res := c.latestResult()
	if res == nil {
		c.noneYet()
		return
	}
	rows := make([][]string, 0, len(res.Findings))
	for i := range res.Findings {
		f := &res.Findings[i]
		rows = append(rows, []string{f.RuleID, f.Title, string(f.Severity), strings.Join(f.Objects, ",")})
	}
	c.app.Printer.PrintTable([]string{"rule", "title", "severity", "objects"}, rows)
}

func (c *Console) evidence() {
	res := c.latestResult()
	if res == nil {
		c.noneYet()
		return
	}
	rows := make([][]string, 0, len(res.Evidence))
	for i := range res.Evidence {
		e := &res.Evidence[i]
		rows = append(rows, []string{e.Source, e.SourceID, string(e.Kind), e.Data})
	}
	c.app.Printer.PrintTable([]string{"source", "source_id", "kind", "data"}, rows)
}

func (c *Console) noneYet() {
	rows := [][]string{{"run `assess --sim` first to collect findings and evidence"}}
	c.app.Printer.PrintTable([]string{"note"}, rows)
}

// latestResult loads the persisted result from the standard report dir.
func (c *Console) latestResult() *models.Result {
	data, err := os.ReadFile(filepath.Join("reports", "result.json"))
	if err != nil {
		return nil
	}
	var res models.Result
	if err := json.Unmarshal(data, &res); err != nil {
		return nil
	}
	return &res
}

func (c *Console) sources() {
	capabilities.RenderSources(c.app.Printer)
}

func (c *Console) capabilities() {
	capabilities.Render(c.app.Printer)
}

func (c *Console) rules() {
	if c.app.Registry == nil {
		_, _ = fmt.Fprintln(c.app.ErrOut, "no rule registry configured")
		return
	}
	rows := make([][]string, 0, c.app.Registry.Len())
	for _, m := range c.app.Registry.Metas() {
		rows = append(rows, []string{m.ID, m.Name, m.Category, string(m.DefaultSeverity)})
	}
	c.app.Printer.PrintTable([]string{"id", "name", "category", "severity"}, rows)
}

// tokenize splits a line on spaces, respecting simple double quotes.
func tokenize(line string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range line {
		switch r {
		case '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case ' ', '\t':
			if inQuote {
				cur.WriteRune(r)
			} else {
				flush()
			}
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	for i := range out {
		out[i] = strings.Trim(out[i], "\"")
	}
	return out
}

// completion provides command-name completion for the line reader.
type completion struct{ App App }

func (c completion) Do(line []rune, pos int) (newLine [][]rune, length int) {
	var words [][]rune
	for _, w := range commandWords() {
		if len(line) == 0 || strings.HasPrefix(string(w), string(line)) {
			words = append(words, []rune(w))
		}
	}
	return words, len(line)
}

func commandWords() []string {
	return []string{"assess", "case", "targets", "findings", "evidence",
		"sources", "capabilities", "rules", "version", "help", "clear", "exit", "quit"}
}

// caseJSON marshals the deterministic simulation case.
func caseJSON() ([]byte, error) {
	return forensics.Marshal(forensics.Simulate(forensics.SimulationOptions{}))
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
