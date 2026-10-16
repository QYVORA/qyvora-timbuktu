package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-script/ast"
	"github.com/QYVORA/qyvora-script/binding"
	"github.com/QYVORA/qyvora-script/interpreter"
	"github.com/QYVORA/qyvora-script/parser"

	"github.com/QYVORA/qyvora-timbuktu/internal/analysis"
	"github.com/QYVORA/qyvora-timbuktu/internal/capabilities"
	"github.com/QYVORA/qyvora-timbuktu/internal/config"
	pexit "github.com/QYVORA/qyvora-timbuktu/internal/errors"
	"github.com/QYVORA/qyvora-timbuktu/internal/events"
	"github.com/QYVORA/qyvora-timbuktu/internal/evidence"
	"github.com/QYVORA/qyvora-timbuktu/internal/output"
	"github.com/QYVORA/qyvora-timbuktu/internal/pipeline"
	"github.com/QYVORA/qyvora-timbuktu/internal/reporting"
	"github.com/QYVORA/qyvora-timbuktu/internal/validation"
	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

// allowShellOut gates the shared engine's exec/run.cmd construct. It is set by
// the persistent --allow-shellout flag; the binding also honours
// interpreter.AllowShellOutEnv.
var allowShellOut bool

// commandScript adds the flat `script` utility that runs the shared
// qyvora-script engine (ARCH-004 Part C). `script run <file>` executes a
// script; `script build <file>` prints a dry-run plan. A bare `script <file>`
// runs the file for convenience.
func (a *App) commandScript() *cobra.Command {
	run := func(dryRun bool) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, args []string) error {
			return a.runScriptFile(cmd, args[0], dryRun)
		}
	}
	cmd := &cobra.Command{
		Use:   "script <file>",
		Short: "run a .qs script with the shared scripting engine",
		Args:  cobra.ExactArgs(1),
		RunE:  run(false),
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:   "run <file>",
			Short: "execute a script file",
			Args:  cobra.ExactArgs(1),
			RunE:  run(false),
		},
		&cobra.Command{
			Use:   "build <file>",
			Short: "validate a script file and print a dry-run plan",
			Args:  cobra.ExactArgs(1),
			RunE:  run(true),
		},
	)
	return cmd
}

// runScriptFile parses (build) or executes (run) a script against timbuktu's
// binding.
func (a *App) runScriptFile(cmd *cobra.Command, path string, dryRun bool) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return pexit.WrapExitError(CodeRuntime, "reading script", err)
	}
	if dryRun {
		prog, err := parser.Parse(string(src))
		if err != nil {
			return pexit.NewExitError(CodeUsage, err.Error())
		}
		_, _ = fmt.Fprintln(a.Stdout, "script plan "+path)
		for _, line := range ast.Describe(prog) {
			_, _ = fmt.Fprintln(a.Stdout, "  -", line)
		}
		return nil
	}
	prog, err := parser.Parse(string(src))
	if err != nil {
		return pexit.NewExitError(CodeUsage, err.Error())
	}
	p, err := a.printerFor(cmd)
	if err != nil {
		return err
	}
	b := &scriptBinding{
		app:     a,
		ctx:     cmd.Context(),
		printer: p,
		allow:   allowShellOut,
		cfg:     map[string]string{},
	}
	engine := interpreter.NewEngine(b)
	engine.Events = a.Stderr
	if err := engine.RunProgram(prog); err != nil {
		return pexit.NewExitError(CodeUsage, err.Error())
	}
	return nil
}

// scriptBinding implements binding.Binding against timbuktu's offline
// forensics pipeline. Each tool capability ID resolves to a pipeline prefix:
// running "forensics.artifacts" runs every stage up to and including artifact
// identification, and "assess" runs the whole pipeline.
type scriptBinding struct {
	app     *App
	ctx     context.Context
	printer *output.Printer
	allow   bool
	cfg     map[string]string
	last    *models.Result
}

var _ binding.Binding = (*scriptBinding)(nil)

// Capabilities lists the capability IDs this binding accepts: the tool's
// machine contract plus the whole-pipeline "assess" entry.
func (b *scriptBinding) Capabilities() []string {
	doc := capabilities.Build()
	ids := make([]string, 0, len(doc.Capabilities)+1)
	ids = append(ids, "assess")
	for _, c := range doc.Capabilities {
		ids = append(ids, c.ID)
	}
	return ids
}

// AllowShellOut reports whether exec/run.cmd may run: only with the explicit
// flag or the shared opt-in environment variable.
func (b *scriptBinding) AllowShellOut() bool { return b.allow || shellOutEnv() }

func shellOutEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(interpreter.AllowShellOutEnv))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Call dispatches one engine capability invocation.
func (b *scriptBinding) Call(capabilityID string, args []binding.Value) (binding.Value, error) {
	switch capabilityID {
	case binding.CapEcho:
		_, _ = fmt.Fprintln(b.printer.Writer(), asStr(args, 0))
		return nil, nil

	case binding.CapSetConfig:
		b.cfg[asStr(args, 0)] = asStr(args, 1)
		return nil, nil

	case binding.CapGetConfig:
		return b.cfg[asStr(args, 0)], nil

	case binding.CapStart:
		return nil, b.start(asStr(args, 0))

	case binding.CapStop, binding.CapIsRunning:
		// The analysis pipeline is synchronous, so nothing is ever "running".
		if capabilityID == binding.CapIsRunning {
			return false, nil
		}
		return nil, nil

	case binding.CapShow:
		return nil, b.show(asStr(args, 0))

	case binding.CapReport:
		return nil, b.report(asStr(args, 0))

	case binding.CapProp:
		return b.prop(asStr(args, 0)), nil

	case binding.CapExec:
		return nil, b.exec(asStr(args, 0))
	}
	return nil, fmt.Errorf("unknown capability %q", capabilityID)
}

// start runs the pipeline associated with a module id.
func (b *scriptBinding) start(id string) error {
	opts := b.assessOpts()
	upto := ""
	switch {
	case id == "assess" || id == "":
		// whole pipeline
	case strings.HasPrefix(id, "forensics."):
		c := findCapability(id)
		if c == nil {
			return fmt.Errorf("unknown module %q", id)
		}
		if !c.Implemented {
			return fmt.Errorf("%s is not implemented", id)
		}
		upto = strings.TrimPrefix(id, "forensics.")
	default:
		return fmt.Errorf("unknown module %q", id)
	}
	res, err := b.app.runStages(b.ctx, b.printer, opts, upto)
	if err != nil {
		return err
	}
	b.last = res
	return nil
}

// assessOpts derives assessment options from the script's config map, mapping
// timbuktu's usual flags. With no explicit target a simulation run is used.
func (b *scriptBinding) assessOpts() assessOpts {
	get := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := b.cfg[k]; ok {
				return v
			}
		}
		return ""
	}
	simSet := false
	sim := false
	if v := get("assess.sim", "sim"); v != "" {
		sim = isTrue(v)
		simSet = true
	}
	opts := assessOpts{
		Sim:       sim,
		Case:      get("assess.case", "case"),
		Profile:   get("assess.profile", "profile"),
		ReportDir: get("assess.report-dir", "report.dir"),
		NoReport:  isTrue(get("assess.no-report", "no-report")),
		Quiet:     isTrue(get("assess.quiet", "quiet")),
	}
	if opts.Case == "" && !simSet {
		// No target was chosen: default to the offline simulation so a plain
		// `run assess` script works out of the box.
		opts.Sim = true
	}
	return opts
}

// findCapability looks up a capability id in the tool's machine contract.
func findCapability(id string) *capabilities.Capability {
	for _, c := range capabilities.Build().Capabilities {
		if c.ID == id {
			return &c
		}
	}
	return nil
}

// show prints metadata for a module/capability id.
func (b *scriptBinding) show(id string) error {
	if id == "assess" || id == "" {
		b.printer.PrintTable([]string{"command", "summary"}, [][]string{
			{"assess", "run the full analysis pipeline"},
		})
		return nil
	}
	for _, c := range capabilities.Build().Capabilities {
		if c.ID == id {
			b.printer.PrintTable([]string{"capability", "name", "implemented", "live"}, [][]string{
				{c.ID, c.Name, boolWord(c.Implemented), boolWord(c.Live)},
			})
			return nil
		}
	}
	return fmt.Errorf("unknown module %q", id)
}

// report writes a report artifact for the most recent run.
func (b *scriptBinding) report(path string) error {
	if b.last == nil {
		return fmt.Errorf("no assessment to report; run a module first")
	}
	dir := path
	if dir == "" {
		dir = b.app.Cfg.GetString("report.dir")
	}
	if dir == "" {
		dir = "."
	}
	written, err := reporting.Write(dir, "markdown", b.last)
	if err != nil {
		return err
	}
		_, _ = fmt.Fprintln(b.printer.Writer(), "report written to "+written)
	return nil
}

// prop resolves live properties for $(...) interpolation from the last run.
func (b *scriptBinding) prop(name string) binding.Value {
	if b.last == nil {
		return nil
	}
	switch name {
	case "session.id", "result.id":
		return b.last.ID
	case "result.framework":
		return b.last.Framework
	case "result.profile":
		return b.last.Profile
	case "result.assets":
		return fmt.Sprintf("%d", b.last.Assets)
	case "result.findings":
		return fmt.Sprintf("%d", len(b.last.Findings))
	case "result.evidence":
		return fmt.Sprintf("%d", len(b.last.Evidence))
	case "result.events":
		return fmt.Sprintf("%d", b.last.Events)
	case "result.score":
		return fmt.Sprintf("%d", b.last.Score)
	case "result.level":
		return b.last.Level
	case "target.name":
		if b.last.Target != nil {
			return b.last.Target.Name
		}
	}
	return nil
}

// exec runs a one-shot timbuktu command line. The interpreter only reaches here
// after AllowShellOut reported true.
func (b *scriptBinding) exec(line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	code := ExecuteArgsContext(b.ctx, strings.Fields(line))
	if code != 0 {
		return fmt.Errorf("command exited with code %d", code)
	}
	return nil
}

// runStages is the script-facing equivalent of runAssess: it runs the analysis
// pipeline (optionally only up to and including one stage) and returns the
// result. It mirrors runAssess but yields the result to the binding instead of
// discarding it.
func (a *App) runStages(ctx context.Context, p *output.Printer, opts assessOpts, upto string) (*models.Result, error) {
	cfgLocal := a.Cfg
	profile := cfgLocal.GetString("profile")
	if opts.Profile != "" {
		profile = opts.Profile
	}
	if !config.IsValidProfile(profile) {
		return nil, pexit.NewExitError(CodeUsage, "unknown profile "+profile)
	}
	t, err := a.selectTarget(opts)
	if err != nil {
		return nil, err
	}
	var v validation.Validator
	plan := v.Validate(t, func(p string) bool {
		_, err := os.Stat(p)
		return err == nil
	})
	if !plan.Ready {
		return nil, pexit.NewExitError(CodeUsage, firstCheckMessage(plan))
	}
	sink, sinkCloser, err := a.eventsSink()
	if err != nil {
		return nil, pexit.WrapExitError(CodeRuntime, "resolving --events destination", err)
	}
	defer sinkCloser()
	counter := &countWriter{w: sink}
	stream := events.NewStream(counter)
	repDir := opts.ReportDir
	if repDir == "" {
		repDir = cfgLocal.GetString("report.dir")
	}
	store := evidence.New(filepath.Join(repDir, "evidence.json"))
	reg, err := a.registry()
	if err != nil {
		return nil, pexit.WrapExitError(CodeRuntime, "registering rules", err)
	}
	assets := config.MaxAssets(cfgLocal)
	stages := analysis.Stages(reg, flagMap(cfgLocal, profile), assets)
	if upto != "" {
		idx := -1
		for i, s := range stages {
			if s.ID == upto {
				idx = i
				break
			}
		}
		// A capability whose id has no exactly-named stage still runs the
		// whole pipeline (its producing stages are interdependent).
		if idx >= 0 {
			stages = stages[:idx+1]
		}
	}
	step := &pipeline.Step{
		Target:   t,
		Sim:      opts.Sim,
		Events:   stream,
		Evidence: store,
		Result: &models.Result{
			ID:        stream.ExecutionID(),
			Framework: "timbuktu",
			Target:    t,
			Profile:   profile,
			Sim:       opts.Sim,
			StartedAt: models.Now(),
		},
	}
	stream.Info(events.ScanStarted, map[string]any{
		"target": t.TypedName(), "profile": profile, "sim": opts.Sim,
	})
	if err := pipeline.New(stages...).Run(ctx, step); err != nil {
		if ctx.Err() != nil {
			return nil, pexit.NewExitError(CodeInterrupt, "assessment interrupted")
		}
		return nil, pexit.WrapExitError(CodeRuntime, "assessment failed", err)
	}
	step.Result.CompletedAt = models.Now()
	step.Result.Events = stream.Count()
	if err := store.Save(); err != nil {
		return nil, pexit.WrapExitError(CodeRuntime, "writing evidence", err)
	}
	redactForOutput := cloneResult(step.Result)
	models.RedactSecretData(redactForOutput.Evidence)
	if !opts.Quiet || p.Format() != output.FormatTerminal {
		p.Print(redactForOutput)
	}
	persistResult(step.Result, repDir)
	if !opts.NoReport && repDir != "" {
		reportFormat := "markdown"
		switch p.Format() {
		case output.FormatJSON:
			reportFormat = "json"
		case output.FormatYAML:
			reportFormat = "yaml"
		case output.FormatHTML:
			reportFormat = "html"
		}
		path, err := reporting.Write(repDir, reportFormat, step.Result)
		if err != nil {
			return nil, pexit.WrapExitError(CodeRuntime, "writing report", err)
		}
		stream.Info(events.ReportGenerated, map[string]any{"path": path})
	}
	stream.Info(events.ScanCompleted, map[string]any{
		"assets": step.Result.Assets, "findings": len(step.Result.Findings),
		"score": step.Result.Score, "level": step.Result.Level,
	})
	return step.Result, nil
}

func asStr(args []binding.Value, i int) string {
	if i >= len(args) || args[i] == nil {
		return ""
	}
	if s, ok := args[i].(string); ok {
		return s
	}
	return fmt.Sprintf("%v", args[i])
}

func isTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
