// Package cli wires the timbuktu command surface. It follows the QYVORA
// contract: exit codes 0/1/2/130, machine output on stdout only (events and
// diagnostics on stderr), NO_COLOR discipline, and honest refusal of any
// unimplemented live operation.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/QYVORA/qyvora-timbuktu/internal/analysis"
	"github.com/QYVORA/qyvora-timbuktu/internal/capabilities"
	"github.com/QYVORA/qyvora-timbuktu/internal/config"
	"github.com/QYVORA/qyvora-timbuktu/internal/console"
	pexit "github.com/QYVORA/qyvora-timbuktu/internal/errors"
	"github.com/QYVORA/qyvora-timbuktu/internal/events"
	"github.com/QYVORA/qyvora-timbuktu/internal/evidence"
	"github.com/QYVORA/qyvora-timbuktu/internal/exitcode"
	"github.com/QYVORA/qyvora-timbuktu/internal/forensics"
	"github.com/QYVORA/qyvora-timbuktu/internal/output"
	"github.com/QYVORA/qyvora-timbuktu/internal/pipeline"
	"github.com/QYVORA/qyvora-timbuktu/internal/reporting"
	"github.com/QYVORA/qyvora-timbuktu/internal/rules"
	"github.com/QYVORA/qyvora-timbuktu/internal/rules/builtin"
	"github.com/QYVORA/qyvora-timbuktu/internal/selfupdate"
	"github.com/QYVORA/qyvora-timbuktu/internal/target"
	"github.com/QYVORA/qyvora-timbuktu/internal/validation"
	"github.com/QYVORA/qyvora-timbuktu/internal/version"
	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

// Exit codes, exported so tests can assert on them.
const (
	CodeOK        = exitcode.Success
	CodeRuntime   = exitcode.Runtime
	CodeUsage     = exitcode.Usage
	CodeInterrupt = exitcode.Interrupted
)

// App carries the dependencies of one CLI invocation.
type App struct {
	Stdout  *os.File
	Stderr  *os.File
	Cfg     *viper.Viper
	Printer *output.Printer
	Manager *target.Manager
}

// newApp builds an App bound to the process streams.
func newApp() (*App, error) {
	cfg, err := config.Load("")
	if err != nil {
		return nil, pexit.WrapExitError(CodeRuntime, "loading configuration", err)
	}
	return &App{
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Cfg:     cfg,
		Printer: output.New(),
		Manager: target.NewManager(cfg.GetString("target.state")),
	}, nil
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app, err := newApp()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return CodeRuntime
	}
	cmd := app.rootCommand()
	cmd.SetContext(ctx)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		var ee *pexit.ExitError
		if errors.As(err, &ee) {
			if ee.Code == 0 {
				return CodeOK
			}
			return ee.Code
		}
		if errors.Is(err, context.Canceled) {
			return CodeInterrupt
		}
		return CodeRuntime
	}
	return CodeOK
}

// initPrinter applies output flags and returns the formatted printer.
func (a *App) initPrinter(format string, noColor bool) (*output.Printer, error) {
	p := output.New()
	p.SetWriter(a.Stdout)
	p.SetFormat(output.FormatTerminal)
	if format != "" && format != "terminal" {
		f, err := output.ParseFormat(format)
		if err != nil {
			return nil, pexit.NewExitError(CodeUsage, err.Error())
		}
		p.SetFormat(f)
	}
	p.SetColor(!noColor && os.Getenv("NO_COLOR") == "")
	return p, nil
}

// printerFor resolves the persistent output/no-color flags at execution time.
func (a *App) printerFor(cmd *cobra.Command) (*output.Printer, error) {
	format, _ := cmd.Root().PersistentFlags().GetString("output")
	noColor, _ := cmd.Root().PersistentFlags().GetBool("no-color")
	return a.initPrinter(format, noColor)
}

// rootCommand assembles the command tree.
func (a *App) rootCommand() *cobra.Command {
	var (
		format  string
		noColor bool
		quiet   bool
	)
	root := &cobra.Command{
		Use:           "timbuktu",
		Short:         "QYVORA digital forensics and incident response framework",
		Long:          "timbuktu analyzes offline forensic cases and deterministic simulations for evidence integrity, artifact, filesystem, memory, timeline, log, indicator and investigation risk. Live host acquisition is not implemented and is refused honestly.",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	pf := root.PersistentFlags()
	pf.StringVarP(&format, "output", "o", "", "output format: terminal, json, yaml, markdown, html")
	pf.BoolVar(&noColor, "no-color", false, "disable ANSI color (NO_COLOR is also honored)")
	pf.BoolVarP(&quiet, "quiet", "q", false, "suppress informational terminal output")
	_ = quiet

	root.AddCommand(a.commandAssess())
	root.AddCommand(a.commandVersion("version"))
	root.AddCommand(a.commandCase())
	root.AddCommand(a.commandCapabilities())
	root.AddCommand(a.commandSources())
	root.AddCommand(a.commandRules())
	root.AddCommand(a.commandTarget())
	root.AddCommand(a.commandReport())
	root.AddCommand(a.commandFindings())
	root.AddCommand(a.commandEvidence())
	root.AddCommand(a.commandUpdates())
	root.AddCommand(a.commandConsole())
	root.AddCommand(a.commandCompletion())
	return root
}

func (a *App) commandVersion(name string) *cobra.Command {
	return &cobra.Command{
		Use:   name,
		Short: "print version and build metadata",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := a.printerFor(cmd)
			if err != nil {
				return err
			}
			info := version.GetInfo()
			if p.Format() == output.FormatTerminal {
				rows := [][]string{
					{"framework", info.Framework},
					{"version", info.Version},
					{"commit", info.Commit},
					{"date", info.Date},
					{"built_in", info.BuiltIn},
					{"os/arch", info.OS + "/" + info.Arch},
					{"go", info.GoVersion},
					{"website", info.Website},
					{"support", info.Support},
				}
				p.PrintTable([]string{"key", "value"}, rows)
				return nil
			}
			p.Print(info)
			return nil
		},
	}
}

func (a *App) commandCapabilities() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "capabilities",
		Short: "print the machine-readable capability contract",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := a.printerFor(cmd)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("table") {
				capabilities.RenderCapabilities(p)
				return nil
			}
			capabilities.Render(p)
			return nil
		},
	}
	cmd.Flags().Bool("table", false, "render as a compact table")
	return cmd
}

func (a *App) commandSources() *cobra.Command {
	return &cobra.Command{
		Use:   "sources",
		Short: "list supported evidence sources and their status",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := a.printerFor(cmd)
			if err != nil {
				return err
			}
			capabilities.RenderSources(p)
			return nil
		},
	}
}

func (a *App) commandRules() *cobra.Command {
	return &cobra.Command{
		Use:   "rules",
		Short: "list the registered analysis rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := a.printerFor(cmd)
			if err != nil {
				return err
			}
			reg, err := a.registry()
			if err != nil {
				return pexit.WrapExitError(CodeRuntime, "loading rules", err)
			}
			if p.Format() == output.FormatTerminal {
				rows := make([][]string, 0, reg.Len())
				for _, m := range reg.Metas() {
					rows = append(rows, []string{m.ID, m.Name, m.Category, string(m.DefaultSeverity)})
				}
				p.PrintTable([]string{"id", "name", "category", "severity"}, rows)
				return nil
			}
			p.Print(reg.Metas())
			return nil
		},
	}
}

func (a *App) commandCase() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "case",
		Short: "generate a deterministic sample forensic case",
		RunE: func(cmd *cobra.Command, args []string) error {
			outPath, _ := cmd.Flags().GetString("out")
			cs := forensics.Simulate(forensics.SimulationOptions{})
			data, err := forensics.Marshal(cs)
			if err != nil {
				return pexit.WrapExitError(CodeRuntime, "marshaling case", err)
			}
			if outPath == "" || outPath == "-" {
				_, _ = a.Stdout.Write(data)
				_, _ = a.Stdout.Write([]byte("\n"))
				return nil
			}
			if err := os.WriteFile(outPath, data, 0o600); err != nil {
				return pexit.WrapExitError(CodeRuntime, "writing case", err)
			}
			_, _ = a.Stderr.WriteString("case written to " + outPath + "\n")
			return nil
		},
	}
	cmd.Flags().String("out", "", "write the case to this file instead of stdout")
	return cmd
}

// assessOpts are the resolved inputs of one assess run.
type assessOpts struct {
	Sim       bool
	Case      string
	Profile   string
	ReportDir string
	NoReport  bool
	Quiet     bool
}

func (a *App) commandAssess() *cobra.Command {
	var opts assessOpts
	cmd := &cobra.Command{
		Use:   "assess",
		Short: "run the analysis pipeline against a case or simulation",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := a.printerFor(cmd)
			if err != nil {
				return err
			}
			opts.Quiet, _ = cmd.Root().PersistentFlags().GetBool("quiet")
			return a.runAssess(cmd.Context(), p, opts)
		},
	}
	cmd.Flags().BoolVar(&opts.Sim, "sim", false, "analyze the built-in deterministic simulation")
	cmd.Flags().StringVar(&opts.Case, "case", "", "analyze a forensic case file (offline JSON)")
	cmd.Flags().StringVar(&opts.Profile, "profile", "", "analysis profile: quick, standard, deep")
	cmd.Flags().StringVar(&opts.ReportDir, "report-dir", "", "write a report file to this directory")
	cmd.Flags().BoolVar(&opts.NoReport, "no-report", false, "do not write any report artifact")
	return cmd
}

// runAssess is the shared assessment driver used by the CLI and console.
func (a *App) runAssess(ctx context.Context, p *output.Printer, opts assessOpts) error {
	cfgLocal := a.Cfg
	profile := cfgLocal.GetString("profile")
	if opts.Profile != "" {
		profile = opts.Profile
	}
	if !config.IsValidProfile(profile) {
		return pexit.NewExitError(CodeUsage, "unknown profile "+profile)
	}

	t, err := a.selectTarget(opts)
	if err != nil {
		return err
	}

	// Preflight: refuse provider targets, verify snapshot file presence.
	var v validation.Validator
	plan := v.Validate(t, func(p string) bool {
		_, err := os.Stat(p)
		return err == nil
	})
	if !plan.Ready {
		return pexit.NewExitError(CodeUsage, firstCheckMessage(plan))
	}

	counter := &countWriter{w: a.Stderr}
	stream := events.NewStream(counter)
	repDir := opts.ReportDir
	if repDir == "" {
		repDir = cfgLocal.GetString("report.dir")
	}
	store := evidence.New(filepath.Join(repDir, "evidence.json"))

	reg, err := a.registry()
	if err != nil {
		return pexit.WrapExitError(CodeRuntime, "registering rules", err)
	}
	assets := config.MaxAssets(cfgLocal)
	stages := analysis.Stages(reg, flagMap(cfgLocal, profile), assets)

	step := &pipeline.Step{
		Target:   t,
		Sim:      opts.Sim,
		Events:   stream,
		Evidence: store,
		Result: &models.Result{
			ID:        models.NewID("run"),
			Framework: version.Framework,
			Target:    t,
			Profile:   profile,
			Sim:       opts.Sim,
			StartedAt: models.Now(),
		},
	}

	if stream != nil {
		stream.Info(events.ScanStarted, map[string]any{
			"target": t.TypedName(), "profile": profile, "sim": opts.Sim,
		})
	}

	if err := pipeline.New(stages...).Run(ctx, step); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			return pexit.NewExitError(CodeInterrupt, "assessment interrupted")
		}
		return pexit.WrapExitError(CodeRuntime, "assessment failed", err)
	}

	step.Result.CompletedAt = models.Now()
	step.Result.Events = stream.Count()
	if err := store.Save(); err != nil {
		return pexit.WrapExitError(CodeRuntime, "writing evidence", err)
	}

	// Render results to stdout in the requested format. Redaction is applied
	// to a deep copy at the render surface so the canonical run result is
	// never mutated; non-secret evidence stays readable for triage.
	redactForOutput := cloneResult(step.Result)
	models.RedactSecretData(redactForOutput.Evidence)
	if !(opts.Quiet && p.Format() == output.FormatTerminal) {
		p.Print(&redactForOutput)
	}

	// Persistent report artifact (unless suppressed). Reports are redacted.
	persistResult(step.Result, repDir)
	if !opts.NoReport {
		reportFormat := "markdown"
		switch p.Format() {
		case output.FormatJSON:
			reportFormat = "json"
		case output.FormatYAML:
			reportFormat = "yaml"
		case output.FormatHTML:
			reportFormat = "html"
		}
		if repDir != "" {
			path, err := reporting.Write(repDir, reportFormat, step.Result)
			if err != nil {
				return pexit.WrapExitError(CodeRuntime, "writing report", err)
			}
			if stream != nil {
				stream.Info(events.ReportGenerated, map[string]any{"path": path})
			}
		}
	}

	if stream != nil {
		stream.Info(events.ScanCompleted, map[string]any{
			"assets": step.Result.Assets, "findings": len(step.Result.Findings),
			"score": step.Result.Score, "level": step.Result.Level,
		})
	}
	return nil
}

// selectTarget resolves the target for an assess run.
func (a *App) selectTarget(opts assessOpts) (*models.Target, error) {
	if opts.Sim && opts.Case != "" {
		return nil, pexit.NewExitError(CodeUsage, "use either --sim or --case, not both")
	}
	switch {
	case opts.Sim:
		return &models.Target{
			ID: "sim:" + models.NewID("sim"), Name: "simulation",
			Type: models.TargetSimulation, Value: "simulation",
			Auth: models.Authorization{Granted: true, Scope: "offline"},
		}, nil
	case opts.Case != "":
		return &models.Target{
			ID: "snap:" + models.NewID("snap"), Name: filepath.Base(opts.Case),
			Type: models.TargetSnapshot, Value: opts.Case,
			Auth: models.Authorization{Granted: true, Scope: "offline"},
		}, nil
	}
	cur := a.Manager.Current()
	if cur == nil {
		return nil, pexit.NewExitError(CodeUsage, "no target selected: use --sim, --case, or `target add`")
	}
	if cur.Type.IsProvider() {
		return nil, pexit.NewExitError(CodeUsage,
			"live acquisition is not implemented; provide a case file instead")
	}
	return cur, nil
}

func (a *App) commandTarget() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "target",
		Short: "manage assessment targets (case files and simulation)",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := a.printerFor(cmd)
			if err != nil {
				return err
			}
			rows := make([][]string, 0)
			for _, t := range a.Manager.List() {
				mark := ""
				if cur := a.Manager.Current(); cur != nil && cur.ID == t.ID {
					mark = "*"
				}
				rows = append(rows, []string{mark, t.ID, string(t.Type), t.TypedName(), t.Auth.Scope})
			}
			p.PrintTable([]string{"cur", "id", "type", "target", "auth"}, rows)
			return nil
		},
	}
	add := &cobra.Command{
		Use:   "add",
		Short: "register a target",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := a.printerFor(cmd)
			if err != nil {
				return err
			}
			typ := strings.ToLower(args[0])
			val := args[1]
			var t *models.Target
			switch typ {
			case "snapshot", "snap":
				t = &models.Target{
					Name: filepath.Base(val), Type: models.TargetSnapshot, Value: val,
					Auth: models.Authorization{Granted: true, Scope: "offline"},
				}
			case "sim", "simulation":
				t = &models.Target{Name: "simulation", Type: models.TargetSimulation, Value: "simulation",
					Auth: models.Authorization{Granted: true, Scope: "offline"}}
			default:
				return pexit.NewExitError(CodeUsage, "target type must be snapshot or sim; live acquisition is not implemented")
			}
			if err := a.Manager.Set(t); err != nil {
				if errors.Is(err, target.ErrUnauthorizedTarget) {
					return pexit.NewExitError(CodeUsage, err.Error())
				}
				return pexit.WrapExitError(CodeRuntime, "registering target", err)
			}
			p.Print(map[string]string{"registered": t.ID, "type": string(t.Type), "target": t.TypedName()})
			return nil
		},
	}
	clear := &cobra.Command{
		Use:   "clear",
		Short: "clear the current target",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.Manager.Clear(); err != nil {
				return pexit.WrapExitError(CodeRuntime, "clearing target", err)
			}
			return nil
		},
	}
	cmd.AddCommand(add, clear)
	return cmd
}

func (a *App) commandReport() *cobra.Command {
	return &cobra.Command{
		Use:   "report",
		Short: "render the latest assessment report from disk",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := a.printerFor(cmd)
			if err != nil {
				return err
			}
			repDir := a.Cfg.GetString("report.dir")
			res, err := loadLatestResult(repDir)
			if err != nil {
				return pexit.WrapExitError(CodeRuntime, "loading report state", err)
			}
			p.Print(res)
			return nil
		},
	}
}

func (a *App) commandFindings() *cobra.Command {
	return &cobra.Command{
		Use:   "findings",
		Short: "inspect the latest assessment findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := a.printerFor(cmd)
			if err != nil {
				return err
			}
			res, err := loadLatestResult(a.Cfg.GetString("report.dir"))
			if err != nil {
				return pexit.WrapExitError(CodeRuntime, "loading report state", err)
			}
			findings := res.Findings
			if p.Format() == output.FormatTerminal {
				rows := make([][]string, 0, len(findings))
				for i := range findings {
					f := &findings[i]
					rows = append(rows, []string{f.RuleID, f.Title, string(f.Severity), strings.Join(f.Objects, ",")})
				}
				p.PrintTable([]string{"rule", "title", "severity", "objects"}, rows)
				return nil
			}
			p.Print(findings)
			return nil
		},
	}
}

func (a *App) commandEvidence() *cobra.Command {
	return &cobra.Command{
		Use:   "evidence",
		Short: "inspect the latest assessment evidence",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := a.printerFor(cmd)
			if err != nil {
				return err
			}
			res, err := loadLatestResult(a.Cfg.GetString("report.dir"))
			if err != nil {
				return pexit.WrapExitError(CodeRuntime, "loading report state", err)
			}
			evs := res.Evidence
			if p.Format() == output.FormatTerminal {
				rows := make([][]string, 0, len(evs))
				for i := range evs {
					e := &evs[i]
					rows = append(rows, []string{e.Source, e.SourceID, string(e.Kind), e.Data})
				}
				p.PrintTable([]string{"source", "source_id", "kind", "data"}, rows)
				return nil
			}
			p.Print(evs)
			return nil
		},
	}
}

func (a *App) commandUpdates() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "updates",
		Short: "check for and install verified releases",
		RunE: func(cmd *cobra.Command, args []string) error {
			return pexit.NewExitError(CodeUsage, "updates requires a subcommand: check or install")
		},
	}
	cfgUpdate := selfupdate.Config{
		Owner: "QYVORA", Repo: "qyvora-timbuktu", ToolName: "timbuktu",
		CurrentVer: version.Version,
		ArtifactName: func(goos, goarch string) string {
			return fmt.Sprintf("timbuktu_%s_%s.tar.gz", goos, goarch)
		},
		ChecksumAsset: func(artifact string) string { return artifact + ".sha256" },
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "check",
		Short: "check whether a newer verified release exists",
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := selfupdate.CheckForUpdates(cmd.Context(), cfgUpdate)
			if err != nil {
				return pexit.WrapExitError(CodeRuntime, "checking for updates", err)
			}
			a.Printer.Print(map[string]any{"status": res.Status.String(), "current": res.Current, "latest": res.Latest})
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "download, verify and install the latest release",
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := selfupdate.Run(cmd.Context(), cfgUpdate, selfupdate.Options{Out: a.Stderr})
			if err != nil {
				return pexit.WrapExitError(CodeRuntime, "installing update", err)
			}
			a.Printer.Print(map[string]any{"status": res.Status.String(), "current": res.Current, "latest": res.Latest})
			return nil
		},
	})
	return cmd
}

func (a *App) commandConsole() *cobra.Command {
	return &cobra.Command{
		Use:   "console",
		Short: "start the interactive assessment console",
		RunE: func(cmd *cobra.Command, args []string) error {
			con, err := console.New(console.App{
				Execute: func(ctx context.Context, conArgs []string, p *output.Printer) error {
					opts := assessOpts{}
					for i := 0; i < len(conArgs); i++ {
						switch conArgs[i] {
						case "--sim":
							opts.Sim = true
						case "--case":
							if i+1 < len(conArgs) {
								opts.Case = conArgs[i+1]
								i++
							}
						case "--report-dir":
							if i+1 < len(conArgs) {
								opts.ReportDir = conArgs[i+1]
								i++
							}
						}
					}
					return a.runAssess(ctx, p, opts)
				},
				Printer:  a.Printer,
				Manager:  a.Manager,
				Registry: mustRegistry(a.registry()),
				Version:  version.String(),
				Out:      a.Stdout,
				ErrOut:   a.Stderr,
			})
			if err != nil {
				return pexit.WrapExitError(CodeRuntime, "starting console", err)
			}
			con.Run(cmd.Context())
			return nil
		},
	}
}

func (a *App) commandCompletion() *cobra.Command {
	return &cobra.Command{
		Use:   "completion",
		Short: "print shell completion for bash or zsh",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return pexit.NewExitError(CodeUsage, "usage: completion bash|zsh")
			}
			root := a.rootCommand()
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(a.Stdout)
			case "zsh":
				return root.GenZshCompletion(a.Stdout)
			default:
				return pexit.NewExitError(CodeUsage, "unsupported shell (bash|zsh)")
			}
		},
	}
}

func (a *App) registry() (*rules.Registry, error) {
	reg := rules.NewRegistry()
	if err := reg.RegisterAll(builtin.All()...); err != nil {
		return nil, err
	}
	return reg, nil
}

func flagMap(v *viper.Viper, profile string) map[string]any {
	return map[string]any{
		"profile":             profile,
		"analysis.max_assets": config.MaxAssets(v),
	}
}

func firstCheckMessage(plan validation.Plan) string {
	for _, c := range plan.Checks {
		if !c.Pass {
			return c.Message
		}
	}
	return "target validation failed"
}

// countWriter counts lines written; used to track event volume per run.
type countWriter struct {
	w io.Writer
	n int
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += n
	return n, err
}

// persistResult stores the latest run as JSON so report/findings/evidence
// commands can render it without re-running the pipeline.
func persistResult(res *models.Result, dir string) {
	if dir == "" {
		return
	}
	cp := cloneResult(res)
	for i := range cp.Findings {
		cp.Findings[i].RedactSecrets()
	}
	models.RedactSecretData(cp.Evidence)
	data, err := json.MarshalIndent(&cp, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(filepath.Join(dir, "result.json"), data, 0o600)
}

// cloneResult returns a deep copy of a result so render-surface redaction can
// never leak or corrupt the canonical run state.
func cloneResult(res *models.Result) models.Result {
	cp := *res
	if res.Target != nil {
		t := *res.Target
		cp.Target = &t
	}
	cp.Findings = make([]models.Finding, len(res.Findings))
	for i := range res.Findings {
		cp.Findings[i] = cloneFinding(&res.Findings[i])
	}
	cp.Evidence = make([]models.Evidence, len(res.Evidence))
	copy(cp.Evidence, res.Evidence)
	return cp
}

func cloneFinding(f *models.Finding) models.Finding {
	c := *f
	c.Objects = append([]string(nil), f.Objects...)
	c.References = append([]string(nil), f.References...)
	if f.Evidence != nil {
		c.Evidence = append([]models.Evidence(nil), f.Evidence...)
	}
	c.Attributes = make(map[string]string, len(f.Attributes))
	for k, v := range f.Attributes {
		c.Attributes[k] = v
	}
	return c
}

// mustRegistry returns the built-in rule registry, panicking only on a
// defective static rule set (duplicate IDs are a build-time bug).
func mustRegistry(reg *rules.Registry, err error) *rules.Registry {
	if err != nil {
		panic(err)
	}
	return reg
}

func loadLatestResult(dir string) (*models.Result, error) {
	// The latest run is persisted alongside reports as result.json.
	data, err := os.ReadFile(filepath.Join(dir, "result.json"))
	if err != nil {
		return nil, err
	}
	var res models.Result
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
