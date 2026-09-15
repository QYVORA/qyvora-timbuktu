// Package analysis wires the assessment into pipeline stages: source
// detection, evidence acquisition, integrity verification, artifact
// identification, filesystem/memory/log analysis, timeline reconstruction,
// rule analysis and risk calculation. Env is the shared state handed to every
// rule.
package analysis

import (
	"context"

	"github.com/QYVORA/qyvora-timbuktu/internal/errors"
	"github.com/QYVORA/qyvora-timbuktu/internal/events"
	"github.com/QYVORA/qyvora-timbuktu/internal/evidence"
	"github.com/QYVORA/qyvora-timbuktu/internal/forensics"
	"github.com/QYVORA/qyvora-timbuktu/internal/pipeline"
	"github.com/QYVORA/qyvora-timbuktu/internal/risk"
	"github.com/QYVORA/qyvora-timbuktu/internal/rules"
	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

// Env is the environment passed to every rule during one assessment.
type Env struct {
	Case   *forensics.Case
	Events *events.Stream
	Store  *evidence.Store
	Config map[string]any
}

// AddEvidence records an observation backing a finding, hashed and stored.
func (e *Env) AddEvidence(kind models.EvidenceKind, source, sourceID, target, data string) models.Evidence {
	ev := models.Evidence{
		Kind:     kind,
		Source:   source,
		SourceID: sourceID,
		Target:   target,
		Data:     data,
		State:    models.StateObserved,
	}
	if e.Store != nil {
		e.Store.Add(ev)
	}
	ev.Hash = models.HashContent(ev.Data)
	return ev
}

// Stages returns the full offline/simulation assessment pipeline.
func Stages(reg *rules.Registry, cfg map[string]any, maxAssets int) []pipeline.Stage {
	return []pipeline.Stage{
		{
			ID: "acquisition", Name: "Evidence acquisition",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				cs, err := currentCase(step)
				if err != nil {
					return err
				}
				if step.Events != nil {
					step.Events.Info(events.EvidenceRegistered, map[string]any{
						"case_id": cs.CaseID,
						"source":  string(cs.Source),
						"items":   len(cs.Evidence),
					})
				}
				step.Result.Assets = len(cs.Evidence)
				return nil
			},
		},
		{
			ID: "integrity", Name: "Evidence integrity",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				cs, err := currentCase(step)
				if err != nil {
					return err
				}
				verified, failed := forensics.IntegrityStatus(cs)
				if step.Events != nil {
					step.Events.Info(events.IntegrityVerified, map[string]any{
						"verified": verified, "failed": failed, "total": len(cs.Evidence),
					})
				}
				return nil
			},
		},
		{
			ID: "artifacts", Name: "Artifact identification",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				cs, err := currentCase(step)
				if err != nil {
					return err
				}
				if step.Events != nil {
					step.Events.Info(events.ArtifactIdentified, map[string]any{
						"artifacts":  len(cs.Artifacts),
						"suspicious": len(forensics.SuspiciousArtifacts(cs)),
					})
				}
				return nil
			},
		},
		{
			ID: "filesystem", Name: "Filesystem analysis",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				cs, err := currentCase(step)
				if err != nil {
					return err
				}
				sus := forensics.SuspiciousFiles(cs)
				if step.Events != nil {
					step.Events.Info(events.FileSystemAnalyzed, map[string]any{
						"volumes": len(cs.Volumes), "suspicious_files": len(sus),
					})
				}
				return nil
			},
		},
		{
			ID: "memory", Name: "Memory analysis",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				cs, err := currentCase(step)
				if err != nil {
					return err
				}
				procs := forensics.SuspiciousProcesses(cs)
				if step.Events != nil {
					step.Events.Info(events.MemoryAnalyzed, map[string]any{
						"processes": len(cs.Processes), "suspicious": len(procs),
					})
				}
				return nil
			},
		},
		{
			ID: "logs", Name: "Log analysis",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				cs, err := currentCase(step)
				if err != nil {
					return err
				}
				anoms := forensics.LogAnomalies(cs)
				if step.Events != nil {
					step.Events.Info(events.LogAnalyzed, map[string]any{
						"entries": len(cs.Logs), "anomalies": len(anoms),
					})
				}
				return nil
			},
		},
		{
			ID: "timeline", Name: "Timeline reconstruction",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				cs, err := currentCase(step)
				if err != nil {
					return err
				}
				tl := forensics.BuildTimeline(cs)
				if step.Events != nil {
					step.Events.Info(events.TimelineBuilt, map[string]any{
						"entries": len(tl),
					})
				}
				return nil
			},
		},
		{
			ID: "analysis", Name: "Rule analysis",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				if reg == nil {
					return nil
				}
				cs, err := currentCase(step)
				if err != nil {
					return err
				}
				env := &Env{
					Case:   cs,
					Events: step.Events,
					Store:  step.Evidence,
					Config: cfg,
				}
				sink := rules.NewSink()
				if err := reg.Run(ctx, env, sink); err != nil {
					return err
				}
				for _, f := range sink.List() {
					if step.Target != nil {
						f.TargetID = step.Target.ID
					}
					step.Result.Findings = append(step.Result.Findings, *f)
					if step.Events != nil {
						step.Events.Info(events.FindingDiscovered, map[string]any{
							"rule_id": f.RuleID, "title": f.Title, "severity": string(f.Severity),
							"objects": f.Objects,
						})
					}
				}
				return nil
			},
		},
		{
			ID: "risk", Name: "Risk calculation",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				var assessor risk.Assessor
				score, level := assessor.Assess(ctx, headings(step.Result.Findings))
				step.Result.Score = score
				step.Result.Level = level
				step.Result.Evidence = step.Evidence.List()
				if step.Events != nil {
					step.Events.Info(events.RiskCalculated, map[string]any{
						"score": score, "level": level, "findings": len(step.Result.Findings),
					})
				}
				return nil
			},
		},
	}
}

// Execute stages builds a Result shell ready for a pipeline run.
func Execute(stages func() []pipeline.Stage, step *pipeline.Step) error {
	if step == nil || step.Events == nil {
		return errors.NewExitError(1, "pipeline execution requires an event stream")
	}
	eng := pipeline.New(stages()...)
	if err := eng.Run(context.Background(), step); err != nil {
		return err
	}
	return nil
}

func headings(fs []models.Finding) []*models.Finding {
	out := make([]*models.Finding, len(fs))
	for i := range fs {
		out[i] = &fs[i]
	}
	return out
}

func currentCase(step *pipeline.Step) (*forensics.Case, error) {
	if step == nil || step.Target == nil {
		return nil, errors.NewExitError(1, "assessment requires a case or simulation target")
	}
	if step.Sim {
		return forensics.Simulate(forensics.SimulationOptions{}), nil
	}
	if step.Target.Type != models.TargetSnapshot {
		return nil, errors.NewExitError(1, "unsupported target: live acquisition is not implemented; provide a case file")
	}
	cs, err := forensics.LoadFile(step.Target.Value)
	if err != nil {
		return nil, errors.WrapExitError(1, "loading case", err)
	}
	return cs, nil
}
