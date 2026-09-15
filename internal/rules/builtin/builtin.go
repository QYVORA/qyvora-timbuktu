// Package builtin registers the timbuktu rule set. Every rule reads only the
// provided analysis Env — the forensic case — and produces machine-readable
// findings with attached evidence. Nothing here executes samples, pings live
// hosts, or mutates original evidence: analysis is read-only over the case.
package builtin

import (
	"context"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-timbuktu/internal/analysis"
	"github.com/QYVORA/qyvora-timbuktu/internal/events"
	"github.com/QYVORA/qyvora-timbuktu/internal/forensics"
	"github.com/QYVORA/qyvora-timbuktu/internal/rules"
	"github.com/QYVORA/qyvora-timbuktu/pkg/models"
)

// All returns the rules implicit in a stock assessment.
func All() []rules.Rule {
	return []rules.Rule{
		&evidenceIntegrity{},
		&autorunPersistence{},
		&scheduledTask{},
		&serviceInstall{},
		&webShell{},
		&suspiciousFiles{},
		&suspiciousProcesses{},
		&masqueradeBinary{},
		&credentialExposure{},
		&logonAnomaly{},
		&networkIndicator{},
		&hostsTampering{},
		&timelineGap{},
	}
}

// metadata assembles a rule Meta with sane defaults for this rule set.
func metadata(id, name, category, description, recommendation string, sev models.Severity) rules.Meta {
	return rules.Meta{
		ID:                id,
		Name:              name,
		Category:          category,
		Description:       description,
		DefaultSeverity:   sev,
		DefaultConfidence: models.ConfidenceObserved,
		Recommendation:    recommendation,
	}
}

// newFinding fills the derived fields of a finding uniformly.
func newFinding(m rules.Meta, env *analysis.Env, objects []string, attrs map[string]string, ev ...models.Evidence) *models.Finding {
	return &models.Finding{
		RuleID:         m.ID,
		Title:          m.Name,
		Category:       m.Category,
		Description:    m.Description,
		Recommendation: m.Recommendation,
		Severity:       m.DefaultSeverity,
		Confidence:     m.DefaultConfidence,
		Status:         models.StatusDetected,
		State:          models.StateObserved,
		Objects:        objects,
		Attributes:     attrs,
		Evidence:       ev,
		Timestamp:      models.Now(),
	}
}

// ---------------------------------------------------------------------------
// Evidence integrity

type evidenceIntegrity struct{}

func (r *evidenceIntegrity) Meta() rules.Meta {
	return metadata("DFI-001", "Evidence integrity failure", "integrity",
		"At least one evidence item's declared hash does not match its content, "+
			"breaking the chain of custody for that item.",
		"Re-acquire the affected evidence with a documented write blocker and verify "+
			"hashes at collection and again at handover.",
		models.SeverityCritical)
}

func (r *evidenceIntegrity) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	results := forensics.VerifyIntegrity(env.Case)
	for _, res := range results {
		if res.Verified {
			continue
		}
		ev := env.AddEvidence(models.EvidenceObservation, "evidence", res.ItemID,
			res.Name, "hash verification failed during integrity check")
		if env.Events != nil {
			env.Events.Info(events.IntegrityVerified, map[string]any{
				"item_id": res.ItemID, "verified": false,
			})
		}
		sink.Add(newFinding(r.Meta(), env, []string{"evidence:" + res.ItemID},
			map[string]string{
				"declared": res.Declared,
				"actual":   res.Actual,
			}, ev))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Persistence

type autorunPersistence struct{}

func (r *autorunPersistence) Meta() rules.Meta {
	return metadata("DFI-002", "Autorun persistence", "persistence",
		"A run key or startup entry launches an executable from a temporary directory, "+
			"providing persistence across reboots.",
		"Remove the autorun entry and the staged binary; confirm the machine is reimaged.",
		models.SeverityHigh)
}

func (r *autorunPersistence) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, a := range forensics.SuspiciousArtifacts(env.Case) {
		if a.Kind != "autorun" {
			continue
		}
		ev := env.AddEvidence(models.EvidenceArtifact, "artifact", a.ID,
			a.Name, a.Detail)
		sink.Add(newFinding(r.Meta(), env, []string{"artifact:" + a.ID},
			map[string]string{"kind": a.Kind, "path": a.Path}, ev))
	}
	return nil
}

type scheduledTask struct{}

func (r *scheduledTask) Meta() rules.Meta {
	return metadata("DFI-003", "Suspicious scheduled task", "persistence",
		"A scheduled task runs an encoded shell command, a common persistence and "+
			"privilege escalation primitive.",
		"Review the task definition and the account that created it; disable and "+
			"investigate the command.",
		models.SeverityHigh)
}

func (r *scheduledTask) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, a := range forensics.SuspiciousArtifacts(env.Case) {
		if a.Kind != "scheduled_task" {
			continue
		}
		ev := env.AddEvidence(models.EvidenceArtifact, "artifact", a.ID,
			a.Name, a.Detail)
		sink.Add(newFinding(r.Meta(), env, []string{"artifact:" + a.ID},
			map[string]string{"kind": a.Kind, "path": a.Path}, ev))
	}
	return nil
}

type serviceInstall struct{}

func (r *serviceInstall) Meta() rules.Meta {
	return metadata("DFI-004", "Service with temp image path", "persistence",
		"A Windows service image points into the temp directory, which is outside the "+
			"normal service binary location.",
		"Quarantine the service, capture its image, and check for additional services "+
			"installed in the same window.",
		models.SeverityHigh)
}

func (r *serviceInstall) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, a := range forensics.SuspiciousArtifacts(env.Case) {
		if a.Kind != "service" {
			continue
		}
		ev := env.AddEvidence(models.EvidenceArtifact, "artifact", a.ID,
			a.Name, a.Detail)
		sink.Add(newFinding(r.Meta(), env, []string{"artifact:" + a.ID},
			map[string]string{"kind": a.Kind, "path": a.Path}, ev))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Web shell

type webShell struct{}

func (r *webShell) Meta() rules.Meta {
	return metadata("DFI-005", "Web shell deployed", "intrusion",
		"A web shell script was dropped into the web root during the incident window, "+
			"indicating server compromise and post-exploitation access.",
		"Remove the web shell, rotate web app secrets, and perform a full server "+
			"remediation scoped to the web tier.",
		models.SeverityCritical)
}

func (r *webShell) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, a := range forensics.SuspiciousArtifacts(env.Case) {
		if a.Kind != "webshell" {
			continue
		}
		ev := env.AddEvidence(models.EvidenceArtifact, "artifact", a.ID,
			a.Name, a.Detail)
		sink.Add(newFinding(r.Meta(), env, []string{"artifact:" + a.ID},
			map[string]string{"kind": a.Kind, "path": a.Path}, ev))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Filesystem

type suspiciousFiles struct{}

func (r *suspiciousFiles) Meta() rules.Meta {
	return metadata("DFI-006", "Suspicious files in unusual locations", "filesystem",
		"Executables, scripts or credential-bearing files were found in temporary, "+
			"hidden or recycled locations.",
		"Triage each flagged file for delivery, execution and persistence primitives; "+
			"preserve copies under the chain of custody.",
		models.SeverityHigh)
}

func (r *suspiciousFiles) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, f := range forensics.SuspiciousFiles(env.Case) {
		ev := env.AddEvidence(models.EvidenceFile, "filesystem", f.Path,
			f.Name, f.Reason)
		if env.Events != nil {
			env.Events.Info(events.FileSystemAnalyzed, map[string]any{
				"file": f.Path, "suspicious": true,
			})
		}
		sink.Add(newFinding(r.Meta(), env, []string{"file:" + f.Path},
			map[string]string{"reason": f.Reason, "hidden": boolStr(f.Hidden)}, ev))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Memory

type suspiciousProcesses struct{}

func (r *suspiciousProcesses) Meta() rules.Meta {
	return metadata("DFI-007", "Suspicious process activity", "memory",
		"Process analysis flagged executables running from temp directories, spawned "+
			"by document or web server parents, or using encoded command lines.",
		"Correlate process events against the timeline and capture memory for the "+
			"flagged PID tree before remediation.",
		models.SeverityCritical)
}

func (r *suspiciousProcesses) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, p := range forensics.SuspiciousProcesses(env.Case) {
		ev := env.AddEvidence(models.EvidenceObservation, "memory", p.EvidenceID,
			p.Name, p.Reason)
		if env.Events != nil {
			env.Events.Info(events.MemoryAnalyzed, map[string]any{
				"pid": p.PID, "name": p.Name, "suspicious": true,
			})
		}
		sink.Add(newFinding(r.Meta(), env, []string{"process:" + itoa(p.PID) + ":" + p.Name},
			map[string]string{"pid": itoa(p.PID), "path": p.Path, "reason": p.Reason}, ev))
	}
	return nil
}

type masqueradeBinary struct{}

func (r *masqueradeBinary) Meta() rules.Meta {
	return metadata("DFI-013", "Masquerading system binary", "memory",
		"A process or file name imitates a well-known system binary, a common evasion "+
			"and persistence technique.",
		"Follow the masquerading process to its source binary and parent; determine "+
			"delivery and execution chain.",
		models.SeverityHigh)
}

func (r *masqueradeBinary) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	seen := map[string][]string{}
	for _, p := range env.Case.Processes {
		if forensics.IsMasqueradeName(p.Name) {
			seen[p.Name] = append(seen[p.Name], "process:"+itoa(p.PID))
		}
	}
	for _, f := range forensics.SuspiciousFiles(env.Case) {
		if forensics.IsMasqueradeName(f.Name) {
			seen[f.Name] = append(seen[f.Name], "file:"+f.Path)
		}
	}
	for name, refs := range seen {
		ev := env.AddEvidence(models.EvidenceObservation, "case", "masquerade",
			name, "name imitates a system binary")
		sink.Add(newFinding(r.Meta(), env, refs,
			map[string]string{"name": name}, ev))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Credentials

type credentialExposure struct{}

func (r *credentialExposure) Meta() rules.Meta {
	return metadata("DFI-008", "Credential material on disk", "credentials",
		"Files that typically carry credentials or secrets were found on accessible "+
			"volumes, putting accounts at risk of theft.",
		"Retrieve the file under evidence control, identify and rotate every credential "+
			"it referenced, and enforce scanning for plaintext secrets.",
		models.SeverityHigh)
}

func (r *credentialExposure) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, f := range forensics.CredentialFiles(env.Case) {
		ev := env.AddEvidence(models.EvidenceFile, "case", f.Path,
			f.Name, "credential material present (values redacted)")
		sink.Add(newFinding(r.Meta(), env, []string{"file:" + f.Path},
			map[string]string{"redacted": "true"}, ev))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Logs

type logonAnomaly struct{}

func (r *logonAnomaly) Meta() rules.Meta {
	return metadata("DFI-009", "Logon anomalies detected", "logs",
		"Log analysis identified failed logons, off-hour interactive logons, "+
			"credential-anomaly events, service installs or scheduled task creation.",
		"Correlate the flagged events with the timeline; verify each account action "+
			"against the change-management baseline.",
		models.SeverityMedium)
}

func (r *logonAnomaly) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	byCategory := map[string][]forensics.LogAnomaly{}
	for _, an := range forensics.LogAnomalies(env.Case) {
		byCategory[an.Category] = append(byCategory[an.Category], an)
	}
	for category, list := range byCategory {
		refs := make([]string, 0, len(list))
		for _, an := range list {
			refs = append(refs, "log:"+an.Evidence)
		}
		ev := env.AddEvidence(models.EvidenceObservation, "logs",
			"anomaly:"+category,
			category, "log anomaly observed ("+itoa(len(list))+" events)")
		if env.Events != nil {
			env.Events.Info(events.LogAnalyzed, map[string]any{
				"category": category, "events": len(list),
			})
		}
		sink.Add(newFinding(r.Meta(), env, refs,
			map[string]string{"category": category, "events": itoa(len(list))}, ev))
	}
	return nil
}

type networkIndicator struct{}

func (r *networkIndicator) Meta() rules.Meta {
	return metadata("DFI-010", "Network indicators present", "indicators",
		"Indicators of compromise (C2 domains, endpoints and file hashes) have "+
			"corresponding presence in the case data.",
		"Investigate all outbound connections to the flagged endpoints and block them "+
			"at the perimeter once triage confirms them.",
		models.SeverityMedium)
}

func (r *networkIndicator) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, in := range forensics.ExtractIndicators(env.Case) {
		if in.Kind != "ip" && in.Kind != "domain" && in.Kind != "sha256" {
			continue
		}
		ev := env.AddEvidence(models.EvidenceObservation, "indicators", in.Kind,
			in.Value, in.Description)
		if env.Events != nil {
			env.Events.Info(events.IndicatorExtracted, map[string]any{
				"kind": in.Kind, "value": in.Value, "confidence": in.Confidence,
			})
		}
		sink.Add(newFinding(r.Meta(), env, []string{"indicator:" + in.Kind},
			map[string]string{"kind": in.Kind, "value": in.Value, "confidence": in.Confidence}, ev))
	}
	return nil
}

type hostsTampering struct{}

func (r *hostsTampering) Meta() rules.Meta {
	return metadata("DFI-011", "HOSTS file modification", "intrusion",
		"The HOSTS file was modified after the imaging baseline, which can redirect "+
			"first-party traffic.",
		"Restore the HOSTS file, verify DNS resolution to first-party services, and "+
			"look for additional persistence on the same host.",
		models.SeverityMedium)
}

func (r *hostsTampering) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, a := range forensics.SuspiciousArtifacts(env.Case) {
		if a.Kind != "hosts_file" {
			continue
		}
		ev := env.AddEvidence(models.EvidenceArtifact, "artifact", a.ID,
			a.Name, a.Detail)
		sink.Add(newFinding(r.Meta(), env, []string{"artifact:" + a.ID},
			map[string]string{"kind": a.Kind, "path": a.Path}, ev))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Timeline

type timelineGap struct{}

func (r *timelineGap) Meta() rules.Meta {
	return metadata("DFI-012", "Timeline coverage gap", "timeline",
		"Timeline reconstruction found no events for an extended window, which can "+
			"hide relevant activity or indicate incomplete collection.",
		"Re-check acquisition coverage for the gap window; correlate with gap size to "+
			"rule out reproduction issues.",
		models.SeverityLow)
}

func (r *timelineGap) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	tl := forensics.BuildTimeline(env.Case)
	gap, at := forensics.TimelineGap(tl)
	const threshold = 12 * time.Hour
	if gap < threshold {
		return nil
	}
	ev := env.AddEvidence(models.EvidenceObservation, "timeline", at,
		"timeline gap", "no events for "+gap.Truncate(time.Minute).String())
	sink.Add(newFinding(r.Meta(), env, []string{"timeline:" + at},
		map[string]string{"gap": gap.Truncate(time.Minute).String(), "at": at}, ev))
	return nil
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

var _ = strings.TrimSpace // reserved for future string helpers
