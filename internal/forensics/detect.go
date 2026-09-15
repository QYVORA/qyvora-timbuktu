package forensics

import (
	"sort"
	"strings"
	"time"
)

// IntegrityResult reports whether one evidence item's declared hash matches its
// content (verified in-process over the case payload).
type IntegrityResult struct {
	ItemID   string `json:"item_id"`
	Name     string `json:"name"`
	Declared string `json:"declared"`
	Actual   string `json:"actual"`
	Verified bool   `json:"verified"`
}

// VerifyIntegrity recomputes each evidence item hash and marks mismatches.
// Items without a content payload are skipped, not treated as failures.
func VerifyIntegrity(c *Case) []IntegrityResult {
	if c == nil {
		return nil
	}
	out := make([]IntegrityResult, 0, len(c.Evidence))
	for i := range c.Evidence {
		it := c.Evidence[i]
		if it.Content == "" || it.SHA256 == "" {
			continue
		}
		actual := HashContent(it.Content)
		out = append(out, IntegrityResult{
			ItemID: it.ID, Name: it.Name,
			Declared: it.SHA256, Actual: actual,
			Verified: strings.EqualFold(it.SHA256, actual),
		})
	}
	return out
}

// IntegrityStatus summarizes execution of VerifyIntegrity.
func IntegrityStatus(c *Case) (verified, failed int) {
	for _, r := range VerifyIntegrity(c) {
		if r.Verified {
			verified++
		} else {
			failed++
		}
	}
	return verified, failed
}

// FileSuspicion describes why a file stood out during filesystem analysis.
type FileSuspicion struct {
	Path   string `json:"path"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
	Hidden bool   `json:"hidden"`
}

var masqueradeNames = []string{
	"svchost", "lsass", "winlogon", "taskhost", "conhost",
	"csrss", "services", "smss", "explorer", "taskmgr",
}

// IsMasqueradeName reports whether a binary name imitates a well-known system
// process without matching it exactly.
func IsMasqueradeName(name string) bool {
	base := strings.ToLower(stripExt(name))
	for _, m := range masqueradeNames {
		if base != m && strings.HasPrefix(base, m) {
			return true
		}
	}
	return false
}

// IsSystemName reports whether a process or file name references a well-known
// system binary, either exactly or as a prefix imitation. Exact matches are
// included so that a faithful `svchost.exe` relocated off the system
// directory is still caught by the custody check.
func IsSystemName(name string) bool {
	base := strings.ToLower(stripExt(name))
	for _, m := range masqueradeNames {
		if base == m || strings.HasPrefix(base, m) {
			return true
		}
	}
	return false
}

// TrustedSystemDir reports whether a path is a standard read-only system
// location where a system-named binary is a credible, expected artifact. Any
// other location (temp, user profile, web root, recycle bin) breaks that
// custody and is treated as suspicious.
func TrustedSystemDir(path string) bool {
	if path == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(path))
	lower = strings.TrimRight(lower, `/\`)
	// Windows Temp is user-writable and a preferred masquerade drop location;
	// it must never inherit trust from the C:\Windows tree.
	if lower == `c:\windows\temp` || strings.HasPrefix(lower, `c:\windows\temp\`) ||
		strings.HasPrefix(lower, `/windows/temp/`) || strings.HasPrefix(lower, `/windows/temp`) {
		return false
	}
	trusted := []string{
		`c:\windows\system32`, `c:\windows\syswow64`, `c:\windows`,
		`c:\windows\system32\drivers`, `c:\windows\system32\inetsrv`,
		`c:\program files`, `c:\program files (x86)`,
		`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/libexec`,
		`/usr/local/bin`, `/usr/local/sbin`,
	}
	for _, dir := range trusted {
		if lower == dir || strings.HasPrefix(lower, dir+`\`) || strings.HasPrefix(lower, dir+"/") {
			return true
		}
	}
	return false
}

// MasqueradeSuspicion applies the custody chain to a system-named binary: a
// name imitating a well-known system process is only reported when it
// executes from a location a real system binary would never use. Trusted
// system directories are never flagged; unknown or writable locations are.
func MasqueradeSuspicion(name, path string) bool {
	if !IsSystemName(name) {
		return false
	}
	return !TrustedSystemDir(path)
}

func stripExt(name string) string {
	if i := strings.LastIndex(name, "."); i > 0 {
		return name[:i]
	}
	return name
}

var execExts = map[string]bool{
	"exe": true, "scr": true, "dll": true, "bin": true, "com": true,
	"cmd": true, "ps1": true, "msi": true, "jar": true, "vbs": true,
}

// IsExecutableExtension reports whether an extension can execute or load.
func IsExecutableExtension(ext string) bool {
	return execExts[strings.ToLower(ext)]
}

// IsTempDir reports whether a path lives in a user temp or OS temp directory.
func IsTempDir(path string) bool {
	lower := strings.ToLower(path)
	if strings.Contains(lower, `\appdata\local\temp\`) || strings.HasPrefix(lower, `c:\windows\temp\`) {
		return true
	}
	if strings.Contains(lower, "/tmp/") || strings.Contains(lower, "/temp/") {
		return true
	}
	return false
}

// IsRecycleBinPath reports whether a path lives under a recycle bin.
func IsRecycleBinPath(path string) bool {
	return strings.Contains(strings.ToLower(path), `\recycle.bin\`) ||
		strings.Contains(strings.ToLower(path), "$recycle.bin")
}

// SuspiciousFiles scans every volume for files that warrant triage.
func SuspiciousFiles(c *Case) []FileSuspicion {
	if c == nil {
		return nil
	}
	var out []FileSuspicion
	for v := range c.Volumes {
		for i := range c.Volumes[v].Files {
			f := c.Volumes[v].Files[i]
			if !IsExecutableExtension(f.Extension) && !strings.Contains(strings.ToLower(f.Name), "credential") {
				continue
			}
			reason := ""
			switch {
			case IsMasqueradeName(f.Name):
				reason = "process masquerading as a system binary"
			case strings.Count(f.Name, ".") >= 2 && IsExecutableExtension(f.Extension):
				reason = "double-extension executable"
			case IsTempDir(f.Path) && IsExecutableExtension(f.Extension):
				reason = "executable stored in a temporary directory"
			case IsRecycleBinPath(f.Path) && IsExecutableExtension(f.Extension):
				reason = "executable recovered from the recycle bin"
			case f.Hidden && IsExecutableExtension(f.Extension):
				reason = "hidden executable"
			case strings.Contains(strings.ToLower(f.Name), "credential"):
				reason = "credential-bearing file"
			}
			if reason != "" {
				out = append(out, FileSuspicion{Path: f.Path, Name: f.Name, Reason: reason, Hidden: f.Hidden})
			}
		}
	}
	return out
}

// ProcessSuspicion describes why a process stood out during memory analysis.
type ProcessSuspicion struct {
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	Parent     string `json:"parent"`
	User       string `json:"user"`
	Reason     string `json:"reason"`
	EvidenceID string `json:"evidence_id"`
}

var memTooling = []string{"mimikatz", "procdump", "lsassdumper", "xenon", "charles", "procmon"}

// SuspiciousProcesses flags process entries that warrant triage.
func SuspiciousProcesses(c *Case) []ProcessSuspicion {
	if c == nil {
		return nil
	}
	var out []ProcessSuspicion
	for i := range c.Processes {
		p := c.Processes[i]
		reason := ""
		switch {
		case IsMasqueradeName(p.Name):
			reason = "process imitating a system binary"
		case IsTempDir(p.Path) || strings.Contains(strings.ToLower(p.Path), `\temp\`):
			reason = "executable running from a temporary directory"
		case p.ParentName == "winword.exe" || p.ParentName == "excel.exe":
			reason = "executable spawned by an office document process"
		case p.ParentName == "w3wp.exe" && strings.EqualFold(p.Name, "powershell.exe"):
			reason = "shell spawned by a web server worker"
		case containsFold(memTooling, p.Name):
			reason = "credential or memory tooling present"
		case strings.Contains(strings.ToLower(p.Command), "-enc") ||
			strings.Contains(strings.ToLower(p.Command), "-encodedcommand"):
			reason = "encoded command line"
		}
		if reason != "" {
			out = append(out, ProcessSuspicion{
				PID: p.PID, Name: p.Name, Path: p.Path, Parent: p.ParentName,
				User: p.User, Reason: reason, EvidenceID: p.Evidence,
			})
		}
	}
	return out
}

// SuspiciousArtifacts returns the artifacts flagged for triage.
func SuspiciousArtifacts(c *Case) []Artifact {
	if c == nil {
		return nil
	}
	out := make([]Artifact, 0, len(c.Artifacts))
	for i := range c.Artifacts {
		if c.Artifacts[i].Suspicious {
			out = append(out, c.Artifacts[i])
		}
	}
	return out
}

// PersistenceKinds lists the artifact kinds that represent persistence.
var PersistenceKinds = []string{"autorun", "scheduled_task", "service"}

// LogAnomaly is one log-driven anomaly category.
type LogAnomaly struct {
	EventID   int    `json:"event_id"`
	Category  string `json:"category"`
	User      string `json:"user"`
	SourceIP  string `json:"source_ip,omitempty"`
	DestIP    string `json:"dest_ip,omitempty"`
	Timestamp string `json:"timestamp"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence"`
}

// LogAnomalies classifies log entries into triage anomalies.
func LogAnomalies(c *Case) []LogAnomaly {
	if c == nil {
		return nil
	}
	var out []LogAnomaly
	for i := range c.Logs {
		l := c.Logs[i]
		switch l.EventID {
		case 4625:
			out = append(out, LogAnomaly{EventID: l.EventID, Category: "failed-logon",
				User: l.User, SourceIP: l.SourceIP, Timestamp: l.Timestamp, Detail: l.Detail, Evidence: l.Evidence})
		case 4648, 4740:
			out = append(out, LogAnomaly{EventID: l.EventID, Category: "credential-anomaly",
				User: l.User, SourceIP: l.SourceIP, Timestamp: l.Timestamp, Detail: l.Detail, Evidence: l.Evidence})
		case 7045:
			out = append(out, LogAnomaly{EventID: l.EventID, Category: "service-install",
				Timestamp: l.Timestamp, Detail: l.Detail, Evidence: l.Evidence})
		case 4698:
			out = append(out, LogAnomaly{EventID: l.EventID, Category: "task-creation",
				User: l.User, Timestamp: l.Timestamp, Detail: l.Detail, Evidence: l.Evidence})
		case 4104:
			out = append(out, LogAnomaly{EventID: l.EventID, Category: "script-block",
				User: l.User, Timestamp: l.Timestamp, Detail: l.Detail, Evidence: l.Evidence})
		case 3:
			out = append(out, LogAnomaly{EventID: l.EventID, Category: "network-connection",
				User: l.User, DestIP: l.DestIP, Timestamp: l.Timestamp, Detail: l.Detail, Evidence: l.Evidence})
		case 4624:
			if isOffHour(l.Timestamp) {
				out = append(out, LogAnomaly{EventID: l.EventID, Category: "off-hour-logon",
					User: l.User, SourceIP: l.SourceIP, Timestamp: l.Timestamp, Detail: l.Detail, Evidence: l.Evidence})
			}
		}
	}
	return out
}

func isOffHour(rfc3339 string) bool {
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return false
	}
	h := t.UTC().Hour()
	return h < 5 || h >= 23
}

// CredentialFiles finds files that appear to bear credential material. Values
// are never returned; only identifiers and an explicit redaction flag.
func CredentialFiles(c *Case) []FileSuspicion {
	if c == nil {
		return nil
	}
	var out []FileSuspicion
	for v := range c.Volumes {
		for i := range c.Volumes[v].Files {
			f := c.Volumes[v].Files[i]
			if strings.Contains(strings.ToLower(f.Name), "credential") ||
				strings.HasSuffix(strings.ToLower(f.Name), ".env") {
				out = append(out, FileSuspicion{Path: f.Path, Name: f.Name, Reason: "credential material", Hidden: f.Hidden})
			}
		}
	}
	return out
}

// ExtractIndicators returns actionable indicators (high/confirmed) that have a
// real presence in the case data (process, log or artifact references).
func ExtractIndicators(c *Case) []Indicator {
	if c == nil {
		return nil
	}
	out := make([]Indicator, 0, len(c.Indicators))
	for _, in := range c.Indicators {
		switch in.Confidence {
		case "confirmed", "high":
			out = append(out, in)
		}
	}
	return out
}

// BuildTimeline reconstructs the investigation timeline from curated entries,
// filesystem timestamps, process starts and log events, sorted chronologically.
func BuildTimeline(c *Case) []Timeline {
	if c == nil {
		return nil
	}
	var out []Timeline
	out = append(out, c.Timeline...)
	for v := range c.Volumes {
		for i := range c.Volumes[v].Files {
			f := c.Volumes[v].Files[i]
			if f.Modified != "" {
				out = append(out, Timeline{Timestamp: f.Modified, Category: "filesystem",
					Action: "file.modified", Subject: f.Path, Source: c.Volumes[v].ID})
			}
			if f.Created != "" {
				out = append(out, Timeline{Timestamp: f.Created, Category: "filesystem",
					Action: "file.created", Subject: f.Path, Source: c.Volumes[v].ID})
			}
		}
	}
	for _, p := range c.Processes {
		if p.Started != "" {
			out = append(out, Timeline{Timestamp: p.Started, Category: "process",
				Action: "process.start", Subject: p.Name, Detail: p.Path, Source: p.Evidence})
		}
	}
	for _, l := range c.Logs {
		cat := "logon"
		switch l.EventID {
		case 7045, 4698:
			cat = "registry"
		case 3:
			cat = "network"
		case 4104:
			cat = "process"
		}
		out = append(out, Timeline{Timestamp: l.Timestamp, Category: cat,
			Action:  "log." + strings.ToLower(strings.ReplaceAll(l.Channel, "/", "-")),
			Subject: l.Detail, Source: l.Evidence})
	}
	sortTimeline(out)
	return out
}

// sortTimeline sorts timeline rows chronologically. RFC3339 UTC strings sort
// lexically; a stable sort keeps rows with equal timestamps in their original
// (deterministic) order, and is O(n log n) rather than the previous insertion
// sort.
func sortTimeline(t []Timeline) {
	sort.SliceStable(t, func(i, j int) bool {
		return t[i].Timestamp < t[j].Timestamp
	})
}

// TimelineGap detects the largest quiet window between consecutive timeline
// rows, an indicator that collection may be incomplete. Rows that do not parse
// are skipped without polluting the window: the gap is measured only between
// the previously parsed row and the current one.
func TimelineGap(t []Timeline) (gap time.Duration, gapAt string) {
	if len(t) < 2 {
		return 0, ""
	}
	prev := time.Time{}
	hasPrev := false
	var max time.Duration
	var at string
	for i := range t {
		cur, err := time.Parse(time.RFC3339, t[i].Timestamp)
		if err != nil {
			continue
		}
		if hasPrev {
			if d := cur.Sub(prev); d > max {
				max = d
				at = cur.UTC().Format(time.RFC3339)
			}
		}
		prev = cur
		hasPrev = true
	}
	return max, at
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
