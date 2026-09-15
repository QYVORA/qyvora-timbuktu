// Package forensics implements the DFIR case model for timbuktu. A case is a
// read-only JSON document describing collected evidence, filesystem exports,
// artifacts, process and log data, timeline entries and extracted indicators.
//
// The model separates original evidence from derived evidence and findings:
// every artifact, process, log or timeline row carries the source evidence
// item it came from, and analysis never mutates the case. Live acquisition is
// deliberately not implemented; assessments analyze case files (or the
// built-in deterministic simulation) instead of touching a live host.
package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// SchemaVersion is the case document schema this build reads and writes.
const SchemaVersion = "qyvora.timbuktu.case.v1"

// Source identifies the collection origin of a case or an evidence item.
type Source string

const (
	SourceDisk     Source = "disk"
	SourceMemory   Source = "memory"
	SourceLogs     Source = "logs"
	SourceRegistry Source = "registry"
	SourceBrowser  Source = "browser"
	SourcePrefetch Source = "prefetch"
	SourceLive     Source = "live"
	SourceNone     Source = ""
)

// ParseSource normalizes a source name, returning None for unknown values.
func ParseSource(s string) Source {
	switch Source(strings.ToLower(strings.TrimSpace(s))) {
	case SourceDisk, SourceMemory, SourceLogs, SourceRegistry, SourceBrowser, SourcePrefetch:
		return Source(strings.ToLower(strings.TrimSpace(s)))
	case "live", "host":
		return SourceLive
	default:
		return SourceNone
	}
}

// Case is the full offline investigation surface of one forensic case.
type Case struct {
	Schema     string         `json:"schema"`
	CaseID     string         `json:"case_id"`
	Title      string         `json:"title,omitempty"`
	Source     Source         `json:"source"`
	ScopeID    string         `json:"scope_id,omitempty"`
	Label      string         `json:"label,omitempty"`
	Acquired   string         `json:"acquired,omitempty"`
	Examiner   string         `json:"examiner,omitempty"`
	System     *System        `json:"system,omitempty"`
	Evidence   []EvidenceItem `json:"evidence,omitempty"`
	Volumes    []Volume       `json:"volumes,omitempty"`
	Artifacts  []Artifact     `json:"artifacts,omitempty"`
	Processes  []Process      `json:"processes,omitempty"`
	Logs       []LogEntry     `json:"logs,omitempty"`
	Timeline   []Timeline     `json:"timeline,omitempty"`
	Indicators []Indicator    `json:"indicators,omitempty"`
}

// System is the examined host and its enrolled accounts.
type System struct {
	Hostname   string   `json:"hostname"`
	Domain     string   `json:"domain,omitempty"`
	OSFamily   string   `json:"os_family,omitempty"`
	OSVersion  string   `json:"os_version,omitempty"`
	Arch       string   `json:"arch,omitempty"`
	BootedAt   string   `json:"booted_at,omitempty"`
	Users      []string `json:"users,omitempty"`
	LocalAdmin string   `json:"admin_account,omitempty"`
}

// Custody is one chain-of-custody transition.
type Custody struct {
	When    string `json:"when"`
	By      string `json:"by"`
	Action  string `json:"action"`
	Comment string `json:"comment,omitempty"`
}

// EvidenceItem is one acquired unit of original evidence.
type EvidenceItem struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"` // disk_image/memory_image/evtx_logs/prefetch/registry_hive/browser_data...
	Name        string    `json:"name"`
	Source      Source    `json:"source"`
	Path        string    `json:"path,omitempty"`
	CollectedAt string    `json:"collected_at,omitempty"`
	Examiner    string    `json:"examiner,omitempty"`
	Size        int64     `json:"size,omitempty"`
	SHA256      string    `json:"sha256,omitempty"`
	Content     string    `json:"content,omitempty"`
	Note        string    `json:"note,omitempty"`
	Custody     []Custody `json:"custody,omitempty"`
}

// HashContent computes the canonical sha256 hex of an evidence payload.
func HashContent(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// File is one file entry exported from a volume.
type File struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	Size      int64  `json:"size,omitempty"`
	Created   string `json:"created,omitempty"`
	Modified  string `json:"modified,omitempty"`
	Accessed  string `json:"accessed,omitempty"`
	Hidden    bool   `json:"hidden"`
	System    bool   `json:"system"`
	Owner     string `json:"owner,omitempty"`
	Extension string `json:"extension,omitempty"`
	Note      string `json:"note,omitempty"`
}

// Volume is a filesystem volume export.
type Volume struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	FSType  string `json:"fs_type,omitempty"`
	Mounted bool   `json:"mounted"`
	Files   []File `json:"files,omitempty"`
}

// Artifact is a known forensic artifact and where it was found.
type Artifact struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"` // autorun/scheduled_task/service/webshell/prefetch/browser_history/recycle_bin/hosts_file
	Name       string `json:"name"`
	Path       string `json:"path"`
	Detail     string `json:"detail,omitempty"`
	Evidence   string `json:"evidence,omitempty"` // id of the source evidence item
	Suspicious bool   `json:"suspicious"`
}

// Process is a process entry from a memory image or process log.
type Process struct {
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	Path       string `json:"path,omitempty"`
	ParentPID  int    `json:"parent_pid,omitempty"`
	ParentName string `json:"parent_name,omitempty"`
	User       string `json:"user,omitempty"`
	Command    string `json:"command_line,omitempty"`
	Started    string `json:"started,omitempty"`
	Network    bool   `json:"network_activity"`
	Evidence   string `json:"evidence,omitempty"`
	Note       string `json:"note,omitempty"`
}

// LogEntry is one parsed log line (Windows Event ID, auth log, syslog, ...).
type LogEntry struct {
	ID        string `json:"id"`
	Source    string `json:"source"`
	Channel   string `json:"channel,omitempty"`
	EventID   int    `json:"event_id,omitempty"`
	Level     string `json:"level"`
	Timestamp string `json:"timestamp"`
	User      string `json:"user,omitempty"`
	SourceIP  string `json:"source_ip,omitempty"`
	DestIP    string `json:"dest_ip,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Evidence  string `json:"evidence,omitempty"`
}

// Timeline is one reconstructed event on the investigation timeline.
type Timeline struct {
	Timestamp string `json:"timestamp"`
	Category  string `json:"category"` // acquisition/filesystem/process/logon/network/registry/artifact
	Action    string `json:"action"`
	Subject   string `json:"subject"`
	Detail    string `json:"detail,omitempty"`
	Source    string `json:"source,omitempty"` // evidence item or artifact id
}

// Indicator is one extracted indicator of compromise.
type Indicator struct {
	Kind        string   `json:"kind"` // sha256/ip/domain/filename/registry_key/mutex/command
	Value       string   `json:"value"`
	Confidence  string   `json:"confidence,omitempty"`
	Attribution string   `json:"attribution,omitempty"`
	Description string   `json:"description,omitempty"`
	Sources     []string `json:"sources,omitempty"`
}

// Load parses a case from r, rejecting documents that do not declare the case
// schema.
func Load(r io.Reader) (*Case, error) {
	var c Case
	dec := json.NewDecoder(r)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing case: %w", err)
	}
	if c.Schema != SchemaVersion {
		return nil, fmt.Errorf("unsupported case schema %q (want %s)", c.Schema, SchemaVersion)
	}
	if c.Source = ParseSource(string(c.Source)); c.Source == SourceNone {
		return nil, fmt.Errorf("case declares no supported evidence source (disk|memory|logs|registry|browser|prefetch)")
	}
	normalize(&c)
	return &c, nil
}

// LoadFile loads a case from a file path.
func LoadFile(path string) (*Case, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return Load(f)
}

// normalize fills evidence item hashes and file metadata defaults.
func normalize(c *Case) {
	for i := range c.Evidence {
		it := &c.Evidence[i]
		if it.Source = ParseSource(string(it.Source)); it.Source == SourceNone {
			it.Source = c.Source
		}
	}
	for i := range c.Volumes {
		v := &c.Volumes[i]
		if v.Name == "" {
			v.Name = "volume-" + itoa(i+1)
		}
		for j := range v.Files {
			f := &v.Files[j]
			if f.Extension == "" {
				f.Extension = extOf(f.Name)
			}
		}
	}
}

func extOf(name string) string {
	if i := strings.LastIndex(name, "."); i >= 0 && i < len(name)-1 {
		return strings.ToLower(name[i+1:])
	}
	return ""
}

// Counts returns per-category inventory totals, used by reports.
type Counts struct {
	Evidence   int `json:"evidence"`
	Volumes    int `json:"volumes"`
	Files      int `json:"files"`
	Artifacts  int `json:"artifacts"`
	Processes  int `json:"processes"`
	Logs       int `json:"logs"`
	Timeline   int `json:"timeline"`
	Indicators int `json:"indicators"`
}

// Counts computes the inventory totals of a case.
func (c *Case) Counts() Counts {
	files := 0
	for i := range c.Volumes {
		files += len(c.Volumes[i].Files)
	}
	return Counts{
		Evidence:   len(c.Evidence),
		Volumes:    len(c.Volumes),
		Files:      files,
		Artifacts:  len(c.Artifacts),
		Processes:  len(c.Processes),
		Logs:       len(c.Logs),
		Timeline:   len(c.Timeline),
		Indicators: len(c.Indicators),
	}
}

// Validate runs structural sanity checks on a parsed case.
func (c *Case) Validate() []string {
	var problems []string
	if c.Schema != SchemaVersion {
		problems = append(problems, "missing case schema version")
	}
	if c.CaseID == "" {
		problems = append(problems, "missing case_id")
	}
	if ParseSource(string(c.Source)) == SourceNone {
		problems = append(problems, "missing evidence source")
	}
	if len(c.Evidence) == 0 {
		problems = append(problems, "case holds no evidence items; run `timbuktu case` to generate a sample")
	}
	return problems
}

// Marshal renders a case as indented JSON.
func Marshal(c *Case) ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
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
