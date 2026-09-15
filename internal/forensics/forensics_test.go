package forensics_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-timbuktu/internal/forensics"
)

func TestLoadRejectsForeignSchema(t *testing.T) {
	doc := `{"schema":"qyvora.bogus.v1","case_id":"X","source":"disk"}`
	if _, err := forensics.Load(strings.NewReader(doc)); err == nil {
		t.Fatal("expected schema rejection, got nil")
	}
}

func TestLoadRejectsUnknownSource(t *testing.T) {
	doc := `{"schema":"qyvora.timbuktu.case.v1","case_id":"X","source":"frobnicate"}`
	if _, err := forensics.Load(strings.NewReader(doc)); err == nil {
		t.Fatal("expected source rejection, got nil")
	}
}

func TestLoadNormalizesItemSource(t *testing.T) {
	doc := `{"schema":"qyvora.timbuktu.case.v1","case_id":"INC-1","source":"logs",
	  "evidence":[{"id":"e1","kind":"evtx_logs","content":"x"}]}`
	c, err := forensics.Load(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Evidence[0].Source != forensics.SourceLogs {
		t.Errorf("item source not inherited from case: %s", c.Evidence[0].Source)
	}
}

func TestValidateFlagsMissingEvidence(t *testing.T) {
	c := &forensics.Case{Schema: forensics.SchemaVersion, CaseID: "INC-1", Source: forensics.SourceDisk}
	if problems := c.Validate(); len(problems) == 0 {
		t.Fatal("expected validation problems for a case without evidence")
	}
}

func TestSimulateIsDeterministic(t *testing.T) {
	a := forensics.Simulate(forensics.SimulationOptions{})
	b := forensics.Simulate(forensics.SimulationOptions{})
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatal("simulation is not deterministic")
	}
}

func TestSimulateExercisesEverySurface(t *testing.T) {
	c := forensics.Simulate(forensics.SimulationOptions{})
	cs := c.Counts()
	if cs.Evidence < 5 || cs.Files < 5 || cs.Artifacts < 5 || cs.Processes < 5 || cs.Logs < 5 || cs.Indicators < 5 {
		t.Errorf("simulation too thin: %+v", cs)
	}
	if c.Validate() != nil {
		t.Errorf("simulation fails validation: %v", c.Validate())
	}
}

func TestVerifyIntegrityDetectsTampering(t *testing.T) {
	c := forensics.Simulate(forensics.SimulationOptions{})
	results := forensics.VerifyIntegrity(c)
	failed := 0
	for _, r := range results {
		if !r.Verified {
			failed++
			if r.ItemID != "ev-tampered" {
				t.Errorf("unexpected integrity failure on %s", r.ItemID)
			}
		}
	}
	if failed != 1 {
		t.Errorf("expected exactly one tampered item, got %d", failed)
	}
}

func TestIsMasqueradeName(t *testing.T) {
	cases := map[string]bool{
		"svchost_.exe": true,
		"svchost.exe":  false,
		"lsasss.exe":   true,
		"explorer.exe": false,
		"notepad.exe":  false,
		"winlogon.gd":  false,
	}
	for name, want := range cases {
		if got := forensics.IsMasqueradeName(name); got != want {
			t.Errorf("IsMasqueradeName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestSuspiciousFiles(t *testing.T) {
	c := forensics.Simulate(forensics.SimulationOptions{})
	files := forensics.SuspiciousFiles(c)
	byPath := map[string]string{}
	for _, f := range files {
		byPath[f.Path] = f.Reason
	}
	want := map[string]string{
		`C:\Windows\Temp\sysmon_legit.bin.exe`:                        "double-extension executable",
		`C:\Users\mansi\AppData\Local\Temp\winupdate.scr`:             "executable stored in a temporary directory",
		`C:\Users\mansi\AppData\Local\Temp\svchost_.exe`:              "process masquerading as a system binary",
		`C:\$Recycle.Bin\S-1-5-21-2849754312-29013-6631\$RYQ9W2C.exe`: "executable recovered from the recycle bin",
	}
	for path, reason := range want {
		if got := byPath[path]; got != reason {
			t.Errorf("file %s reason = %q, want %q", path, got, reason)
		}
	}
}

func TestSuspiciousProcesses(t *testing.T) {
	c := forensics.Simulate(forensics.SimulationOptions{})
	procs := forensics.SuspiciousProcesses(c)
	var names []string
	for _, p := range procs {
		names = append(names, p.Name)
	}
	for _, want := range []string{"svchost_.exe", "powershell.exe", "mimikatz.exe", "winupdate.scr"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected suspicious process %s, got %v", want, names)
		}
	}
}

func TestLogAnomaliesClassify(t *testing.T) {
	c := forensics.Simulate(forensics.SimulationOptions{})
	anoms := forensics.LogAnomalies(c)
	byCat := map[string]int{}
	for _, a := range anoms {
		byCat[a.Category]++
	}
	if byCat["failed-logon"] < 1 {
		t.Error("expected failed-logon anomaly")
	}
	if byCat["off-hour-logon"] < 1 {
		t.Error("expected off-hour-logon anomaly")
	}
	if byCat["service-install"] < 1 {
		t.Error("expected service-install anomaly")
	}
	if byCat["network-connection"] < 1 {
		t.Error("expected network-connection anomaly")
	}
}

func TestCredentialFilesNeverReturnValues(t *testing.T) {
	c := forensics.Simulate(forensics.SimulationOptions{})
	files := forensics.CredentialFiles(c)
	if len(files) < 1 {
		t.Fatal("expected at least one credential-bearing file")
	}
	for _, f := range files {
		if strings.Contains(strings.ToLower(f.Path), "= ") {
			t.Errorf("credential value leaked in path %q", f.Path)
		}
	}
}

func TestBuildTimelineSortedAndGapped(t *testing.T) {
	c := forensics.Simulate(forensics.SimulationOptions{})
	tl := forensics.BuildTimeline(c)
	if len(tl) < 10 {
		t.Fatalf("timeline too thin: %d", len(tl))
	}
	for i := 1; i < len(tl); i++ {
		if tl[i].Timestamp < tl[i-1].Timestamp {
			t.Fatalf("timeline out of order at %d: %s < %s", i, tl[i].Timestamp, tl[i-1].Timestamp)
		}
	}
	gap, at := forensics.TimelineGap(tl)
	if gap < 12*time.Hour {
		t.Errorf("expected a coverable gap, got %s at %s", gap, at)
	}
}

func TestExtractIndicatorsKeepsActionable(t *testing.T) {
	c := forensics.Simulate(forensics.SimulationOptions{})
	for _, in := range forensics.ExtractIndicators(c) {
		if in.Confidence != "high" && in.Confidence != "confirmed" {
			t.Errorf("non-actionable indicator kept: %s (%s)", in.Kind, in.Confidence)
		}
	}
}
