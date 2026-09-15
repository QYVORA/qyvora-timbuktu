package forensics

import "testing"

func TestTimelineIsStablySorted(t *testing.T) {
	rows := []Timeline{
		{Timestamp: "2026-03-04T08:11:00Z", Subject: "b"},
		{Timestamp: "2026-03-04T06:40:10Z", Subject: "system"},
		{Timestamp: "2026-03-04T08:11:00Z", Subject: "a"},
		{Timestamp: "2026-03-04T07:01:00Z", Subject: "explorer"},
	}
	sorted := make([]Timeline, len(rows))
	copy(sorted, rows)
	sortTimeline(sorted)
	got := []string{}
	for _, r := range sorted {
		got = append(got, r.Subject)
	}
	want := []string{"system", "explorer", "b", "a"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v (ties must stay stable)", got, want)
		}
	}
}

func TestTimelineGapSkipsCorruptRows(t *testing.T) {
	rows := []Timeline{
		{Timestamp: "not-a-date"},
		{Timestamp: "2026-03-04T06:40:10Z"},
		{Timestamp: "2026-03-04T06:40:30Z"},
	}
	gap, at := TimelineGap(rows)
	if gap != 20_000_000_000 || at != "2026-03-04T06:40:30Z" {
		t.Errorf("gap(s) = %v, want 20s; a corrupt leading row must not fabricate a zero-anchored gap (got %s)", gap, at)
	}
}

func TestTimelineGapNoOrphanPrev(t *testing.T) {
	rows := []Timeline{
		{Timestamp: "2026-03-04T08:11:00Z"},
		{Timestamp: "corrupt"},
	}
	gap, at := TimelineGap(rows)
	if gap != 0 || at != "" {
		t.Errorf("unpaired row must yield no gap, got %v at %s", gap, at)
	}
}

func TestMasqueradeSuspicionCustodyChain(t *testing.T) {
	cases := []struct {
		name, path string
		want       bool
	}{
		{`svchost_.exe`, `C:\Users\mansi\AppData\Local\Temp\svchost_.exe`, true},
		{`svchost_.exe`, `C:\Windows\Temp\svchost_.exe`, true},
		{`svchost.exe`, `C:\Users\mansi\AppData\Local\Temp\svchost.exe`, true},
		{`explorer2.exe`, `/tmp/explorer2.exe`, true},
		{`svchost.exe`, `C:\Windows\System32\svchost.exe`, false},
		{`lsass.exe`, `C:\Windows\system32\lsass.exe`, false},
		{`taskhostw.exe`, `C:\Windows\System32\taskhostw.exe`, false},
		{`explorer.exe`, `C:\Windows\explorer.exe`, false},
		{`powershell.exe`, `C:\Program Files\PowerShell\7\pwsh.exe`, false},
		{`notepad.exe`, `C:\Users\jane\AppData\Local\Temp\x.exe`, false},
		{`svchost_.exe`, ``, true},
	}
	for _, c := range cases {
		if got := MasqueradeSuspicion(c.name, c.path); got != c.want {
			t.Errorf("MasqueradeSuspicion(%q, %q) = %v, want %v", c.name, c.path, got, c.want)
		}
	}
}

func TestTrustedSystemDir(t *testing.T) {
	trusted := []string{
		`C:\Windows\System32`, `C:\Windows\System32\drivers\etc`,
		`C:\Windows`, `c:\program files\microsoft office`,
		`/bin/ls`, `/usr/bin/x`, `/usr/local/bin/y`, `/usr/libexec/a`,
	}
	for _, p := range trusted {
		if !TrustedSystemDir(p) {
			t.Errorf("%q must be a trusted system directory", p)
		}
	}
	untrusted := []string{
		`C:\Users\x\AppData\Local\Temp\a.exe`, `C:\Windows\Temp\a.exe`,
		`/tmp/a`, `/home/x/a`, `C:\inetpub\wwwroot\a.exe`, `C:\$Recycle.Bin\x`,
		"", `C:\UWindows\System32\evil.exe`,
	}
	for _, p := range untrusted {
		if TrustedSystemDir(p) {
			t.Errorf("%q must not be a trusted system directory", p)
		}
	}
}
