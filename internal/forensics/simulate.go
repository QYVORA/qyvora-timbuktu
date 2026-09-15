package forensics

import (
	"time"
)

// SimulationOptions tunes the deterministic demo case.
type SimulationOptions struct{}

// Simulate returns a deterministic sample forensic case exercising every
// analysis path: evidence integrity (including one deliberate tampered item),
// persistence artifacts, suspicious processes, webshell, credential exposure,
// logon anomalies, timeline reconstruction and indicator extraction. All
// values (hashes, hostnames, IPs, secrets) are clearly fake simulation data.
func Simulate(opts SimulationOptions) *Case {
	diskContent := "fake disk sector payload, not a real forensic image\n" +
		"acquisition: verified write-blocked duplicate removed for simulation\n"
	memContent := "fake process memory map, not a real memory image\n"
	logContent := "evtx export placeholder - structured entries are in case.logs\n"
	pfContent := "prefetch binary metadata placeholder\n"
	hiveContent := "registry hive hex dump placeholder\n"
	browserContent := "browser profile sqlite placeholder\n"
	tamperedContent := "original sector sample taken under write blocker\n"

	s := &Case{
		Schema:   SchemaVersion,
		CaseID:   "INC-2026-1207",
		Title:    "corp-ws-0427 unauthorized activity (deterministic simulation)",
		Source:   SourceDisk,
		ScopeID:  "corp.qyvora.test/workspace",
		Label:    "simulated forensic case - all data fabricated",
		Acquired: "2026-03-05T06:40:00Z",
		Examiner: "qyvora-forensics-sim",
		System: &System{
			Hostname:   "CORP-WS-0427",
			Domain:     "corp.qyvora.test",
			OSFamily:   "windows",
			OSVersion:  "10.0.19045.4046",
			Arch:       "x86_64",
			BootedAt:   "2026-03-04T06:40:00Z",
			Users:      []string{"Administrator", "mansi", "analyst", "webapps"},
			LocalAdmin: "Administrator",
		},
		Evidence: []EvidenceItem{
			{
				ID: "ev-disk", Kind: "disk_image", Name: "CORP-WS-0427-system.e01",
				Source: SourceDisk, Path: "evidence/disk/CORP-WS-0427-system.e01",
				CollectedAt: "2026-03-05T06:45:00Z", Examiner: "forensic-examiner-a",
				Size: 4096, SHA256: HashContent(diskContent), Content: diskContent,
				Note: "write-blocked duplicate, sha256 verified at collection",
				Custody: []Custody{
					{When: "2026-03-05T06:45:00Z", By: "forensic-examiner-a", Action: "acquired", Comment: "write-blocked preview image"},
					{When: "2026-03-05T07:02:00Z", By: "evidence-room", Action: "transferred", Comment: "sealed bag EV-2201"},
				},
			},
			{
				ID: "ev-mem", Kind: "memory_image", Name: "CORP-WS-0427.mem",
				Source: SourceMemory, Path: "evidence/memory/CORP-WS-0427.mem",
				CollectedAt: "2026-03-05T06:52:00Z", Examiner: "forensic-examiner-a",
				Size: 2048, SHA256: HashContent(memContent), Content: memContent,
				Note: "volatile data first, process list in case.processes",
			},
			{
				ID: "ev-logs", Kind: "evtx_logs", Name: "win-evtx-export.zip",
				Source: SourceLogs, Path: "evidence/logs/win-evtx-export.zip",
				CollectedAt: "2026-03-05T07:10:00Z", Examiner: "analyst-c",
				Size: 2048, SHA256: HashContent(logContent), Content: logContent,
				Note: "Security, System and PowerShell operational channels",
			},
			{
				ID: "ev-prefetch", Kind: "prefetch", Name: "prefetch-export",
				Source: SourcePrefetch, Path: "evidence/prefetch",
				CollectedAt: "2026-03-05T07:12:00Z", Examiner: "analyst-c",
				Size: 1024, SHA256: HashContent(pfContent), Content: pfContent,
			},
			{
				ID: "ev-hives", Kind: "registry_hive", Name: "hives-export",
				Source: SourceRegistry, Path: "evidence/registry",
				CollectedAt: "2026-03-05T07:14:00Z", Examiner: "analyst-c",
				Size: 1024, SHA256: HashContent(hiveContent), Content: hiveContent,
			},
			{
				ID: "ev-browser", Kind: "browser_data", Name: "webapps-profile-export",
				Source: SourceBrowser, Path: "evidence/browser/webapps",
				CollectedAt: "2026-03-05T07:15:00Z", Examiner: "analyst-c",
				Size: 1024, SHA256: HashContent(browserContent), Content: browserContent,
			},
			{
				ID: "ev-tampered", Kind: "disk_image", Name: "CORP-WS-0427-unchecked.bin",
				Source: SourceDisk, Path: "evidence/triage/unchecked.bin",
				CollectedAt: "2026-03-05T06:41:00Z", Examiner: "evidence-room",
				Size: 512, SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
				Content: tamperedContent,
				Note:    "sector sample stored without collection-time hash validation",
			},
		},
		Volumes: []Volume{
			{
				ID: "vol-c", Name: "C:", FSType: "NTFS", Mounted: true,
				Files: []File{
					{
						Path: `C:\Windows\explorer.exe`, Name: "explorer.exe",
						Size: 4199392, Created: "2025-08-01T10:00:00Z",
						Modified: "2026-02-11T08:00:00Z", Owner: "NT AUTHORITY\\SYSTEM",
					},
					{
						Path: `C:\Windows\System32\svchost.exe`, Name: "svchost.exe",
						Size: 53336, Created: "2025-08-01T10:00:00Z",
						Modified: "2026-02-11T08:00:00Z", Owner: "NT AUTHORITY\\SYSTEM",
					},
					{
						Path: `C:\Windows\Temp\sysmon_legit.bin.exe`, Name: "sysmon_legit.bin.exe",
						Size: 217088, Created: "2026-03-04T03:41:00Z",
						Modified: "2026-03-04T03:41:00Z", Hidden: true, Owner: "SYSTEM",
						Note: "executable stored in Temp with a double extension",
					},
					{
						Path: `C:\Windows\Temp\updater_2026.exe`, Name: "updater_2026.exe",
						Size: 145920, Created: "2026-03-04T03:47:00Z",
						Modified: "2026-03-04T03:47:00Z", Owner: "CORP\\mansi",
						Note: "signed updater binary matching the vendor checksum (benign control)",
					},
					{
						Path: `C:\Users\mansi\AppData\Local\Temp\winupdate.scr`,
						Name: "winupdate.scr", Size: 18432, Created: "2026-03-04T03:21:00Z",
						Modified: "2026-03-04T03:21:00Z", Hidden: true, Owner: "CORP\\mansi",
						Note: "screensaver-titled executable in the user temp directory",
					},
					{
						Path: `C:\Users\mansi\AppData\Local\Temp\svchost_.exe`,
						Name: "svchost_.exe", Size: 250880, Created: "2026-03-04T03:22:00Z",
						Modified: "2026-03-04T03:22:00Z", Hidden: true, Owner: "CORP\\mansi",
						Note: "process masquerading as a system service binary",
					},
					{
						Path: `C:\inetpub\wwwroot\shell.aspx`, Name: "shell.aspx",
						Size: 4096, Created: "2026-03-04T04:02:00Z",
						Modified: "2026-03-04T04:02:00Z", Owner: "IUSR",
						Note: "asp.net script dropped into the web root",
					},
					{
						Path: `C:\Users\webapps\AppData\Roaming\Microsoft\Windows\Recent\order-export.lnk`,
						Name: "order-export.lnk", Size: 8192, Created: "2026-03-04T03:55:00Z",
						Modified: "2026-03-04T03:55:00Z", Owner: "CORP\\webapps",
						Note: "recent shortcut resolving to a temp executable",
					},
					{
						Path: `C:\$Recycle.Bin\S-1-5-21-2849754312-29013-6631\$RYQ9W2C.exe`,
						Name: "$RYQ9W2C.exe", Size: 151552, Created: "2026-03-04T03:36:00Z",
						Modified: "2026-03-04T03:36:00Z", Hidden: true, Owner: "CORP\\mansi",
						Note: "deleted executable recovered from the recycle bin",
					},
					{
						Path: `C:\Windows\System32\drivers\etc\hosts`, Name: "hosts",
						Size: 1024, Created: "2025-08-01T10:00:00Z",
						Modified: "2026-03-04T03:58:00Z", Owner: "NT AUTHORITY\\SYSTEM",
						Note: "modified after image baseline; see artifact hosts-redirect",
					},
					{
						Path: `D:\backups\credentials.txt`, Name: "credentials.txt",
						Size: 512, Created: "2026-03-04T01:22:00Z",
						Modified: "2026-03-04T01:22:00Z", Owner: "CORP\\analyst",
						Note: "backup export containing service account credentials (redacted in output)",
					},
					{
						Path: `C:\Windows\System32\config\SAM`, Name: "SAM",
						Size: 65536, Created: "2025-08-01T10:00:00Z",
						Modified: "2026-03-04T03:30:00Z", System: true, Owner: "NT AUTHORITY\\SYSTEM",
						Note: "local account database; modified during the incident window",
					},
				},
			},
		},
		Artifacts: []Artifact{
			{
				ID: "AR-1", Kind: "autorun", Name: "WindowsUpdateCheck",
				Path:     `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
				Detail:   `WindowsUpdateCheck -> C:\Users\mansi\AppData\Local\Temp\winupdate.scr`,
				Evidence: "ev-hives", Suspicious: true,
			},
			{
				ID: "AR-2", Kind: "scheduled_task", Name: "CorpHealthCheck",
				Path:     `\CorpHealthCheck`,
				Detail:   "powershell.exe -enc aWMgbmV0d29yayBzY2FubmVyIGRvd25sb2Fk",
				Evidence: "ev-hives", Suspicious: true,
			},
			{
				ID: "AR-3", Kind: "service", Name: "W32TimeSvc",
				Path:     `HKLM\System\CurrentControlSet\Services\W32TimeSvc`,
				Detail:   "ImagePath = C:\\Windows\\Temp\\sysmon_legit.bin.exe",
				Evidence: "ev-hives", Suspicious: true,
			},
			{
				ID: "AR-4", Kind: "webshell", Name: "shell.aspx",
				Path:     `C:\inetpub\wwwroot\shell.aspx`,
				Detail:   "asp.net script with command injection primitives",
				Evidence: "ev-disk", Suspicious: true,
			},
			{
				ID: "AR-5", Kind: "browser_history", Name: "updates-check.io",
				Path:     `updates-check.io/panel`,
				Detail:   "visited 2026-03-04T03:26:00Z from webapps profile",
				Evidence: "ev-browser", Suspicious: true,
			},
			{
				ID: "AR-6", Kind: "hosts_file", Name: "hosts-redirect",
				Path:     `C:\Windows\System32\drivers\etc\hosts`,
				Detail:   "185.199.108.153 account-portal.corp.qyvora.test",
				Evidence: "ev-disk", Suspicious: true,
			},
			{
				ID: "AR-7", Kind: "prefetch", Name: "SVCHOST_.EXE-3E2F0E5A.pf",
				Path:     `C:\Windows\Prefetch\SVCHOST_.EXE-3E2F0E5A.pf`,
				Detail:   "prefetch for masquerading binary created in incident window",
				Evidence: "ev-prefetch", Suspicious: true,
			},
			{
				ID: "AR-8", Kind: "recycle_bin", Name: "$RYQ9W2C.exe",
				Path:     `C:\$Recycle.Bin\S-1-5-21-2849754312-29013-6631\$RYQ9W2C.exe`,
				Detail:   "presence inside recycle bin while parent handle still open",
				Evidence: "ev-disk", Suspicious: true,
			},
			{
				ID: "AR-9", Kind: "browser_history", Name: "cloud-sync.online",
				Path:     `cloud-sync.online/api`,
				Detail:   "visited 2026-03-04T03:58:00Z from webapps profile",
				Evidence: "ev-browser", Suspicious: true,
			},
		},
		Processes: []Process{
			{PID: 4, Name: "System", ParentPID: 0, User: "SYSTEM", Started: "2026-03-04T06:40:10Z"},
			{PID: 632, Name: "lsass.exe", Path: `C:\Windows\System32\lsass.exe`, ParentPID: 4,
				User: "NT AUTHORITY\\SYSTEM", Started: "2026-03-04T06:40:12Z", Evidence: "ev-mem"},
			{PID: 824, Name: "svchost.exe", Path: `C:\Windows\System32\svchost.exe`, ParentPID: 4,
				User: "NT AUTHORITY\\SYSTEM", Started: "2026-03-04T06:40:13Z", Evidence: "ev-mem"},
			{PID: 4200, Name: "explorer.exe", Path: `C:\Windows\explorer.exe`, ParentPID: 824,
				User: "CORP\\mansi", Started: "2026-03-04T07:01:00Z", Evidence: "ev-mem"},
			{PID: 5244, Name: "winword.exe", Path: `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`,
				ParentPID: 4200, User: "CORP\\mansi", Started: "2026-03-04T08:10:00Z", Evidence: "ev-mem",
				Note: "opened the phishing attachment (benign context control)"},
			{PID: 4244, Name: "svchost_.exe", Path: `C:\Users\mansi\AppData\Local\Temp\svchost_.exe`,
				ParentPID: 5244, ParentName: "winword.exe", User: "CORP\\mansi",
				Started: "2026-03-04T08:11:00Z", Network: true, Evidence: "ev-mem",
				Note: "masquerading service binary spawned by a document process"},
			{PID: 880, Name: "powershell.exe", Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				ParentPID: 6512, ParentName: "w3wp.exe", User: "CORP\\webapps",
				Started: "2026-03-04T08:41:00Z", Network: true, Evidence: "ev-mem",
				Command: "powershell.exe -enc aWMgbmV0d29yayBzY2FubmVyIGRvd25sb2Fk",
				Note:    "encoded command launched from the IIS worker process"},
			{PID: 6512, Name: "w3wp.exe", Path: `C:\Windows\System32\inetsrv\w3wp.exe`,
				ParentPID: 4244, User: "CORP\\webapps", Started: "2026-03-04T08:37:00Z", Evidence: "ev-mem",
				Note: "IIS worker - process tree anomaly with svchost_.exe"},
			{PID: 909, Name: "mimikatz.exe", Path: `C:\Users\mansi\AppData\Local\Temp\mimikatz.exe`,
				ParentPID: 4244, User: "CORP\\mansi", Started: "2026-03-04T08:19:00Z", Evidence: "ev-mem",
				Note: "credential dumper toolkit present in the incident window"},
			{PID: 1132, Name: "winupdate.scr", Path: `C:\Users\mansi\AppData\Local\Temp\winupdate.scr`,
				ParentPID: 5244, User: "CORP\\mansi", Started: "2026-03-04T08:12:00Z", Evidence: "ev-mem",
				Note: "screensaver-titled payload matching autorun value"},
		},
		Logs: []LogEntry{
			{ID: "LG-1", Source: "evtx", Channel: "Security", EventID: 4625, Level: "warning",
				Timestamp: "2026-03-04T03:24:11Z", User: "CORP\\Administrator",
				SourceIP: "172.16.14.207", Detail: "failed logon, password mismatch (5th)", Evidence: "ev-logs"},
			{ID: "LG-2", Source: "evtx", Channel: "Security", EventID: 4624, Level: "info",
				Timestamp: "2026-03-04T02:37:00Z", User: "CORP\\webapps", SourceIP: "10.20.3.90",
				Detail: "rdp logon at 02:37 over baseline window", Evidence: "ev-logs"},
			{ID: "LG-3", Source: "evtx", Channel: "Security", EventID: 4648, Level: "warning",
				Timestamp: "2026-03-04T03:27:00Z", User: "CORP\\mansi", SourceIP: "10.20.3.90",
				Detail: "logon attempted with explicit credentials", Evidence: "ev-logs"},
			{ID: "LG-4", Source: "evtx", Channel: "Security", EventID: 4740, Level: "warning",
				Timestamp: "2026-03-04T03:25:00Z", User: "CORP\\mansi",
				Detail: "account locked out after repeated failures", Evidence: "ev-logs"},
			{ID: "LG-5", Source: "evtx", Channel: "System", EventID: 7045, Level: "warning",
				Timestamp: "2026-03-04T03:42:00Z", User: "SYSTEM",
				Detail: "service W32TimeSvc installed with binary in Temp", Evidence: "ev-logs"},
			{ID: "LG-6", Source: "evtx", Channel: "Security", EventID: 4698, Level: "info",
				Timestamp: "2026-03-04T03:44:00Z", User: "CORP\\mansi",
				Detail: "scheduled task CorpHealthCheck created", Evidence: "ev-logs"},
			{ID: "LG-7", Source: "evtx", Channel: "Microsoft-Windows-PowerShell/Operational", EventID: 4104,
				Level: "warning", Timestamp: "2026-03-04T08:42:00Z", User: "CORP\\webapps",
				Detail: "script block logging captured encoded command", Evidence: "ev-logs"},
			{ID: "LG-8", Source: "sysmon", Channel: "Microsoft-Windows-Sysmon/Operational", EventID: 1,
				Level: "info", Timestamp: "2026-03-04T08:11:00Z", User: "CORP\\mansi",
				Detail: "process creation svchost_.exe (child of winword)", Evidence: "ev-logs"},
			{ID: "LG-9", Source: "sysmon", Channel: "Microsoft-Windows-Sysmon/Operational", EventID: 3,
				Level: "warning", Timestamp: "2026-03-04T08:13:00Z", User: "CORP\\mansi",
				DestIP: "45.129.96.27", Detail: "network connection svchost_.exe -> 45.129.96.27:443", Evidence: "ev-logs"},
			{ID: "LG-10", Source: "evtx", Channel: "Security", EventID: 4688, Level: "info",
				Timestamp: "2026-03-04T08:19:00Z", User: "CORP\\mansi",
				Detail: "process creation mimikatz.exe in temp directory", Evidence: "ev-logs"},
			{ID: "LG-11", Source: "evtx", Channel: "Security", EventID: 4624, Level: "info",
				Timestamp: "2026-03-04T03:29:00Z", User: "CORP\\Administrator", SourceIP: "172.16.14.207",
				Detail: "successful logon following the failure storm", Evidence: "ev-logs"},
		},
		Timeline: []Timeline{
			{Timestamp: "2026-03-04T06:40:00Z", Category: "acquisition", Action: "system.boot", Subject: "boot", Detail: "corp-ws-0427 booted"},
			{Timestamp: "2026-03-04T07:01:00Z", Category: "logon", Action: "logon.interactive", Subject: "mansi", Detail: "console logon"},
			{Timestamp: "2026-03-04T08:10:00Z", Category: "process", Action: "process.start", Subject: "winword.exe", Detail: "opened phishing attachment"},
			{Timestamp: "2026-03-04T08:11:00Z", Category: "process", Action: "process.start", Subject: "svchost_.exe", Detail: "masquerade binary from temp"},
			{Timestamp: "2026-03-04T08:12:00Z", Category: "process", Action: "process.start", Subject: "winupdate.scr", Detail: "autorun payload"},
			{Timestamp: "2026-03-04T08:13:00Z", Category: "network", Action: "network.outbound", Subject: "45.129.96.27:443", Detail: "c2 endpoint contact"},
			{Timestamp: "2026-03-04T08:19:00Z", Category: "process", Action: "process.start", Subject: "mimikatz.exe", Detail: "credential toolkit"},
			{Timestamp: "2026-03-04T08:37:00Z", Category: "process", Action: "process.start", Subject: "w3wp.exe", Detail: "iis worker with anomalous parent"},
			{Timestamp: "2026-03-04T08:41:00Z", Category: "process", Action: "process.start", Subject: "powershell.exe", Detail: "encoded command under w3wp"},
			{Timestamp: "2026-03-04T08:42:00Z", Category: "logon", Action: "script.block", Subject: "powershell", Detail: "encoded block executed"},
			{Timestamp: "2026-03-04T09:30:00Z", Category: "registry", Action: "autorun.modified", Subject: "WindowsUpdateCheck", Detail: "autorun added"},
			{Timestamp: "2026-03-04T09:40:00Z", Category: "artifact", Action: "webshell.dropped", Subject: "shell.aspx", Detail: "web root modification"},
			{Timestamp: "2026-03-04T10:00:00Z", Category: "filesystem", Action: "file.restored", Subject: "$RYQ9W2C.exe", Detail: "recycle bin restore"},
			{Timestamp: "2026-03-05T06:40:00Z", Category: "acquisition", Action: "evidence.acquired", Subject: "disk image", Detail: "write-blocked duplicate"},
		},
		Indicators: []Indicator{
			{Kind: "sha256", Value: "f2c0a5b1c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef2",
				Confidence: "confirmed", Attribution: "simulated apt-2026-03", Description: "svchost_.exe payload hash"},
			{Kind: "domain", Value: "updates-check.io", Confidence: "high", Attribution: "simulated",
				Description: "c2 panel domain"},
			{Kind: "domain", Value: "cloud-sync.online", Confidence: "medium", Attribution: "simulated",
				Description: "exfil staging domain"},
			{Kind: "ip", Value: "45.129.96.27", Confidence: "high", Attribution: "simulated",
				Description: "c2 endpoint"},
			{Kind: "ip", Value: "172.16.14.207", Confidence: "low", Attribution: "simulated",
				Description: "internal failure-storm source"},
			{Kind: "filename", Value: "svchost_.exe", Confidence: "high", Attribution: "simulated",
				Description: "masquerading binary name"},
			{Kind: "filename", Value: "winupdate.scr", Confidence: "high", Attribution: "simulated",
				Description: "autorun payload name"},
			{Kind: "filename", Value: "sysmon_legit.bin.exe", Confidence: "high", Attribution: "simulated",
				Description: "double-extension service binary"},
			{Kind: "registry_key", Value: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateCheck`,
				Confidence: "high", Attribution: "simulated", Description: "persistence autorun key"},
			{Kind: "mutex", Value: "Global\\UPD-CK-MUTEX", Confidence: "medium", Attribution: "simulated",
				Description: "c2 mutex observed in memory"},
			{Kind: "command", Value: "powershell -enc", Confidence: "high", Attribution: "simulated",
				Description: "encoded powershell invocation"},
		},
	}
	normalize(s)
	return s
}

// TimestampedLabel appends a timestamp so generated example files are
// distinguishable; the dataset itself stays deterministic.
func TimestampedLabel(c *Case, now time.Time) {
	if now.IsZero() {
		return
	}
	c.Label = c.Label + " @" + now.UTC().Format("2006-01-02T15:04:05Z")
}
