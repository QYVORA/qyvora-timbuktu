package forensics

import (
	"fmt"
	"testing"
)

// benchmarkCaseForTimeline builds a case with n files (created+modified),
// n/reportGranularity processes and n/2 log lines so BuildTimeline has a
// multi-entry per artifact input set.
func benchmarkCaseForTimeline(n int) *Case {
	c := &Case{}
	vol := Volume{ID: "vol-1", Name: "C", FSType: "ntfs", Mounted: true}
	for i := 0; i < n; i++ {
		vol.Files = append(vol.Files, File{
			Path:     fmt.Sprintf(`C:\Users\u\docs\file_%d.txt`, i),
			Name:     fmt.Sprintf("file_%d.txt", i),
			Created:  fmt.Sprintf("2026-03-04T06:00:%02dZ", i%60),
			Modified: fmt.Sprintf("2026-03-04T06:30:%02dZ", i%60),
		})
	}
	c.Volumes = append(c.Volumes, vol)
	for i := 0; i < n/4; i++ {
		c.Processes = append(c.Processes, Process{
			PID: i, Name: fmt.Sprintf("proc_%d.exe", i), Path: `C:\Windows\System32\p.exe`,
			Started: fmt.Sprintf("2026-03-04T07:%02d:%02dZ", i/60, i%60),
		})
	}
	for i := 0; i < n/4; i++ {
		c.Logs = append(c.Logs, LogEntry{
			ID: fmt.Sprintf("l-%d", i), EventID: 4624, Channel: "Security",
			Timestamp: fmt.Sprintf("2026-03-04T08:%02d:%02dZ", i/60, i%60),
		})
	}
	return c
}

func BenchmarkBuildTimeline1k(b *testing.B) {
	c := benchmarkCaseForTimeline(1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if tl := BuildTimeline(c); len(tl) == 0 {
			b.Fatal("empty timeline")
		}
	}
}

func BenchmarkBuildTimeline10k(b *testing.B) {
	c := benchmarkCaseForTimeline(10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if tl := BuildTimeline(c); len(tl) == 0 {
			b.Fatal("empty timeline")
		}
	}
}

func BenchmarkTimelineGap(b *testing.B) {
	c := benchmarkCaseForTimeline(5000)
	tl := BuildTimeline(c)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, at := TimelineGap(tl); at == "" {
			b.Fatal("expected a gap location")
		}
	}
}
