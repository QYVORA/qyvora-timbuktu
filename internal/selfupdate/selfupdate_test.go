package selfupdate_test

import (
	"testing"

	"github.com/QYVORA/qyvora-timbuktu/internal/selfupdate"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"v1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"0.9.9", "1.0.0", -1},
		{"1.10.0", "1.9.9", 1},
		{"2.0", "1.999.999", 1},
		{"1.0.0-alpha", "1.0.0", 0}, // non-numeric suffixes ignored
	}
	for _, c := range cases {
		if got := selfupdate.CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestStatusString(t *testing.T) {
	if got := selfupdate.StatusUpdated.String(); got != "updated" {
		t.Errorf("updated = %q", got)
	}
	if got := selfupdate.StatusDev.String(); got != "dev-build" {
		t.Errorf("dev = %q", got)
	}
}
