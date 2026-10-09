package cli

import (
	"strings"
	"testing"
)

// TestReleaseArtifactName pins the release asset naming contract.
//
// The same names are produced by three independent places that can drift
// apart: the release workflow (.github/workflows/release.yml), install.sh, and
// this updater. When they disagree the updater downloads a 404 and the user is
// told to reinstall by hand, so the mapping is asserted here.
//
// Canonical: timbuktu_<version>_<linux|macos|windows|android>_<arch>.tar.gz
// (zip on windows), where <version> is the tag with its leading "v" stripped.
func TestReleaseArtifactName(t *testing.T) {
	tests := []struct {
		version, goos, goarch, want string
	}{
		{"v0.1.0", "linux", "amd64", "timbuktu_0.1.0_linux_amd64.tar.gz"},
		{"v0.1.0", "linux", "arm64", "timbuktu_0.1.0_linux_arm64.tar.gz"},
		{"v0.1.0", "darwin", "amd64", "timbuktu_0.1.0_macos_amd64.tar.gz"},
		{"v0.1.0", "darwin", "arm64", "timbuktu_0.1.0_macos_arm64.tar.gz"},
		{"v0.1.0", "windows", "amd64", "timbuktu_0.1.0_windows_amd64.zip"},
		{"v0.1.0", "windows", "arm64", "timbuktu_0.1.0_windows_arm64.zip"},
		{"v0.1.0", "android", "arm64", "timbuktu_0.1.0_android_arm64.tar.gz"},
		{"0.1.0", "linux", "amd64", "timbuktu_0.1.0_linux_amd64.tar.gz"},
	}

	for _, tt := range tests {
		if got := releaseArtifactName(tt.version, tt.goos, tt.goarch); got != tt.want {
			t.Errorf("releaseArtifactName(%q, %q, %q) = %q, want %q",
				tt.version, tt.goos, tt.goarch, got, tt.want)
		}
	}
}

// TestReleaseArtifactNameStripsVersionPrefix guards the specific bug this
// contract exists for: leaving the "v" on produces a name no release published.
func TestReleaseArtifactNameStripsVersionPrefix(t *testing.T) {
	for _, tag := range []string{"v0.1.0", "V0.1.0", "0.1.0"} {
		got := releaseArtifactName(tag, "linux", "amd64")
		if strings.Contains(got, "_v0.1.0_") || strings.Contains(got, "_V0.1.0_") {
			t.Errorf("releaseArtifactName(%q, linux, amd64) = %q, kept the version prefix", tag, got)
		}
	}
}
