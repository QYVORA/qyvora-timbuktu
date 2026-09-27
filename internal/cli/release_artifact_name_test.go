package cli

import "testing"

// TestReleaseArtifactName pins the release asset naming contract.
//
// The same names are produced by three independent places that can drift
// apart: the release workflow (.github/workflows/release.yml), install.sh, and
// this updater. When they disagree the updater downloads a 404 and the user is
// told to reinstall by hand, so the mapping is asserted here rather than left
// to inspection.
//
// The cases that have actually been wrong in this ecosystem:
//
//   - macOS assets are published as "macos", but Go reports GOOS "darwin".
//     Using GOOS directly requested ".../imhotep_darwin_arm64", which no
//     release has ever published.
//   - Android/Termux is its own target. GOOS is "android" for a GOOS=android
//     build, and the asset is published as "{tool}-android-arm64". A
//     linux/arm64 asset must never be substituted: Android's bionic linker
//     rejects an ET_EXEC binary with "unexpected e_type: 2".
//   - The updater writes the downloaded bytes straight to the executable path,
//     so the asset must be the bare binary and never a tarball or zip. Naming
//     an archive here produced a "successful" update that replaced the binary
//     with a compressed file.
func TestReleaseArtifactName(t *testing.T) {
	tests := []struct {
		goos, goarch, want string
	}{
		{"linux", "amd64", "timbuktu-linux-amd64"},
		{"linux", "arm64", "timbuktu-linux-arm64"},
		{"darwin", "amd64", "timbuktu-macos-amd64"},
		{"darwin", "arm64", "timbuktu-macos-arm64"},
		{"windows", "amd64", "timbuktu-windows-amd64.exe"},
		{"windows", "arm64", "timbuktu-windows-arm64.exe"},
		{"android", "arm64", "timbuktu-android-arm64"},
	}

	for _, tt := range tests {
		if got := releaseArtifactName(tt.goos, tt.goarch); got != tt.want {
			t.Errorf("releaseArtifactName(%q, %q) = %q, want %q", tt.goos, tt.goarch, got, tt.want)
		}
	}
}

// TestReleaseArtifactNameIsNeverAnArchive guards the specific failure mode of
// an update that "succeeds" and leaves an unrunnable binary behind.
func TestReleaseArtifactNameIsNeverAnArchive(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows", "android"} {
		name := releaseArtifactName(goos, "arm64")
		for _, bad := range []string{".tar.gz", ".tgz", ".zip", ".tar"} {
			if len(name) >= len(bad) && name[len(name)-len(bad):] == bad {
				t.Errorf("releaseArtifactName(%q, \"arm64\") = %q, which names an archive; "+
					"the updater installs these bytes as the executable directly", goos, name)
			}
		}
	}
}
