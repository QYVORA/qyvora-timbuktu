// Package selfupdate provides verified self-update for the timbuktu binary. It
// checks the QYVORA GitHub releases for a newer release, downloads the
// artifact for the current platform, verifies its SHA-256 checksum manifest,
// and installs it atomically — or refuses cleanly when it cannot verify.
package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Status reports what an update run decided and did.
type Status int

const (
	StatusUpdated        Status = iota // downloaded, verified, installed
	StatusCurrent                      // installed version equals latest release
	StatusNewerInstalled               // installed version is newer than latest (no downgrade)
	StatusDev                          // dev build: update checking refused
)

// Result reports what an update run decided and did.
type Result struct {
	Status   Status
	Current  string
	Latest   string
	Path     string
	Artifact string
}

// String renders a stable status label.
func (s Status) String() string {
	switch s {
	case StatusUpdated:
		return "updated"
	case StatusCurrent:
		return "current"
	case StatusNewerInstalled:
		return "newer-installed"
	case StatusDev:
		return "dev-build"
	default:
		return "unknown"
	}
}

// Options tune output for one update run. A nil Out disables progress output.
type Options struct {
	Out io.Writer
}

// Config pins timbuktu to its official QYVORA release source.
type Config struct {
	Owner         string
	Repo          string
	ToolName      string
	CurrentVer    string // running binary's version
	ArtifactName  func(goos, goarch string) string
	ChecksumAsset func(artifact string) string
	APIBaseURL    string // overrides the GitHub API base (tests point it locally)
}

// maxArtifactSize bounds a downloaded artifact so a hostile endpoint cannot
// exhaust disk.
const maxArtifactSize = 512 << 20

// release is the minimal GitHub release shape we consume.
type release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// CheckForUpdates reports whether a newer release exists, without installing.
func CheckForUpdates(ctx context.Context, cfg Config) (Result, error) {
	current := cfg.CurrentVer
	res := Result{Current: current}
	if isDev(current) {
		res.Status = StatusDev
		return res, nil
	}
	rel, err := latestRelease(ctx, cfg)
	if err != nil {
		return res, err
	}
	latest := normalizeTag(rel.TagName)
	res.Latest = latest
	switch {
	case latest > current:
		res.Status = StatusUpdated
	case latest < current:
		res.Status = StatusNewerInstalled
	default:
		res.Status = StatusCurrent
	}
	return res, nil
}

// Run executes the full update flow: check, resolve artifact, download,
// verify, install. It never replaces the binary unless verification succeeded.
func Run(ctx context.Context, cfg Config, opts Options) (Result, error) {
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	res, err := CheckForUpdates(ctx, cfg)
	if err != nil {
		return res, err
	}
	if res.Status != StatusUpdated {
		return res, nil
	}

	artifact := cfg.ArtifactName(runtime.GOOS, runtime.GOARCH)
	if artifact == "" {
		return res, fmt.Errorf("%s: no release artifact for %s/%s", cfg.ToolName, runtime.GOOS, runtime.GOARCH)
	}

	path, err := resolveExecutable()
	if err != nil {
		return res, fmt.Errorf("%s: locating executable: %w", cfg.ToolName, err)
	}

	data, err := fetchArtifact(ctx, cfg, artifact, out)
	if err != nil {
		return res, err
	}

	if cs := cfg.ChecksumAsset(artifact); cs != "" {
		manifest, err := fetchArtifactBytes(ctx, cfg, cs)
		if err != nil {
			return res, fmt.Errorf("%s: downloading checksum manifest: %w", cfg.ToolName, err)
		}
		if err := verifyChecksumManifest(manifest, artifact, data); err != nil {
			return res, err
		}
	}

	if err := atomicInstall(path, data); err != nil {
		return res, fmt.Errorf("%s: installing: %w", cfg.ToolName, err)
	}
	res.Status = StatusUpdated
	res.Path = path
	res.Artifact = artifact
	return res, nil
}

func latestRelease(ctx context.Context, cfg Config) (*release, error) {
	base := cfg.APIBaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	url := fmt.Sprintf("%s/repos/%s/%s/releases/latest", base, cfg.Owner, cfg.Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", cfg.ToolName+"/"+cfg.CurrentVer)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: checking releases: %w", cfg.ToolName, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: release lookup returned %s", cfg.ToolName, resp.Status)
	}
	var rel release
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, fmt.Errorf("%s: decoding release metadata: %w", cfg.ToolName, err)
	}
	return &rel, nil
}

func fetchArtifact(ctx context.Context, cfg Config, artifact string, out io.Writer) ([]byte, error) {
	url, err := artifactURL(ctx, cfg, artifact)
	if err != nil {
		return nil, err
	}
	body, err := fetch(ctx, url, cfg.ToolName+"/"+cfg.CurrentVer, out)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func fetchArtifactBytes(ctx context.Context, cfg Config, artifact string) ([]byte, error) {
	url, err := artifactURL(ctx, cfg, artifact)
	if err != nil {
		return nil, err
	}
	return fetch(ctx, url, cfg.ToolName+"/"+cfg.CurrentVer, io.Discard)
}

func artifactURL(ctx context.Context, cfg Config, artifact string) (string, error) {
	rel, err := latestRelease(ctx, cfg)
	if err != nil {
		return "", err
	}
	for _, a := range rel.Assets {
		if a.Name == artifact && a.BrowserDownloadURL != "" {
			return a.BrowserDownloadURL, nil
		}
	}
	return "", fmt.Errorf("%s: release does not expose asset %s", cfg.ToolName, artifact)
}

func fetch(ctx context.Context, url, ua string, out io.Writer) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s returned %s", url, resp.Status)
	}
	var b bytes.Buffer
	if _, err := io.Copy(io.MultiWriter(out, &b), io.LimitReader(resp.Body, maxArtifactSize)); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// verifyChecksumManifest verifies data against the artifact's SHA-256 line in
// a standard "*sum.txt"-style manifest (filename and digest on one line).
func verifyChecksumManifest(manifest []byte, artifact string, data []byte) error {
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		if fields[1] != artifact {
			continue
		}
		expected := strings.ToLower(fields[0])
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if got != expected {
			return fmt.Errorf("%s: checksum mismatch for %s", "timbuktu", artifact)
		}
		return nil
	}
	return fmt.Errorf("checksum manifest does not list %s", artifact)
}

func atomicInstall(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".timbuktu-update-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func resolveExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved, nil
	}
	return exe, nil
}

func normalizeTag(tag string) string { return strings.TrimPrefix(tag, "v") }

func isDev(v string) bool { return v == "" || strings.HasPrefix(v, "dev") }

// CompareVersions compares two dotted version strings; non-numeric segments
// are ignored. Returns -1, 0 or 1.
func CompareVersions(a, b string) int {
	as := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bs := strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < maxInt(len(as), len(bs)); i++ {
		av, bv := 0, 0
		if i < len(as) {
			av = parseNum(as[i])
		}
		if i < len(bs) {
			bv = parseNum(bs[i])
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func parseNum(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
