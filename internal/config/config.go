// Package config loads and exposes assessment configuration. Configuration
// comes from a YAML file, the QYVORA_TIMBUKTU_* environment namespace, and
// safe defaults, in that order of precedence.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

const appName = "qyvora-timbuktu"

// Profile names select the depth/width of a cloud assessment run.
const (
	ProfileQuick    = "quick"
	ProfileStandard = "standard"
	ProfileDeep     = "deep"
)

// Profiles lists every supported profile in documentation order.
var Profiles = []string{ProfileQuick, ProfileStandard, ProfileDeep}

// IsValidProfile reports whether name is a known profile.
func IsValidProfile(name string) bool {
	for _, p := range Profiles {
		if p == name {
			return true
		}
	}
	return false
}

// Load builds a viper configuration from a config file (when given), the
// QYVORA_TIMBUKTU_* environment namespace, and defaults. A missing config file
// is not an error; a malformed one is.
func Load(cfgFile string) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")

	for _, dir := range configSearchDirs(cfgFile) {
		v.AddConfigPath(dir)
	}

	v.SetEnvPrefix("QYVORA_TIMBUKTU")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	v.SetDefault("profile", ProfileStandard)
	v.SetDefault("output", "terminal")
	v.SetDefault("verbose", false)
	v.SetDefault("quiet", false)
	v.SetDefault("json", false)
	v.SetDefault("authorized", false)
	v.SetDefault("report.dir", "reports")
	v.SetDefault("report.format", "terminal")
	v.SetDefault("log.level", "info")
	v.SetDefault("session.dir", "")
	v.SetDefault("target.state", defaultTargetState())

	// Analysis layer defaults.
	v.SetDefault("analysis.max_assets", 10000)
	v.SetDefault("analysis.max_evidence_bytes", 1048576)
	v.SetDefault("analysis.live_acquisition_contact", false)
	v.SetDefault("analysis.timeline_enabled", true)
	v.SetDefault("analysis.log_analysis_enabled", true)
	v.SetDefault("analysis.memory_analysis_enabled", true)
	v.SetDefault("analysis.indicator_scan_enabled", true)
	v.SetDefault("analysis.hash_verification_enabled", true)
	v.SetDefault("analysis.secret_scan_enabled", true)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}
	return v, nil
}

// Profile returns the configured profile name, validated against the known
// set.
func Profile(v *viper.Viper) (string, error) {
	p := v.GetString("profile")
	if !IsValidProfile(p) {
		return "", fmt.Errorf("unknown profile %q (valid: %s)", p, strings.Join(Profiles, ", "))
	}
	return p, nil
}

// MaxAssets returns the configured cap on assets analyzed per run.
func MaxAssets(v *viper.Viper) int {
	n := v.GetInt("analysis.max_assets")
	if n <= 0 {
		return 10000
	}
	return n
}

// SecretScanEnabled reports whether secret detection is on.
func SecretScanEnabled(v *viper.Viper) bool { return v.GetBool("analysis.secret_scan_enabled") }

// TimelineEnabled reports whether timeline construction is on.
func TimelineEnabled(v *viper.Viper) bool { return v.GetBool("analysis.timeline_enabled") }

// LogAnalysisEnabled reports whether log analysis is on.
func LogAnalysisEnabled(v *viper.Viper) bool { return v.GetBool("analysis.log_analysis_enabled") }

// defaultTargetState returns the default on-disk target-manager state path.
func defaultTargetState() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "qyvora", "timbuktu", "targets.json")
}

func configSearchDirs(cfgFile string) []string {
	dirs := []string{"."}

	if cfgFile != "" {
		if info, err := os.Stat(cfgFile); err == nil && info.IsDir() {
			dirs = append(dirs, cfgFile)
		} else {
			dirs = append(dirs, filepath.Dir(cfgFile))
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "."+appName))
		dirs = append(dirs, filepath.Join(home, ".config", "qyvora", "timbuktu"))
	}

	dirs = append(dirs, filepath.Join("/etc", appName))
	return dirs
}
