// Package config loads .cyberai.yaml (or .cyberai.yml) from the project root
// and merges it with CLI flags. The config file is optional — cyberai runs
// with sensible defaults if it isn't present.
//
// Schema is intentionally small: scanner toggles, severity threshold, ignore
// patterns. Anything more dynamic (rulesets, target lists) is decided by the
// LLM router at scan time and *not* pinned in config; pinning it is the
// user's escape hatch for fully-deterministic behavior in CI.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/shfahiim/cyberai/internal/llm"
	"github.com/shfahiim/cyberai/internal/model"
)

// FileName is the config filename we look for at the project root.
const FileName = ".cyberai.yaml"

// FileNameAlt is the alternative spelling; both are accepted.
const FileNameAlt = ".cyberai.yml"

// Config is the in-memory representation of .cyberai.yaml.
type Config struct {
	// Scanners enabled by the user. Empty = "let the LLM router decide" (or
	// all scanners if --no-llm).
	Scanners []string `yaml:"scanners"`

	// DisabledScanners is the inverse list: tools to *never* run even if the
	// router wants them. Useful for noisy rules in monorepos.
	DisabledScanners []string `yaml:"disabled_scanners"`

	// SeverityThreshold filters findings below this level. "low" = show all.
	SeverityThreshold model.Severity `yaml:"severity_threshold"`

	// IgnorePatterns are globs (matched by doublestar or filepath.Match) that
	// suppress findings whose file path matches.
	IgnorePatterns []string `yaml:"ignore_patterns"`

	// Output controls report formats and the default output path.
	Output OutputConfig `yaml:"output"`

	// LLM holds LLM-related knobs. The router and summarizer read this.
	LLM LLMConfig `yaml:"llm"`

	// BaselinePath is the file to diff against. Empty = no baseline.
	BaselinePath string `yaml:"baseline"`

	// UI holds presentation knobs: color, progress, unicode glyphs.
	// All keys optional — missing ⇒ auto.
	UI UIConfig `yaml:"ui"`

	// Policies holds named gates that can fail a CI scan.
	Policies PoliciesConfig `yaml:"policies"`
}

// UIConfig controls terminal presentation. Empty values mean "auto".
type UIConfig struct {
	// Color: auto | always | never. Empty = auto.
	Color string `yaml:"color"`
	// Progress: auto | spinner | plain | off. Empty = auto.
	Progress string `yaml:"progress"`
	// Unicode: true / false. nil = auto (true when stderr is a TTY).
	Unicode *bool `yaml:"unicode"`
}

// OutputConfig is the report-related subset.
type OutputConfig struct {
	// Formats: sarif, json, markdown, html, terminal. Empty = all.
	Formats []string `yaml:"formats"`
	// Path is the output file or directory. For multi-format, this is a dir.
	Path string `yaml:"path"`
}

// LLMConfig is the LLM-related subset.
type LLMConfig struct {
	// Enabled overrides the --no-llm CLI flag. false = skip LLM entirely
	// (equivalent to --no-llm). nil = follow CLI flag.
	Enabled *bool `yaml:"enabled"`

	// Provider selects which LLM backend to use. Empty = use default.
	Provider string `yaml:"provider"`

	// Model overrides the default provider model. Empty = use provider default.
	Model string `yaml:"model"`

	// Summarize controls whether the post-scan summarizer runs.
	Summarize *bool `yaml:"summarize"`
}

// GateConfig is one policy gate entry from .cyberai.yaml.
type GateConfig struct {
	Name   string `yaml:"name"`
	FailOn string `yaml:"fail_on"`
}

// SLAConfig holds per-severity remediation SLA strings (e.g. "7d", "30d").
type SLAConfig struct {
	Critical string `yaml:"critical"`
	High     string `yaml:"high"`
	Medium   string `yaml:"medium"`
	Low      string `yaml:"low"`
}

// PoliciesConfig is the `policies:` block in .cyberai.yaml.
type PoliciesConfig struct {
	Gates []GateConfig `yaml:"gates"`
	SLA   SLAConfig    `yaml:"sla"`
}

// Default returns a Config with sensible defaults for a first run.
func Default() *Config {
	llmOff := false
	return &Config{
		Scanners:          nil,
		SeverityThreshold: model.SeverityLow,
		IgnorePatterns:    []string{},
		Output: OutputConfig{
			Formats: []string{"terminal"},
			Path:    "cyberai-reports",
		},
		LLM: LLMConfig{
			Enabled:   &llmOff,
			Provider:  llm.DefaultProvider,
			Model:     llm.ResolveModel(llm.DefaultProvider, ""),
			Summarize: nil,
		},
	}
}

// Load reads .cyberai.yaml from root, falling back to .cyberai.yml.
// If neither exists, returns Default() with no error. Other errors (parse,
// permission) are returned.
func Load(root string) (*Config, error) {
	cfg := Default()

	for _, name := range []string{FileName, FileNameAlt} {
		path := filepath.Join(root, name)
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		// Normalize defaults the YAML didn't override.
		cfg.applyDefaults()
		return cfg, nil
	}

	return cfg, nil
}

// applyDefaults fills in zero values that the user didn't explicitly set.
// Only call this on a Config that came from YAML.
func (c *Config) applyDefaults() {
	if c.SeverityThreshold == "" {
		c.SeverityThreshold = model.SeverityLow
	}
	if c.LLM.Provider == "" {
		c.LLM.Provider = llm.DefaultProvider
	}
	if c.LLM.Model == "" {
		c.LLM.Model = llm.ResolveModel(c.LLM.Provider, "")
	}
	if len(c.Output.Formats) == 0 {
		c.Output.Formats = []string{"terminal"}
	}
	if c.Output.Path == "" {
		c.Output.Path = "cyberai-reports"
	}
	if c.UI.Color == "" {
		c.UI.Color = "auto"
	}
	if c.UI.Progress == "" {
		c.UI.Progress = "auto"
	}
	// UI.Unicode is *bool — nil means auto, no defaulting needed.
}

// IsScannerEnabled returns true if the named scanner (e.g. "sast", "secrets")
// should run, given the user's Scanners and DisabledScanners lists.
//
// - If Scanners is non-empty, the scanner must be in it.
// - If DisabledScanners contains the scanner, it's off regardless.
// - "all" in Scanners means enable every category.
func (c *Config) IsScannerEnabled(name string) bool {
	for _, d := range c.DisabledScanners {
		if d == name {
			return false
		}
	}
	if len(c.Scanners) == 0 {
		return true // no explicit list = all on
	}
	for _, s := range c.Scanners {
		if s == "all" || s == name {
			return true
		}
	}
	return false
}

// LLMEnabled returns whether the LLM should run, given config + CLI override.
//
// Precedence (highest first): CLI override (if non-nil), LLMConfig.Enabled
// (if non-nil), default (false).
func (c *Config) LLMEnabled(cliOverride *bool) bool {
	if cliOverride != nil {
		return *cliOverride
	}
	if c.LLM.Enabled != nil {
		return *c.LLM.Enabled
	}
	return false
}

// SummarizerEnabled mirrors LLMEnabled but for the summarizer specifically.
// The summarizer is off in --ci mode regardless of config.
func (c *Config) SummarizerEnabled(cliOverride *bool, ciMode bool) bool {
	if ciMode {
		return false
	}
	if cliOverride != nil {
		return *cliOverride
	}
	if c.LLM.Summarize != nil {
		return *c.LLM.Summarize
	}
	return true
}

// ShouldIgnorePath returns true if any ignore pattern matches the given path.
// Patterns are matched with filepath.Match (glob, no doublestar).
// A pattern of "**/foo/**" is supported by translating it to a prefix match.
func (c *Config) ShouldIgnorePath(path string) bool {
	for _, pat := range c.IgnorePatterns {
		if matchPattern(pat, path) {
			return true
		}
	}
	return false
}

// matchPattern supports both standard globs ("*.go", "test/*") and the
// doublestar convention ("**/node_modules/**", "**/*.test.go"). We translate
// doublestar patterns into "match the inner glob anywhere in the path".
func matchPattern(pat, path string) bool {
	// "**/<dir>/**" — match any path containing <dir>
	if hasPrefix(pat, "**/") && hasSuffix(pat, "/**") {
		inner := pat[3 : len(pat)-3]
		// treat inner as a glob, not a literal (in case it has globs)
		return matchAnySegment(inner, path)
	}
	// "**/<glob>" — match <glob> against any path component
	if hasPrefix(pat, "**/") {
		inner := pat[3:]
		// try matching the glob against the full path and each path component
		if matchGlob(inner, path) {
			return true
		}
		// also try matching the suffix of the path
		for i := 0; i < len(path); i++ {
			if path[i] == '/' && matchGlob(inner, path[i+1:]) {
				return true
			}
		}
		// also match the basename
		for i := len(path) - 1; i >= 0; i-- {
			if path[i] == '/' {
				if matchGlob(inner, path[i+1:]) {
					return true
				}
				break
			}
		}
		return false
	}
	// "<dir>/**" — match any nested path under <dir>
	if hasSuffix(pat, "/**") {
		prefix := pat[:len(pat)-3]
		return hasPrefix(path, prefix+"/") || contains(path, "/"+prefix+"/")
	}
	ok, err := filepath.Match(pat, path)
	if err != nil {
		return false
	}
	return ok
}

// matchAnySegment checks if a path contains a component matching the glob.
// Used for "**/<dir>/**" semantics.
func matchAnySegment(glob, path string) bool {
	// Walk components of path
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '/' {
			if i > start {
				if matchGlob(glob, path[start:i]) {
					return true
				}
			}
			start = i + 1
		}
	}
	// Also try the full path
	return matchGlob(glob, path)
}

// matchGlob wraps filepath.Match with a fallback for ** in the middle.
func matchGlob(pat, s string) bool {
	ok, err := filepath.Match(pat, s)
	if err == nil {
		return ok
	}
	return false
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	// Avoid importing strings just for this — simple O(n*m) is fine for the
	// patterns we deal with.
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// WriteExample writes a documented example config to path. Used by
// `cyberai init` and in tests.
func WriteExample(path string) error {
	example := `# cyberai config — all keys optional. Uncomment to override defaults.

# scanners enabled by you. Empty = router decides (or all if --no-llm).
# Valid: sast, secrets, sca, iac, license, docker, cicd
# scanners:
#   - sast
#   - secrets

# scanners to never run, even if the router wants them
# disabled_scanners:
#   - license

# Only show findings at or above this severity.
# Valid: critical, high, medium, low, info
# severity_threshold: low

# Suppress findings whose file matches any of these globs.
# Supports ** (doublestar) and standard globs.
# ignore_patterns:
#   - "**/node_modules/**"
#   - "**/vendor/**"
#   - "**/*.test.go"

# Output formats and path. Formats: sarif, json, markdown, html, terminal.
# output:
#   formats: [sarif, json, markdown, html, terminal]
#   path: cyberai-reports

# LLM knobs. The router decides which scanners to run; the summarizer
# writes an executive summary for the HTML report.
# llm:
#   enabled: true
#   provider: gemini
#   model: gemini-3.5-flash
#   summarize: true

# Path to a baseline JSON to diff against. Empty = no baseline.
# baseline: ""

# UI presentation knobs. All keys optional; missing ⇒ auto.
# color:    auto | always | never     (also honors NO_COLOR env and --no-color flag)
# progress: auto | spinner | plain | off
# unicode:  true | false              (auto = on when stderr is a TTY)
# ui:
#   color: auto
#   progress: spinner
#   unicode: true
`
	return os.WriteFile(path, []byte(example), 0o644)
}
