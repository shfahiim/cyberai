package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	c := Default()
	if c.SeverityThreshold != "low" {
		t.Errorf("default severity threshold = %q, want low", c.SeverityThreshold)
	}
	if c.LLM.Model != "gemini-2.5-flash" {
		t.Errorf("default model = %q, want gemini-2.5-flash", c.LLM.Model)
	}
}

func TestLoad_NoFile(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.SeverityThreshold != "low" {
		t.Errorf("expected default severity, got %q", c.SeverityThreshold)
	}
}

func TestLoad_YAML(t *testing.T) {
	dir := t.TempDir()
	yaml := `
scanners: [sast, secrets]
severity_threshold: high
ignore_patterns:
  - "**/node_modules/**"
  - "**/*.test.go"
output:
  formats: [json, html]
  path: /tmp/reports
llm:
  enabled: false
  model: gemini-2.5-pro
ui:
  color: never
  progress: off
  unicode: false
`
	if err := os.WriteFile(filepath.Join(dir, ".cyberai.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.SeverityThreshold != "high" {
		t.Errorf("severity_threshold = %q, want high", c.SeverityThreshold)
	}
	if len(c.Scanners) != 2 || c.Scanners[0] != "sast" {
		t.Errorf("scanners = %v", c.Scanners)
	}
	if c.LLM.Model != "gemini-2.5-pro" {
		t.Errorf("model = %q", c.LLM.Model)
	}
	if c.LLM.Enabled == nil || *c.LLM.Enabled != false {
		t.Errorf("llm.enabled = %v, want false", c.LLM.Enabled)
	}
	if c.Output.Path != "/tmp/reports" {
		t.Errorf("output.path = %q", c.Output.Path)
	}
	if c.UI.Color != "never" {
		t.Errorf("ui.color = %q, want never", c.UI.Color)
	}
	if c.UI.Progress != "off" {
		t.Errorf("ui.progress = %q, want off", c.UI.Progress)
	}
	if c.UI.Unicode == nil || *c.UI.Unicode != false {
		t.Errorf("ui.unicode = %v, want false", c.UI.Unicode)
	}
}

func TestLoad_UI_DefaultsApplied(t *testing.T) {
	dir := t.TempDir()
	// No ui: block at all — defaults should be filled in.
	yaml := "scanners: [sast]\n"
	if err := os.WriteFile(filepath.Join(dir, ".cyberai.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.UI.Color != "auto" {
		t.Errorf("ui.color default = %q, want auto", c.UI.Color)
	}
	if c.UI.Progress != "auto" {
		t.Errorf("ui.progress default = %q, want auto", c.UI.Progress)
	}
	if c.UI.Unicode != nil {
		t.Errorf("ui.unicode default = %v, want nil (auto)", c.UI.Unicode)
	}
}

func TestLoad_AltYML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".cyberai.yml"), []byte("severity_threshold: medium\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.SeverityThreshold != "medium" {
		t.Errorf("severity_threshold = %q, want medium", c.SeverityThreshold)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".cyberai.yaml"), []byte("scanners: [unclosed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestIsScannerEnabled(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		scanner string
		enabled bool
	}{
		{"empty list enables all", Config{}, "sast", true},
		{"in allowed list", Config{Scanners: []string{"sast", "secrets"}}, "sast", true},
		{"not in allowed list", Config{Scanners: []string{"sast"}}, "iac", false},
		{"disabled overrides", Config{Scanners: []string{"all"}, DisabledScanners: []string{"iac"}}, "iac", false},
		{"disabled without explicit list", Config{DisabledScanners: []string{"license"}}, "license", false},
		{"all keyword enables any", Config{Scanners: []string{"all"}}, "iac", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.IsScannerEnabled(tc.scanner); got != tc.enabled {
				t.Errorf("IsScannerEnabled(%q) = %v, want %v", tc.scanner, got, tc.enabled)
			}
		})
	}
}

func TestLLMEnabled_Precedence(t *testing.T) {
	tru := true
	fal := false

	// CLI override beats config
	c := Config{LLM: LLMConfig{Enabled: &tru}}
	if c.LLMEnabled(&fal) {
		t.Error("CLI override (false) should beat config (true)")
	}
	if !c.LLMEnabled(&tru) {
		t.Error("CLI override (true) should beat config (true)")
	}

	// No CLI override → use config
	c2 := Config{LLM: LLMConfig{Enabled: &fal}}
	if c2.LLMEnabled(nil) {
		t.Error("config (false) should be used when no CLI override")
	}

	// Both unset → default true
	c3 := Config{}
	if !c3.LLMEnabled(nil) {
		t.Error("default should be enabled when nothing set")
	}
}

func TestSummarizerEnabled_CIAlwaysOff(t *testing.T) {
	tru := true
	c := Config{LLM: LLMConfig{Summarize: &tru}}
	if c.SummarizerEnabled(nil, true) {
		t.Error("--ci should force summarizer off")
	}
	if !c.SummarizerEnabled(nil, false) {
		t.Error("summarizer should be on when ciMode=false and config says true")
	}
}

func TestShouldIgnorePath(t *testing.T) {
	c := &Config{IgnorePatterns: []string{
		"**/node_modules/**",
		"**/vendor/**",
		"**/*.test.js",
		"**/dist/**",
		"build/*",
	}}
	cases := []struct {
		path string
		want bool
	}{
		{"src/foo.go", false},
		{"node_modules/lodash/index.js", true},
		{"packages/web/node_modules/x.js", true},
		{"vendor/lib.go", true},
		{"pkg/foo.test.js", true},
		{"build/output.bin", true},
		{"build/nested/file", false}, // build/* doesn't recurse
		{"dist/bundle.js", true},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := c.ShouldIgnorePath(tc.path); got != tc.want {
				t.Errorf("ShouldIgnorePath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestWriteExample(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".cyberai.yaml")
	if err := WriteExample(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Error("example file is empty")
	}
	// Re-load what we wrote
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("Load after WriteExample: %v", err)
	}
	if c.SeverityThreshold != "low" {
		t.Errorf("example should preserve default severity, got %q", c.SeverityThreshold)
	}
}
