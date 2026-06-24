package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunScan_BareRepo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/x\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	buf := &bytes.Buffer{}
	cmd := NewRootCmd()
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"scan", dir, "--no-llm"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	out := buf.String()
	required := []string{
		"Scan complete",
		"target: " + dir,
		"router: default (default)",
		"terminal only",
		"no findings at or above the configured threshold",
	}
	for _, want := range required {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "{") {
			t.Fatalf("unexpected raw JSON summary line in default output:\n%s", out)
		}
	}
}

func TestRunScan_NoLLMOverridesCI(t *testing.T) {
	dir := t.TempDir()
	buf := &bytes.Buffer{}
	cmd := NewRootCmd()
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"scan", dir, "--ci"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	found := false
	for _, line := range strings.Split(buf.String(), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(line), &out); err != nil {
			t.Fatalf("bad JSON summary line %q: %v", line, err)
		}
		found = true
		if out["phase"] != "1.8-summarizer" {
			t.Errorf("phase = %v, want 1.8-summarizer", out["phase"])
		}
		if out["llm_enabled"] != false {
			t.Errorf("--ci should force LLM off, got llm_enabled = %v", out["llm_enabled"])
		}
		if out["target"] != dir {
			t.Errorf("target = %v, want %s", out["target"], dir)
		}
	}
	if !found {
		t.Fatalf("expected JSON summary in CI output:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "Scan complete") {
		t.Fatalf("did not expect pretty summary in CI output:\n%s", buf.String())
	}
}

func TestShouldInstallMissingTools_ExplicitOnly(t *testing.T) {
	cmd := NewRootCmd()
	if shouldInstallMissingTools(&scanOptions{}, cmd) {
		t.Fatal("missing scanner installs should require --install-missing")
	}
	if !shouldInstallMissingTools(&scanOptions{InstallMissing: true}, cmd) {
		t.Fatal("--install-missing should enable scanner installation")
	}
}

func TestRunScan_RejectsFileAsTarget(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"scan", f})
	if err := cmd.Execute(); err == nil {
		t.Error("expected error when target is a file")
	}
}

func TestRunScan_OnlyFlag(t *testing.T) {
	dir := t.TempDir()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := NewRootCmd()
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetArgs([]string{"scan", dir, "--no-llm", "--only", "secrets", "--save", "--summary", "off"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	reportPath := filepath.Join(dir, "cyberai-reports", "report.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var report struct {
		Scanners []struct {
			Tool string `json:"tool"`
		} `json:"scanners"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if len(report.Scanners) != 1 || report.Scanners[0].Tool != "gitleaks" {
		t.Fatalf("expected only gitleaks scanner, got %+v", report.Scanners)
	}
	if strings.Contains(stderr.String(), "trivy:") || strings.Contains(stderr.String(), "semgrep:") {
		t.Fatalf("unexpected scanner activity in stderr:\n%s", stderr.String())
	}
}
