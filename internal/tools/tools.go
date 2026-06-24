// Package tools provides availability detection for the external scanners
// cyberai shells out to. Centralizing this lets the orchestrator, the CLI,
// and the install command all agree on what's installed.
package tools

import (
	"fmt"
	"os/exec"
	"strings"
)

// Tool describes a scanner binary we may invoke.
type Tool struct {
	// Name is the canonical name used in cyberai output (e.g. "semgrep").
	Name string
	// Binary is the executable name looked up on $PATH.
	Binary string
	// Category maps to model.Category: sast, secrets, sca, iac, license.
	Category string
	// Install is a one-line human install hint shown by `tools list`.
	Install string
	// MinVersion (optional) is the minimum version we support; empty = any.
	MinVersion string
}

// All lists every scanner cyberai can use, in stable order.
func All() []Tool {
	return []Tool{
		{
			Name: "semgrep", Binary: "semgrep",
			Category: "sast",
			Install:  "pip install semgrep",
		},
		{
			Name: "gitleaks", Binary: "gitleaks",
			Category: "secrets",
			Install:  "brew install gitleaks OR go install github.com/gitleaks/gitleaks/v8@latest",
		},
		{
			Name: "trivy", Binary: "trivy",
			Category: "sca",
			Install:  "brew install trivy OR https://aquasecurity.github.io/trivy/",
		},
		{
			Name: "checkov", Binary: "checkov",
			Category: "iac",
			Install:  "cyberai tools install checkov OR pipx install checkov",
		},
		{
			Name: "hadolint", Binary: "hadolint",
			Category: "docker",
			Install:  "cyberai tools install hadolint OR brew install hadolint",
		},
		{
			Name: "zizmor", Binary: "zizmor",
			Category: "cicd",
			Install:  "cyberai tools install zizmor OR pipx install zizmor",
		},
	}
}

// Status describes whether a tool is installed and what version it reports.
type Status struct {
	Installed bool
	Version   string
	Path      string
}

// Probe checks whether binary is on $PATH and tries to read its version.
// Returns Installed=false if not found. If found, Version is the first
// non-empty line of `<binary> --version` (trimmed).
func Probe(binary string) Status {
	path, err := exec.LookPath(binary)
	if err != nil {
		return Status{Installed: false}
	}
	v, err := exec.Command(path, "--version").Output()
	if err != nil {
		// Found but --version failed — still report installed; version unknown.
		return Status{Installed: true, Version: "unknown", Path: path}
	}
	lines := strings.Split(string(v), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			return Status{Installed: true, Version: line, Path: path}
		}
	}
	return Status{Installed: true, Version: "unknown", Path: path}
}

// ProbeAll returns Status for every known tool.
func ProbeAll() map[string]Status {
	out := make(map[string]Status, len(All()))
	for _, t := range All() {
		out[t.Name] = Probe(t.Binary)
	}
	return out
}

// VersionLine returns a short, human-friendly version label, e.g. "1.45.0".
func (s Status) VersionLine() string {
	if !s.Installed {
		return "missing"
	}
	v := strings.TrimSpace(s.Version)
	// Pull first semver-looking token (e.g. "semgrep 1.45.0" -> "1.45.0").
	for _, tok := range strings.Fields(v) {
		if strings.HasPrefix(tok, "v") {
			tok = tok[1:]
		}
		if isSemverish(tok) {
			return tok
		}
	}
	return v
}

func isSemverish(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// MissingCategories returns the categories (sast/secrets/sca/...) for which
// no scanner is currently installed. Used by the orchestrator to warn when
// a category the user requested can't actually run.
func MissingCategories(want []string) []string {
	installed := make(map[string]bool)
	for name, st := range ProbeAll() {
		if st.Installed {
			for _, t := range All() {
				if t.Name == name {
					installed[t.Category] = true
				}
			}
		}
	}
	var missing []string
	for _, cat := range want {
		if !installed[cat] {
			missing = append(missing, cat)
		}
	}
	return missing
}

// String formats a tool status as "name: installed (version)" or "name: missing".
func (s Status) String(name string) string {
	if !s.Installed {
		return fmt.Sprintf("%s: missing", name)
	}
	return fmt.Sprintf("%s: installed (%s)", name, s.VersionLine())
}
