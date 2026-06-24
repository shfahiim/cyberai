// Package model defines the unified Finding schema that every scanner
// normalizes into. Reports (SARIF / JSON / HTML / Markdown) all consume this
// type; nothing else does.
//
// The schema is intentionally tool-agnostic: it carries what a security
// report needs (where, what, how bad, how to fix) and nothing scanner-specific.
// Per-tool raw output lives only in Metadata.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity follows SARIF's level vocabulary, extended with critical which is
// the industry default for "fix this yesterday". Ordered from most to least
// severe for sorting purposes.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// AllSeverities returns severities ordered from most to least severe.
func AllSeverities() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
}

// Rank returns 0 for critical, 4 for info. Used for comparisons.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	case SeverityInfo:
		return 4
	}
	return 5 // unknown sorts last
}

// Category is the scanner's high-level role, used to bucket findings in reports
// and to enable/disable categories via config.
type Category string

const (
	CategorySAST    Category = "sast"    // static application security testing
	CategorySecrets Category = "secrets" // hardcoded creds
	CategorySCA     Category = "sca"     // software composition analysis (deps)
	CategoryIaC     Category = "iac"     // infrastructure as code (terraform, k8s)
	CategoryLicense Category = "license" // license compliance
	CategoryDocker  Category = "docker"  // container security
	CategoryCICD    Category = "cicd"    // CI/CD workflow security
	CategorySBOM    Category = "sbom"    // software bill of materials
	CategoryDAST    Category = "dast"    // dynamic application security testing
)

// Finding is the unit of output. A scan returns a slice of these.
//
// ID is computed deterministically from the fingerprint so that re-running
// the same scan on unchanged code produces the same IDs (this is what makes
// `cyberai report compare` work as a baseline diff).
type Finding struct {
	// ID is a stable hash-derived identifier, e.g. "F-a1b2c3d4e5f6".
	ID string `json:"id"`

	// Tool is the scanner that produced this finding, e.g. "semgrep", "gitleaks".
	Tool string `json:"tool"`

	// RuleID is the scanner's native rule identifier, e.g.
	// "python.lang.security.audit.formatted-sql-query".
	RuleID string `json:"rule_id"`

	// Title is a one-line human-readable description.
	Title string `json:"title"`

	// Description is multi-line, may include remediation guidance from the tool.
	Description string `json:"description,omitempty"`

	// Severity is the normalized severity. Tools that emit numeric scores
	// (Trivy CVSS) are mapped to this vocabulary in the normalizer.
	Severity Severity `json:"severity"`

	// Confidence is "high" | "medium" | "low" — how sure the tool is.
	// Mirrors SARIF's confidence field. Optional; some tools don't emit it.
	Confidence string `json:"confidence,omitempty"`

	// Category is the scanner's high-level role.
	Category Category `json:"category"`

	// Location
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line,omitempty"`
	Column    int    `json:"column,omitempty"`

	// Snippet is the offending code region (trimmed, ≤ ~500 chars).
	Snippet string `json:"snippet,omitempty"`

	// Security metadata
	CWE        []string `json:"cwe,omitempty"`         // e.g. ["CWE-89"]
	CVE        []string `json:"cve,omitempty"`         // e.g. ["CVE-2024-12345"]
	CVSS       float64  `json:"cvss,omitempty"`        // 0.0–10.0, optional
	Fix        string   `json:"fix,omitempty"`         // suggested remediation text (NEVER auto-applied)
	FixVersion string   `json:"fix_version,omitempty"` // e.g. ">= 1.2.3" for deps
	References []string `json:"references,omitempty"`

	// Phase 2 enrichment
	EPSSScore      float64   `json:"epss_score,omitempty"`
	EPSSPercentile float64   `json:"epss_percentile,omitempty"`
	IsInKEV        bool      `json:"is_in_kev,omitempty"`
	FixAvailable   bool      `json:"fix_available,omitempty"`
	IsReachable    *bool     `json:"is_reachable,omitempty"`
	SLADeadline    time.Time `json:"sla_deadline,omitempty"`
	Priority       string    `json:"priority,omitempty"`
	FirstSeen      time.Time `json:"first_seen,omitempty"`
	ComplianceTags []string  `json:"compliance_tags,omitempty"`

	// Metadata is a free-form bag for tool-specific fields we don't normalize.
	// Reports omit it by default; --verbose includes it.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Fingerprint produces a stable hash from the fields that uniquely identify
// a finding across runs of the same code. The hash deliberately excludes
// description, snippet (which can have unstable whitespace), and metadata.
//
// Same code + same rule + same file + same line → same fingerprint → same ID.
// That's what makes baseline diffs work.
func (f *Finding) Fingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "tool=%s\n", f.Tool)
	fmt.Fprintf(h, "rule=%s\n", f.RuleID)
	fmt.Fprintf(h, "file=%s\n", f.File)
	fmt.Fprintf(h, "start=%d\n", f.StartLine)
	fmt.Fprintf(h, "end=%d\n", f.EndLine)
	fmt.Fprintf(h, "col=%d\n", f.Column)
	fmt.Fprintf(h, "cat=%s\n", f.Category)
	if len(f.CWE) > 0 {
		// sort CWE for stable input
		sorted := append([]string(nil), f.CWE...)
		sort.Strings(sorted)
		fmt.Fprintf(h, "cwe=%s\n", strings.Join(sorted, ","))
	}
	if len(f.CVE) > 0 {
		sorted := append([]string(nil), f.CVE...)
		sort.Strings(sorted)
		fmt.Fprintf(h, "cve=%s\n", strings.Join(sorted, ","))
	}
	return "F-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// AssignID sets f.ID to the value derived from the fingerprint, if it's empty.
// Called by normalizers and the orchestrator after building the Finding.
func (f *Finding) AssignID() {
	if f.ID == "" {
		f.ID = f.Fingerprint()
	}
}

// ComputePriority calculates a P0-P4 priority label from KEV, EPSS, and CVSS.
func (f *Finding) ComputePriority() string {
	if f.IsInKEV || (f.EPSSScore > 0.5 && f.CVSS >= 9.0) {
		return "P0"
	}
	if f.EPSSScore > 0.1 || f.CVSS >= 9.0 {
		return "P1"
	}
	if f.CVSS >= 7.0 {
		return "P2"
	}
	if f.CVSS >= 4.0 || f.Severity == SeverityCritical || f.Severity == SeverityHigh {
		return "P3"
	}
	return "P4"
}

// Normalize trims whitespace, lowercases severity, validates required fields.
// Returns an error if the finding is unusable (missing file or rule).
func (f *Finding) Normalize() error {
	f.Title = strings.TrimSpace(f.Title)
	f.Description = strings.TrimSpace(f.Description)
	f.File = strings.TrimSpace(f.File)

	switch strings.ToLower(string(f.Severity)) {
	case "critical":
		f.Severity = SeverityCritical
	case "high":
		f.Severity = SeverityHigh
	case "medium", "moderate", "med":
		f.Severity = SeverityMedium
	case "low":
		f.Severity = SeverityLow
	case "info", "informational", "note":
		f.Severity = SeverityInfo
	}

	if f.File == "" {
		return fmt.Errorf("finding missing file")
	}
	if f.RuleID == "" {
		return fmt.Errorf("finding missing rule_id (tool=%s, file=%s)", f.Tool, f.File)
	}
	if f.StartLine == 0 {
		// Some tools report line 0 for repo-wide findings (e.g. license, dep vulns).
		// That's OK; we keep it.
		f.StartLine = 1
	}
	return nil
}

// MeetsThreshold returns true if the finding's severity is at least as severe
// as the threshold. Severity ordering: critical > high > medium > low > info.
func (f *Finding) MeetsThreshold(threshold Severity) bool {
	return f.Severity.Rank() <= threshold.Rank()
}

// ScanResult is the orchestrator's output: findings + a small amount of
// per-scanner metadata for the report (duration, errors, partial result flag).
type ScanResult struct {
	Tool       string        `json:"tool"`
	Category   Category      `json:"category"`
	Findings   []Finding     `json:"findings"`
	Duration   time.Duration `json:"duration"`
	Error      string        `json:"error,omitempty"`
	Skipped    bool          `json:"skipped,omitempty"`
	SkipReason string        `json:"skip_reason,omitempty"`
}
