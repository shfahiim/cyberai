package reporter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/shfahiim/cyberai/internal/model"
)

func fixtureReport() *Report {
	return &Report{
		Target:      "/tmp/repo",
		Hash:        "sha256:abc",
		GeneratedAt: time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC),
		Findings: []model.Finding{
			{
				ID:        "F-high1",
				Tool:      "semgrep",
				RuleID:    "python.lang.security.audit.formatted-sql-query",
				Title:     "SQL injection via formatted query",
				Severity:  model.SeverityHigh,
				Category:  model.CategorySAST,
				File:      "src/db.py",
				StartLine: 87,
				Column:    4,
				CWE:       []string{"CWE-89"},
				Snippet:   "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
			},
			{
				ID:         "F-crit1",
				Tool:       "trivy",
				RuleID:     "CVE-2024-12345",
				Title:      "Prototype Pollution in lodash",
				Severity:   model.SeverityCritical,
				Category:   model.CategorySCA,
				File:       "package.json",
				StartLine:  1,
				CVE:        []string{"CVE-2024-12345"},
				CWE:        []string{"CWE-1321"},
				CVSS:       8.1,
				Fix:        "Upgrade lodash to 4.17.21",
				FixVersion: "4.17.21",
			},
		},
		Scanners: []model.ScanResult{
			{Tool: "semgrep", Category: model.CategorySAST, Findings: []model.Finding{}, Duration: 1200 * time.Millisecond},
			{Tool: "trivy", Category: model.CategorySCA, Findings: []model.Finding{}, Duration: 800 * time.Millisecond, Skipped: false},
		},
		TotalFindings: 2,
		Duration:      2 * time.Second,
	}
}

func TestNewReport_SortsBySeverity(t *testing.T) {
	r := NewReport("/x", "h",
		[]model.Finding{
			{ID: "low", Tool: "x", RuleID: "r", File: "a", Severity: model.SeverityLow},
			{ID: "crit", Tool: "x", RuleID: "r", File: "a", Severity: model.SeverityCritical},
			{ID: "med", Tool: "x", RuleID: "r", File: "a", Severity: model.SeverityMedium},
		},
		nil, 3, 0, time.Second)
	if r.Findings[0].Severity != model.SeverityCritical {
		t.Errorf("expected critical first, got %s", r.Findings[0].Severity)
	}
}

func TestJSON_Valid(t *testing.T) {
	r := fixtureReport()
	data, err := JSON(r)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("JSON output not parseable: %v", err)
	}
	if out["target"] != "/tmp/repo" {
		t.Errorf("target = %v", out["target"])
	}
	if out["hash"] != "sha256:abc" {
		t.Errorf("hash = %v", out["hash"])
	}
	findings, _ := out["findings"].([]any)
	if len(findings) != 2 {
		t.Errorf("findings = %d", len(findings))
	}
}

func TestMarkdown_ContainsRequiredSections(t *testing.T) {
	r := fixtureReport()
	md := Markdown(r)
	required := []string{
		"# cyberai scan report",
		"**Target:**",
		"**Project hash:**",
		"## Summary",
		"## Scanners",
		"## Findings",
		"SQL injection",
		"Prototype Pollution",
		"CWE-89",
		"CVE-2024-12345",
		"Upgrade lodash to 4.17.21",
	}
	for _, s := range required {
		if !strings.Contains(md, s) {
			t.Errorf("markdown missing %q", s)
		}
	}
}

func TestMarkdown_NoFindings(t *testing.T) {
	r := &Report{Target: "/x", Hash: "h"}
	md := Markdown(r)
	if !strings.Contains(md, "No findings") {
		t.Error("empty report should say 'No findings'")
	}
}

func TestSARIF_Valid(t *testing.T) {
	r := fixtureReport()
	data, err := SARIF(r, "0.1.0")
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("SARIF not parseable: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %s, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	if doc.Runs[0].Tool.Driver.Name != "cyberai" {
		t.Errorf("tool name = %s", doc.Runs[0].Tool.Driver.Name)
	}
	if len(doc.Runs[0].Results) != 2 {
		t.Errorf("results = %d, want 2", len(doc.Runs[0].Results))
	}
	// Each finding should map to a level of error (high/critical) or warning/note.
	levels := map[string]int{}
	for _, res := range doc.Runs[0].Results {
		levels[string(res.Level)]++
	}
	if levels["error"] != 2 {
		t.Errorf("expected 2 errors (high+critical), got %d", levels["error"])
	}
	// Rules should be deduplicated by tool+ruleID (2 unique: semgrep+rule, trivy+CVE)
	if len(doc.Runs[0].Tool.Driver.Rules) != 2 {
		t.Errorf("rules = %d, want 2", len(doc.Runs[0].Tool.Driver.Rules))
	}
}

func TestSARIF_IncludesLocationAndFingerprint(t *testing.T) {
	r := fixtureReport()
	data, _ := SARIF(r, "0.1.0")
	var doc sarifDoc
	_ = json.Unmarshal(data, &doc)
	res := doc.Runs[0].Results[0]
	if len(res.Locations) == 0 {
		t.Fatal("result missing locations")
	}
	loc := res.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "src/db.py" {
		t.Errorf("uri = %s", loc.ArtifactLocation.URI)
	}
	if loc.Region.StartLine != 87 {
		t.Errorf("startLine = %d", loc.Region.StartLine)
	}
	if res.PartialFingerprints["cyberai/v1"] == "" {
		t.Error("fingerprint missing")
	}
}

func TestSeverityToSARIF(t *testing.T) {
	cases := []struct {
		s    model.Severity
		want sarifLevel
	}{
		{model.SeverityCritical, levelError},
		{model.SeverityHigh, levelError},
		{model.SeverityMedium, levelWarning},
		{model.SeverityLow, levelNote},
		{model.SeverityInfo, levelNone},
	}
	for _, tc := range cases {
		if got := severityToSARIF(tc.s); got != tc.want {
			t.Errorf("severityToSARIF(%s) = %s, want %s", tc.s, got, tc.want)
		}
	}
}

func TestTerminal_NoColor(t *testing.T) {
	term := &Terminal{IsTTY: false}
	var b strings.Builder
	term.Write(&b, fixtureReport())
	out := b.String()
	if strings.Contains(out, "\033[") {
		t.Error("non-TTY output should not contain ANSI escapes")
	}
	if !strings.Contains(out, "cyberai") {
		t.Error("expected 'cyberai' header")
	}
	if !strings.Contains(out, "SQL injection") {
		t.Error("expected SQL injection finding")
	}
}

func TestTerminal_WithColor(t *testing.T) {
	term := &Terminal{IsTTY: true}
	var b strings.Builder
	term.Write(&b, fixtureReport())
	out := b.String()
	// Should have at least one ANSI color sequence.
	if !strings.Contains(out, "\033[") {
		t.Error("TTY output should contain ANSI escapes")
	}
}

func TestTerminal_NoFindings(t *testing.T) {
	term := &Terminal{IsTTY: false}
	var b strings.Builder
	term.Write(&b, &Report{Target: "/x", Hash: "h"})
	if !strings.Contains(b.String(), "no findings") {
		t.Errorf("expected 'no findings', got %q", b.String())
	}
}

func TestTerminal_MaxFindings(t *testing.T) {
	r := &Report{
		Target: "/x",
		Findings: []model.Finding{
			{ID: "1", Tool: "x", RuleID: "r", File: "a", Severity: model.SeverityHigh, Title: "f1"},
			{ID: "2", Tool: "x", RuleID: "r", File: "b", Severity: model.SeverityHigh, Title: "f2"},
			{ID: "3", Tool: "x", RuleID: "r", File: "c", Severity: model.SeverityHigh, Title: "f3"},
		},
	}
	term := &Terminal{IsTTY: false, MaxFindings: 1}
	var b strings.Builder
	term.Write(&b, r)
	if !strings.Contains(b.String(), "and 2 more") {
		t.Errorf("expected truncation message, got %q", b.String())
	}
}
