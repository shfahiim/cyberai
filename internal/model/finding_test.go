package model

import (
	"testing"
)

func TestFinding_Fingerprint_Stable(t *testing.T) {
	a := &Finding{
		Tool: "semgrep", RuleID: "x", File: "foo.go",
		StartLine: 10, EndLine: 12, Column: 4,
		Category: CategorySAST, CWE: []string{"CWE-89", "CWE-79"},
	}
	b := &Finding{
		Tool: "semgrep", RuleID: "x", File: "foo.go",
		StartLine: 10, EndLine: 12, Column: 4,
		Category: CategorySAST, CWE: []string{"CWE-79", "CWE-89"}, // order swapped
	}
	if a.Fingerprint() != b.Fingerprint() {
		t.Errorf("fingerprint should ignore CWE ordering: %s vs %s", a.Fingerprint(), b.Fingerprint())
	}
}

func TestFinding_Fingerprint_ChangesOnRule(t *testing.T) {
	a := &Finding{Tool: "semgrep", RuleID: "x", File: "foo.go", StartLine: 1, Category: CategorySAST}
	b := &Finding{Tool: "semgrep", RuleID: "y", File: "foo.go", StartLine: 1, Category: CategorySAST}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("different rules should produce different fingerprints")
	}
}

func TestFinding_Fingerprint_IgnoresWhitespace(t *testing.T) {
	a := &Finding{
		Tool: "gitleaks", RuleID: "aws-access-token", File: "config.py",
		StartLine: 5, Category: CategorySecrets,
		Description: "first description\n\n",
		Snippet:     "  AKIA...\n",
	}
	b := &Finding{
		Tool: "gitleaks", RuleID: "aws-access-token", File: "config.py",
		StartLine: 5, Category: CategorySecrets,
		Description: "different description",
		Snippet:     "totally different",
	}
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("description/snippet should not affect fingerprint (descriptions re-render differently)")
	}
}

func TestFinding_AssignID(t *testing.T) {
	f := &Finding{Tool: "semgrep", RuleID: "x", File: "a.go", StartLine: 1, Category: CategorySAST}
	if f.ID != "" {
		t.Fatal("new finding should have empty ID")
	}
	f.AssignID()
	if f.ID == "" {
		t.Fatal("AssignID should set ID")
	}
	if f.ID != f.Fingerprint() {
		t.Errorf("ID %s != fingerprint %s", f.ID, f.Fingerprint())
	}
}

func TestFinding_Normalize_Severity(t *testing.T) {
	cases := []struct {
		in   Severity
		want Severity
	}{
		{"CRITICAL", SeverityCritical},
		{"High", SeverityHigh},
		{"moderate", SeverityMedium}, // Trivy uses "moderate"
		{"LOW", SeverityLow},
		{"informational", SeverityInfo},
	}
	for _, tc := range cases {
		f := &Finding{Tool: "x", RuleID: "y", File: "z", Severity: tc.in}
		if err := f.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		if f.Severity != tc.want {
			t.Errorf("Normalize(%q) = %q, want %q", tc.in, f.Severity, tc.want)
		}
	}
}

func TestFinding_Normalize_RequiresFileAndRule(t *testing.T) {
	if err := (&Finding{Tool: "x", RuleID: "y"}).Normalize(); err == nil {
		t.Error("expected error for missing file")
	}
	if err := (&Finding{Tool: "x", File: "z"}).Normalize(); err == nil {
		t.Error("expected error for missing rule_id")
	}
}

func TestFinding_Normalize_FillsZeroLine(t *testing.T) {
	f := &Finding{Tool: "x", RuleID: "y", File: "z", StartLine: 0}
	if err := f.Normalize(); err != nil {
		t.Fatal(err)
	}
	if f.StartLine != 1 {
		t.Errorf("expected StartLine=1 (filled from 0), got %d", f.StartLine)
	}
}

func TestSeverity_Rank(t *testing.T) {
	if SeverityCritical.Rank() >= SeverityHigh.Rank() {
		t.Error("critical should rank higher (lower number) than high")
	}
	if SeverityHigh.Rank() >= SeverityMedium.Rank() {
		t.Error("high should rank higher than medium")
	}
	if SeverityMedium.Rank() >= SeverityLow.Rank() {
		t.Error("medium should rank higher than low")
	}
	if SeverityLow.Rank() >= SeverityInfo.Rank() {
		t.Error("low should rank higher than info")
	}
}

func TestFinding_MeetsThreshold(t *testing.T) {
	cases := []struct {
		find   Severity
		thresh Severity
		want   bool
	}{
		{SeverityCritical, SeverityInfo, true},
		{SeverityHigh, SeverityHigh, true},
		{SeverityMedium, SeverityHigh, false},
		{SeverityLow, SeverityMedium, false},
		{SeverityInfo, SeverityInfo, true},
	}
	for _, tc := range cases {
		f := &Finding{Severity: tc.find}
		if got := f.MeetsThreshold(tc.thresh); got != tc.want {
			t.Errorf("MeetsThreshold(find=%s, thresh=%s) = %v, want %v", tc.find, tc.thresh, got, tc.want)
		}
	}
}
