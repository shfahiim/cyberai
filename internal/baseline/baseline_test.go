package baseline

import (
	"strings"
	"testing"

	"github.com/shfahiim/cyberai/internal/model"
	"github.com/shfahiim/cyberai/internal/reporter"
)

func f(id, sev string) model.Finding {
	return model.Finding{
		ID: id, Tool: "x", RuleID: "r", File: "f.go", StartLine: 1,
		Severity: model.Severity(sev),
		Title:    "finding " + id,
	}
}

func TestCompare_NewResolvedUnchanged(t *testing.T) {
	base := &reporter.Report{Hash: "h-base", Findings: []model.Finding{
		f("F-a", "high"),
		f("F-b", "medium"),
		f("F-c", "low"),
	}}
	curr := &reporter.Report{Hash: "h-base", Findings: []model.Finding{
		f("F-a", "high"),     // unchanged
		f("F-b", "medium"),   // unchanged
		f("F-d", "critical"), // new
	}}

	d := Compare(base, curr, "/tmp/base.json", "/tmp/curr.json")

	if len(d.NewFindings) != 1 || d.NewFindings[0].ID != "F-d" {
		t.Errorf("NewFindings = %v", d.NewFindings)
	}
	if len(d.ResolvedFindings) != 1 || d.ResolvedFindings[0].ID != "F-c" {
		t.Errorf("ResolvedFindings = %v", d.ResolvedFindings)
	}
	if len(d.Unchanged) != 2 {
		t.Errorf("Unchanged = %v", d.Unchanged)
	}
	if d.NewBySeverity["critical"] != 1 {
		t.Errorf("NewBySeverity = %v", d.NewBySeverity)
	}
}

func TestCompare_HashMismatchWarning(t *testing.T) {
	base := &reporter.Report{Hash: "h-base"}
	curr := &reporter.Report{Hash: "h-curr"}
	d := Compare(base, curr, "b", "c")
	md := d.Markdown()
	if !strings.Contains(md, "Project hashes differ") {
		t.Error("expected hash mismatch warning in markdown")
	}
}

func TestCompare_NoDiff(t *testing.T) {
	base := &reporter.Report{Hash: "h", Findings: []model.Finding{f("F-a", "high")}}
	curr := &reporter.Report{Hash: "h", Findings: []model.Finding{f("F-a", "high")}}
	d := Compare(base, curr, "b", "c")
	if len(d.NewFindings) != 0 || len(d.ResolvedFindings) != 0 || len(d.Unchanged) != 1 {
		t.Errorf("expected no diff, got new=%d resolved=%d unchanged=%d", len(d.NewFindings), len(d.ResolvedFindings), len(d.Unchanged))
	}
}

func TestLoad_RoundTrip(t *testing.T) {
	original := &reporter.Report{Hash: "h", Findings: []model.Finding{f("F-a", "high")}}
	data, _ := reporter.JSON(original)
	loaded, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if loaded.Hash != "h" {
		t.Errorf("Hash = %s", loaded.Hash)
	}
	if len(loaded.Findings) != 1 || loaded.Findings[0].ID != "F-a" {
		t.Errorf("Findings = %v", loaded.Findings)
	}
}

func TestParse_NullFindingsBecomesEmpty(t *testing.T) {
	// Some reporters write `"findings": null` when there's nothing.
	r, err := Parse([]byte(`{"findings": null, "hash": "h"}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.Findings == nil {
		t.Error("Findings should be non-nil after Parse (len 0)")
	}
	if len(r.Findings) != 0 {
		t.Errorf("Findings should be empty, got %d", len(r.Findings))
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	if _, err := Parse([]byte("not json")); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestDiff_Markdown_Sections(t *testing.T) {
	base := &reporter.Report{Hash: "h-base"}
	curr := &reporter.Report{Hash: "h-base"}
	curr.Findings = append(curr.Findings, f("F-new", "high"))
	base.Findings = append(base.Findings, f("F-old", "low"))
	d := Compare(base, curr, "b", "c")
	md := d.Markdown()
	for _, want := range []string{"# cyberai diff", "## New (1)", "## Resolved (1)", "F-new", "F-old", "high"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}
