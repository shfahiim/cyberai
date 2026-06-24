package reporter

import (
	"strings"
	"testing"

	"github.com/shfahiim/cyberai/internal/model"
)

func TestHTML_BasicStructure(t *testing.T) {
	r := fixtureReport()
	data, err := HTML(r, "")
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := string(data)

	required := []string{
		"<!doctype html>",
		"<title>cyberai - /tmp/repo</title>",
		"/tmp/repo",
		"sha256:abc",
		"Severity summary",
		"Scanners",
		"Findings",
		"SQL injection via formatted query",
		"Prototype Pollution in lodash",
		"<style>",
		"sev high",
		"sev crit",
	}
	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("HTML missing %q", s)
		}
	}
}

func TestHTML_WithSummary(t *testing.T) {
	r := fixtureReport()
	data, err := HTML(r, "### Executive\n- This is the executive summary.")
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "Executive summary") {
		t.Error("HTML should have Executive summary banner when summaryHTML provided")
	}
	if !strings.Contains(out, "This is the executive summary.") {
		t.Error("HTML should include the summary text")
	}
	if !strings.Contains(out, "<h3>Executive</h3>") {
		t.Error("expected heading markup in summary banner")
	}
}

func TestHTML_NoFindings(t *testing.T) {
	r := &Report{Target: "/x", Hash: "h"}
	data, err := HTML(r, "")
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "No findings at or above the configured threshold.") {
		t.Error("empty report should say 'No findings'")
	}
}

func TestHTML_EscapesTitle(t *testing.T) {
	// Make sure XSS-y title text doesn't inject script tags.
	r := &Report{
		Target: "/x", Hash: "h",
		Findings: []model.Finding{{
			ID: "F-x", Tool: "x", RuleID: "r", File: "f.go", StartLine: 1,
			Severity: "high",
			Title:    `<script>alert("xss")</script>`,
		}},
	}
	data, _ := HTML(r, "")
	out := string(data)
	if strings.Contains(out, "<script>alert") {
		t.Error("HTML title should escape < and >")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("HTML should escape the script tag to entities")
	}
}

func TestHTML_SummaryEscapesRawHTML(t *testing.T) {
	r := fixtureReport()
	data, err := HTML(r, "### Executive\n<img src=x onerror=alert(1)>")
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := string(data)
	if strings.Contains(out, "<img src=x") {
		t.Fatal("summary HTML should escape raw tags")
	}
	if !strings.Contains(out, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Fatal("expected escaped summary HTML in banner")
	}
}

func TestSeverityCounts(t *testing.T) {
	r := &Report{Findings: []model.Finding{
		{Severity: "critical"},
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "low"},
	}}
	c := severityCounts(r.Findings)
	if c["critical"] != 2 || c["high"] != 1 || c["medium"] != 0 || c["low"] != 1 || c["info"] != 0 {
		t.Errorf("counts = %v", c)
	}
}

func TestHTML_WithSummary_RendersBanner(t *testing.T) {
	r := fixtureReport()
	data, err := HTML(r, "### Executive\nTop issue is F-1.")
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "Executive summary") {
		t.Error("expected 'Executive summary' banner in HTML")
	}
	if !strings.Contains(out, "<h3>Executive</h3>") {
		t.Error("expected rendered summary heading in banner")
	}
}

func TestHTML_WithoutSummary_OmitsBanner(t *testing.T) {
	r := fixtureReport()
	data, err := HTML(r, "")
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := string(data)
	if strings.Contains(out, "Executive summary") {
		t.Error("did not expect 'Executive summary' banner when summary is empty")
	}
}
