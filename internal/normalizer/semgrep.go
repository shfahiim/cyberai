// Package normalizer converts each scanner's raw output into []model.Finding.
// Every scanner has its own normalizer because the raw formats differ.
// Each normalizer is pure (no I/O) and side-effect free — easy to test
// against fixture JSON files.
package normalizer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
)

// semgrepOutput is the subset of the Semgrep JSON shape we parse. Semgrep
// emits more fields; we ignore them. Extra fields in the input don't break us.
type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
	Errors  []semgrepError  `json:"errors"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	End     semgrepPos   `json:"end"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Severity string      `json:"severity"`
	Message  string      `json:"message"`
	Metadata semgrepMeta `json:"metadata"`
	Lines    string      `json:"lines"`
}

type semgrepMeta struct {
	CWE              []string `json:"cwe"`
	OWASP            []string `json:"owasp"`
	References       []string `json:"references"`
	Confidence       string   `json:"confidence"`
	Shortlink        string   `json:"shortlink"`
	Impact           string   `json:"impact"`
	Likelihood       string   `json:"likelihood"`
	Category         string   `json:"category"`
	CVSS             any      `json:"cvss"`
	SecuritySeverity any      `json:"security-severity"`
}

type semgrepError struct {
	Message string `json:"message"`
	Level   string `json:"level"`
}

// Semgrep parses the JSON output of `semgrep scan --json` into Findings.
//
// Semgrep severity strings are "INFO" | "WARNING" | "ERROR" (case-insensitive
// in older versions). We map them to model.Severity as:
//
//	ERROR   -> high (Semgrep's "ERROR" is its high, not a literal critical)
//	WARNING -> medium
//	INFO    -> low
//
// For our purposes we treat any ERROR-level finding as worth surfacing; if a
// user needs to split critical/high, they can pin a config that uses CVSS
// or specify custom severities.
func Semgrep(raw []byte) ([]model.Finding, error) {
	var out semgrepOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse semgrep JSON: %w", err)
	}

	// Surface semgrep-side errors as a fatal parse issue. semgrep writes
	// these when its own config is broken; we don't want to silently
	// produce zero findings in that case.
	if len(out.Errors) > 0 {
		// Filter to fatal-level errors only.
		var fatals []string
		for _, e := range out.Errors {
			if strings.EqualFold(e.Level, "error") {
				fatals = append(fatals, e.Message)
			}
		}
		if len(fatals) > 0 {
			return nil, fmt.Errorf("semgrep reported errors: %s", strings.Join(fatals, "; "))
		}
	}

	findings := make([]model.Finding, 0, len(out.Results))
	for _, r := range out.Results {
		f := model.Finding{
			Tool:        "semgrep",
			RuleID:      r.CheckID,
			Title:       firstLine(r.Extra.Message),
			Description: r.Extra.Message,
			Severity:    mapSemgrepSeverity(r.Extra.Severity, r.Extra.Metadata),
			Confidence:  strings.ToLower(r.Extra.Metadata.Confidence),
			Category:    model.CategorySAST,
			File:        r.Path,
			StartLine:   r.Start.Line,
			EndLine:     r.End.Line,
			Column:      r.Start.Col,
			Snippet:     strings.TrimRight(r.Extra.Lines, "\n"),
			CWE:         r.Extra.Metadata.CWE,
			References:  append([]string(nil), r.Extra.Metadata.References...),
			Metadata: map[string]string{
				"owasp":     strings.Join(r.Extra.Metadata.OWASP, ","),
				"shortlink": r.Extra.Metadata.Shortlink,
			},
		}
		if err := f.Normalize(); err != nil {
			// Skip malformed findings rather than fail the whole report.
			continue
		}
		f.AssignID()
		findings = append(findings, f)
	}
	return findings, nil
}

func mapSemgrepSeverity(s string, meta semgrepMeta) model.Severity {
	if metadataCritical(meta) {
		return model.SeverityCritical
	}
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR":
		return model.SeverityHigh
	case "WARNING":
		return model.SeverityMedium
	case "INFO":
		return model.SeverityLow
	}
	// Unknown severity defaults to medium so it's visible but not alarming.
	return model.SeverityMedium
}

func metadataCritical(meta semgrepMeta) bool {
	if score, ok := metadataScore(meta.SecuritySeverity); ok && score >= 9 {
		return true
	}
	if score, ok := metadataScore(meta.CVSS); ok && score >= 9 {
		return true
	}
	combined := strings.ToLower(strings.Join([]string{meta.Impact, meta.Likelihood, meta.Category}, " "))
	return strings.Contains(combined, "critical")
}

func metadataScore(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case string:
		if strings.TrimSpace(x) == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// firstLine returns the first non-empty line of s, used for the Finding
// title so reports show a one-liner instead of a paragraph.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return s
}
