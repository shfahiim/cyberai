package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
)

// Markdown renders the report as a GitHub-flavored Markdown document.
// Suitable for posting as a PR comment or viewing in a text editor.
//
// Structure:
//   - Title + summary line
//   - "By severity" — counts
//   - "By tool" — counts and any scanner errors
//   - "Findings" — one ## block per finding, sorted by severity
func Markdown(r *Report) string {
	var b strings.Builder

	// Header
	fmt.Fprintf(&b, "# cyberai scan report\n\n")
	fmt.Fprintf(&b, "**Target:** `%s`\n\n", r.Target)
	fmt.Fprintf(&b, "**Project hash:** `%s`\n\n", r.Hash)
	fmt.Fprintf(&b, "**Generated:** %s\n\n", r.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "**Duration:** %s\n\n", r.Duration)
	if r.SuppressedByIgnore > 0 {
		fmt.Fprintf(&b, "**Suppressed by ignore patterns:** %d\n\n", r.SuppressedByIgnore)
	}
	if r.SuppressedBySuppression > 0 {
		fmt.Fprintf(&b, "**Suppressed by .cyberai-suppressions.yaml:** %d\n\n", r.SuppressedBySuppression)
	}
	if len(r.SuppressionAudit) > 0 {
		fmt.Fprintf(&b, "## Suppression audit\n\n")
		for _, entry := range r.SuppressionAudit {
			fmt.Fprintf(&b, "- `%s` via `%s`: %s\n", entry.FindingID, entry.SuppressionID, entry.Reason)
		}
		fmt.Fprintf(&b, "\n")
	}

	// Summary line
	if len(r.Findings) == 0 {
		fmt.Fprintf(&b, "## Summary\n\nNo findings at or above the configured threshold.\n\n")
	} else {
		crit, high, med, low, info := 0, 0, 0, 0, 0
		for _, f := range r.Findings {
			switch f.Severity {
			case model.SeverityCritical:
				crit++
			case model.SeverityHigh:
				high++
			case model.SeverityMedium:
				med++
			case model.SeverityLow:
				low++
			case model.SeverityInfo:
				info++
			}
		}
		fmt.Fprintf(&b, "## Summary\n\n")
		fmt.Fprintf(&b, "%d findings: %d critical, %d high, %d medium, %d low, %d info\n\n",
			len(r.Findings), crit, high, med, low, info)
	}

	// Per-scanner status
	fmt.Fprintf(&b, "## Scanners\n\n")
	for _, sr := range r.Scanners {
		switch {
		case sr.Skipped:
			fmt.Fprintf(&b, "- **%s** (%s) — skipped: %s\n", sr.Tool, sr.Category, sr.SkipReason)
		case sr.Error != "":
			fmt.Fprintf(&b, "- **%s** (%s) — error: `%s`\n", sr.Tool, sr.Category, sr.Error)
		default:
			fmt.Fprintf(&b, "- **%s** (%s) — %d findings in %s\n", sr.Tool, sr.Category, len(sr.Findings), sr.Duration)
		}
	}
	fmt.Fprintf(&b, "\n")

	// Findings, grouped by severity
	if len(r.Findings) == 0 {
		return b.String()
	}

	fmt.Fprintf(&b, "## Findings\n\n")
	currentSev := model.Severity("")
	for _, f := range r.Findings {
		if f.Severity != currentSev {
			currentSev = f.Severity
			fmt.Fprintf(&b, "### %s\n\n", severityHeader(currentSev))
		}
		writeFinding(&b, f)
	}
	return b.String()
}

func writeFinding(b *strings.Builder, f model.Finding) {
	fmt.Fprintf(b, "#### %s\n\n", f.Title)
	fmt.Fprintf(b, "- **ID:** `%s`\n", f.ID)
	fmt.Fprintf(b, "- **Tool:** %s\n", f.Tool)
	fmt.Fprintf(b, "- **Rule:** `%s`\n", f.RuleID)
	fmt.Fprintf(b, "- **File:** `%s:%d`", f.File, f.StartLine)
	if f.Column > 0 {
		fmt.Fprintf(b, ":%d", f.Column)
	}
	fmt.Fprintf(b, "\n")
	if len(f.CWE) > 0 {
		fmt.Fprintf(b, "- **CWE:** %s\n", strings.Join(f.CWE, ", "))
	}
	if len(f.CVE) > 0 {
		fmt.Fprintf(b, "- **CVE:** %s\n", strings.Join(f.CVE, ", "))
	}
	if f.CVSS > 0 {
		fmt.Fprintf(b, "- **CVSS:** %.1f\n", f.CVSS)
	}
	if f.Fix != "" {
		fmt.Fprintf(b, "- **Suggested fix:** %s\n", f.Fix)
	}
	if f.Description != "" {
		fmt.Fprintf(b, "\n%s\n", f.Description)
	}
	if f.Snippet != "" {
		fmt.Fprintf(b, "\n```\n%s\n```\n", f.Snippet)
	}
	if len(f.References) > 0 {
		fmt.Fprintf(b, "\n**References:**\n")
		for _, ref := range f.References {
			fmt.Fprintf(b, "- %s\n", ref)
		}
	}
	fmt.Fprintf(b, "\n---\n\n")
}

func severityHeader(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "Critical"
	case model.SeverityHigh:
		return "High"
	case model.SeverityMedium:
		return "Medium"
	case model.SeverityLow:
		return "Low"
	case model.SeverityInfo:
		return "Informational"
	}
	return string(s)
}

// WriteMarkdown writes the Markdown report to w.
func WriteMarkdown(w io.Writer, r *Report) (int, error) {
	s := Markdown(r)
	n, err := w.Write([]byte(s))
	return n, err
}
