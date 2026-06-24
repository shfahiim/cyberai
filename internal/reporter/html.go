package reporter

import (
	"bytes"
	"embed"
	"fmt"
	"html"
	"html/template"
	"io"
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
)

//go:embed templates/report.html.tmpl
var templateFS embed.FS

// htmlTemplateData is what we pass to the HTML template. We extend Report
// with derived fields (Counts, SummaryHTML) so the template can be dumb.
type htmlTemplateData struct {
	*Report
	Counts      map[string]int
	SummaryHTML template.HTML
}

// HTML renders the report as a self-contained HTML page (CSS embedded).
//
// If summaryHTML is non-empty, it is rendered into the "Executive summary"
// banner at the top of the report. The summarizer provides markdown-like text;
// we convert a tiny safe subset to HTML here instead of trusting raw model
// output.
func HTML(r *Report, summaryHTML string) ([]byte, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/report.html.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse HTML template: %w", err)
	}
	data := htmlTemplateData{
		Report:      r,
		Counts:      severityCounts(r.Findings),
		SummaryHTML: renderSummaryMarkdown(summaryHTML),
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("execute HTML template: %w", err)
	}
	return buf.Bytes(), nil
}

// WriteHTML writes the HTML report to w.
func WriteHTML(w io.Writer, r *Report, summaryHTML string) error {
	data, err := HTML(r, summaryHTML)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func renderSummaryMarkdown(markdown string) template.HTML {
	markdown = strings.ReplaceAll(markdown, "\r\n", "\n")
	markdown = strings.TrimSpace(markdown)
	if markdown == "" {
		return ""
	}

	lines := strings.Split(markdown, "\n")
	var (
		out       strings.Builder
		paragraph []string
		listItems []string
	)

	flushParagraph := func() {
		if len(paragraph) == 0 {
			return
		}
		out.WriteString("<p>")
		out.WriteString(inlineSummaryHTML(strings.Join(paragraph, " ")))
		out.WriteString("</p>")
		paragraph = nil
	}
	flushList := func() {
		if len(listItems) == 0 {
			return
		}
		out.WriteString("<ul>")
		for _, item := range listItems {
			out.WriteString("<li>")
			out.WriteString(inlineSummaryHTML(item))
			out.WriteString("</li>")
		}
		out.WriteString("</ul>")
		listItems = nil
	}

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		switch {
		case line == "":
			flushParagraph()
			flushList()
		case strings.HasPrefix(line, "### "):
			flushParagraph()
			flushList()
			out.WriteString("<h3>")
			out.WriteString(inlineSummaryHTML(strings.TrimSpace(line[4:])))
			out.WriteString("</h3>")
		case isSummaryListItem(line):
			flushParagraph()
			listItems = append(listItems, summaryListText(line))
		default:
			flushList()
			paragraph = append(paragraph, line)
		}
	}

	flushParagraph()
	flushList()
	return template.HTML(out.String())
}

func inlineSummaryHTML(s string) string {
	s = html.EscapeString(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func isSummaryListItem(line string) bool {
	return strings.HasPrefix(line, "- ") ||
		strings.HasPrefix(line, "* ") ||
		hasOrderedListPrefix(line)
}

func summaryListText(line string) string {
	switch {
	case strings.HasPrefix(line, "- "), strings.HasPrefix(line, "* "):
		return strings.TrimSpace(line[2:])
	case hasOrderedListPrefix(line):
		i := 0
		for i < len(line) && line[i] >= '0' && line[i] <= '9' {
			i++
		}
		if i+1 < len(line) && line[i] == '.' && line[i+1] == ' ' {
			return strings.TrimSpace(line[i+2:])
		}
	}
	return strings.TrimSpace(line)
}

func hasOrderedListPrefix(line string) bool {
	i := 0
	for i < len(line) && line[i] >= '0' && line[i] <= '9' {
		i++
	}
	return i > 0 && i+1 < len(line) && line[i] == '.' && line[i+1] == ' '
}

// severityCounts returns a {critical,high,medium,low,info} -> count map.
// The template uses zero counts as a signal to skip rendering that bucket.
func severityCounts(findings []model.Finding) map[string]int {
	out := map[string]int{
		"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
	}
	for _, f := range findings {
		switch f.Severity {
		case model.SeverityCritical:
			out["critical"]++
		case model.SeverityHigh:
			out["high"]++
		case model.SeverityMedium:
			out["medium"]++
		case model.SeverityLow:
			out["low"]++
		case model.SeverityInfo:
			out["info"]++
		}
	}
	return out
}
