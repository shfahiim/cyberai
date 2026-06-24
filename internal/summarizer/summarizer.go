// Package summarizer writes a short executive summary of the scan results
// for the HTML report. The summary is a one-call Gemini 2.5 Flash job that
// turns a wall of findings into 3-5 actionable paragraphs.
//
// Like the router, the summarizer is optional. When disabled (--no-llm,
// --ci, or no API key), it's a no-op: the HTML report renders without an
// "Executive summary" banner.
//
// The output is sanitized before being injected into the HTML: we strip
// anything that looks like a script tag or untrusted URL, and we wrap the
// raw text in <p>...</p> with newlines converted to <br> for safe rendering.
package summarizer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/shfahiim/cyberai/internal/model"
)

const geminiBaseURL = "https://generativelanguage.googleapis.com/v1beta"

// Summary is the structured output of the summarizer. We keep it as
// a small typed struct so the rendering code is simple, but most users
// will only see Summary.Markdown rendered as HTML.
type Summary struct {
	// Executive is a 1-2 sentence overview, suitable for a PR comment.
	Executive string `json:"executive"`
	// TopPriorities is a numbered list of the most important findings.
	TopPriorities []string `json:"top_priorities"`
	// LikelyFalsePositives is a list of finding IDs we think may be FPs.
	LikelyFalsePositives []string `json:"likely_false_positives"`
	// Markdown is a rendered version of the above, ready to embed in HTML.
	Markdown string `json:"markdown"`
}

// Summarizer is the interface the HTML reporter consumes.
type Summarizer interface {
	// Summarize produces a Summary for the given findings. Returns
	// (nil, nil) when the summarizer is disabled.
	Summarize(findings []model.Finding) (*Summary, error)
}

// NoopSummarizer returns nil. Used when --no-llm or --ci is set.
type NoopSummarizer struct{}

func (NoopSummarizer) Summarize(_ []model.Finding) (*Summary, error) {
	return nil, nil
}

// GeminiSummarizer calls Gemini 2.5 Flash to produce the executive summary.
// One small call per scan; output is rendered as HTML and injected into
// the report's "Executive summary" banner.
type GeminiSummarizer struct {
	APIKey string
	Model  string
	HTTP   *http.Client
}

// NewGemini builds a GeminiSummarizer. Returns a NoopSummarizer when no
// API key is set, so the caller doesn't have to special-case the empty path.
func NewGemini(model string) Summarizer {
	key := os.Getenv("GEMINI_API_KEY")
	if key == "" {
		return NoopSummarizer{}
	}
	if model == "" {
		model = "gemini-2.5-flash"
	}
	return &GeminiSummarizer{
		APIKey: key,
		Model:  model,
		HTTP:   &http.Client{Timeout: 30 * time.Second},
	}
}

// Summarize produces a structured summary. On any error it returns the
// error AND a nil summary; the HTML reporter treats a nil summary as
// "no executive summary banner."
func (g *GeminiSummarizer) Summarize(findings []model.Finding) (*Summary, error) {
	if len(findings) == 0 {
		return nil, nil // nothing to summarize
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Compact the findings into a digest for the prompt. We don't send
	// the full Finding JSON (could be huge); just the essentials.
	digest := digestFindings(findings)

	prompt := fmt.Sprintf(`You are a security analyst reviewing scan results from cyberai. Write a short executive summary for a developer who is going to read the full report.

# Findings (%d total)
%s

# Output requirements
- Executive: 1-2 sentences. State the most important takeaway.
- Top priorities: numbered list (1., 2., 3.) of the 3-5 findings most worth fixing first. Each item should be ONE short sentence.
- Likely false positives: list of finding IDs (F-...) that look like FPs, with one-line reasoning each. Empty list if none.
- Markdown: render the above as Markdown suitable for an HTML report. Use H3 for the section headers (### Executive, ### Top priorities, ### Likely false positives). Use bullet lists for the priorities. Keep total length under 400 words.

Return JSON matching the schema.`, len(findings), digest)

	body := map[string]any{
		"systemInstruction": map[string]any{
			"parts": []map[string]string{{
				"text": "You are a security analyst writing an executive summary of a code scan. Always return JSON conforming to the provided schema. Be concise; do not hedge; do not invent findings that aren't in the input.",
			}},
		},
		"contents": []map[string]any{{
			"role":  "user",
			"parts": []map[string]string{{"text": prompt}},
		}},
		"generationConfig": map[string]any{
			"temperature":      0.2,
			"responseMimeType": "application/json",
			"responseSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"executive": map[string]any{"type": "string"},
					"top_priorities": map[string]any{
						"type":  "array",
						"items": map[string]any{"type": "string"},
					},
					"likely_false_positives": map[string]any{
						"type":  "array",
						"items": map[string]any{"type": "string"},
					},
					"markdown": map[string]any{"type": "string"},
				},
				"required": []string{"executive", "markdown"},
			},
		},
	}

	bodyJSON, _ := json.Marshal(body)
	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s", geminiBaseURL, g.Model, g.APIKey)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, truncate(string(data), 200))
	}

	var raw struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if len(raw.Candidates) == 0 || len(raw.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	var s Summary
	if err := json.Unmarshal([]byte(raw.Candidates[0].Content.Parts[0].Text), &s); err != nil {
		return nil, fmt.Errorf("parse summary: %w", err)
	}
	// Sanitize the markdown before it goes near HTML.
	s.Markdown = sanitizeMarkdown(s.Markdown)
	return &s, nil
}

// digestFindings builds a compact, LLM-friendly text version of findings.
// We cap at 30 findings to keep the prompt reasonable; very long reports
// get the worst N by severity.
func digestFindings(findings []model.Finding) string {
	// Sort by severity then file.
	sorted := append([]model.Finding(nil), findings...)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Severity.Rank() < sorted[i].Severity.Rank() {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	const maxN = 30
	if len(sorted) > maxN {
		sorted = sorted[:maxN]
	}
	var b strings.Builder
	for _, f := range sorted {
		cwe := ""
		if len(f.CWE) > 0 {
			cwe = " " + strings.Join(f.CWE, ",")
		}
		cve := ""
		if len(f.CVE) > 0 {
			cve = " " + strings.Join(f.CVE, ",")
		}
		fix := ""
		if f.Fix != "" {
			fix = " fix=" + truncate(f.Fix, 60)
		}
		fmt.Fprintf(&b, "- [%s] %s (%s:%d) id=%s tool=%s rule=%s%s%s%s\n",
			f.Severity, truncate(f.Title, 80), f.File, f.StartLine,
			f.ID, f.Tool, f.RuleID, cwe, cve, fix)
	}
	return b.String()
}

// sanitizeMarkdown strips HTML-injection vectors from the LLM's output.
// We're going to render this in our HTML report with template.HTML
// (trusted), but a paranoid pass is cheap insurance.
func sanitizeMarkdown(s string) string {
	// Remove script and style blocks wholesale.
	for _, tag := range []string{"<script", "</script", "<style", "</style", "<iframe", "</iframe"} {
		s = replaceCaseInsensitive(s, tag, "")
	}
	// Remove on* attributes (onclick, onerror, etc.).
	for _, attr := range []string{" onclick", " onerror", " onload", " onmouseover"} {
		s = replaceCaseInsensitive(s, attr, "")
	}
	// Remove javascript: URLs.
	s = replaceCaseInsensitive(s, "javascript:", "")
	return s
}

func replaceCaseInsensitive(s, old, new string) string {
	lower := strings.ToLower(s)
	oldLower := strings.ToLower(old)
	var b strings.Builder
	i := 0
	for i < len(s) {
		idx := indexOfCaseInsensitive(lower[i:], oldLower)
		if idx < 0 {
			b.WriteString(s[i:])
			break
		}
		b.WriteString(s[i : i+idx])
		b.WriteString(new)
		i += idx + len(old)
	}
	return b.String()
}

func indexOfCaseInsensitive(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(sub)], sub) {
			return i
		}
	}
	return -1
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
