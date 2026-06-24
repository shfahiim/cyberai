// Package summarizer writes a short executive summary of the scan results
// for the HTML report. The summary is a one-call LLM job that turns a wall
// of findings into 3-5 actionable paragraphs.
package summarizer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/shfahiim/cyberai/internal/gemini"
	"github.com/shfahiim/cyberai/internal/llm"
	"github.com/shfahiim/cyberai/internal/model"
)

type Summary struct {
	Executive            string   `json:"executive"`
	TopPriorities        []string `json:"top_priorities"`
	LikelyFalsePositives []string `json:"likely_false_positives"`
	Markdown             string   `json:"markdown"`
}

type Summarizer interface {
	Summarize(findings []model.Finding) (*Summary, error)
}

type NoopSummarizer struct{}

func (NoopSummarizer) Summarize(_ []model.Finding) (*Summary, error) {
	return nil, nil
}

type LLMSummarizer struct {
	Client llm.Client
}

func NewLLM(provider, model string) (Summarizer, error) {
	client, live, err := llm.NewClient(provider, model, nil)
	if err != nil {
		return nil, err
	}
	if !live {
		return NoopSummarizer{}, nil
	}
	return &LLMSummarizer{Client: client}, nil
}

// NewGemini is kept as a compatibility wrapper for existing tests and callers.
func NewGemini(model string) Summarizer {
	s, err := NewLLM(gemini.Provider, model)
	if err != nil {
		return NoopSummarizer{}
	}
	return s
}

var summarySchema = map[string]any{
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
}

func (g *LLMSummarizer) Summarize(findings []model.Finding) (*Summary, error) {
	if len(findings) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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

	var s Summary
	err := g.Client.GenerateStructured(ctx, llm.StructuredRequest{
		SystemInstruction: "You are a security analyst writing an executive summary of a code scan. Always return JSON conforming to the provided schema. Be concise; do not hedge; do not invent findings that aren't in the input.",
		Prompt:            prompt,
		Temperature:       0.2,
		Schema:            summarySchema,
	}, &s)
	if err != nil {
		return nil, err
	}
	s.Markdown = sanitizeMarkdown(s.Markdown)
	return &s, nil
}

func digestFindings(findings []model.Finding) string {
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

// sanitizeMarkdown removes dangerous HTML from LLM-generated markdown to prevent
// XSS when the content is embedded in reports.
func sanitizeMarkdown(s string) string {
	// Strip dangerous block-level tags and their content.
	for _, tag := range []string{"script", "style", "iframe", "object", "embed", "form"} {
		s = stripTagBlock(s, tag)
	}
	// Strip self-closing dangerous tags.
	for _, tag := range []string{"link", "meta", "base"} {
		s = stripTagSelfClosing(s, tag)
	}
	// Remove javascript: URIs.
	for {
		lower := strings.ToLower(s)
		idx := strings.Index(lower, "javascript:")
		if idx < 0 {
			break
		}
		s = s[:idx] + s[idx+len("javascript:"):]
	}
	// Remove on* event handlers.
	s = removeOnHandlers(s)
	return s
}

// stripTagBlock removes <tag>...</tag> or <tag .../> blocks case-insensitively.
func stripTagBlock(s, tag string) string {
	for i := 0; i < 20; i++ { // limit iterations to prevent infinite loops
		lower := strings.ToLower(s)
		opener := "<" + tag
		start := strings.Index(lower, opener)
		if start < 0 {
			break
		}
		// Verify the character after tag name is a space, > or /
		aftTag := start + len(opener)
		if aftTag < len(lower) {
			nc := lower[aftTag]
			if nc != ' ' && nc != '>' && nc != '/' && nc != '\t' && nc != '\n' && nc != '\r' {
				break // not our tag
			}
		}
		// Find closing tag.
		closer := "</" + tag + ">"
		end := strings.Index(lower[start:], closer)
		if end >= 0 {
			s = s[:start] + s[start+end+len(closer):]
		} else {
			// No close tag: remove to next >
			gt := strings.Index(s[start:], ">")
			if gt >= 0 {
				s = s[:start] + s[start+gt+1:]
			} else {
				s = s[:start]
				break
			}
		}
	}
	return s
}

// stripTagSelfClosing removes standalone tags like <link ...> or <meta ...>.
func stripTagSelfClosing(s, tag string) string {
	for i := 0; i < 20; i++ {
		lower := strings.ToLower(s)
		opener := "<" + tag
		start := strings.Index(lower, opener)
		if start < 0 {
			break
		}
		aftTag := start + len(opener)
		if aftTag < len(lower) {
			nc := lower[aftTag]
			if nc != ' ' && nc != '>' && nc != '/' && nc != '\t' && nc != '\n' && nc != '\r' {
				break
			}
		}
		gt := strings.Index(s[start:], ">")
		if gt >= 0 {
			s = s[:start] + s[start+gt+1:]
		} else {
			s = s[:start]
			break
		}
	}
	return s
}

// removeOnHandlers removes on* event handler attributes.
func removeOnHandlers(s string) string {
	for i := 0; i < 50; i++ {
		lower := strings.ToLower(s)
		// Find " on" followed by a letter
		idx := -1
		for j := 0; j+3 < len(lower); j++ {
			if (lower[j] == ' ' || lower[j] == '\t') &&
				lower[j+1] == 'o' && lower[j+2] == 'n' &&
				lower[j+3] >= 'a' && lower[j+3] <= 'z' {
				idx = j
				break
			}
		}
		if idx < 0 {
			break
		}
		// Find '=' then skip value
		rest := s[idx:]
		eqIdx := strings.Index(rest, "=")
		if eqIdx < 0 {
			s = s[:idx] + s[idx+1:]
			continue
		}
		valStart := idx + eqIdx + 1
		if valStart >= len(s) {
			s = s[:idx]
			break
		}
		var valEnd int
		quote := s[valStart]
		if quote == '"' || quote == '\'' {
			next := strings.IndexByte(s[valStart+1:], quote)
			if next < 0 {
				s = s[:idx]
				break
			}
			valEnd = valStart + 1 + next + 1
		} else {
			valEnd = valStart
			for valEnd < len(s) && s[valEnd] != ' ' && s[valEnd] != '>' && s[valEnd] != '\t' {
				valEnd++
			}
		}
		s = s[:idx] + s[valEnd:]
	}
	return s
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
