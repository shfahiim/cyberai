package reporter

import (
	"encoding/json"
	"fmt"

	"github.com/shfahiim/cyberai/internal/model"
)

// SARIF 2.1.0 — Static Analysis Results Interchange Format.
//
// Cyberai emits SARIF for two reasons:
//   1. CI integrations (GitHub Code Scanning, GitLab, Azure DevOps) consume SARIF directly
//   2. IDE integrations (VS Code, IntelliJ) surface SARIF inline
//
// We model the minimum subset needed for those integrations:
//   - One run, with one tool (cyberai), with one ruleset per scanner
//   - Each finding becomes a result with a physical location + ruleId
//
// Full spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

// sarifDoc is the root SARIF document.
type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationUri string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifMessage   `json:"shortDescription,omitempty"`
	FullDescription  sarifMessage   `json:"fullDescription,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
	DefaultConfig    *sarifConfig   `json:"defaultConfiguration,omitempty"`
}

type sarifConfig struct {
	Level sarifLevel `json:"level,omitempty"`
}

type sarifLevel string

const (
	levelError   sarifLevel = "error"
	levelWarning sarifLevel = "warning"
	levelNote    sarifLevel = "note"
	levelNone    sarifLevel = "none"
)

type sarifMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex,omitempty"`
	Level               sarifLevel        `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int           `json:"startLine"`
	EndLine     int           `json:"endLine,omitempty"`
	StartColumn int           `json:"startColumn,omitempty"`
	EndColumn   int           `json:"endColumn,omitempty"`
	Snippet     *sarifSnippet `json:"snippet,omitempty"`
}

type sarifSnippet struct {
	Text string `json:"text"`
}

// SARIF renders the report as SARIF 2.1.0 JSON.
func SARIF(r *Report, toolVersion string) ([]byte, error) {
	// Build rules first (one per unique tool+rule pair), tracking indices.
	rules := []sarifRule{}
	ruleIndex := map[string]int{} // tool+":"+ruleID -> index
	keyOf := func(tool, ruleID string) string {
		return tool + ":" + ruleID
	}
	for _, f := range r.Findings {
		k := keyOf(f.Tool, f.RuleID)
		if _, ok := ruleIndex[k]; ok {
			continue
		}
		idx := len(rules)
		ruleIndex[k] = idx
		rules = append(rules, sarifRule{
			ID:               f.RuleID,
			Name:             f.Title,
			ShortDescription: sarifMessage{Text: f.Title},
			FullDescription:  sarifMessage{Text: f.Description},
			DefaultConfig:    &sarifConfig{Level: severityToSARIF(f.Severity)},
			HelpURI:          firstOrEmpty(f.References),
			Properties: map[string]any{
				"tool": f.Tool,
				"cwe":  f.CWE,
			},
		})
	}

	// Build results, one per finding.
	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		k := keyOf(f.Tool, f.RuleID)
		idx, ok := ruleIndex[k]
		if !ok {
			// Should not happen — we built the index from the same findings.
			continue
		}
		res := sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: idx,
			Level:     severityToSARIF(f.Severity),
			Message:   sarifMessage{Text: f.Title, Markdown: markdownBold(f.Title)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.File},
					Region: sarifRegion{
						StartLine:   f.StartLine,
						EndLine:     nz(f.EndLine, f.StartLine),
						StartColumn: f.Column,
						EndColumn:   0,
						Snippet:     nilOrSnippet(f.Snippet),
					},
				},
			}},
			PartialFingerprints: map[string]string{
				"cyberai/v1": f.ID, // stable cross-run identifier
			},
			Properties: buildSARIFProps(f),
		}
		results = append(results, res)
	}

	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "cyberai",
					InformationUri: "https://github.com/shfahiim/cyberai",
					Version:        toolVersion,
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func severityToSARIF(s model.Severity) sarifLevel {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return levelError
	case model.SeverityMedium:
		return levelWarning
	case model.SeverityLow:
		return levelNote
	}
	return levelNone
}

func buildSARIFProps(f model.Finding) map[string]any {
	p := map[string]any{
		"category":   f.Category,
		"confidence": f.Confidence,
		"tool":       f.Tool,
	}
	if len(f.CVE) > 0 {
		p["cve"] = f.CVE
	}
	if len(f.CWE) > 0 {
		p["cwe"] = f.CWE
	}
	if f.CVSS > 0 {
		p["cvss"] = f.CVSS
	}
	if f.Fix != "" {
		p["fix"] = f.Fix
	}
	if f.FixVersion != "" {
		p["fixVersion"] = f.FixVersion
	}
	if len(f.Metadata) > 0 {
		meta := make(map[string]string, len(f.Metadata))
		for k, v := range f.Metadata {
			meta[k] = v
		}
		p["metadata"] = meta
	}
	return p
}

func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

func nz(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}

func nilOrSnippet(s string) *sarifSnippet {
	if s == "" {
		return nil
	}
	return &sarifSnippet{Text: s}
}

func markdownBold(s string) string {
	// Trivial Markdown emphasis; SARIF consumers that render Markdown
	// (e.g. GitHub) will bold the title.
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return fmt.Sprintf("**%s**", s)
}
