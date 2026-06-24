package normalizer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
)

type checkovOutput struct {
	Results checkovResults `json:"results"`
}

type checkovResults struct {
	FailedChecks []checkovCheck `json:"failed_checks"`
}

type checkovCheck struct {
	CheckID     string `json:"check_id"`
	CheckName   string `json:"check_name"`
	CheckResult struct {
		Result string `json:"result"`
	} `json:"check_result"`
	FilePath      string   `json:"file_path"`
	FileLineRange []int    `json:"file_line_range"`
	Resource      string   `json:"resource"`
	Guideline     string   `json:"guideline"`
	Severity      string   `json:"severity"`
	CheckClass    string   `json:"check_class"`
	BCCheckID     string   `json:"bc_check_id"`
	RepoFilePath  string   `json:"repo_file_path"`
	CodeBlock     [][]any  `json:"code_block"`
	CWE           []string `json:"cwe"`
}

// Checkov parses `checkov -o json` output into IaC findings.
func Checkov(raw []byte) ([]model.Finding, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	var list []checkovOutput
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("parse checkov JSON array: %w", err)
		}
	} else {
		var out checkovOutput
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("parse checkov JSON object: %w", err)
		}
		list = []checkovOutput{out}
	}

	var allChecks []checkovCheck
	for _, item := range list {
		allChecks = append(allChecks, item.Results.FailedChecks...)
	}

	findings := make([]model.Finding, 0, len(allChecks))
	for _, c := range allChecks {
		file := firstNonEmpty(c.RepoFilePath, c.FilePath)
		start, end := lineRange(c.FileLineRange)
		desc := c.CheckName
		if c.Resource != "" {
			desc = fmt.Sprintf("%s\nResource: %s", c.CheckName, c.Resource)
		}
		f := model.Finding{
			Tool:        "checkov",
			RuleID:      firstNonEmpty(c.CheckID, c.BCCheckID),
			Title:       firstNonEmpty(c.CheckName, c.CheckID),
			Description: desc,
			Severity:    mapCheckovSeverity(c.Severity),
			Category:    model.CategoryIaC,
			File:        strings.TrimPrefix(file, "/"),
			StartLine:   start,
			EndLine:     end,
			Snippet:     checkovSnippet(c.CodeBlock),
			CWE:         c.CWE,
			References:  nonEmptyStrings(c.Guideline),
			Metadata: map[string]string{
				"resource":    c.Resource,
				"check_class": c.CheckClass,
			},
		}
		if err := f.Normalize(); err != nil {
			continue
		}
		f.AssignID()
		findings = append(findings, f)
	}
	return findings, nil
}

func mapCheckovSeverity(s string) model.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM", "MODERATE":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	case "INFO", "INFORMATIONAL":
		return model.SeverityInfo
	}
	// Checkov community checks often omit severity. Keep them visible.
	return model.SeverityMedium
}

func lineRange(lines []int) (int, int) {
	if len(lines) == 0 {
		return 1, 0
	}
	if len(lines) == 1 {
		return lines[0], 0
	}
	return lines[0], lines[1]
}

func checkovSnippet(block [][]any) string {
	if len(block) == 0 {
		return ""
	}
	var lines []string
	for _, row := range block {
		if len(row) < 2 {
			continue
		}
		if s, ok := row[1].(string); ok {
			lines = append(lines, strings.TrimRight(s, "\n"))
		}
	}
	return strings.Join(lines, "\n")
}

func nonEmptyStrings(values ...string) []string {
	var out []string
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}
