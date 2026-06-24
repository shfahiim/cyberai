package normalizer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
)

// actionlintFinding is one entry in the JSON array emitted by
// `actionlint -format '{{json .}}'`.
type actionlintFinding struct {
	Filepath string          `json:"filepath"`
	Line     int             `json:"line"`
	Column   int             `json:"col"`
	Message  string          `json:"message"`
	Kind     string          `json:"kind"`
}

// Actionlint parses `actionlint -format '{{json .}}'` output into CI/CD findings.
func Actionlint(raw []byte) ([]model.Finding, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "[]" || trimmed == "null" {
		return nil, nil
	}

	var arr []actionlintFinding
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("parse actionlint JSON: %w", err)
	}

	findings := make([]model.Finding, 0, len(arr))
	for _, a := range arr {
		ruleID := firstNonEmpty(a.Kind, "actionlint")
		title := firstNonEmpty(a.Message, ruleID)

		f := model.Finding{
			Tool:        "actionlint",
			RuleID:      ruleID,
			Title:       title,
			Description: a.Message,
			Severity:    model.SeverityMedium, // actionlint doesn't report severity; default to medium
			Category:    model.CategoryCICD,
			File:        a.Filepath,
			StartLine:   a.Line,
			Column:      a.Column,
			Metadata: map[string]string{
				"kind": a.Kind,
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
