package normalizer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
)

type hadolintFinding struct {
	Code    string `json:"code"`
	Column  int    `json:"column"`
	File    string `json:"file"`
	Level   string `json:"level"`
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// Hadolint parses `hadolint --format json` output into Docker findings.
func Hadolint(raw []byte) ([]model.Finding, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "[]" {
		return nil, nil
	}
	var arr []hadolintFinding
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("parse hadolint JSON: %w", err)
	}
	findings := make([]model.Finding, 0, len(arr))
	for _, h := range arr {
		f := model.Finding{
			Tool:        "hadolint",
			RuleID:      h.Code,
			Title:       firstNonEmpty(h.Message, h.Code),
			Description: h.Message,
			Severity:    mapHadolintLevel(h.Level),
			Category:    model.CategoryDocker,
			File:        h.File,
			StartLine:   h.Line,
			Column:      h.Column,
			Metadata: map[string]string{
				"level": h.Level,
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

func mapHadolintLevel(level string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return model.SeverityHigh
	case "warning":
		return model.SeverityMedium
	case "info":
		return model.SeverityLow
	case "style", "ignore":
		return model.SeverityInfo
	}
	return model.SeverityMedium
}
