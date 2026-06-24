package normalizer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
)

type sarifLog struct {
	Runs []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Name  string      `json:"name"`
			Rules []sarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	FullDescription  sarifMessage    `json:"fullDescription"`
	HelpURI          string          `json:"helpUri"`
	Properties       sarifProperties `json:"properties"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine   int `json:"startLine"`
			EndLine     int `json:"endLine"`
			StartColumn int `json:"startColumn"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

type sarifProperties struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
}

// SARIF parses a generic SARIF log into CyberAI findings.
func SARIF(raw []byte, fallbackTool string, category model.Category) ([]model.Finding, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	var log sarifLog
	if err := json.Unmarshal(raw, &log); err != nil {
		return nil, fmt.Errorf("parse SARIF: %w", err)
	}
	var findings []model.Finding
	for _, run := range log.Runs {
		tool := firstNonEmpty(strings.ToLower(run.Tool.Driver.Name), fallbackTool)
		rules := map[string]sarifRule{}
		for _, r := range run.Tool.Driver.Rules {
			rules[r.ID] = r
		}
		for _, res := range run.Results {
			rule := rules[res.RuleID]
			loc := firstSARIFLocation(res.Locations)
			f := model.Finding{
				Tool:        fallbackTool,
				RuleID:      res.RuleID,
				Title:       firstNonEmpty(rule.ShortDescription.Text, rule.Name, res.Message.Text, res.RuleID),
				Description: firstNonEmpty(res.Message.Text, rule.FullDescription.Text, rule.ShortDescription.Text),
				Severity:    mapSARIFSeverity(res.Level, rule.Properties.SecuritySeverity),
				Category:    category,
				File:        loc.file,
				StartLine:   loc.startLine,
				EndLine:     loc.endLine,
				Column:      loc.column,
				References:  nonEmptyStrings(rule.HelpURI),
				Metadata: map[string]string{
					"sarif_tool": tool,
					"tags":       strings.Join(rule.Properties.Tags, ","),
				},
			}
			if err := f.Normalize(); err != nil {
				continue
			}
			f.AssignID()
			findings = append(findings, f)
		}
	}
	return findings, nil
}

type sarifLoc struct {
	file      string
	startLine int
	endLine   int
	column    int
}

func firstSARIFLocation(locations []sarifLocation) sarifLoc {
	if len(locations) == 0 {
		return sarifLoc{file: "unknown", startLine: 1}
	}
	p := locations[0].PhysicalLocation
	return sarifLoc{
		file:      p.ArtifactLocation.URI,
		startLine: p.Region.StartLine,
		endLine:   p.Region.EndLine,
		column:    p.Region.StartColumn,
	}
}

func mapSARIFSeverity(level, securitySeverity string) model.Severity {
	if securitySeverity != "" {
		if score, err := strconv.ParseFloat(securitySeverity, 64); err == nil {
			switch {
			case score >= 9:
				return model.SeverityCritical
			case score >= 7:
				return model.SeverityHigh
			case score >= 4:
				return model.SeverityMedium
			case score > 0:
				return model.SeverityLow
			}
		}
	}
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return model.SeverityHigh
	case "warning":
		return model.SeverityMedium
	case "note":
		return model.SeverityLow
	case "none":
		return model.SeverityInfo
	}
	return model.SeverityMedium
}
