package normalizer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
)

type govulnMessage struct {
	Config  *govulnConfig   `json:"config,omitempty"`
	OSV     *govulnOSV      `json:"osv,omitempty"`
	Finding *govulnFinding  `json:"finding,omitempty"`
}

type govulnConfig struct {
	GoVersion string `json:"go_version"`
}

type govulnOSV struct {
	ID         string         `json:"id"`
	Aliases    []string       `json:"aliases,omitempty"`
	Summary    string         `json:"summary,omitempty"`
	Details    string         `json:"details,omitempty"`
	Severity   []osvSeverity  `json:"severity,omitempty"`
	Affected   []osvAffected  `json:"affected,omitempty"`
	References []osvReference `json:"references,omitempty"`
}

type govulnFinding struct {
	OSV          string        `json:"osv"`
	FixedVersion string        `json:"fixed_version,omitempty"`
	Trace        []govulnFrame `json:"trace,omitempty"`
}

type govulnFrame struct {
	Package  string         `json:"package"`
	Function string         `json:"function"`
	Position govulnPosition `json:"position,omitempty"`
}

type govulnPosition struct {
	Filename string `json:"filename"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

// Govulncheck parses `govulncheck -json ./...` streaming JSON Lines output.
func Govulncheck(raw []byte) ([]model.Finding, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}

	lines := strings.Split(trimmed, "\n")
	osvs := make(map[string]*govulnOSV)
	var rawFindings []*govulnFinding

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var msg govulnMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		if msg.OSV != nil && msg.OSV.ID != "" {
			osvs[msg.OSV.ID] = msg.OSV
		}
		if msg.Finding != nil && msg.Finding.OSV != "" {
			rawFindings = append(rawFindings, msg.Finding)
		}
	}

	var findings []model.Finding
	for _, rf := range rawFindings {
		osvEntry := osvs[rf.OSV]

		var cves []string
		if strings.HasPrefix(rf.OSV, "CVE-") {
			cves = append(cves, rf.OSV)
		}
		var summary, details string
		var osvSeverityList []osvSeverity
		var refs []string

		if osvEntry != nil {
			for _, alias := range osvEntry.Aliases {
				if strings.HasPrefix(alias, "CVE-") {
					cves = append(cves, alias)
				}
			}
			summary = osvEntry.Summary
			details = osvEntry.Details
			osvSeverityList = osvEntry.Severity
			for _, ref := range osvEntry.References {
				if ref.URL != "" {
					refs = append(refs, ref.URL)
				}
			}
		}

		title := summary
		if title == "" {
			title = fmt.Sprintf("Reachable Go vulnerability %s", rf.OSV)
		}
		desc := details
		if desc == "" {
			desc = title
		}

		// Find call site in user's package
		file := "go.mod"
		lineNum := 1
		var snippet string

		if len(rf.Trace) > 0 {
			for _, frame := range rf.Trace {
				if frame.Position.Filename != "" && frame.Position.Line > 0 {
					file = frame.Position.Filename
					lineNum = frame.Position.Line
					snippet = fmt.Sprintf("pkg: %s, fn: %s", frame.Package, frame.Function)
					break
				}
			}
		}

		fixStr := ""
		if rf.FixedVersion != "" {
			fixStr = "Upgrade to " + rf.FixedVersion
		}

		f := model.Finding{
			Tool:        "govulncheck",
			RuleID:      rf.OSV,
			Title:       title,
			Description: desc,
			Severity:    mapOSVSeverity(osvSeverityList),
			Category:    model.CategorySCA,
			File:        file,
			StartLine:   lineNum,
			Snippet:     snippet,
			CVE:         cves,
			Fix:         fixStr,
			FixVersion:  rf.FixedVersion,
			References:  refs,
			Metadata: map[string]string{
				"vulnerability": rf.OSV,
			},
		}

		// Govulncheck findings are reachable by definition.
		reachable := true
		f.IsReachable = &reachable

		if err := f.Normalize(); err != nil {
			continue
		}
		f.AssignID()
		findings = append(findings, f)
	}

	return findings, nil
}
