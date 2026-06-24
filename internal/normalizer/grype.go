package normalizer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
)

// grypeReport is the top-level shape of `grype dir:<target> -o json`.
type grypeReport struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability grypeVulnerability `json:"vulnerability"`
	Artifact      grypeArtifact      `json:"artifact"`
}

type grypeVulnerability struct {
	ID          string            `json:"id"`          // e.g. "CVE-2021-44228" or "GHSA-..."
	Severity    string            `json:"severity"`    // Critical/High/Medium/Low/Negligible/Unknown
	Description string            `json:"description"`
	Fix         grypeVulnFix      `json:"fix"`
	URLs        []string          `json:"urls"`
	Advisories  []grypeAdvisory   `json:"advisories"`
	CVSS        []grypeCVSSEntry  `json:"cvss"`
	RelatedVulnerabilities []grypeRelatedVuln `json:"relatedVulnerabilities"`
}

type grypeVulnFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"` // "fixed" | "not-fixed" | "unknown" | "wont-fix"
}

type grypeAdvisory struct {
	ID   string `json:"id"`
	Link string `json:"link"`
}

type grypeCVSSEntry struct {
	Version string  `json:"version"`
	Value   float64 `json:"value"`
}

type grypeRelatedVuln struct {
	ID       string   `json:"id"`
	DataSource string `json:"dataSource"`
}

type grypeArtifact struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"` // e.g. "npm", "python", "go-module"
	Language string `json:"language"`
	Locations []grypeLocation `json:"locations"`
}

type grypeLocation struct {
	Path string `json:"path"`
}

// Grype parses `grype dir:<target> -o json` output into SCA findings.
func Grype(raw []byte) ([]model.Finding, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}

	var report grypeReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse grype JSON: %w", err)
	}

	findings := make([]model.Finding, 0, len(report.Matches))
	for _, m := range report.Matches {
		v := m.Vulnerability
		art := m.Artifact

		// Determine file from artifact locations.
		file := ""
		if len(art.Locations) > 0 {
			file = art.Locations[0].Path
		}

		// Build fix version string.
		fixVersion := ""
		fixStr := ""
		if len(v.Fix.Versions) > 0 && v.Fix.State == "fixed" {
			fixVersion = strings.Join(v.Fix.Versions, ", ")
			fixStr = "Upgrade to " + fixVersion
		}

		// Collect CVEs (ID itself if it starts with CVE-, plus related vulns).
		var cves []string
		if strings.HasPrefix(v.ID, "CVE-") {
			cves = append(cves, v.ID)
		}
		for _, rv := range v.RelatedVulnerabilities {
			if strings.HasPrefix(rv.ID, "CVE-") {
				cves = append(cves, rv.ID)
			}
		}

		// Collect reference URLs.
		refs := make([]string, 0, len(v.URLs)+len(v.Advisories))
		refs = append(refs, v.URLs...)
		for _, adv := range v.Advisories {
			if adv.Link != "" {
				refs = append(refs, adv.Link)
			}
		}

		title := firstNonEmpty(v.Description, fmt.Sprintf("%s in %s", v.ID, art.Name))
		if len(title) > 120 {
			title = title[:120] + "..."
		}

		f := model.Finding{
			Tool:        "grype",
			RuleID:      v.ID,
			Title:       title,
			Description: v.Description,
			Severity:    mapGrypeSeverity(v.Severity),
			Category:    model.CategorySCA,
			File:        file,
			StartLine:   1,
			Snippet:     fmt.Sprintf("%s @ %s", art.Name, art.Version),
			CVE:         cves,
			Fix:         fixStr,
			FixVersion:  fixVersion,
			References:  refs,
			Metadata: map[string]string{
				"package":  art.Name,
				"version":  art.Version,
				"type":     art.Type,
				"language": art.Language,
				"fix_state": v.Fix.State,
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

func mapGrypeSeverity(s string) model.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	case "NEGLIGIBLE":
		return model.SeverityInfo
	}
	return model.SeverityMedium // unknown -> medium
}
