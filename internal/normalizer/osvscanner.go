package normalizer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
)

// osvReport is the top-level shape of `osv-scanner --format json` output.
type osvReport struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source   osvSource    `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"` // e.g. "lockfile"
}

type osvPackage struct {
	Package         osvPkgInfo         `json:"package"`
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
	Groups          []osvGroup         `json:"groups"`
}

type osvPkgInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvVulnerability struct {
	ID       string         `json:"id"`       // OSV ID, e.g. "GHSA-..." or "CVE-..."
	Aliases  []string       `json:"aliases"`  // may contain CVE-* IDs
	Summary  string         `json:"summary"`
	Details  string         `json:"details"`
	Severity []osvSeverity  `json:"severity"`
	Affected []osvAffected  `json:"affected"`
	References []osvReference `json:"references"`
}

type osvSeverity struct {
	Type  string `json:"type"`  // e.g. "CVSS_V3"
	Score string `json:"score"` // CVSS vector string
}

type osvAffected struct {
	Package osvPkgInfo  `json:"package"`
	Ranges  []osvRange  `json:"ranges"`
}

type osvRange struct {
	Type   string      `json:"type"` // "SEMVER" | "GIT" | "ECOSYSTEM"
	Events []osvEvent  `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvGroup struct {
	IDs []string `json:"ids"`
}

// OSVScanner parses `osv-scanner --format json` output into SCA findings.
func OSVScanner(raw []byte) ([]model.Finding, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}

	var report osvReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse osv-scanner JSON: %w", err)
	}

	var findings []model.Finding
	for _, result := range report.Results {
		sourcePath := result.Source.Path
		for _, pkg := range result.Packages {
			for _, vuln := range pkg.Vulnerabilities {
				// Gather CVEs from ID itself or aliases.
				var cves []string
				if strings.HasPrefix(vuln.ID, "CVE-") {
					cves = append(cves, vuln.ID)
				}
				for _, alias := range vuln.Aliases {
					if strings.HasPrefix(alias, "CVE-") {
						cves = append(cves, alias)
					}
				}

				// Extract fix versions from affected ranges events.
				fixVersion := extractOSVFixVersion(vuln.Affected, pkg.Package)
				fixStr := ""
				if fixVersion != "" {
					fixStr = "Upgrade to " + fixVersion
				}

				// Collect references.
				refs := make([]string, 0, len(vuln.References))
				for _, ref := range vuln.References {
					if ref.URL != "" {
						refs = append(refs, ref.URL)
					}
				}

				title := firstNonEmpty(vuln.Summary, vuln.ID)
				desc := firstNonEmpty(vuln.Details, vuln.Summary)

				f := model.Finding{
					Tool:        "osv-scanner",
					RuleID:      vuln.ID,
					Title:       title,
					Description: desc,
					Severity:    mapOSVSeverity(vuln.Severity),
					Category:    model.CategorySCA,
					File:        sourcePath,
					StartLine:   1,
					Snippet:     fmt.Sprintf("%s @ %s", pkg.Package.Name, pkg.Package.Version),
					CVE:         cves,
					Fix:         fixStr,
					FixVersion:  fixVersion,
					References:  refs,
					Metadata: map[string]string{
						"package":   pkg.Package.Name,
						"version":   pkg.Package.Version,
						"ecosystem": pkg.Package.Ecosystem,
					},
				}
				if err := f.Normalize(); err != nil {
					continue
				}
				f.AssignID()
				findings = append(findings, f)
			}
		}
	}
	return findings, nil
}

// extractOSVFixVersion extracts the earliest fix version from the affected
// ranges for the given package.
func extractOSVFixVersion(affected []osvAffected, pkg osvPkgInfo) string {
	for _, aff := range affected {
		// Match on package name (case-insensitive) if possible.
		if aff.Package.Name != "" && !strings.EqualFold(aff.Package.Name, pkg.Name) {
			continue
		}
		for _, r := range aff.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return ""
}

// mapOSVSeverity maps OSV CVSS severity scores into model.Severity.
// OSV doesn't provide a plain severity string; it provides CVSS vectors.
// We default to Medium for now since parsing CVSS vectors is complex.
func mapOSVSeverity(severities []osvSeverity) model.Severity {
	// OSV uses CVSS vector strings; without a full CVSS parser we default
	// to medium unless there's a recognisable prefix in the score string.
	for _, s := range severities {
		score := strings.ToUpper(s.Score)
		// CVSS v3 vectors start with "CVSS:3.x/AV:..." and include a base score.
		// We look for the environmental metric group to find the base score prefix.
		// A simpler heuristic: check for common high-impact severity markers.
		switch {
		case strings.Contains(score, "/AV:N/AC:L/PR:N/UI:N/S:C/C:H"):
			return model.SeverityCritical
		case strings.Contains(score, "/AV:N/AC:L/PR:N/UI:N/S:U/C:H"):
			return model.SeverityHigh
		}
	}
	if len(severities) == 0 {
		return model.SeverityMedium
	}
	return model.SeverityMedium
}
