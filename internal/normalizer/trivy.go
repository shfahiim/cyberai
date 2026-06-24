package normalizer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
)

// trivyReport is the top-level shape of `trivy fs --format json`.
//
// Trivy emits an array of these when given multiple targets, but with a
// single fs target we get a single object. The normalizer accepts both.
type trivyReport struct {
	ArtifactName string        `json:"ArtifactName"`
	ArtifactType string        `json:"ArtifactType"`
	Results      []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target            string           `json:"Target"`
	Class             string           `json:"Class"` // "os-pkgs", "lang-pkgs", "config", "secret", "license"
	Type              string           `json:"Type"`  // e.g. "npm", "pip", "terraform"
	Vulnerabilities   []trivyVuln      `json:"Vulnerabilities"`
	Misconfigurations []trivyMisconfig `json:"Misconfigurations"`
	Secrets           []trivySecret    `json:"Secrets"`
}

type trivyVuln struct {
	VulnerabilityID  string               `json:"VulnerabilityID"` // CVE-XXXX-XXXX or GHSA-...
	PkgName          string               `json:"PkgName"`
	InstalledVersion string               `json:"InstalledVersion"`
	FixedVersion     string               `json:"FixedVersion"`
	Severity         string               `json:"Severity"` // CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN
	Title            string               `json:"Title"`
	Description      string               `json:"Description"`
	References       []string             `json:"References"`
	CVSS             map[string]trivyCVSS `json:"CVSS"`
	CweIDs           []string             `json:"CweIDs"`
}

type trivyCVSS struct {
	V3Score float64 `json:"V3Score"`
}

type trivyMisconfig struct {
	ID          string   `json:"ID"` // e.g. "AVD-AWS-0001"
	AVDID       string   `json:"AVDID"`
	Title       string   `json:"Title"`
	Description string   `json:"Description"`
	Severity    string   `json:"Severity"`
	Resolution  string   `json:"Resolution"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	References  []string `json:"References"`
}

type trivySecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match"`
}

// Trivy parses the JSON output of `trivy fs --format json` into Findings.
// It handles both single-report and array-of-reports output.
//
// Per-finding category is derived from trivy's `Class` field:
//   - os-pkgs | lang-pkgs -> CategorySCA
//   - config               -> CategoryIaC
//   - secret               -> CategorySecrets
//   - license              -> CategoryLicense
func Trivy(raw []byte) ([]model.Finding, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}

	// Array form: [report, report, ...]
	if strings.HasPrefix(trimmed, "[") {
		var reports []trivyReport
		if err := json.Unmarshal(raw, &reports); err != nil {
			return nil, fmt.Errorf("parse trivy JSON array: %w", err)
		}
		var out []model.Finding
		for _, r := range reports {
			out = append(out, trivyResultToFindings(r)...)
		}
		return out, nil
	}

	// Single-report form.
	var report trivyReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("parse trivy JSON: %w", err)
	}
	return trivyResultToFindings(report), nil
}

func trivyResultToFindings(rep trivyReport) []model.Finding {
	var out []model.Finding
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			out = append(out, trivyVulnToFinding(v, r))
		}
		for _, m := range r.Misconfigurations {
			out = append(out, trivyMisconfigToFinding(m, r))
		}
		for _, s := range r.Secrets {
			out = append(out, trivySecretToFinding(s, r))
		}
	}
	return out
}

func trivyVulnToFinding(v trivyVuln, r trivyResult) model.Finding {
	severity := mapTrivySeverity(v.Severity)
	desc := v.Description
	if desc == "" {
		desc = v.Title
	}
	fix := v.FixedVersion
	var fixStr string
	if fix != "" {
		fixStr = "Upgrade to " + fix
	}
	return model.Finding{
		Tool:        "trivy",
		RuleID:      v.VulnerabilityID,
		Title:       firstNonEmpty(v.Title, fmt.Sprintf("%s in %s", v.VulnerabilityID, v.PkgName)),
		Description: desc,
		Severity:    severity,
		Category:    trivyClassToCategory(r.Class),
		File:        r.Target,
		StartLine:   1, // trivy reports package-level, not file-line
		Snippet:     fmt.Sprintf("%s @ %s", v.PkgName, v.InstalledVersion),
		CVE:         []string{v.VulnerabilityID},
		CWE:         v.CweIDs,
		CVSS:        pickMaxCVSS(v.CVSS),
		Fix:         fixStr,
		FixVersion:  fix,
		References:  v.References,
		Metadata: map[string]string{
			"scanner": r.Type,
			"class":   r.Class,
			"package": v.PkgName,
		},
	}
}

func trivyMisconfigToFinding(m trivyMisconfig, r trivyResult) model.Finding {
	return model.Finding{
		Tool:        "trivy",
		RuleID:      m.ID,
		Title:       m.Title,
		Description: m.Description,
		Severity:    mapTrivySeverity(m.Severity),
		Category:    model.CategoryIaC,
		File:        r.Target,
		StartLine:   m.StartLine,
		EndLine:     m.EndLine,
		Snippet:     m.Resolution,
		Fix:         m.Resolution,
		References:  m.References,
		Metadata: map[string]string{
			"scanner": "misconfig",
			"avdid":   m.AVDID,
		},
	}
}

func trivySecretToFinding(s trivySecret, r trivyResult) model.Finding {
	return model.Finding{
		Tool:        "trivy",
		RuleID:      s.RuleID,
		Title:       firstNonEmpty(s.Title, "Secret: "+s.RuleID),
		Description: s.Title,
		Severity:    mapTrivySeverity(s.Severity),
		Category:    model.CategorySecrets,
		File:        r.Target,
		StartLine:   s.StartLine,
		EndLine:     s.EndLine,
		Snippet:     redactTrivySecretMatch(s.Match),
		Metadata: map[string]string{
			"scanner":  "secret",
			"category": s.Category,
		},
	}
}

func redactTrivySecretMatch(match string) string {
	match = strings.TrimSpace(match)
	if match == "" {
		return ""
	}
	return fmt.Sprintf("[redacted secret match, %d chars]", len(match))
}

func mapTrivySeverity(s string) model.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	}
	return model.SeverityMedium // unknown -> medium, visible but not alarming
}

func trivyClassToCategory(class string) model.Category {
	switch class {
	case "os-pkgs", "lang-pkgs":
		return model.CategorySCA
	case "config":
		return model.CategoryIaC
	case "secret":
		return model.CategorySecrets
	case "license":
		return model.CategoryLicense
	}
	return model.CategorySCA // sane default
}

// pickMaxCVSS returns the highest V3 score across all CVSS sources, or 0.
func pickMaxCVSS(m map[string]trivyCVSS) float64 {
	if len(m) == 0 {
		return 0
	}
	scores := make([]float64, 0, len(m))
	for _, c := range m {
		if c.V3Score > 0 {
			scores = append(scores, c.V3Score)
		}
	}
	if len(scores) == 0 {
		return 0
	}
	sort.Float64s(scores)
	return scores[len(scores)-1]
}
