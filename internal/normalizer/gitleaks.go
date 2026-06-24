package normalizer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
)

// gitleaksFinding is the JSON shape gitleaks writes per detected secret.
// See https://github.com/gitleaks/gitleaks/blob/master/report/finding.go
type gitleaksFinding struct {
	Description string   `json:"Description"`
	RuleID      string   `json:"RuleID"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	SymlinkFile string   `json:"SymlinkFile"`
	Commit      string   `json:"Commit"`
	Entropy     float32  `json:"Entropy"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Author      string   `json:"Author"`
	Email       string   `json:"Email"`
	Date        string   `json:"Date"`
	Tags        []string `json:"Tags"`
}

// Gitleaks parses the JSON output of `gitleaks detect --report-format json`.
// The output is either:
//   - A single finding object, or
//   - An array of finding objects, or
//   - An empty string (no findings).
//
// We accept all three. Empty → zero findings.
func Gitleaks(raw []byte) ([]model.Finding, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "[]" {
		return nil, nil
	}

	// Try array first; if that fails, try a single object.
	var arr []gitleaksFinding
	if err := json.Unmarshal(raw, &arr); err == nil {
		return gitleaksToFindings(arr), nil
	}
	var one gitleaksFinding
	if err := json.Unmarshal(raw, &one); err == nil && one.RuleID != "" {
		return gitleaksToFindings([]gitleaksFinding{one}), nil
	}
	return nil, fmt.Errorf("parse gitleaks JSON: unrecognised shape")
}

func gitleaksToFindings(in []gitleaksFinding) []model.Finding {
	out := make([]model.Finding, 0, len(in))
	for _, g := range in {
		// Redact the actual secret in the snippet; never embed raw secrets
		// in reports that may be shared.
		snippet := g.Match
		if g.Secret != "" {
			snippet = redactSecret(g.Match, g.Secret)
		}

		f := model.Finding{
			Tool:        "gitleaks",
			RuleID:      g.RuleID,
			Title:       firstNonEmpty(g.Description, "Hardcoded secret: "+g.RuleID),
			Description: g.Description,
			Severity:    mapGitleaksSeverity(g),
			Category:    model.CategorySecrets,
			File:        g.File,
			StartLine:   g.StartLine,
			EndLine:     g.EndLine,
			Column:      g.StartColumn,
			Snippet:     snippet,
			Metadata: map[string]string{
				"entropy": fmt.Sprintf("%.2f", g.Entropy),
			},
		}
		if g.Commit != "" {
			f.Metadata["commit"] = g.Commit
		}
		if len(g.Tags) > 0 {
			f.Metadata["tags"] = strings.Join(g.Tags, ",")
		}
		_ = f.Normalize() // silently skip findings missing file/rule
		if f.File == "" || f.RuleID == "" {
			continue
		}
		f.AssignID()
		out = append(out, f)
	}
	return out
}

func mapGitleaksSeverity(g gitleaksFinding) model.Severity {
	haystack := strings.ToLower(strings.Join(append([]string{g.RuleID, g.Description}, g.Tags...), " "))
	switch {
	case strings.Contains(haystack, "private-key") ||
		strings.Contains(haystack, "private key") ||
		strings.Contains(haystack, "aws-access-token") ||
		strings.Contains(haystack, "aws") && strings.Contains(haystack, "secret"):
		return model.SeverityCritical
	case strings.Contains(haystack, "github") ||
		strings.Contains(haystack, "gitlab") ||
		strings.Contains(haystack, "slack") ||
		strings.Contains(haystack, "stripe") ||
		strings.Contains(haystack, "token"):
		return model.SeverityHigh
	case g.Entropy > 0 && g.Entropy < 3.5:
		return model.SeverityLow
	case strings.Contains(haystack, "generic"):
		return model.SeverityMedium
	}
	return model.SeverityHigh
}

// redactSecret replaces the secret value in match with a short mask,
// preserving enough context (e.g. "AKIA****XXXX") to identify what
// was leaked without exposing it. If secret isn't in match, we just
// truncate the match.
func redactSecret(match, secret string) string {
	if secret == "" {
		if len(match) > 80 {
			return match[:80] + "…"
		}
		return match
	}
	// Show first 4 + last 4 chars of the secret, with stars between.
	if len(secret) <= 12 {
		return strings.Replace(match, secret, "***", 1)
	}
	mask := secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
	return strings.Replace(match, secret, mask, 1)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
