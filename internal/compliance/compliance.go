// Package compliance filters findings by normalized compliance/framework tags.
package compliance

import (
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
)

// frameworkPrefixes maps user-facing framework names to tag prefixes.
var frameworkPrefixes = map[string]string{
	"owasp-top-10":  "OWASP:",
	"owasp":         "OWASP:",
	"cwe-top-25":    "CWE-25",
	"cwe-25":        "CWE-25",
	"pci-dss":       "PCI-DSS:",
	"pci":           "PCI-DSS:",
	"soc-2":         "SOC-2:",
	"soc2":          "SOC-2:",
	"hipaa":           "HIPAA:",
	"iso-27001":     "ISO-27001:",
	"iso27001":      "ISO-27001:",
	"nist-800-53":   "NIST-800-53:",
	"nist80053":     "NIST-800-53:",
}

// ParseFilters splits and normalizes comma-separated compliance filters.
func ParseFilters(raw []string) []string {
	var out []string
	for _, part := range raw {
		for _, item := range strings.Split(part, ",") {
			item = normalizeFilter(item)
			if item != "" {
				out = append(out, item)
			}
		}
	}
	return out
}

func normalizeFilter(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// Matches reports whether any of the finding's compliance tags satisfy a filter.
func Matches(tags []string, filter string) bool {
	filter = normalizeFilter(filter)
	if filter == "" {
		return true
	}
	prefix, known := frameworkPrefixes[filter]
	for _, tag := range tags {
		tagLower := strings.ToLower(tag)
		if known {
			if strings.HasPrefix(tagLower, strings.ToLower(prefix)) {
				return true
			}
			continue
		}
		if tagLower == filter || strings.Contains(tagLower, filter) {
			return true
		}
	}
	return false
}

// FilterFindings returns findings that match at least one compliance filter.
// An empty filter list returns the input unchanged.
func FilterFindings(findings []model.Finding, filters []string) []model.Finding {
	filters = ParseFilters(filters)
	if len(filters) == 0 {
		return findings
	}
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		for _, filter := range filters {
			if Matches(f.ComplianceTags, filter) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}
