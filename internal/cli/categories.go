package cli

import (
	"fmt"
	"strings"
)

// categoryAliases maps user-friendly names to internal scanner category IDs.
var categoryAliases = map[string]string{
	"code":           "sast",
	"sast":           "sast",
	"secrets":        "secrets",
	"secret":         "secrets",
	"sca":            "sca",
	"dependencies":   "sca",
	"deps":           "sca",
	"dependency":     "sca",
	"iac":            "iac",
	"infrastructure": "iac",
	"infra":          "iac",
	"license":        "license",
	"licenses":       "license",
	"docker":         "docker",
	"containers":     "docker",
	"container":      "docker",
	"cicd":           "cicd",
	"ci-cd":          "cicd",
	"pipelines":      "cicd",
	"pipeline":       "cicd",
	"actions":        "cicd",
}

// normalizeCategories expands comma-separated aliases into canonical category names.
func normalizeCategories(categories []string) ([]string, error) {
	if len(categories) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range categories {
		for _, part := range strings.Split(raw, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			if part == "" {
				continue
			}
			canonical, ok := categoryAliases[part]
			if !ok {
				return nil, fmt.Errorf("unknown scanner category %q (try: sast, secrets, sca, iac, docker, cicd, license)", part)
			}
			if seen[canonical] {
				continue
			}
			seen[canonical] = true
			out = append(out, canonical)
		}
	}
	return out, nil
}
