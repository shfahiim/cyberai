package scanner

import (
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
	"github.com/shfahiim/cyberai/internal/project"
	"github.com/shfahiim/cyberai/internal/router"
)

// BuildOptions controls which scanners are constructed for a scan.
type BuildOptions struct {
	// CategoryEnabled returns true when a scanner category (sast, sca, …) is on.
	CategoryEnabled func(category string) bool
	Profile         *project.Profile
	SemgrepRulesets []string
	TrivyScanners   []string
}

// RegistryEntry describes one scanner the orchestrator can run.
type RegistryEntry struct {
	Name       string
	Category   model.Category
	Categories []string
	When       func(*project.Profile) bool
	Build      func(BuildOptions) NormalizingScanner
}

// Registry returns the declared scanner catalog in stable order.
func Registry() []RegistryEntry {
	return []RegistryEntry{
		{
			Name: "semgrep", Category: model.CategorySAST, Categories: []string{"sast"},
			When: func(*project.Profile) bool { return true },
			Build: func(opts BuildOptions) NormalizingScanner {
				rulesets := opts.SemgrepRulesets
				if len(rulesets) == 0 {
					rulesets = router.DefaultSemgrepRulesets(opts.Profile)
				}
				return &Semgrep{Configs: rulesets}
			},
		},
		{
			Name: "gitleaks", Category: model.CategorySecrets, Categories: []string{"secrets"},
			When: func(*project.Profile) bool { return true },
			Build: func(BuildOptions) NormalizingScanner { return &Gitleaks{} },
		},
		{
			Name: "checkov", Category: model.CategoryIaC, Categories: []string{"iac"},
			When: ProfileHasIaC,
			Build: func(BuildOptions) NormalizingScanner { return &Checkov{} },
		},
		{
			Name: "hadolint", Category: model.CategoryDocker, Categories: []string{"docker"},
			When: func(p *project.Profile) bool { return p != nil && p.HasDocker },
			Build: func(BuildOptions) NormalizingScanner { return &Hadolint{} },
		},
		{
			Name: "zizmor", Category: model.CategoryCICD, Categories: []string{"cicd"},
			When: func(p *project.Profile) bool { return p != nil && p.HasCI },
			Build: func(BuildOptions) NormalizingScanner { return &Zizmor{} },
		},
		{
			Name: "actionlint", Category: model.CategoryCICD, Categories: []string{"cicd"},
			When: func(p *project.Profile) bool { return p != nil && p.HasCI },
			Build: func(BuildOptions) NormalizingScanner { return &Actionlint{} },
		},
		{
			Name: "grype", Category: model.CategorySCA, Categories: []string{"sca"},
			When: func(*project.Profile) bool { return true },
			Build: func(BuildOptions) NormalizingScanner { return &Grype{} },
		},
		{
			Name: "osv-scanner", Category: model.CategorySCA, Categories: []string{"sca"},
			When: func(*project.Profile) bool { return true },
			Build: func(BuildOptions) NormalizingScanner { return &OSVScanner{} },
		},
		{
			Name: "govulncheck", Category: model.CategorySCA, Categories: []string{"sca"},
			When: func(p *project.Profile) bool { return HasLanguage(p, "go") },
			Build: func(BuildOptions) NormalizingScanner { return &Govulncheck{} },
		},
	}
}

// BuildAll returns scanners enabled by category flags and project profile.
func BuildAll(opts BuildOptions) []NormalizingScanner {
	if opts.CategoryEnabled == nil {
		return nil
	}
	var out []NormalizingScanner
	for _, entry := range Registry() {
		if !categoryEnabled(opts.CategoryEnabled, entry.Categories) {
			continue
		}
		if entry.When != nil && !entry.When(opts.Profile) {
			continue
		}
		out = append(out, entry.Build(opts))
	}

	trivyScanners := buildTrivyScanners(opts)
	if len(trivyScanners) > 0 {
		out = append(out, &Trivy{Scanners: trivyScanners})
	}
	return out
}

func categoryEnabled(enabled func(string) bool, categories []string) bool {
	for _, c := range categories {
		if enabled(c) {
			return true
		}
	}
	return false
}

func buildTrivyScanners(opts BuildOptions) []string {
	trivyScanners := []string{}
	if opts.CategoryEnabled("sca") {
		trivyScanners = append(trivyScanners, "vuln")
	}
	if opts.CategoryEnabled("iac") {
		trivyScanners = append(trivyScanners, "misconfig")
	}
	if opts.CategoryEnabled("license") {
		trivyScanners = append(trivyScanners, "license")
	}
	for _, s := range opts.TrivyScanners {
		if !trivyScannerAllowed(opts.CategoryEnabled, s) {
			continue
		}
		found := false
		for _, e := range trivyScanners {
			if e == s {
				found = true
				break
			}
		}
		if !found {
			trivyScanners = append(trivyScanners, s)
		}
	}
	return trivyScanners
}

func trivyScannerAllowed(enabled func(string) bool, scannerName string) bool {
	switch scannerName {
	case "vuln":
		return enabled("sca")
	case "misconfig":
		return enabled("iac")
	case "license":
		return enabled("license")
	default:
		return false
	}
}

func ProfileHasIaC(p *project.Profile) bool {
	if p == nil {
		return false
	}
	return p.HasTerraform || p.HasK8s || p.HasAnsible || p.HasDocker || p.HasCI
}

func HasLanguage(p *project.Profile, lang string) bool {
	if p == nil {
		return false
	}
	for _, l := range p.Languages {
		if strings.EqualFold(l, lang) {
			return true
		}
	}
	return false
}
