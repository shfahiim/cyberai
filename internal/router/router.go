// Package router decides which scanners and rules to enable based on a
// quick look at the project. It sits in front of the deterministic scanner
// pipeline; the scanners themselves do the actual work.
//
// The router takes a ProjectProfile (deterministic) and returns a ScanPlan
// (which scanners to run, which rulesets, severity threshold, ignore
// patterns). The plan is cached per project_hash so re-running on the same
// repo costs zero LLM calls.
//
// Two implementations live in this package:
//
//   - DefaultRouter: returns a sensible plan based on the profile alone,
//     without any LLM call. Used when --no-llm is set, when no API key is
//     available, or when the LLM call fails.
//
//   - GeminiRouter (in gemini.go): one Gemini 2.5 Flash call with structured
//     JSON output mode, with a graceful fallback to DefaultRouter on any
//     error.
//
// Both implementations satisfy the Router interface so the rest of the
// pipeline doesn't care which one is active.
package router

import (
	"fmt"
	"time"

	"github.com/shfahiim/cyberai/internal/project"
)

// ScanPlan is the router's decision. It's the contract between the LLM
// (or default) router and the orchestrator.
//
// The orchestrator uses Scanners to pick tools; SeverityThreshold and
// IgnorePatterns are passed through to the report-filtering step.
type ScanPlan struct {
	// Scanners lists the categories to run. Valid values:
	// "sast", "secrets", "sca", "iac", "license", "docker", "cicd".
	Scanners []string `json:"scanners"`

	// SemgrepRulesets is the list of semgrep rulesets to enable, e.g.
	// ["p/golang", "p/security-audit"]. Empty = semgrep auto-selects.
	SemgrepRulesets []string `json:"semgrep_rulesets"`

	// GitleaksConfig is the path to a custom gitleaks config; "default"
	// means use the built-in rule set.
	GitleaksConfig string `json:"gitleaks_config"`

	// TrivyScanners are the trivy --scanners values to enable, e.g.
	// ["vuln", "misconfig", "license"].
	TrivyScanners []string `json:"trivy_scanners"`

	// SeverityThreshold is the minimum severity to surface, e.g. "low".
	SeverityThreshold string `json:"severity_threshold"`

	// IgnorePatterns are additional globs to suppress findings on.
	IgnorePatterns []string `json:"ignore_patterns"`

	// Reasoning is a one-paragraph human explanation of why this plan was
	// chosen. The CLI prints it with --verbose; it's also embedded in
	// scan reports so users can audit the LLM's decisions.
	Reasoning string `json:"reasoning"`

	// ProjectHash is the cache key (from project.Profile.Hash()).
	ProjectHash string `json:"project_hash"`

	// FromCache is true if this plan was loaded from disk instead of
	// freshly generated. Logged for visibility.
	FromCache bool `json:"from_cache"`

	// Source identifies which router produced this plan ("default" or
	// "gemini" or "cache"). Logged for transparency.
	Source string `json:"source"`

	// GeneratedAt is when the plan was produced.
	GeneratedAt time.Time `json:"generated_at"`
}

// Router is the interface every implementation satisfies.
type Router interface {
	// Route returns a ScanPlan for the given profile.
	Route(profile *project.Profile) (*ScanPlan, error)
	// Name returns the router's identity ("default", "gemini", ...).
	Name() string
}

// DefaultRouter produces a plan without any LLM call. The plan is
// safe-but-broad: it enables every scanner that has any signal in the
// profile, uses language-specific Semgrep configs when known, and a
// low severity threshold.
type DefaultRouter struct{}

// NewDefault builds a DefaultRouter.
func NewDefault() *DefaultRouter { return &DefaultRouter{} }

func (d *DefaultRouter) Name() string { return "default" }

func (d *DefaultRouter) Route(p *project.Profile) (*ScanPlan, error) {
	if p == nil {
		return nil, fmt.Errorf("router: nil profile")
	}

	scanners := []string{"sast", "secrets", "sca"}

	// Enable IaC only when there's actual IaC to scan. Without it,
	// trivy runs vuln+misconfig+secret for nothing.
	if p.HasTerraform || p.HasAnsible || p.HasK8s || p.HasDocker {
		scanners = append(scanners, "iac")
	}
	if p.HasDocker {
		scanners = append(scanners, "docker")
	}
	if p.HasCI {
		scanners = append(scanners, "cicd")
	}
	// License scanning only when there's a manifest we can scan.
	if len(p.Manifests) > 0 {
		scanners = append(scanners, "license")
	}

	// Language-specific semgrep configs (mirrors what buildScanners does
	// in the CLI — we duplicate here so the router's plan is the source
	// of truth).
	rulesets := []string{"p/security-audit", "p/owasp-top-ten"}
	for _, lang := range p.Languages {
		switch lang {
		case "go":
			rulesets = append(rulesets, "p/golang")
		case "javascript":
			rulesets = append(rulesets, "p/javascript", "p/nodejs")
		case "typescript":
			rulesets = append(rulesets, "p/typescript")
		case "python":
			rulesets = append(rulesets, "p/python")
		case "rust":
			rulesets = append(rulesets, "p/rust")
		case "java":
			rulesets = append(rulesets, "p/java")
		case "ruby":
			rulesets = append(rulesets, "p/ruby")
		case "php":
			rulesets = append(rulesets, "p/php")
		}
	}

	trivyScanners := []string{"vuln", "misconfig"}
	if len(p.Manifests) > 0 {
		trivyScanners = append(trivyScanners, "license")
	}

	reasoning := fmt.Sprintf(
		"default plan: %d languages (%v), %d manifests, IaC=%v, container=%v. Enabled scanners=%v, semgrep rulesets=%d.",
		len(p.Languages), p.Languages, len(p.Manifests),
		p.HasTerraform || p.HasAnsible || p.HasK8s,
		p.HasDocker, scanners, len(rulesets))

	return &ScanPlan{
		Scanners:          scanners,
		SemgrepRulesets:   rulesets,
		GitleaksConfig:    "default",
		TrivyScanners:     trivyScanners,
		SeverityThreshold: "low",
		IgnorePatterns:    nil,
		Reasoning:         reasoning,
		ProjectHash:       p.Hash(),
		FromCache:         false,
		Source:            "default",
		GeneratedAt:       time.Now().UTC(),
	}, nil
}
