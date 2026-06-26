package scanner

import (
	"testing"

	"github.com/shfahiim/cyberai/internal/project"
)

func TestBuildAll_RespectsCategoriesAndProfile(t *testing.T) {
	profile := &project.Profile{
		HasDocker: true,
		HasCI:     true,
		Languages: []string{"go"},
	}
	enabled := map[string]bool{"sast": true, "secrets": true, "sca": true, "docker": true, "cicd": true}
	scanners := BuildAll(BuildOptions{
		CategoryEnabled: func(category string) bool { return enabled[category] },
		Profile:         profile,
	})
	if len(scanners) < 8 {
		t.Fatalf("expected many scanners, got %d", len(scanners))
	}
	names := map[string]bool{}
	for _, s := range scanners {
		names[s.Name()] = true
	}
	for _, want := range []string{"semgrep", "gitleaks", "grype", "osv-scanner", "govulncheck", "hadolint", "zizmor", "actionlint", "trivy"} {
		if !names[want] {
			t.Fatalf("missing scanner %q in %v", want, names)
		}
	}
}

func TestRegistry_HasExpectedEntries(t *testing.T) {
	if len(Registry()) < 9 {
		t.Fatalf("registry too small: %d", len(Registry()))
	}
}
