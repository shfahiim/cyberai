package compliance

import (
	"testing"

	"github.com/shfahiim/cyberai/internal/model"
)

func TestMatches_FrameworkPrefix(t *testing.T) {
	tags := []string{"OWASP:A03-Injection", "PCI-DSS:6.3.2"}
	if !Matches(tags, "owasp-top-10") {
		t.Fatal("expected OWASP match")
	}
	if !Matches(tags, "pci-dss") {
		t.Fatal("expected PCI-DSS match")
	}
	if Matches(tags, "hipaa") {
		t.Fatal("unexpected HIPAA match")
	}
}

func TestFilterFindings(t *testing.T) {
	findings := []model.Finding{
		{ID: "a", ComplianceTags: []string{"OWASP:A03-Injection"}},
		{ID: "b", ComplianceTags: []string{"HIPAA:§164.312(a)(2)(iv)"}},
	}
	out := FilterFindings(findings, []string{"owasp-top-10"})
	if len(out) != 1 || out[0].ID != "a" {
		t.Fatalf("got %#v", out)
	}
}
