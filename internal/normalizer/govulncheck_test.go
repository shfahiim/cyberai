package normalizer

import (
	"testing"
)

func TestGovulncheck(t *testing.T) {
	raw := `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.0.0"}}
{"osv":{"id":"GO-2022-0945","aliases":["CVE-2022-30630"],"summary":"Panic in path/filepath","details":"Vulnerability details..."}}
{"finding":{"osv":"GO-2022-0945","fixed_version":"v1.18.4","trace":[{"package":"example.com/foo","function":"main","position":{"filename":"main.go","line":12,"column":5}}]}}`

	findings, err := Govulncheck([]byte(raw))
	if err != nil {
		t.Fatalf("Govulncheck error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Tool != "govulncheck" {
		t.Errorf("expected tool govulncheck, got %s", f.Tool)
	}
	if f.RuleID != "GO-2022-0945" {
		t.Errorf("expected rule ID GO-2022-0945, got %s", f.RuleID)
	}
	if f.File != "main.go" || f.StartLine != 12 {
		t.Errorf("expected file main.go:12, got %s:%d", f.File, f.StartLine)
	}
	if len(f.CVE) != 1 || f.CVE[0] != "CVE-2022-30630" {
		t.Errorf("expected CVE-2022-30630, got %v", f.CVE)
	}
	if f.IsReachable == nil || !*f.IsReachable {
		t.Errorf("expected IsReachable to be true")
	}
}
