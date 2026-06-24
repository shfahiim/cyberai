package normalizer

import (
	"strings"
	"testing"

	"github.com/shfahiim/cyberai/internal/model"
)

const sampleTrivyReport = `{
  "ArtifactName": "app",
  "ArtifactType": "filesystem",
  "Results": [
    {
      "Target": "package.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-12345",
          "PkgName": "lodash",
          "InstalledVersion": "4.17.20",
          "FixedVersion": "4.17.21",
          "Severity": "HIGH",
          "Title": "Prototype Pollution in lodash",
          "Description": "Lodash versions prior to 4.17.21 are vulnerable to prototype pollution.",
          "CweIDs": ["CWE-1321"],
          "CVSS": {
            "nvd": {"V3Score": 7.5},
            "redhat": {"V3Score": 8.1}
          },
          "References": ["https://nvd.nist.gov/vuln/detail/CVE-2024-12345"]
        }
      ]
    },
    {
      "Target": "main.tf",
      "Class": "config",
      "Type": "terraform",
      "Misconfigurations": [
        {
          "ID": "AVD-AWS-0001",
          "AVDID": "AVD-AWS-0001",
          "Title": "S3 bucket has public access",
          "Description": "Bucket allows public ACLs.",
          "Severity": "CRITICAL",
          "Resolution": "Set aws_s3_bucket.public_access_block",
          "StartLine": 12,
          "EndLine": 18,
          "References": ["https://avd.aquasec.com/misconfig/avd-aws-0001"]
        }
      ]
    },
    {
      "Target": ".env",
      "Class": "secret",
      "Type": "",
      "Secrets": [
        {
          "RuleID": "aws-access-key",
          "Category": "AWS",
          "Severity": "CRITICAL",
          "Title": "AWS Access Key",
          "StartLine": 3,
          "Match": "AKIA..."
        }
      ]
    }
  ]
}`

func TestTrivy_FullReport(t *testing.T) {
	findings, err := Trivy([]byte(sampleTrivyReport))
	if err != nil {
		t.Fatalf("Trivy: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
	}

	// Vuln: SCA, high severity, has CVE + CWE + CVSS + FixVersion
	v := findings[0]
	if v.Tool != "trivy" || v.RuleID != "CVE-2024-12345" {
		t.Errorf("vuln rule wrong: %s/%s", v.Tool, v.RuleID)
	}
	if v.Category != model.CategorySCA {
		t.Errorf("vuln category = %s, want SCA", v.Category)
	}
	if v.Severity != model.SeverityHigh {
		t.Errorf("vuln severity = %s, want High", v.Severity)
	}
	if len(v.CVE) != 1 || v.CVE[0] != "CVE-2024-12345" {
		t.Errorf("vuln CVE = %v", v.CVE)
	}
	if v.CVSS != 8.1 {
		t.Errorf("vuln CVSS = %v, want max 8.1", v.CVSS)
	}
	if v.FixVersion != "4.17.21" {
		t.Errorf("vuln FixVersion = %q", v.FixVersion)
	}
	if !strings.Contains(v.Fix, "Upgrade") {
		t.Errorf("vuln Fix should mention upgrade, got %q", v.Fix)
	}

	// Misconfig: IaC, critical
	m := findings[1]
	if m.Category != model.CategoryIaC {
		t.Errorf("misconfig category = %s, want IaC", m.Category)
	}
	if m.Severity != model.SeverityCritical {
		t.Errorf("misconfig severity = %s, want Critical", m.Severity)
	}
	if m.File != "main.tf" || m.StartLine != 12 {
		t.Errorf("misconfig location: %s:%d", m.File, m.StartLine)
	}
	if !strings.Contains(m.Fix, "aws_s3_bucket") {
		t.Errorf("misconfig Fix should include resolution, got %q", m.Fix)
	}

	// Secret: Secrets, critical, and redacted
	s := findings[2]
	if s.Category != model.CategorySecrets {
		t.Errorf("secret category = %s, want Secrets", s.Category)
	}
	if s.Severity != model.SeverityCritical {
		t.Errorf("secret severity = %s, want Critical", s.Severity)
	}
	if strings.Contains(s.Snippet, "AKIA") {
		t.Errorf("secret snippet should be redacted, got %q", s.Snippet)
	}
	if !strings.Contains(s.Snippet, "redacted secret match") {
		t.Errorf("secret snippet should mention redaction, got %q", s.Snippet)
	}
}

func TestTrivy_Empty(t *testing.T) {
	if findings, err := Trivy([]byte("")); err != nil || findings != nil {
		t.Errorf("empty input: err=%v findings=%v", err, findings)
	}
	if findings, err := Trivy([]byte("{}")); err != nil || findings != nil {
		t.Errorf("empty report: err=%v findings=%v", err, findings)
	}
}

func TestTrivy_ArrayForm(t *testing.T) {
	arr := `[{"ArtifactName":"a","ArtifactType":"fs","Results":[]},{"ArtifactName":"b","ArtifactType":"fs","Results":[]}]`
	findings, err := Trivy([]byte(arr))
	if err != nil {
		t.Fatalf("Trivy: %v", err)
	}
	if findings != nil {
		t.Errorf("expected nil findings for empty reports, got %v", findings)
	}
}

func TestTrivy_InvalidJSON(t *testing.T) {
	if _, err := Trivy([]byte("not json")); err == nil {
		t.Error("expected error for garbage input")
	}
}

func TestMapTrivySeverity(t *testing.T) {
	cases := []struct {
		in   string
		want model.Severity
	}{
		{"CRITICAL", model.SeverityCritical},
		{"high", model.SeverityHigh},
		{"Medium", model.SeverityMedium},
		{"LOW", model.SeverityLow},
		{"unknown", model.SeverityMedium},
		{"", model.SeverityMedium},
	}
	for _, tc := range cases {
		if got := mapTrivySeverity(tc.in); got != tc.want {
			t.Errorf("mapTrivySeverity(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestPickMaxCVSS(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]trivyCVSS
		want float64
	}{
		{"empty", map[string]trivyCVSS{}, 0},
		{"single", map[string]trivyCVSS{"nvd": {V3Score: 7.5}}, 7.5},
		{"max wins", map[string]trivyCVSS{"nvd": {V3Score: 7.5}, "redhat": {V3Score: 8.1}, "ghsa": {V3Score: 6.0}}, 8.1},
		{"zeros ignored", map[string]trivyCVSS{"nvd": {V3Score: 0}, "redhat": {V3Score: 5.5}}, 5.5},
	}
	for _, tc := range cases {
		if got := pickMaxCVSS(tc.in); got != tc.want {
			t.Errorf("%s: pickMaxCVSS = %v, want %v", tc.name, got, tc.want)
		}
	}
}
