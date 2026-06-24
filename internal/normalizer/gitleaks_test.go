package normalizer

import (
	"strings"
	"testing"

	"github.com/shfahiim/cyberai/internal/model"
)

const sampleGitleaksArray = `[
  {
    "Description": "AWS Access Token",
    "RuleID": "aws-access-token",
    "Match": "AKIAIOSFODNN7EXAMPLE",
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "File": "config.py",
    "StartLine": 12,
    "EndLine": 12,
    "StartColumn": 1,
    "EndColumn": 21,
    "Entropy": 3.4,
    "Tags": ["aws", "key"]
  },
  {
    "Description": "GitHub Personal Access Token",
    "RuleID": "github-pat",
    "Match": "token = \"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
    "Secret": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "File": ".env.local",
    "StartLine": 5,
    "EndLine": 5,
    "Entropy": 4.1,
    "Tags": ["github", "token"]
  }
]`

func TestGitleaks_Array(t *testing.T) {
	findings, err := Gitleaks([]byte(sampleGitleaksArray))
	if err != nil {
		t.Fatalf("Gitleaks: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d, want 2", len(findings))
	}
	a := findings[0]
	if a.Tool != "gitleaks" || a.RuleID != "aws-access-token" {
		t.Errorf("rule wrong: %s/%s", a.Tool, a.RuleID)
	}
	if a.Severity != model.SeverityCritical {
		t.Errorf("AWS secrets should be critical, got %s", a.Severity)
	}
	if a.File != "config.py" || a.StartLine != 12 {
		t.Errorf("location wrong: %s:%d", a.File, a.StartLine)
	}
	if strings.Contains(a.Snippet, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("snippet should NOT contain raw secret, got %q", a.Snippet)
	}
	if a.Metadata["entropy"] == "" {
		t.Error("entropy should be recorded in metadata")
	}
}

func TestGitleaks_Empty(t *testing.T) {
	cases := []string{"", "[]", "  \n"}
	for _, in := range cases {
		findings, err := Gitleaks([]byte(in))
		if err != nil {
			t.Errorf("input %q: %v", in, err)
		}
		if len(findings) != 0 {
			t.Errorf("input %q: got %d findings, want 0", in, len(findings))
		}
	}
}

func TestGitleaks_SingleObject(t *testing.T) {
	one := `{"Description":"Slack Token","RuleID":"slack-token","Match":"xoxb-...","Secret":"xoxb-123","File":"a.py","StartLine":1}`
	findings, err := Gitleaks([]byte(one))
	if err != nil {
		t.Fatalf("Gitleaks: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d, want 1", len(findings))
	}
	if findings[0].RuleID != "slack-token" {
		t.Errorf("rule wrong: %s", findings[0].RuleID)
	}
}

func TestGitleaks_Garbage(t *testing.T) {
	if _, err := Gitleaks([]byte("not json at all")); err == nil {
		t.Error("expected error for garbage input")
	}
}

func TestRedactSecret(t *testing.T) {
	cases := []struct {
		match, secret, contains, excludes string
	}{
		{"AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE", "AKIA", "IOSFODNN7EXAMPLE"},
		{"short", "short", "***", "short"},
		{"x = AKIA12345ABCDEF", "AKIA12345ABCDEF", "AKIA", "12345ABCDEF"},
	}
	for _, tc := range cases {
		got := redactSecret(tc.match, tc.secret)
		if !strings.Contains(got, tc.contains) {
			t.Errorf("redactSecret(%q, %q) = %q, want to contain %q", tc.match, tc.secret, got, tc.contains)
		}
		if tc.excludes != "" && strings.Contains(got, tc.excludes) {
			t.Errorf("redactSecret(%q, %q) = %q, should NOT contain %q", tc.match, tc.secret, got, tc.excludes)
		}
	}
}
