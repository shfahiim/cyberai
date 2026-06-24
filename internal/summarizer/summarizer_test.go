package summarizer

import (
	"strings"
	"testing"

	"github.com/shfahiim/cyberai/internal/model"
)

func sampleFindings() []model.Finding {
	return []model.Finding{
		{
			ID:        "F-1",
			Tool:      "semgrep",
			RuleID:    "go.lang.security.audit.crypto.golang",
			Title:     "Use of weak crypto",
			Severity:  model.SeverityHigh,
			File:      "src/auth.go",
			StartLine: 42,
			Category:  model.CategorySAST,
			CWE:       []string{"CWE-327"},
			Fix:       "Use crypto/rand instead of math/rand for tokens",
		},
		{
			ID:        "F-2",
			Tool:      "gitleaks",
			RuleID:    "aws-access-token",
			Title:     "AWS access key",
			Severity:  model.SeverityCritical,
			File:      "config/dev.env",
			StartLine: 3,
			Category:  model.CategorySecrets,
		},
		{
			ID:        "F-3",
			Tool:      "trivy",
			RuleID:    "CVE-2024-9999",
			Title:     "Outdated lodash",
			Severity:  model.SeverityMedium,
			File:      "package-lock.json",
			StartLine: 100,
			Category:  model.CategorySCA,
			CVE:       []string{"CVE-2024-9999"},
		},
	}
}

func TestNoopSummarizer(t *testing.T) {
	s := NoopSummarizer{}
	got, err := s.Summarize(sampleFindings())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != nil {
		t.Errorf("NoopSummarizer should return nil, got %+v", got)
	}
}

func TestNewGemini_NoAPIKey_ReturnsNoop(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "")
	s := NewGemini("gemini-2.5-flash")
	if _, ok := s.(NoopSummarizer); !ok {
		t.Errorf("expected NoopSummarizer when API key is empty, got %T", s)
	}
}

func TestGeminiSummarizer_EmptyFindings_ReturnsNilNil(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "test-key")
	g := &GeminiSummarizer{APIKey: "test-key", Model: "gemini-2.5-flash"}
	got, err := g.Summarize(nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != nil {
		t.Errorf("empty findings should return nil, got %+v", got)
	}
}

func TestDigestFindings_SortsBySeverity(t *testing.T) {
	findings := sampleFindings()
	digest := digestFindings(findings)
	lines := strings.Split(strings.TrimSpace(digest), "\n")
	if len(lines) != 3 {
		t.Fatalf("digest has %d lines, want 3", len(lines))
	}
	// Critical (F-2) should come first.
	if !strings.Contains(lines[0], "F-2") {
		t.Errorf("expected F-2 first (critical), got line: %q", lines[0])
	}
}

func TestDigestFindings_CapAt30(t *testing.T) {
	var findings []model.Finding
	for i := 0; i < 50; i++ {
		findings = append(findings, model.Finding{
			ID:       "F-x",
			Severity: model.SeverityLow,
			Title:    "low sev",
			File:     "f.go",
			Tool:     "semgrep",
			RuleID:   "r",
		})
	}
	digest := digestFindings(findings)
	lines := strings.Split(strings.TrimSpace(digest), "\n")
	if len(lines) != 30 {
		t.Errorf("digest capped at 30, got %d lines", len(lines))
	}
}

func TestSanitizeMarkdown_StripsScript(t *testing.T) {
	in := "hello <script>alert(1)</script> world"
	out := sanitizeMarkdown(in)
	if strings.Contains(strings.ToLower(out), "<script") {
		t.Errorf("script tag not stripped: %q", out)
	}
	if !strings.Contains(out, "hello") || !strings.Contains(out, "world") {
		t.Errorf("text mangled: %q", out)
	}
}

func TestSanitizeMarkdown_StripsStyle(t *testing.T) {
	in := "a<style>body{display:none}</style>b"
	out := sanitizeMarkdown(in)
	if strings.Contains(strings.ToLower(out), "<style") {
		t.Errorf("style tag not stripped: %q", out)
	}
}

func TestSanitizeMarkdown_StripsIframe(t *testing.T) {
	in := "x<iframe src='evil.com'></iframe>y"
	out := sanitizeMarkdown(in)
	if strings.Contains(strings.ToLower(out), "<iframe") {
		t.Errorf("iframe tag not stripped: %q", out)
	}
}

func TestSanitizeMarkdown_StripsOnclick(t *testing.T) {
	in := `<a href="x" onclick="bad()">link</a>`
	out := sanitizeMarkdown(in)
	if strings.Contains(strings.ToLower(out), "onclick") {
		t.Errorf("onclick not stripped: %q", out)
	}
}

func TestSanitizeMarkdown_StripsJavascriptURL(t *testing.T) {
	in := `[click](javascript:alert(1))`
	out := sanitizeMarkdown(in)
	if strings.Contains(strings.ToLower(out), "javascript:") {
		t.Errorf("javascript: URL not stripped: %q", out)
	}
}

func TestSanitizeMarkdown_CaseInsensitive(t *testing.T) {
	in := "<SCRIPT>alert(1)</SCRIPT>"
	out := sanitizeMarkdown(in)
	if strings.Contains(strings.ToLower(out), "<script") {
		t.Errorf("uppercase script tag not stripped: %q", out)
	}
}

func TestSanitizeMarkdown_PreservesSafeContent(t *testing.T) {
	in := "### Executive\n\n- Fix F-1\n- Fix F-2"
	out := sanitizeMarkdown(in)
	if out != in {
		t.Errorf("safe content was modified:\nbefore: %q\nafter:  %q", in, out)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("short string not truncated, got %q", got)
	}
	got := truncate("hello world", 5)
	if !strings.HasSuffix(got, "…") {
		t.Errorf("long string should end with ellipsis, got %q", got)
	}
	// Ellipsis is 3 bytes in UTF-8, so total is n + 3.
	want := 5 + len("…")
	if len(got) != want {
		t.Errorf("len = %d, want %d", len(got), want)
	}
}
