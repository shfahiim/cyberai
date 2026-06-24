package normalizer

import (
	"strings"
	"testing"

	"github.com/shfahiim/cyberai/internal/model"
)

const sampleSemgrepJSON = `{
  "results": [
    {
      "check_id": "python.lang.security.audit.formatted-sql-query",
      "path": "src/db.py",
      "start": {"line": 87, "col": 4},
      "end": {"line": 87, "col": 50},
      "extra": {
        "severity": "ERROR",
        "message": "Detected formatted SQL query. Use parameterized queries instead.",
        "metadata": {
          "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
          "owasp": ["A03:2021 - Injection"],
          "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
          "confidence": "HIGH",
          "shortlink": "https://semgrep.dev/r/python.lang.security.audit.formatted-sql-query"
        },
        "lines": "    cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")"
      }
    },
    {
      "check_id": "javascript.express.security.audit.express-open-redirect",
      "path": "web/redirect.js",
      "start": {"line": 12, "col": 0},
      "end": {"line": 12, "col": 30},
      "extra": {
        "severity": "WARNING",
        "message": "Untrusted input flowed into res.redirect.",
        "metadata": {
          "cwe": ["CWE-601: URL Redirection to Untrusted Site"],
          "confidence": "MEDIUM"
        },
        "lines": "res.redirect(req.query.next)"
      }
    }
  ],
  "errors": []
}`

func TestSemgrep_Happy(t *testing.T) {
	findings, err := Semgrep([]byte(sampleSemgrepJSON))
	if err != nil {
		t.Fatalf("Semgrep: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	a := findings[0]
	if a.Tool != "semgrep" || a.RuleID != "python.lang.security.audit.formatted-sql-query" {
		t.Errorf("unexpected rule: %s/%s", a.Tool, a.RuleID)
	}
	if a.Severity != model.SeverityHigh {
		t.Errorf("ERROR severity should map to High, got %s", a.Severity)
	}
	if a.File != "src/db.py" || a.StartLine != 87 || a.Column != 4 {
		t.Errorf("location wrong: %s:%d:%d", a.File, a.StartLine, a.Column)
	}
	if len(a.CWE) == 0 || !strings.HasPrefix(a.CWE[0], "CWE-89") {
		t.Errorf("CWE missing or wrong: %v", a.CWE)
	}
	if !strings.Contains(a.Snippet, "SELECT") {
		t.Errorf("snippet missing code: %q", a.Snippet)
	}
	if a.Confidence != "high" {
		t.Errorf("confidence should be lowercased: %q", a.Confidence)
	}
	if a.ID == "" {
		t.Error("ID not assigned")
	}

	b := findings[1]
	if b.Severity != model.SeverityMedium {
		t.Errorf("WARNING severity should map to Medium, got %s", b.Severity)
	}
}

func TestSemgrep_InvalidJSON(t *testing.T) {
	if _, err := Semgrep([]byte("not json")); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestSemgrep_FatalErrors(t *testing.T) {
	raw := `{"results": [], "errors": [{"level": "error", "message": "bad config"}]}`
	if _, err := Semgrep([]byte(raw)); err == nil {
		t.Error("expected error when semgrep reports fatal errors")
	}
}

func TestSemgrep_NonFatalErrors_Ignored(t *testing.T) {
	raw := `{
	  "results": [{"check_id":"x","path":"f.py","start":{"line":1,"col":0},"end":{"line":1,"col":0},"extra":{"severity":"INFO","message":"hi"}}],
	  "errors": [{"level": "warn", "message": "skipped a file"}]
	}`
	findings, err := Semgrep([]byte(raw))
	if err != nil {
		t.Fatalf("expected non-fatal error to be ignored, got: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("got %d findings, want 1", len(findings))
	}
}

func TestMapSemgrepSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want model.Severity
	}{
		{"ERROR", model.SeverityHigh},
		{"error", model.SeverityHigh},
		{"WARNING", model.SeverityMedium},
		{"INFO", model.SeverityLow},
		{"unknown", model.SeverityMedium},
		{"", model.SeverityMedium},
	}
	for _, tc := range cases {
		if got := mapSemgrepSeverity(tc.in, semgrepMeta{}); got != tc.want {
			t.Errorf("mapSemgrepSeverity(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestMapSemgrepSeverity_CriticalMetadata(t *testing.T) {
	meta := semgrepMeta{SecuritySeverity: "9.4"}
	if got := mapSemgrepSeverity("ERROR", meta); got != model.SeverityCritical {
		t.Errorf("security-severity >= 9 should map to critical, got %s", got)
	}
}
