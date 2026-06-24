package normalizer

import (
	"testing"

	"github.com/shfahiim/cyberai/internal/model"
)

func TestSARIF(t *testing.T) {
	raw := []byte(`{
	  "version": "2.1.0",
	  "runs": [{
	    "tool": {"driver": {"name": "zizmor", "rules": [{
	      "id": "unpinned-uses",
	      "shortDescription": {"text": "Action reference is not pinned"},
	      "helpUri": "https://example.com/rule",
	      "properties": {"security-severity": "7.2", "tags": ["security"]}
	    }]}},
	    "results": [{
	      "ruleId": "unpinned-uses",
	      "level": "warning",
	      "message": {"text": "uses should be pinned by commit SHA"},
	      "locations": [{"physicalLocation": {
	        "artifactLocation": {"uri": ".github/workflows/ci.yml"},
	        "region": {"startLine": 12, "endLine": 12, "startColumn": 9}
	      }}]
	    }]
	  }]
	}`)
	findings, err := SARIF(raw, "zizmor", model.CategoryCICD)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Tool != "zizmor" || f.RuleID != "unpinned-uses" {
		t.Fatalf("unexpected finding identity: %+v", f)
	}
	if f.Category != model.CategoryCICD || f.Severity != model.SeverityHigh {
		t.Fatalf("category/severity = %s/%s", f.Category, f.Severity)
	}
}
