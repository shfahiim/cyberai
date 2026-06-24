package normalizer

import (
	"testing"

	"github.com/shfahiim/cyberai/internal/model"
)

func TestHadolint(t *testing.T) {
	raw := []byte(`[
	  {"code":"DL3008","message":"Pin versions in apt get install.","line":3,"column":1,"file":"Dockerfile","level":"warning"}
	]`)
	findings, err := Hadolint(raw)
	if err != nil {
		t.Fatalf("Hadolint: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Tool != "hadolint" || f.RuleID != "DL3008" {
		t.Fatalf("unexpected finding identity: %+v", f)
	}
	if f.Category != model.CategoryDocker || f.Severity != model.SeverityMedium {
		t.Fatalf("category/severity = %s/%s", f.Category, f.Severity)
	}
}
