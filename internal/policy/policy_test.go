package policy

import (
	"testing"

	"github.com/shfahiim/cyberai/internal/model"
)

func TestEvaluate_SuppressedAndIsNew(t *testing.T) {
	findings := []model.Finding{
		{ID: "F-1", Severity: model.SeverityCritical},
		{ID: "F-2", Severity: model.SeverityCritical},
	}
	ctx := Context{
		IsSuppressed: func(f model.Finding) bool { return f.ID == "F-1" },
		IsNew:        func(f model.Finding) bool { return f.ID == "F-2" },
	}
	violations := Evaluate([]Gate{
		{Name: "no-critical", FailOn: "severity == critical AND suppressed == false"},
		{Name: "no-new-critical", FailOn: "is_new == true AND severity == critical"},
	}, findings, ctx)
	if len(violations) != 2 {
		t.Fatalf("expected 2 violations, got %d", len(violations))
	}
}
