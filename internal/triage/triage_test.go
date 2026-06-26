package triage

import (
	"testing"
	"time"

	"github.com/shfahiim/cyberai/internal/config"
	"github.com/shfahiim/cyberai/internal/model"
)

func TestApplyMetadata_UsesBaselineFirstSeen(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	findings := []model.Finding{{ID: "F-1", Severity: model.SeverityHigh}}
	ApplyMetadata(findings, map[string]time.Time{"F-1": first}, config.SLAConfig{High: "30d"}, now)
	if !findings[0].FirstSeen.Equal(first) {
		t.Fatalf("FirstSeen = %v", findings[0].FirstSeen)
	}
	if findings[0].SLADeadline.IsZero() {
		t.Fatal("expected SLADeadline")
	}
}

func TestApplyMetadata_NewFindingUsesNow(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	findings := []model.Finding{{ID: "F-new", Severity: model.SeverityLow}}
	ApplyMetadata(findings, nil, config.SLAConfig{}, now)
	if !findings[0].FirstSeen.Equal(now) {
		t.Fatalf("FirstSeen = %v", findings[0].FirstSeen)
	}
}
