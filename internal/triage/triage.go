// Package triage applies FirstSeen and SLA metadata to findings.
package triage

import (
	"time"

	"github.com/shfahiim/cyberai/internal/config"
	"github.com/shfahiim/cyberai/internal/model"
)

// ApplyMetadata sets FirstSeen and SLADeadline on each finding.
//
// firstSeenFrom maps finding ID to the timestamp it was first observed.
// When a finding ID is absent, FirstSeen is set to now.
func ApplyMetadata(findings []model.Finding, firstSeenFrom map[string]time.Time, sla config.SLAConfig, now time.Time) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	for i := range findings {
		firstSeen, ok := firstSeenFrom[findings[i].ID]
		if !ok || firstSeen.IsZero() {
			firstSeen = now
		}
		findings[i].FirstSeen = firstSeen
		findings[i].SLADeadline = sla.Deadline(findings[i].Severity, firstSeen)
	}
}

// FirstSeenMap builds an ID→FirstSeen map from a prior scan report.
func FirstSeenMap(baseline []model.Finding, baselineGenerated time.Time) map[string]time.Time {
	out := make(map[string]time.Time, len(baseline))
	for _, f := range baseline {
		firstSeen := f.FirstSeen
		if firstSeen.IsZero() {
			firstSeen = baselineGenerated
		}
		if !firstSeen.IsZero() {
			out[f.ID] = firstSeen
		}
	}
	return out
}
