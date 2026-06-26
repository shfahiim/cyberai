package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/shfahiim/cyberai/internal/model"
)

// defaultSLA holds remediation deadlines when config omits the sla block.
var defaultSLA = SLAConfig{
	Critical: "7d",
	High:     "30d",
	Medium:   "90d",
	Low:      "180d",
}

// ParseSLADuration parses durations like "7d", "30d", "24h", or "168h".
func ParseSLADuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("empty SLA duration")
	}
	if strings.HasSuffix(raw, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(raw, "d"))
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid day SLA %q", raw)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(raw)
}

// slaString returns the configured SLA string for a severity, falling back to defaults.
func (s SLAConfig) slaString(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		if s.Critical != "" {
			return s.Critical
		}
	case model.SeverityHigh:
		if s.High != "" {
			return s.High
		}
	case model.SeverityMedium:
		if s.Medium != "" {
			return s.Medium
		}
	case model.SeverityLow, model.SeverityInfo:
		if s.Low != "" {
			return s.Low
		}
	}
	return defaultSLA.slaString(severity)
}

// DurationFor returns the remediation SLA duration for a severity.
func (s SLAConfig) DurationFor(severity model.Severity) time.Duration {
	d, err := ParseSLADuration(s.slaString(severity))
	if err != nil {
		d, _ = ParseSLADuration(defaultSLA.slaString(severity))
	}
	return d
}

// Deadline returns firstSeen plus the SLA duration for the finding severity.
func (s SLAConfig) Deadline(severity model.Severity, firstSeen time.Time) time.Time {
	if firstSeen.IsZero() {
		return time.Time{}
	}
	return firstSeen.Add(s.DurationFor(severity))
}
