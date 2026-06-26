// Package reporter renders the unified Finding model into output formats.
// Each format is a separate file; all take a slice of Findings (plus
// optional context like scanner metadata) and produce a string or write
// to an io.Writer.
//
// The reporters are pure functions: no I/O, no shared state, no LLM calls.
// They're safe to call from a goroutine.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/shfahiim/cyberai/internal/model"
)

// Report is the canonical "everything we know about a scan" structure.
// Reporters consume this, not bare []Finding, so they can include scanner
// metadata, durations, etc.
type Report struct {
	// Target is the directory that was scanned.
	Target string `json:"target"`
	// Hash is the project profile hash, used as a cache key for the router.
	Hash string `json:"hash"`
	// GeneratedAt is the wall time the report was built.
	GeneratedAt time.Time `json:"generated_at"`
	// Findings is the post-filter, post-severity, post-ignore list.
	Findings []model.Finding `json:"findings"`
	// Scanners is the per-scanner metadata (durations, errors, skip reasons).
	Scanners []model.ScanResult `json:"scanners"`
	// TotalFindings is the count before severity/ignore filtering.
	TotalFindings int `json:"total_findings"`
	// SuppressedByIgnore is the number of findings dropped by ignore patterns.
	SuppressedByIgnore int `json:"suppressed_by_ignore"`
	// Duration is the total scan time.
	Duration time.Duration `json:"duration"`
}

// NewReport builds a Report from the orchestrator result + the filtered
// findings + counts. It sorts findings by severity then file.
func NewReport(target, hash string, findings []model.Finding, scanners []model.ScanResult, totalFindings, suppressed int, dur time.Duration) *Report {
	model.SortFindings(findings)
	return &Report{
		Target:             target,
		Hash:               hash,
		GeneratedAt:        time.Now().UTC(),
		Findings:           findings,
		Scanners:           scanners,
		TotalFindings:      totalFindings,
		SuppressedByIgnore: suppressed,
		Duration:           dur,
	}
}

// JSON renders the full report as indented JSON. This is the canonical
// machine-readable form (also the input to `report compare`).
//
// Duration is serialized as a human-readable string ("1m23s") rather than
// nanoseconds, so baselines round-trip cleanly and humans can read them.
// We use a shadow struct to override the Duration JSON shape without
// changing the in-memory type.
func JSON(r *Report) ([]byte, error) {
	type out struct {
		*Report
		Duration string `json:"duration"`
	}
	o := out{Report: r, Duration: r.Duration.String()}
	return json.MarshalIndent(o, "", "  ")
}

// WriteJSON writes the JSON report to w.
func WriteJSON(w io.Writer, r *Report) error {
	data, err := JSON(r)
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	_, err = w.Write(data)
	return err
}
