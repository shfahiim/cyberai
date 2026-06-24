// Package baseline loads a previously-saved cyberai JSON report and diffs
// it against a current set of findings. This is what powers
// `cyberai scan --baseline old.json` (only show new findings) and
// `cyberai report compare old.json new.json`.
//
// Baselines are simply the JSON output of `reporter.JSON` — we don't need
// a special format. Any JSON file with a `findings` array of objects
// matching our Finding schema is loadable.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/shfahiim/cyberai/internal/model"
	"github.com/shfahiim/cyberai/internal/reporter"
)

// Report is what we deserialize a baseline file into. We accept the
// full Report struct (so callers can also see the baseline's target/hash),
// but for diffing purposes we only need Findings.
type Report = reporter.Report

// Load reads a baseline JSON file from disk.
func Load(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	return Parse(data)
}

// Parse decodes a baseline from raw JSON bytes.
//
// We accept both forms of the on-disk shape:
//   - "duration": "1m23s"   (string, produced by reporter.JSON)
//   - "duration": 12345      (number of nanoseconds, raw time.Duration)
//
// The string form is what cyberai writes; the number form is what an
// external tool might produce. We normalize both to time.Duration.
func Parse(data []byte) (*Report, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	// Strip duration from the map; we'll handle it separately.
	durRaw, hasDur := raw["duration"]
	delete(raw, "duration")
	rest, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("re-marshal baseline: %w", err)
	}
	var r Report
	if err := json.Unmarshal(rest, &r); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	if hasDur {
		// Try as string first, then as nanoseconds.
		var s string
		if err := json.Unmarshal(durRaw, &s); err == nil {
			if d, err := time.ParseDuration(s); err == nil {
				r.Duration = d
			}
		} else {
			var ns int64
			if err := json.Unmarshal(durRaw, &ns); err == nil {
				r.Duration = time.Duration(ns)
			}
		}
	}
	if r.Findings == nil {
		r.Findings = []model.Finding{}
	}
	return &r, nil
}

// Diff is the result of comparing two scans.
//
// NewFindings are findings in `current` but not in `baseline`.
// ResolvedFindings are findings in `baseline` but not in `current`.
// Unchanged are present in both (kept for completeness; reports can omit them).
type Diff struct {
	BaselinePath     string          `json:"baseline_path"`
	CurrentPath      string          `json:"current_path,omitempty"`
	BaselineHash     string          `json:"baseline_hash"`
	CurrentHash      string          `json:"current_hash,omitempty"`
	BaselineFindings []model.Finding `json:"baseline_findings"`
	CurrentFindings  []model.Finding `json:"current_findings"`
	NewFindings      []model.Finding `json:"new_findings"`
	ResolvedFindings []model.Finding `json:"resolved_findings"`
	Unchanged        []model.Finding `json:"unchanged"`
	NewBySeverity    map[string]int  `json:"new_by_severity"`
}

// Compare diffs current against baseline and returns the Diff.
//
// Matching is by Finding.ID (the stable hash-derived identifier). Same
// ID = same finding across runs; differing ID = new or resolved.
//
// If the two projects have different hashes (different root + languages +
// manifests), we still diff by ID — IDs are stable per finding, not per
// project — but we record the hash mismatch so users can spot a baseline
// that's been pointed at a different repo.
func Compare(baseline, current *Report, baselinePath, currentPath string) *Diff {
	if baseline == nil || current == nil {
		return &Diff{}
	}

	baseIDs := indexByID(baseline.Findings)
	currIDs := indexByID(current.Findings)

	var newF, resolved, unchanged []model.Finding
	for id, f := range currIDs {
		if _, ok := baseIDs[id]; ok {
			unchanged = append(unchanged, f)
		} else {
			newF = append(newF, f)
		}
	}
	for id, f := range baseIDs {
		if _, ok := currIDs[id]; !ok {
			resolved = append(resolved, f)
		}
	}

	return &Diff{
		BaselinePath:     baselinePath,
		CurrentPath:      currentPath,
		BaselineHash:     baseline.Hash,
		CurrentHash:      current.Hash,
		BaselineFindings: baseline.Findings,
		CurrentFindings:  current.Findings,
		NewFindings:      newF,
		ResolvedFindings: resolved,
		Unchanged:        unchanged,
		NewBySeverity:    countBySeverity(newF),
	}
}

func indexByID(findings []model.Finding) map[string]model.Finding {
	out := make(map[string]model.Finding, len(findings))
	for _, f := range findings {
		out[f.ID] = f
	}
	return out
}

func countBySeverity(findings []model.Finding) map[string]int {
	out := map[string]int{
		"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
	}
	for _, f := range findings {
		switch f.Severity {
		case model.SeverityCritical:
			out["critical"]++
		case model.SeverityHigh:
			out["high"]++
		case model.SeverityMedium:
			out["medium"]++
		case model.SeverityLow:
			out["low"]++
		case model.SeverityInfo:
			out["info"]++
		}
	}
	return out
}

// Markdown renders the Diff as a GitHub-friendly Markdown document.
func (d *Diff) Markdown() string {
	if d == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# cyberai diff\n\n")
	fmt.Fprintf(&b, "**Baseline:** `%s` (hash `%s`)\n\n", d.BaselinePath, d.BaselineHash)
	if d.CurrentPath != "" {
		fmt.Fprintf(&b, "**Current:** `%s` (hash `%s`)\n\n", d.CurrentPath, d.CurrentHash)
	}
	if d.BaselineHash != "" && d.CurrentHash != "" && d.BaselineHash != d.CurrentHash {
		fmt.Fprintf(&b, "> ⚠️ Project hashes differ. Diff is by finding ID; double-check the baseline is for this repo.\n\n")
	}

	fmt.Fprintf(&b, "## New (%d)\n\n", len(d.NewFindings))
	if len(d.NewFindings) == 0 {
		fmt.Fprintf(&b, "No new findings.\n\n")
	} else {
		for _, f := range d.NewFindings {
			fmt.Fprintf(&b, "- **[%s]** %s — `%s:%d` (%s)\n",
				f.Severity, f.Title, f.File, f.StartLine, f.Tool)
		}
		fmt.Fprintf(&b, "\nBy severity: %d critical, %d high, %d medium, %d low, %d info\n\n",
			d.NewBySeverity["critical"], d.NewBySeverity["high"],
			d.NewBySeverity["medium"], d.NewBySeverity["low"], d.NewBySeverity["info"])
	}

	fmt.Fprintf(&b, "## Resolved (%d)\n\n", len(d.ResolvedFindings))
	if len(d.ResolvedFindings) == 0 {
		fmt.Fprintf(&b, "No findings resolved since the baseline.\n\n")
	} else {
		for _, f := range d.ResolvedFindings {
			fmt.Fprintf(&b, "- ~~[%s] %s — `%s:%d`~~ (%s)\n",
				f.Severity, f.Title, f.File, f.StartLine, f.Tool)
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}
