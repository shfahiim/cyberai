package scanner

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/shfahiim/cyberai/internal/model"
)

// Orchestrator runs a set of scanners in parallel and aggregates the results.
// Scanners that aren't installed are skipped (with SkipReason set) — they
// don't fail the overall run, they just produce an empty Findings list.
type Orchestrator struct {
	// Scanners is the set of scanners to consider. The orchestrator calls
	// Available() on each and skips the unavailable ones.
	Scanners []NormalizingScanner

	// OnProgress, if non-nil, is called when each scanner finishes. Used
	// for TTY progress bars and CI log lines.
	OnProgress func(name string, status string)

	// MaxParallel caps the number of scanners running simultaneously.
	// Zero or negative = no cap (run all in parallel).
	MaxParallel int
}

// Result is the orchestrator's full output: per-scanner ScanResult slices,
// any global error, and total runtime.
type Result struct {
	// Results is one entry per scanner (even skipped ones), in a stable order.
	Results []model.ScanResult
	// Duration is the wall time from start to last scanner finishing.
	Duration time.Duration
}

// Run executes every registered scanner in parallel against target. It
// returns once all scanners have finished (or failed). Errors from
// individual scanners are recorded in their ScanResult.Error field — they
// don't fail the whole run unless the orchestrator itself hit a fatal
// problem (e.g. ctx cancelled).
func (o *Orchestrator) Run(ctx context.Context, target string) (*Result, error) {
	if len(o.Scanners) == 0 {
		return &Result{}, nil
	}

	start := time.Now()

	// Cap concurrency if requested.
	if o.MaxParallel > 0 && o.MaxParallel < len(o.Scanners) {
		return o.runBounded(ctx, target, start)
	}

	// Unbounded: all scanners at once via errgroup.
	var (
		g       errgroup.Group
		mu      sync.Mutex
		results = make([]model.ScanResult, 0, len(o.Scanners))
	)

	for _, s := range o.Scanners {
		s := s
		g.Go(func() error {
			sr := o.runOne(ctx, s, target)
			mu.Lock()
			results = append(results, sr)
			mu.Unlock()
			return nil // per-scanner errors are in sr, not as g errors
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("orchestrator: %w", err)
	}

	// Sort by tool name for stable output (parallel completion is racy).
	sort.Slice(results, func(i, j int) bool { return results[i].Tool < results[j].Tool })

	return &Result{Results: results, Duration: time.Since(start)}, nil
}

// runBounded limits concurrency to MaxParallel using a semaphore.
func (o *Orchestrator) runBounded(ctx context.Context, target string, start time.Time) (*Result, error) {
	sem := make(chan struct{}, o.MaxParallel)
	var (
		mu      sync.Mutex
		results = make([]model.ScanResult, 0, len(o.Scanners))
		wg      sync.WaitGroup
	)

	for _, s := range o.Scanners {
		s := s
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			sr := o.runOne(ctx, s, target)
			mu.Lock()
			results = append(results, sr)
			mu.Unlock()
		}()
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Tool < results[j].Tool })
	return &Result{Results: results, Duration: time.Since(start)}, nil
}

// runOne executes a single scanner, records timing, and handles the
// not-installed case gracefully (Skipped=true, no error).
func (o *Orchestrator) runOne(ctx context.Context, s NormalizingScanner, target string) model.ScanResult {
	name := s.Name()
	start := time.Now()
	sr := model.ScanResult{Tool: name, Category: s.Category()}

	available, version := s.Available()
	if !available {
		sr.Skipped = true
		sr.SkipReason = fmt.Sprintf("%s not found on $PATH", name)
		sr.Duration = time.Since(start)
		if o.OnProgress != nil {
			o.OnProgress(name, "skipped")
		}
		return sr
	}

	if o.OnProgress != nil {
		o.OnProgress(name, "running")
	}

	findings, err := s.Scan(ctx, target)
	sr.Duration = time.Since(start)
	if err != nil {
		sr.Error = err.Error()
		if o.OnProgress != nil {
			o.OnProgress(name, "error")
		}
		return sr
	}

	sr.Findings = findings
	if o.OnProgress != nil {
		o.OnProgress(name, fmt.Sprintf("done (%d findings, %s, %s)", len(findings), version, sr.Duration.Truncate(time.Millisecond)))
	}
	return sr
}

// Aggregate returns a single flat []model.Finding across all per-scanner
// results, sorted by severity (critical first) then file path.
func (r *Result) Aggregate() []model.Finding {
	var out []model.Finding
	for _, sr := range r.Results {
		out = append(out, sr.Findings...)
	}
	model.SortFindings(out)
	return out
}
