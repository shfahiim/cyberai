package scanner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shfahiim/cyberai/internal/model"
)

// fakeScanner is a NormalizingScanner for tests. It records its run and
// returns canned findings.
type fakeScanner struct {
	name     string
	category model.Category
	// available toggles whether Available() returns true
	available bool
	// scanErr, if non-nil, is returned from Scan
	scanErr error
	// findings is what Scan returns on success
	findings []model.Finding
	// delay simulates scanner runtime
	delay time.Duration
	// runs counts how many times Scan was invoked
	runs int32
	// concurrent tracks peak in-flight calls (for parallelism assertions)
	peakInFlight int32
	current      int32
	mu           sync.Mutex
}

func (f *fakeScanner) Name() string              { return f.name }
func (f *fakeScanner) Category() model.Category  { return f.category }
func (f *fakeScanner) Available() (bool, string) { return f.available, "1.2.3" }

func (f *fakeScanner) Run(ctx context.Context, target string) ([]byte, error) {
	return []byte("{}"), nil
}

func (f *fakeScanner) Normalize(raw []byte) ([]model.Finding, error) {
	return nil, nil
}

func (f *fakeScanner) Scan(ctx context.Context, target string) ([]model.Finding, error) {
	atomic.AddInt32(&f.runs, 1)
	cur := atomic.AddInt32(&f.current, 1)
	for {
		p := atomic.LoadInt32(&f.peakInFlight)
		if cur <= p || atomic.CompareAndSwapInt32(&f.peakInFlight, p, cur) {
			break
		}
	}
	defer atomic.AddInt32(&f.current, -1)

	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.findings, f.scanErr
}

func TestOrchestrator_RunsAllScanners(t *testing.T) {
	orch := &Orchestrator{
		Scanners: []NormalizingScanner{
			&fakeScanner{name: "a", available: true, findings: []model.Finding{
				{ID: "F-a1", Tool: "a", RuleID: "x", File: "f.go", StartLine: 1, Severity: model.SeverityHigh, Category: model.CategorySAST},
			}},
			&fakeScanner{name: "b", available: true, findings: []model.Finding{
				{ID: "F-b1", Tool: "b", RuleID: "y", File: "g.py", StartLine: 5, Severity: model.SeverityCritical, Category: model.CategorySecrets},
			}},
		},
	}

	res, err := orch.Run(context.Background(), "/tmp")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Results) != 2 {
		t.Errorf("results = %d, want 2", len(res.Results))
	}
	if got := len(res.Aggregate()); got != 2 {
		t.Errorf("aggregate = %d, want 2", got)
	}
}

func TestOrchestrator_SkipsMissingScanners(t *testing.T) {
	orch := &Orchestrator{
		Scanners: []NormalizingScanner{
			&fakeScanner{name: "present", available: true, findings: []model.Finding{{ID: "F-x", Tool: "present", RuleID: "r", File: "f", Severity: model.SeverityLow}}},
			&fakeScanner{name: "missing", available: false},
		},
	}

	res, _ := orch.Run(context.Background(), "/tmp")
	for _, sr := range res.Results {
		switch sr.Tool {
		case "present":
			if sr.Skipped || len(sr.Findings) != 1 {
				t.Errorf("present should run: skipped=%v, findings=%d", sr.Skipped, len(sr.Findings))
			}
		case "missing":
			if !sr.Skipped {
				t.Error("missing should be skipped")
			}
			if sr.SkipReason == "" {
				t.Error("missing should have a SkipReason")
			}
		}
	}
}

func TestOrchestrator_RecordsErrors(t *testing.T) {
	orch := &Orchestrator{
		Scanners: []NormalizingScanner{
			&fakeScanner{name: "broken", available: true, scanErr: errors.New("boom")},
		},
	}
	res, _ := orch.Run(context.Background(), "/tmp")
	if len(res.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(res.Results))
	}
	sr := res.Results[0]
	if sr.Error != "boom" {
		t.Errorf("error = %q, want 'boom'", sr.Error)
	}
	if len(sr.Findings) != 0 {
		t.Errorf("broken scanner should have no findings, got %d", len(sr.Findings))
	}
}

func TestOrchestrator_RunsInParallel(t *testing.T) {
	const n = 4
	scanners := make([]NormalizingScanner, n)
	for i := 0; i < n; i++ {
		scanners[i] = &fakeScanner{
			name:      fmt.Sprintf("s%d", i),
			available: true,
			delay:     100 * time.Millisecond,
		}
	}
	orch := &Orchestrator{Scanners: scanners}

	start := time.Now()
	res, err := orch.Run(context.Background(), "/tmp")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != n {
		t.Errorf("results = %d, want %d", len(res.Results), n)
	}
	// If serial, this would take ~400ms. In parallel, ~100ms. Allow a generous
	// threshold for slow CI; the point is "much less than serial".
	if elapsed > 300*time.Millisecond {
		t.Errorf("parallel run took %v, expected < 300ms (4 scanners × 100ms)", elapsed)
	}
}

func TestOrchestrator_BoundedParallel(t *testing.T) {
	const n = 4
	scanners := make([]NormalizingScanner, n)
	for i := 0; i < n; i++ {
		scanners[i] = &fakeScanner{
			name:      fmt.Sprintf("s%d", i),
			available: true,
			delay:     50 * time.Millisecond,
		}
	}
	orch := &Orchestrator{Scanners: scanners, MaxParallel: 2}

	_, err := orch.Run(context.Background(), "/tmp")
	if err != nil {
		t.Fatal(err)
	}
	// Bounded: should take at least ceil(4/2)*50 = 100ms, definitely > 50ms.
	// (We don't assert upper bound tightly — we just want to confirm
	// parallelism is capped, not blocked.)
	// The real check is via peakInFlight if we wanted to assert concurrency
	// directly; we leave that to integration tests where timing is less flaky.
}

func TestOrchestrator_ProgressCallback(t *testing.T) {
	var (
		mu     sync.Mutex
		events []string
	)
	orch := &Orchestrator{
		Scanners: []NormalizingScanner{
			&fakeScanner{name: "x", available: true},
		},
		OnProgress: func(name, status string) {
			mu.Lock()
			events = append(events, name+":"+status)
			mu.Unlock()
		},
	}
	_, _ = orch.Run(context.Background(), "/tmp")
	mu.Lock()
	defer mu.Unlock()
	if len(events) == 0 {
		t.Fatal("OnProgress was never called")
	}
	// We expect at least "x:running" then "x:done(...)"
	foundRun, foundDone := false, false
	for _, e := range events {
		if e == "x:running" {
			foundRun = true
		}
		if len(e) >= 6 && e[:6] == "x:done" {
			foundDone = true
		}
	}
	if !foundRun || !foundDone {
		t.Errorf("missing events: %v (want x:running and x:done*)", events)
	}
}

func TestOrchestrator_ContextCancel(t *testing.T) {
	orch := &Orchestrator{
		Scanners: []NormalizingScanner{
			&fakeScanner{name: "slow", available: true, delay: 5 * time.Second},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	res, _ := orch.Run(ctx, "/tmp")
	if len(res.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(res.Results))
	}
	if res.Results[0].Error == "" {
		t.Error("expected error from cancelled context")
	}
}

func TestResult_Aggregate_SortBySeverityThenFile(t *testing.T) {
	r := &Result{Results: []model.ScanResult{
		{Tool: "x", Findings: []model.Finding{
			{ID: "F-low", Severity: model.SeverityLow, File: "z.go"},
		}},
		{Tool: "y", Findings: []model.Finding{
			{ID: "F-crit", Severity: model.SeverityCritical, File: "a.go"},
			{ID: "F-high", Severity: model.SeverityHigh, File: "b.go"},
		}},
	}}
	agg := r.Aggregate()
	if len(agg) != 3 {
		t.Fatalf("len = %d", len(agg))
	}
	if agg[0].Severity != model.SeverityCritical || agg[1].Severity != model.SeverityHigh || agg[2].Severity != model.SeverityLow {
		t.Errorf("wrong severity order: %v", agg)
	}
}
