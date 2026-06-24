package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
)

// Progress is the abstraction the orchestrator's OnProgress callback goes
// through. Implementations either animate (spinner) or print one line per
// status update (plain). Off returns a no-op.
type Progress interface {
	// Start announces that the named unit of work has begun.
	Start(name string)
	// Update sets the current status text for a previously started unit.
	// Implementations may re-render.
	Update(name, status string)
	// Finish marks a unit as done. The final status is shown.
	Finish(name, status string)
	// Stop releases any resources. Safe to call multiple times.
	Stop()
}

// ProgressOptions configures NewProgress.
type ProgressOptions struct {
	// Spinner: true ⇒ use the animated spinner. false ⇒ plain per-line.
	Spinner bool
	// Writer is where progress output goes. Defaults to os.Stderr.
	Writer io.Writer
	// Unicode: true ⇒ use unicode glyphs. false ⇒ ASCII fallbacks.
	Unicode bool
}

// NewProgress picks an implementation based on opts. The caller decides
// whether to use a spinner (typically: stdout/stderr is a TTY and ui.progress
// != "off" / "plain").
func NewProgress(opts ProgressOptions) Progress {
	w := opts.Writer
	if w == nil {
		w = os.Stderr
	}
	if opts.Spinner {
		return newSpinnerProgress(w, opts.Unicode)
	}
	return &plainProgress{w: w}
}

// --- plain ---

// plainProgress prints one line per status update. The current behavior of
// the orchestrator callback, preserved verbatim for non-TTY contexts.
type plainProgress struct {
	w  io.Writer
	mu sync.Mutex
}

func (p *plainProgress) Start(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "  %s: running\n", name)
}

func (p *plainProgress) Update(name, status string) {
	// No-op in plain mode: we only print on Start/Finish to keep lines tidy.
	_ = name
	_ = status
}

func (p *plainProgress) Finish(name, status string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "  %s: %s\n", name, status)
}

func (p *plainProgress) Stop() {}

// --- spinner ---

// spinnerProgress animates a single line on stderr. It tracks each named
// unit's status in a map and re-renders one line per tick.
//
// Layout:
//
//	◐ semgrep   running
//	✓ gitleaks  done — 2 findings
//	✗ trivy     error: <err>
//
// Final line emitted on Stop() (or each Finish()).
type spinnerProgress struct {
	w       io.Writer
	mu      sync.Mutex
	states  map[string]string // name -> status text
	spinner *spinner.Spinner
	tick    *time.Ticker
	stopCh  chan struct{}
	unicode bool
	done    bool
}

func newSpinnerProgress(w io.Writer, unicode bool) *spinnerProgress {
	sp := spinner.New(spinner.CharSets[14], 100*time.Millisecond, spinner.WithWriter(w))
	sp.HideCursor = true
	p := &spinnerProgress{
		w:       w,
		states:  make(map[string]string),
		spinner: sp,
		stopCh:  make(chan struct{}),
		unicode: unicode,
	}
	sp.PreUpdate = func(_ *spinner.Spinner) { p.render() }
	return p
}

func (p *spinnerProgress) Start(name string) {
	p.mu.Lock()
	p.states[name] = "running"
	p.mu.Unlock()
	if !p.spinner.Active() {
		p.spinner.Start()
	}
}

func (p *spinnerProgress) Update(name, status string) {
	p.mu.Lock()
	p.states[name] = status
	p.mu.Unlock()
	// spinner.PreUpdate renders on every tick
}

func (p *spinnerProgress) Finish(name, status string) {
	p.mu.Lock()
	p.states[name] = status
	// If every unit is finished, stop the spinner.
	allDone := true
	for _, s := range p.states {
		if s == "running" || s == "" {
			allDone = false
			break
		}
	}
	p.done = allDone
	wasActive := p.spinner.Active()
	p.mu.Unlock()
	if allDone && wasActive {
		p.spinner.Stop()
		// Clear the current line so the final block sits flush left.
		fmt.Fprint(p.w, "\r\033[2K")
		p.mu.Lock()
		renderFinal(p.w, p.states, p.unicode)
		p.mu.Unlock()
	}
}

func (p *spinnerProgress) Stop() {
	p.mu.Lock()
	wasActive := p.spinner.Active()
	p.mu.Unlock()
	if wasActive {
		p.spinner.Stop()
		// Clear the current line so the final block sits flush left.
		fmt.Fprint(p.w, "\r\033[2K")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	renderFinal(p.w, p.states, p.unicode)
}

func (p *spinnerProgress) render() {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Move cursor to start of line, clear to end, then write the new state.
	fmt.Fprint(p.w, "\r\033[2K")
	renderFinal(p.w, p.states, p.unicode)
}

// renderFinal writes the multi-line progress block. When called from
// PreUpdate we want a single line; when called from Stop() we want the
// complete block. We always write the complete block — the spinner's
// PreUpdate hooks fire fast enough that the terminal handles the line
// updates cleanly.
func renderFinal(w io.Writer, states map[string]string, unicode bool) {
	// Stable order: insertion order via sorted keys (Go map iteration is
	// randomized, so sort for determinism in tests).
	keys := make([]string, 0, len(states))
	for k := range states {
		keys = append(keys, k)
	}
	// Simple alpha sort; the orchestrator calls Start() for each scanner
	// in order, but we don't depend on that.
	sortStrings(keys)
	for _, k := range keys {
		s := states[k]
		glyph, text := classifyStatus(s, unicode)
		fmt.Fprintf(w, "  %s %-10s %s\n", glyph, k, text)
	}
}

func classifyStatus(s string, unicode bool) (glyph, text string) {
	switch {
	case strings.HasPrefix(s, "done"):
		if unicode {
			return "\u2713", s // ✓
		}
		return "ok", s
	case strings.HasPrefix(s, "error"):
		if unicode {
			return "\u2717", s // ✗
		}
		return "FAIL", s
	case s == "skipped":
		if unicode {
			return "\u00b7", s // ·
		}
		return "skip", s
	default:
		if unicode {
			return "\u25d0", s // ◐
		}
		return "...", s
	}
}

// Tiny local sort to avoid pulling sort into this file's API surface.
func sortStrings(s []string) {
	// insertion sort — these slices are <10 items long in practice.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
