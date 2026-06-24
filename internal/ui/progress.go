package ui

import (
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Progress is the abstraction the orchestrator's OnProgress callback goes
// through. Implementations either animate (live) or print one line per
// status update (plain). Off returns a no-op.
type Progress interface {
	Start(name string)
	Update(name, status string)
	Finish(name, status string)
	Stop()
}

// ProgressOptions configures NewProgress.
type ProgressOptions struct {
	// Spinner: true => use the animated live display. false => plain per-line.
	Spinner bool
	// Writer is where progress output goes. Defaults to os.Stderr.
	Writer io.Writer
	// Unicode: true => use unicode glyphs. false => ASCII fallbacks.
	Unicode bool
	// Renderer enables colored progress output when provided.
	Renderer *Renderer
	// Names initializes states with the expected list of scanner names.
	Names []string
}

func NewProgress(opts ProgressOptions) Progress {
	w := opts.Writer
	if w == nil {
		w = os.Stderr
	}
	unicode := opts.Unicode
	if opts.Renderer != nil {
		unicode = opts.Renderer.UnicodeEnabled()
	}
	if opts.Spinner {
		return newLiveProgress(w, opts.Renderer, unicode, opts.Names)
	}
	return &plainProgress{w: w}
}

// --- plain ---

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
	_ = name
	_ = status
}

func (p *plainProgress) Finish(name, status string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "  %s: %s\n", name, status)
}

func (p *plainProgress) Stop() {}

// --- live ---

// liveProgress maintains a small terminal block: a narrow CyberAI animation and
// one mutable status line. Completed scanners are printed as fixed lines.
type liveProgress struct {
	w        io.Writer
	renderer *Renderer
	unicode  bool

	mu           sync.Mutex
	states       map[string]string
	order        []string
	frame        int
	liveRendered bool
	started      bool
	stopped      bool
	stopCh       chan struct{}
	doneCh       chan struct{}
	stopOnce     sync.Once
	birthSteps   []int
	runes        []rune
}

func newLiveProgress(w io.Writer, renderer *Renderer, unicode bool, names []string) *liveProgress {
	runes := []rune("∅∇∈∉∑∏∝∞≈≠≡≤≥⌠⌡⊕⊗⊥")
	size := 10
	birthSteps := make([]int, size)
	for i := 0; i < size; i++ {
		birthSteps[i] = rand.Intn(20)
	}
	states := make(map[string]string)
	var order []string
	for _, name := range names {
		states[name] = ""
		order = append(order, name)
	}
	return &liveProgress{
		w:          w,
		renderer:   renderer,
		unicode:    unicode,
		states:     states,
		order:      order,
		birthSteps: birthSteps,
		runes:      runes,
	}
}

func (p *liveProgress) Start(name string) {
	p.mu.Lock()
	p.setStateLocked(name, "running")
	p.ensureLoopLocked()
	p.renderLiveLocked()
	p.mu.Unlock()
}

func (p *liveProgress) Update(name, status string) {
	p.mu.Lock()
	p.setStateLocked(name, status)
	p.ensureLoopLocked()
	p.renderLiveLocked()
	p.mu.Unlock()
}

func (p *liveProgress) Finish(name, status string) {
	p.mu.Lock()
	p.setStateLocked(name, status)
	p.ensureLoopLocked()
	allDone := p.allDoneLocked()
	if allDone {
		p.stopped = true
	}
	p.clearLiveLocked()
	fmt.Fprintln(p.w, p.renderState(name, status))
	if !allDone {
		p.renderLiveLocked()
	} else {
		fmt.Fprintln(p.w, p.animationLineLocked()+" Scan complete")
	}
	stopCh := p.stopCh
	doneCh := p.doneCh
	p.mu.Unlock()

	if allDone && stopCh != nil {
		p.stopOnce.Do(func() { close(stopCh) })
		if doneCh != nil {
			<-doneCh
		}
	}
}

func (p *liveProgress) Stop() {
	p.mu.Lock()
	if !p.started {
		p.stopped = true
		p.mu.Unlock()
		return
	}
	if p.stopped {
		doneCh := p.doneCh
		p.mu.Unlock()
		if doneCh != nil {
			<-doneCh
		}
		return
	}
	p.stopped = true
	p.clearLiveLocked()
	stopCh := p.stopCh
	doneCh := p.doneCh
	p.mu.Unlock()

	if stopCh != nil {
		p.stopOnce.Do(func() { close(stopCh) })
	}
	if doneCh != nil {
		<-doneCh
	}
}

func (p *liveProgress) ensureLoopLocked() {
	if p.started {
		return
	}
	p.started = true
	p.stopCh = make(chan struct{})
	p.doneCh = make(chan struct{})
	go p.loop(p.stopCh, p.doneCh)
}

func (p *liveProgress) loop(stopCh chan struct{}, doneCh chan struct{}) {
	defer close(doneCh)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			p.mu.Lock()
			if p.stopped || len(p.states) == 0 {
				p.mu.Unlock()
				continue
			}
			p.frame++
			p.renderLiveLocked()
			p.mu.Unlock()
		}
	}
}

func (p *liveProgress) setStateLocked(name, status string) {
	if _, ok := p.states[name]; !ok {
		p.order = append(p.order, name)
	}
	p.states[name] = status
}

func (p *liveProgress) allDoneLocked() bool {
	if len(p.states) == 0 {
		return false
	}
	for _, status := range p.states {
		if status == "" || status == "running" {
			return false
		}
	}
	return true
}

func (p *liveProgress) renderLiveLocked() {
	if p.stopped {
		p.clearLiveLocked()
		return
	}
	top := p.animationLineLocked()
	bottom := p.liveLineLocked()
	if !p.liveRendered {
		fmt.Fprintln(p.w, top)
		fmt.Fprintln(p.w, bottom)
		p.liveRendered = true
		return
	}
	fmt.Fprint(p.w, "\033[2A\r\033[2K")
	fmt.Fprintln(p.w, top)
	fmt.Fprint(p.w, "\r\033[2K")
	fmt.Fprintln(p.w, bottom)
}

func (p *liveProgress) clearLiveLocked() {
	if !p.liveRendered {
		return
	}
	fmt.Fprint(p.w, "\033[2A\r\033[2K\n\r\033[2K\033[1A\r")
	p.liveRendered = false
}

func interpolateColor(c1, c2 [3]float64, t float64) string {
	r := c1[0] + t*(c2[0]-c1[0])
	g := c1[1] + t*(c2[1]-c1[1])
	b := c1[2] + t*(c2[2]-c1[2])
	return fmt.Sprintf("#%02x%02x%02x", uint8(r), uint8(g), uint8(b))
}

func makeRamp(size int) []string {
	stops := [][3]float64{
		{52, 211, 153},   // #34d399 (Mint Green)
		{94, 234, 212},   // #5eead4 (Teal)
		{74, 222, 128},   // #4ade80 (Bright Green)
		{52, 211, 153},   // Loop back to Mint Green
	}
	ramp := make([]string, size)
	numSegments := len(stops) - 1
	segmentSize := size / numSegments
	if segmentSize == 0 {
		segmentSize = 1
	}

	idx := 0
	for i := 0; i < numSegments; i++ {
		c1 := stops[i]
		c2 := stops[i+1]
		for j := 0; j < segmentSize; j++ {
			if idx >= size {
				break
			}
			t := float64(j) / float64(segmentSize)
			ramp[idx] = interpolateColor(c1, c2, t)
			idx++
		}
	}
	// Pad remaining
	for idx < size {
		ramp[idx] = interpolateColor(stops[len(stops)-2], stops[len(stops)-1], 1.0)
		idx++
	}
	return ramp
}

func (p *liveProgress) animationLineLocked() string {
	logo := "CyberAI"
	size := 10
	var b strings.Builder

	// Render main logo
	if p.renderer != nil {
		b.WriteString(p.renderer.HeaderStyle().Render(logo))
	} else {
		b.WriteString(logo)
	}
	b.WriteByte(' ')

	// Generate color ramp
	ramp := makeRamp(size)

	// Shift index for color rotation
	offset := p.frame
	isInitialized := p.frame >= 20

	for i := 0; i < size; i++ {
		cIdx := (i + offset) % len(ramp)
		colHex := ramp[cIdx]

		var char string
		var style lipgloss.Style

		if !isInitialized && p.frame < p.birthSteps[i] {
			char = "."
			if p.renderer != nil {
				style = p.renderer.DimStyle().Faint(true)
			} else {
				style = lipgloss.NewStyle().Foreground(lipgloss.Color("#4b5563")).Faint(true)
			}
		} else {
			// Select a random cryptographic rune
			runeChar := p.runes[rand.Intn(len(p.runes))]
			char = string(runeChar)
			style = lipgloss.NewStyle().Foreground(lipgloss.Color(colHex))
		}

		b.WriteString(style.Render(char))
	}

	// Render animating ellipsis
	if isInitialized {
		ellipsisFrames := []string{".", "..", "...", ""}
		ellIndex := (p.frame / 8) % len(ellipsisFrames)
		b.WriteString(ellipsisFrames[ellIndex])
	}

	return b.String()
}

func (p *liveProgress) liveLineLocked() string {
	if len(p.order) == 0 {
		return p.dim("waiting for scanner events")
	}
	for i := len(p.order) - 1; i >= 0; i-- {
		name := p.order[i]
		if p.states[name] == "running" {
			return p.renderState(name, "running")
		}
	}
	name := p.order[len(p.order)-1]
	return p.renderState(name, p.states[name])
}

func (p *liveProgress) renderState(name, status string) string {
	short := compactStatus(status)
	if p.renderer == nil {
		return fmt.Sprintf("> %s %s", name, short)
	}
	nameStyled := p.renderer.KeyStyle().Render(name)
	switch {
	case strings.HasPrefix(status, "done"):
		return fmt.Sprintf("%s %s %s", p.renderer.SuccessStyle().Render("✓"), nameStyled, p.renderer.SuccessStyle().Render(short))
	case strings.HasPrefix(status, "error"):
		return fmt.Sprintf("%s %s %s", p.renderer.ErrorStyle().Render("✗"), nameStyled, p.renderer.ErrorStyle().Render(short))
	case status == "skipped":
		return fmt.Sprintf("%s %s %s", p.renderer.DimStyle().Render("·"), nameStyled, p.renderer.DimStyle().Render(short))
	case status == "running":
		return fmt.Sprintf("%s %s %s", p.renderer.WarningStyle().Render("◐"), nameStyled, p.renderer.WarningStyle().Render(short))
	default:
		return fmt.Sprintf("%s %s %s", p.renderer.DimStyle().Render(">"), nameStyled, p.renderer.DimStyle().Render(short))
	}
}

func (p *liveProgress) dim(s string) string {
	if p.renderer == nil {
		return s
	}
	return p.renderer.DimStyle().Render(s)
}

func compactStatus(status string) string {
	switch {
	case strings.HasPrefix(status, "done"):
		return "done"
	case strings.HasPrefix(status, "error"):
		if len(status) > 48 {
			return status[:45] + "..."
		}
		return status
	case status == "running":
		return "running"
	case status == "skipped":
		return "skipped"
	default:
		if len(status) > 48 {
			return status[:45] + "..."
		}
		return status
	}
}

func classifyStatus(status string, unicode bool) (glyph, text string) {
	switch {
	case strings.HasPrefix(status, "done"):
		if unicode {
			return "✓", status
		}
		return "ok", status
	case strings.HasPrefix(status, "error"):
		if unicode {
			return "✗", status
		}
		return "FAIL", status
	case status == "skipped":
		if unicode {
			return "·", status
		}
		return "skip", status
	default:
		if unicode {
			return "◐", status
		}
		return "...", status
	}
}
