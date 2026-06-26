package reporter

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/shfahiim/cyberai/internal/model"
)

// Terminal renders the report for human reading in a TTY.
// Uses ANSI colors when isTTY is true; degrades to plain text otherwise.
//
// Output is intentionally compact — terminal users want signal fast,
// not a wall of text.
type Terminal struct {
	// IsTTY controls color output. Set to false for piping/CI.
	IsTTY bool
	// MaxFindings limits how many findings we print. Zero = no limit.
	// Past this, we print "... and N more".
	MaxFindings int
	// ShowSuppressHints prints a one-line suppress command under each finding.
	ShowSuppressHints bool
	// ColorFn is overridable for tests / forcing color.
	ColorFn func(s string, c Color) string
}

// Color is the semantic color we want, abstracted from ANSI codes.
type Color string

const (
	ColorReset   Color = ""
	ColorBold    Color = "1"
	ColorDim     Color = "2"
	ColorRed     Color = "31"
	ColorGreen   Color = "32"
	ColorYellow  Color = "33"
	ColorBlue    Color = "34"
	ColorMagenta Color = "35"
	ColorCyan    Color = "36"
)

// NewTerminal builds a Terminal with defaults suitable for stdout.
func NewTerminal() *Terminal {
	isTTY := false
	if info, err := os.Stdout.Stat(); err == nil {
		isTTY = (info.Mode() & os.ModeCharDevice) != 0
	}
	return &Terminal{IsTTY: isTTY}
}

// colorize is the legacy escape-code wrapper used when ColorFn is set.
// Kept for tests that rely on the seam. When ColorFn is nil, we use lipgloss.
func (t *Terminal) colorize(s string, c Color) string {
	if t.ColorFn != nil {
		return t.ColorFn(s, c)
	}
	if !t.IsTTY || c == ColorReset {
		return s
	}
	return fmt.Sprintf("\033[%sm%s\033[0m", string(c), s)
}

// ensureColorProfile pins lipgloss's global profile to match t.IsTTY.
// Called at the top of Write so direct lipgloss usage in this file
// respects the test contract (IsTTY:false ⇒ no ANSI).
func (t *Terminal) ensureColorProfile() {
	if t.IsTTY {
		lipgloss.SetColorProfile(termenv.TrueColor)
	} else {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
}

// Write renders the report to w.
func (t *Terminal) Write(w io.Writer, r *Report) {
	// Pin lipgloss's color profile based on our TTY detection. This must
	// happen before any styled output, and lets the migration to lipgloss
	// keep the existing test contract.
	t.ensureColorProfile()

	if len(r.Findings) == 0 {
		if t.ColorFn != nil {
			fmt.Fprintln(w, t.colorize("✓ no findings at or above the configured threshold.", ColorGreen))
			return
		}
		fmt.Fprintln(w, successStyle(t.IsTTY).Render("✓ no findings at or above the configured threshold."))
		return
	}

	// Header
	if t.ColorFn != nil {
		fmt.Fprintf(w, "\n%s %s\n",
			t.colorize("cyberai", ColorBold),
			t.colorize(fmt.Sprintf("— %d findings", len(r.Findings)), ColorDim))
		fmt.Fprintf(w, "%s %s\n\n",
			t.colorize("target:", ColorDim), r.Target)
	} else {
		fmt.Fprintf(w, "\n%s %s\n",
			headerStyle(t.IsTTY).Render("cyberai"),
			dimStyle(t.IsTTY).Render(fmt.Sprintf("— %d findings", len(r.Findings))))
		fmt.Fprintf(w, "%s %s\n\n",
			keyStyle(t.IsTTY).Render("target:"), r.Target)
	}

	// By-severity counts
	counts := map[model.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	order := []model.Severity{
		model.SeverityCritical, model.SeverityHigh,
		model.SeverityMedium, model.SeverityLow, model.SeverityInfo,
	}
	parts := []string{}
	for _, sev := range order {
		if n := counts[sev]; n > 0 {
			if t.ColorFn != nil {
				parts = append(parts, t.colorize(fmt.Sprintf("%d %s", n, sev), severityColor(sev)))
			} else {
				parts = append(parts, severityLipglossStyle(sev, t.IsTTY).Render(
					fmt.Sprintf("%d %s", n, sev)))
			}
		}
	}
	if len(parts) > 0 {
		if t.ColorFn != nil {
			fmt.Fprintf(w, "%s %s\n\n", t.colorize("by severity:", ColorDim), strings.Join(parts, ", "))
		} else {
			fmt.Fprintf(w, "%s %s\n\n",
				keyStyle(t.IsTTY).Render("by severity:"),
				strings.Join(parts, ", "))
		}
	}

	// Per-finding lines (sort by severity then file for stable output)
	sorted := append([]model.Finding(nil), r.Findings...)
	model.SortFindings(sorted)

	max := t.MaxFindings
	if max == 0 {
		max = len(sorted)
	}
	for i, f := range sorted {
		if i >= max {
			if t.ColorFn != nil {
				fmt.Fprintf(w, "  %s\n", t.colorize(
					fmt.Sprintf("… and %d more (use --verbose or open the report)", len(sorted)-max),
					ColorDim))
			} else {
				fmt.Fprintf(w, "  %s\n", dimStyle(t.IsTTY).Render(
					fmt.Sprintf("… and %d more (use --verbose or open the report)", len(sorted)-max)))
			}
			break
		}
		t.writeOne(w, f)
	}

	fmt.Fprintln(w)
}

func (t *Terminal) writeOne(w io.Writer, f model.Finding) {
	if t.ColorFn != nil {
		sev := t.colorize(fmt.Sprintf("[%s]", f.Severity), severityColor(f.Severity))
		title := t.colorize(f.Title, ColorBold)
		loc := t.colorize(fmt.Sprintf("%s:%d", f.File, f.StartLine), ColorCyan)
		fmt.Fprintf(w, "  %s %s\n", sev, title)
		fmt.Fprintf(w, "    %s · %s · %s\n", loc, f.Tool, f.RuleID)
		if f.Description != "" && len(f.Description) < 200 {
			fmt.Fprintf(w, "    %s\n", t.colorize(firstLine(f.Description), ColorDim))
		}
		if t.ShowSuppressHints && f.ID != "" {
			fmt.Fprintf(w, "    %s\n", t.colorize(
				fmt.Sprintf("suppress: cyberai suppress %s --reason \"...\"", f.ID), ColorDim))
		}
		return
	}
	sevStyle := severityLipglossStyle(f.Severity, t.IsTTY)
	locStyle := locationLipglossStyle(t.IsTTY)
	fmt.Fprintf(w, "  %s %s\n",
		sevStyle.Render(fmt.Sprintf("[%s]", f.Severity)),
		headerStyle(t.IsTTY).Render(f.Title))
	fmt.Fprintf(w, "    %s · %s · %s\n",
		locStyle.Render(fmt.Sprintf("%s:%d", f.File, f.StartLine)),
		f.Tool, f.RuleID)
	if f.Description != "" && len(f.Description) < 200 {
		fmt.Fprintf(w, "    %s\n", dimStyle(t.IsTTY).Render(firstLine(f.Description)))
	}
	if t.ShowSuppressHints && f.ID != "" {
		fmt.Fprintf(w, "    %s\n", dimStyle(t.IsTTY).Render(
			fmt.Sprintf("suppress: cyberai suppress %s --reason \"...\"", f.ID)))
	}
}

func severityColor(s model.Severity) Color {
	switch s {
	case model.SeverityCritical:
		return ColorRed
	case model.SeverityHigh:
		return ColorMagenta
	case model.SeverityMedium:
		return ColorYellow
	case model.SeverityLow:
		return ColorBlue
	case model.SeverityInfo:
		return ColorCyan
	}
	return ColorReset
}

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			if len(line) > 160 {
				return line[:160] + "…"
			}
			return line
		}
	}
	return s
}

// --- lipgloss-backed helpers used when ColorFn is nil ---
//
// Each helper builds a fresh lipgloss.Style each call. That's fine for the
// terminal report (printed once per scan). If you need to render thousands
// of styled strings, hoist these into package-level vars.

func severityLipglossStyle(s model.Severity, isTTY bool) lipgloss.Style {
	c := termenv.Ascii
	if isTTY {
		c = termenv.TrueColor
	}
	lipgloss.SetColorProfile(c)
	var color lipgloss.Color
	switch s {
	case model.SeverityCritical:
		color = lipgloss.Color("#ff6b6b")
	case model.SeverityHigh:
		color = lipgloss.Color("#ff9f43")
	case model.SeverityMedium:
		color = lipgloss.Color("#ffd166")
	case model.SeverityLow:
		color = lipgloss.Color("#6ccff6")
	case model.SeverityInfo:
		color = lipgloss.Color("#8ce99a")
	default:
		color = lipgloss.Color("#94a3b8")
	}
	return lipgloss.NewStyle().Bold(true).Foreground(color)
}

func headerStyle(isTTY bool) lipgloss.Style {
	if isTTY {
		lipgloss.SetColorProfile(termenv.TrueColor)
	} else {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#ecfdf5"))
}

func keyStyle(isTTY bool) lipgloss.Style {
	if isTTY {
		lipgloss.SetColorProfile(termenv.TrueColor)
	} else {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#34d399"))
}

func dimStyle(isTTY bool) lipgloss.Style {
	if isTTY {
		lipgloss.SetColorProfile(termenv.TrueColor)
	} else {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#94a3b8"))
}

func successStyle(isTTY bool) lipgloss.Style {
	if isTTY {
		lipgloss.SetColorProfile(termenv.TrueColor)
	} else {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#4ade80"))
}

func locationLipglossStyle(isTTY bool) lipgloss.Style {
	if isTTY {
		lipgloss.SetColorProfile(termenv.TrueColor)
	} else {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#5eead4"))
}
