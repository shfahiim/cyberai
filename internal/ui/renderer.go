// Package ui centralizes CLI styling, progress, tables, and pretty-printing.
//
// Everything in this package is safe to use even when stdout/stderr are not
// terminals — colors, spinners, and pretty-printing all degrade to plain text.
//
// The Renderer is the main entry point. Build one with NewRenderer and pass it
// down to commands. Style helpers (SeverityStyle, HeaderStyle, etc.) take a
// renderer so callers don't need to plumb TTY booleans separately.
package ui

import (
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

// ColorMode describes how the renderer should treat color output.
type ColorMode string

const (
	ColorAuto   ColorMode = "auto"
	ColorAlways ColorMode = "always"
	ColorNever  ColorMode = "never"
)

// ProgressMode describes how the renderer should show long-running work.
type ProgressMode string

const (
	ProgressAuto    ProgressMode = "auto"
	ProgressSpinner ProgressMode = "spinner"
	ProgressPlain   ProgressMode = "plain"
	ProgressOff     ProgressMode = "off"
)

// RendererOptions is the input to NewRenderer. Caller is expected to have
// resolved precedence: --no-color flag > NO_COLOR env > config > TTY detect.
type RendererOptions struct {
	// Color: ColorAuto / ColorAlways / ColorNever. Empty = ColorAuto.
	Color ColorMode
	// Progress: ProgressAuto / ProgressSpinner / ProgressPlain / ProgressOff.
	// Empty = ProgressAuto.
	Progress ProgressMode
	// Unicode: nil = auto (true when stderr is a TTY). &true / &false force.
	Unicode *bool
	// StdoutIsTTY is the auto-detected TTY state of os.Stdout at startup.
	StdoutIsTTY bool
	// StderrIsTTY is the auto-detected TTY state of os.Stderr at startup.
	StderrIsTTY bool
}

// Renderer is the per-process UI state. Cheap to pass around.
type Renderer struct {
	color     ColorMode
	progress  ProgressMode
	unicode   bool
	stdoutTTY bool
	stderrTTY bool
	width     int
}

// NewRenderer builds a Renderer from opts. It also tells lipgloss about the
// resolved color profile globally so any sub-package using lipgloss directly
// inherits the right behavior.
func NewRenderer(opts RendererOptions) *Renderer {
	if opts.Color == "" {
		opts.Color = ColorAuto
	}
	if opts.Progress == "" {
		opts.Progress = ProgressAuto
	}

	useColor := shouldUseColor(opts.Color, opts.StdoutIsTTY)
	useSpinner := shouldUseSpinner(opts.Progress, opts.StderrIsTTY)
	useUnicode := shouldUseUnicode(opts.Unicode, opts.StderrIsTTY)

	// Set lipgloss's global color profile so any direct lipgloss usage in
	// downstream packages (e.g. the migrated terminal.go) inherits the same
	// on/off decision.
	switch {
	case !useColor:
		lipgloss.SetColorProfile(termenv.Ascii)
	case opts.StdoutIsTTY:
		lipgloss.SetColorProfile(termenv.TrueColor)
	default:
		lipgloss.SetColorProfile(termenv.ANSI)
	}

	w := 0
	if opts.StdoutIsTTY {
		if fd := int(os.Stdout.Fd()); fd > 0 {
			if width, _, err := term.GetSize(fd); err == nil {
				w = width
			}
		}
	}

	_ = useSpinner // referenced only via UseSpinner() below

	return &Renderer{
		color:     opts.Color,
		progress:  opts.Progress,
		unicode:   useUnicode,
		stdoutTTY: opts.StdoutIsTTY,
		stderrTTY: opts.StderrIsTTY,
		width:     w,
	}
}

// UseColor reports whether colored output is enabled.
func (r *Renderer) UseColor() bool {
	return r.color == ColorAlways || (r.color == ColorAuto && r.stdoutTTY)
}

// UseSpinner reports whether live-progress (spinner) mode is enabled.
// In auto mode, this resolves to r.stderrTTY (the spinner needs a TTY to
// animate).
func (r *Renderer) UseSpinner() bool {
	switch r.progress {
	case ProgressSpinner:
		return true
	case ProgressPlain, ProgressOff:
		return false
	default: // auto
		return r.stderrTTY
	}
}

// UnicodeEnabled reports whether unicode glyphs are allowed.
func (r *Renderer) UnicodeEnabled() bool { return r.unicode }

// StdoutIsTTY reports whether stdout is a terminal.
func (r *Renderer) StdoutIsTTY() bool { return r.stdoutTTY }

// StderrIsTTY reports whether stderr is a terminal.
func (r *Renderer) StderrIsTTY() bool { return r.stderrTTY }

// Width returns the terminal width in cells, or 0 if undetectable.
func (r *Renderer) Width() int { return r.width }

// ColorMode returns the resolved color mode.
func (r *Renderer) ColorMode() ColorMode { return r.color }

// ProgressMode returns the resolved progress mode.
func (r *Renderer) ProgressMode() ProgressMode { return r.progress }

// shouldUseColor resolves the color decision. Precedence has already been
// folded into opts.Color by the caller; here we just apply auto-detect.
func shouldUseColor(mode ColorMode, stdoutTTY bool) bool {
	switch mode {
	case ColorAlways:
		return true
	case ColorNever:
		return false
	default: // auto
		return stdoutTTY
	}
}

// shouldUseSpinner resolves whether the spinner path is active.
//
// Auto means: use spinner iff stderr is a TTY.
// Plain is the explicit non-animated fallback. Off suppresses progress output.
func shouldUseSpinner(mode ProgressMode, stderrTTY bool) bool {
	switch mode {
	case ProgressSpinner:
		return true
	case ProgressPlain, ProgressOff:
		return false
	default: // auto
		return stderrTTY
	}
}

func shouldUseUnicode(forced *bool, stderrTTY bool) bool {
	if forced != nil {
		return *forced
	}
	return stderrTTY
}

// CheckNoColor returns true if the NO_COLOR env var is set to a non-empty
// value. See https://no-color.org — any non-empty value disables color.
func CheckNoColor() bool {
	v := os.Getenv("NO_COLOR")
	return v != ""
}

// IsTerminal reports whether the given file descriptor is a terminal.
// Thin wrapper around golang.org/x/term.IsTerminal, exported so callers
// (e.g. cmd/cyberai/main.go) don't need to import x/term directly.
func IsTerminal(fd uintptr) bool {
	return term.IsTerminal(int(fd))
}

// ResolveColor folds precedence: --no-color flag > NO_COLOR env > config > auto.
// Returns ColorAlways / ColorNever / ColorAuto.
func ResolveColor(noColorFlag bool, configColor ColorMode) ColorMode {
	if noColorFlag {
		return ColorNever
	}
	if CheckNoColor() {
		return ColorNever
	}
	if configColor == ColorNever || configColor == ColorAlways || configColor == ColorAuto {
		return configColor
	}
	return ColorAuto
}

// ResolveProgress folds precedence: explicit modes win over auto. "off"
// and "plain" are explicit; "spinner" is explicit; empty/missing ⇒ auto.
func ResolveProgress(configProgress ProgressMode) ProgressMode {
	switch configProgress {
	case ProgressSpinner, ProgressPlain, ProgressOff:
		return configProgress
	default:
		return ProgressAuto
	}
}
