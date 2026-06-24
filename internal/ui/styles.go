package ui

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/shfahiim/cyberai/internal/model"
)

// Shared terminal palette. The accent intentionally leans green to give the
// CLI a cleaner, more modern identity without flattening severity colors.
var (
	criticalColor = lipgloss.Color("#ff6b6b")
	highColor     = lipgloss.Color("#ff9f43")
	mediumColor   = lipgloss.Color("#ffd166")
	lowColor      = lipgloss.Color("#6ccff6")
	infoColor     = lipgloss.Color("#8ce99a")
	mutedColor    = lipgloss.Color("#94a3b8")
	keyColor      = lipgloss.Color("#34d399")
	successColor  = lipgloss.Color("#4ade80")
	warningColor  = lipgloss.Color("#fbbf24")
	errorColor    = lipgloss.Color("#f87171")
	headerColor   = lipgloss.Color("#ecfdf5")
	locationColor = lipgloss.Color("#5eead4")
)

// SeverityStyle returns a lipgloss style for the given severity. Used for
// the bracketed tags like [CRITICAL], [HIGH], etc.
func SeverityStyle(s model.Severity) lipgloss.Style {
	var c lipgloss.Color
	switch s {
	case model.SeverityCritical:
		c = criticalColor
	case model.SeverityHigh:
		c = highColor
	case model.SeverityMedium:
		c = mediumColor
	case model.SeverityLow:
		c = lowColor
	case model.SeverityInfo:
		c = infoColor
	default:
		c = mutedColor
	}
	return lipgloss.NewStyle().Bold(true).Foreground(c)
}

func headerStyle() lipgloss.Style {
	return lipgloss.NewStyle().Bold(true).Foreground(headerColor)
}

func keyStyle() lipgloss.Style {
	return lipgloss.NewStyle().Bold(true).Foreground(keyColor)
}

func dimStyle() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(mutedColor)
}

func successStyle() lipgloss.Style {
	return lipgloss.NewStyle().Bold(true).Foreground(successColor)
}

func warningStyle() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(warningColor).Bold(true)
}

func errorStyle() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(errorColor).Bold(true)
}

func locationStyle() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(locationColor)
}

// Renderer method aliases - let callers do r.ErrorStyle() instead of
// fetching styles as free functions. Each method is a thin wrapper that
// calls the corresponding helper. SeverityStyle is a free function (it
// takes a Severity argument), so it doesn't have a method form.
func (r *Renderer) HeaderStyle() lipgloss.Style   { return headerStyle() }
func (r *Renderer) KeyStyle() lipgloss.Style      { return keyStyle() }
func (r *Renderer) DimStyle() lipgloss.Style      { return dimStyle() }
func (r *Renderer) SuccessStyle() lipgloss.Style  { return successStyle() }
func (r *Renderer) WarningStyle() lipgloss.Style  { return warningStyle() }
func (r *Renderer) ErrorStyle() lipgloss.Style    { return errorStyle() }
func (r *Renderer) LocationStyle() lipgloss.Style { return locationStyle() }
