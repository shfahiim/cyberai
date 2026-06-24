package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/shfahiim/cyberai/internal/ui"
)

const brandLogoPlain = `   ______      __              ___    ____
  / ____/_  __/ /_  ___  _____/   |  /  _/
 / /   / / / / __ \/ _ \/ ___/ /| |  / /  
/ /___/ /_/ / /_/ /  __/ /  / ___ |_/ /   
\____/\__, /_.___/\___/_/  /_/  |_/___/   
     /____/`

const brandTagline = "local security scanning, triage, and reports"

func printBrand(cmd *cobra.Command) {
	printBrandTo(cmd.OutOrStdout(), uiFrom(cmd))
}

func printBrandTo(w io.Writer, r *ui.Renderer) {
	fmt.Fprintln(w, renderBrandLogo(r))
	fmt.Fprintln(w, renderBrandTagline(r))
}

func renderBrandLogo(r *ui.Renderer) string {
	if r == nil || !r.UseColor() {
		return brandLogoPlain
	}
	lines := strings.Split(brandLogoPlain, "\n")
	styles := []lipgloss.Style{
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#34d399")),
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#5eead4")),
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#8ce99a")),
	}
	for i, line := range lines {
		lines[i] = styles[i%len(styles)].Render(line)
	}
	return strings.Join(lines, "\n")
}

func renderBrandTagline(r *ui.Renderer) string {
	if r == nil {
		return brandTagline
	}
	return r.DimStyle().Render(brandTagline)
}

func renderBrandTitle(r *ui.Renderer, label string) string {
	title := "CyberAI"
	if label != "" {
		title += " " + label
	}
	if r == nil {
		return title
	}
	return r.HeaderStyle().Render(title)
}
