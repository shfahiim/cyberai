package cli

import (
	"fmt"
	"image/color"
	"math/rand"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/lucasb-eyer/go-colorful"
	"github.com/spf13/cobra"
)

type animModel struct {
	label       string
	size        int
	noScramble  bool
	cycleColors bool
	duration    time.Duration
	startTime   time.Time
	frame       int
	colorA      color.Color
	colorB      color.Color
	colorC      color.Color
	runes       []rune
	birthSteps  []int
	quitting    bool
}

type tickMsg time.Time

func (m animModel) Init() tea.Cmd {
	return tea.Batch(
		tea.Tick(50*time.Millisecond, func(t time.Time) tea.Msg {
			return tickMsg(t)
		}),
	)
}

func (m animModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC || msg.Type == tea.KeyEsc {
			m.quitting = true
			return m, tea.Quit
		}
	case tickMsg:
		if m.duration > 0 && time.Since(m.startTime) >= m.duration {
			m.quitting = true
			return m, tea.Quit
		}
		m.frame++
		return m, tea.Tick(50*time.Millisecond, func(t time.Time) tea.Msg {
			return tickMsg(t)
		})
	}
	return m, nil
}

func (m animModel) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder
	scrambleWidth := m.size
	if m.noScramble {
		scrambleWidth = 0
	}

	totalWidth := scrambleWidth
	if m.label != "" {
		if scrambleWidth > 0 {
			totalWidth += 1 // space
		}
		totalWidth += len(m.label)
	}

	// Generate color ramp with a three-stop cycle
	var colors []color.Color
	if m.cycleColors {
		colors = makeGradientRamp(totalWidth, m.colorA, m.colorB, m.colorC, m.colorA)
	} else {
		colors = makeGradientRamp(totalWidth, m.colorA, m.colorB, m.colorC)
	}

	// Render scrambled characters with birth step logic
	offset := m.frame
	isInitialized := m.frame >= 20 // Max birth steps is 20

	for i := 0; i < scrambleWidth; i++ {
		cIdx := (i + offset) % len(colors)
		col := colors[cIdx]

		var char string
		var style lipgloss.Style

		if !isInitialized && m.frame < m.birthSteps[i] {
			// Dim dot during birth phase
			char = "."
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#4b5563")).Faint(true)
		} else {
			// Scrambled cryptographic rune
			runeChar := m.runes[rand.Intn(len(m.runes))]
			char = string(runeChar)
			style = lipgloss.NewStyle().Foreground(lipgloss.Color(toHex(col)))
		}

		b.WriteString(style.Render(char))
	}

	if scrambleWidth > 0 && m.label != "" {
		b.WriteString(" ")
	}

	// Render label
	for i, char := range m.label {
		cIdx := (scrambleWidth + 1 + i + offset) % len(colors)
		col := colors[cIdx]
		style := lipgloss.NewStyle().Foreground(lipgloss.Color(toHex(col))).Bold(true)
		b.WriteString(style.Render(string(char)))
	}

	// Render animating ellipsis
	if isInitialized && m.label != "" {
		ellipsisFrames := []string{".", "..", "...", ""}
		ellIndex := (m.frame / 8) % len(ellipsisFrames)
		b.WriteString(ellipsisFrames[ellIndex])
	}

	return "\r" + b.String()
}

func toHex(c color.Color) string {
	r, g, b, _ := c.RGBA()
	return fmt.Sprintf("#%02x%02x%02x", uint8(r>>8), uint8(g>>8), uint8(b>>8))
}

func makeGradientRamp(size int, stops ...color.Color) []color.Color {
	if len(stops) < 2 {
		return nil
	}

	points := make([]colorful.Color, len(stops))
	for i, k := range stops {
		c, _ := colorful.MakeColor(k)
		points[i] = c
	}

	numSegments := len(stops) - 1
	blended := make([]color.Color, 0, size)

	segmentSize := size / numSegments
	if segmentSize == 0 {
		segmentSize = 1
	}

	for i := 0; i < numSegments; i++ {
		c1 := points[i]
		c2 := points[i+1]

		for j := 0; j < segmentSize; j++ {
			t := float64(j) / float64(segmentSize)
			c := c1.BlendHcl(c2, t)
			blended = append(blended, c)
		}
	}

	// Pad if short
	for len(blended) < size {
		blended = append(blended, stops[len(stops)-1])
	}
	// Truncate if long
	if len(blended) > size {
		blended = blended[:size]
	}

	return blended
}

func newAnimCmd() *cobra.Command {
	var (
		label       string
		durationStr string
		size        int
		noScramble  bool
		colorAStr   string
		colorBStr   string
		colorCStr   string
		runesStr    string
	)

	cmd := &cobra.Command{
		Use:   "anim",
		Short: "Run a live-progress terminal animation",
		Long:  `Run a custom scrambled-rune terminal animation with customizable colors, runes, and duration.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dur, err := time.ParseDuration(durationStr)
			if err != nil {
				return fmt.Errorf("invalid duration: %w", err)
			}

			// System theme colors: Mint Green (#34d399), Teal (#5eead4), Bright Green (#4ade80)
			cA, err := parseColor(colorAStr, color.RGBA{52, 211, 153, 255})
			if err != nil {
				return err
			}
			cB, err := parseColor(colorBStr, color.RGBA{94, 234, 212, 255})
			if err != nil {
				return err
			}
			cC, err := parseColor(colorCStr, color.RGBA{74, 222, 128, 255})
			if err != nil {
				return err
			}

			runes := []rune(runesStr)
			if len(runes) == 0 {
				runes = []rune("∅∇∈∉∑∏∝∞≈≠≡≤≥⌠⌡⊕⊗⊥")
			}

			birthSteps := make([]int, size)
			for i := 0; i < size; i++ {
				birthSteps[i] = rand.Intn(20) // Random frame trigger between 0 and 19
			}

			model := animModel{
				label:       label,
				size:        size,
				noScramble:  noScramble,
				cycleColors: true,
				duration:    dur,
				startTime:   time.Now(),
				colorA:      cA,
				colorB:      cB,
				colorC:      cC,
				runes:       runes,
				birthSteps:  birthSteps,
			}

			p := tea.NewProgram(model)
			if _, err := p.Run(); err != nil {
				return err
			}
			fmt.Println()
			return nil
		},
	}

	cmd.Flags().StringVar(&label, "label", "Thinking", "Text label to animate")
	cmd.Flags().StringVar(&durationStr, "duration", "2s", "Duration of the animation (e.g. 2s, 500ms, 0s for infinite)")
	cmd.Flags().IntVar(&size, "size", 10, "Number of scrambled characters")
	cmd.Flags().BoolVar(&noScramble, "no-scramble", false, "Disable the scrambled character prefix")
	cmd.Flags().StringVar(&colorAStr, "color-a", "#34d399", "Starting hex color of the gradient (System theme default: Mint Green)")
	cmd.Flags().StringVar(&colorBStr, "color-b", "#5eead4", "Middle hex color of the gradient (System theme default: Teal)")
	cmd.Flags().StringVar(&colorCStr, "color-c", "#4ade80", "Ending hex color of the gradient (System theme default: Bright Green)")
	cmd.Flags().StringVar(&runesStr, "runes", "∅∇∈∉∑∏∝∞≈≠≡≤≥⌠⌡⊕⊗⊥", "Scrambled runes to cycle through")

	return cmd
}

func parseColor(s string, def color.Color) (color.Color, error) {
	if s == "" {
		return def, nil
	}
	c, err := colorful.Hex(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex color %q: %w", s, err)
	}
	return c, nil
}
