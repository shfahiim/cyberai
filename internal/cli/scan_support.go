package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shfahiim/cyberai/internal/model"
	"github.com/shfahiim/cyberai/internal/scanner"
	"github.com/shfahiim/cyberai/internal/tools"
	"github.com/shfahiim/cyberai/internal/ui"
)

type scanSummary struct {
	Phase             string            `json:"phase"`
	Target            string            `json:"target"`
	Hash              string            `json:"hash"`
	Languages         []string          `json:"languages"`
	Manifests         []string          `json:"manifests"`
	HasDocker         bool              `json:"has_docker"`
	HasK8s            bool              `json:"has_k8s"`
	HasTerraform      bool              `json:"has_terraform"`
	IsMonorepo        bool              `json:"is_monorepo"`
	VCS               string            `json:"vcs"`
	Router            string            `json:"router"`
	PlanSource        string            `json:"plan_source"`
	PlanCached        bool              `json:"plan_cached"`
	FindingsCount     int               `json:"findings_count"`
	SeverityCounts    map[string]int    `json:"severity_counts,omitempty"`
	SummaryPath       string            `json:"summary_path"`
	OutputDir         string            `json:"output_dir"`
	FormatPaths       map[string]string `json:"format_paths"`
	Formats           []string          `json:"formats"`
	DurationMs        int64             `json:"duration_ms"`
	LLMEnabled        bool              `json:"llm_enabled"`
	Threshold         string            `json:"threshold"`
	BootstrappedTools []string          `json:"bootstrapped_tools,omitempty"`
}

func shouldInstallMissingTools(opts *scanOptions, _ *cobra.Command) bool {
	return opts.InstallMissing
}

func ensureScannersAvailable(cmd *cobra.Command, scanners []scanner.NormalizingScanner, installMissing bool, ci bool) ([]string, error) {
	seen := map[string]bool{}
	missing := []string{}
	for _, s := range scanners {
		name := s.Name()
		if seen[name] {
			continue
		}
		seen[name] = true
		available, _ := s.Available()
		if !available {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil, nil
	}
	if !installMissing {
		if !ci {
			printBootstrapMessage(cmd, "warning", fmt.Sprintf("skipping missing scanners: %s (run with --install-missing to install)", strings.Join(missing, ", ")))
		}
		return nil, nil
	}

	mgr, err := tools.NewManager()
	if err != nil {
		if ci {
			return nil, fmt.Errorf("resolve tool manager: %w", err)
		}
		printBootstrapMessage(cmd, "warning", fmt.Sprintf("tool bootstrap unavailable: %v", err))
		return nil, nil
	}

	installed := make([]string, 0, len(missing))
	for _, name := range missing {
		printBootstrapMessage(cmd, "info", fmt.Sprintf("installing missing scanner: %s", name))
		if err := mgr.Install(name, tools.InstallOptions{}); err != nil {
			if ci {
				return installed, fmt.Errorf("install %s: %w", name, err)
			}
			printBootstrapMessage(cmd, "warning", fmt.Sprintf("failed to install %s: %v", name, err))
			continue
		}
		installed = append(installed, name)
		printBootstrapMessage(cmd, "success", fmt.Sprintf("installed scanner: %s", name))
	}
	return installed, nil
}

func printBootstrapMessage(cmd *cobra.Command, level, msg string) {
	uiR := uiFrom(cmd)
	line := msg
	if uiR != nil {
		switch level {
		case "success":
			line = uiR.SuccessStyle().Render(msg)
		case "warning":
			line = uiR.WarningStyle().Render(msg)
		default:
			line = uiR.KeyStyle().Render(msg)
		}
	}
	fmt.Fprintln(cmd.ErrOrStderr(), line)
}

func resolveSummaryFormat(opts *scanOptions) string {
	if opts.SummaryFormat != "" {
		return opts.SummaryFormat
	}
	if opts.CI {
		return "json"
	}
	return "pretty"
}

func writeScanSummary(cmd *cobra.Command, opts *scanOptions, summary *scanSummary) error {
	if summary == nil {
		return nil
	}
	switch strings.ToLower(resolveSummaryFormat(opts)) {
	case "", "pretty":
		printPrettyScanSummary(cmd, summary)
		return nil
	case "json":
		data, err := json.Marshal(summary)
		if err != nil {
			return fmt.Errorf("marshal scan summary: %w", err)
		}
		uiR := uiFrom(cmd)
		pretty := uiR != nil && uiR.UseColor()
		fmt.Fprintln(cmd.OutOrStdout(), string(ui.MaybePretty(data, pretty)))
		return nil
	case "off":
		return nil
	default:
		return fmt.Errorf("unknown summary format: %s", resolveSummaryFormat(opts))
	}
}

func printPrettyScanSummary(cmd *cobra.Command, summary *scanSummary) {
	w := cmd.OutOrStdout()
	uiR := uiFrom(cmd)

	head := "Scan complete"
	if summary.FindingsCount == 0 {
		head = "Scan complete - clean"
	}
	head = renderBrandTitle(uiR, head)
	fmt.Fprintln(w)
	fmt.Fprintln(w, head)
	fmt.Fprintf(w, "%s %s\n", scanKey(uiR, "target:"), summary.Target)
	fmt.Fprintf(w, "%s %s (%s)\n", scanKey(uiR, "router:"), summary.Router, summary.PlanSource)
	fmt.Fprintf(w, "%s %s  %s %s\n", scanKey(uiR, "threshold:"), summary.Threshold, scanKey(uiR, "duration:"), humanDuration(summary.DurationMs))
	fmt.Fprintf(w, "%s %s\n", scanKey(uiR, "reports:"), summary.OutputDir)
	if len(summary.BootstrappedTools) > 0 {
		fmt.Fprintf(w, "%s %s\n", scanKey(uiR, "bootstrapped:"), strings.Join(summary.BootstrappedTools, ", "))
	}

	parts := severitySummaryParts(summary.SeverityCounts, uiR)
	if len(parts) == 0 {
		msg := "no findings at or above the configured threshold"
		if uiR != nil {
			msg = uiR.SuccessStyle().Render(msg)
		}
		fmt.Fprintln(w, msg)
	} else {
		fmt.Fprintf(w, "%s %s\n", scanKey(uiR, "findings:"), strings.Join(parts, "  "))
	}

	hasArtifacts := false
	for _, format := range summary.Formats {
		if format != "terminal" && summary.FormatPaths[format] != "" {
			hasArtifacts = true
			break
		}
	}
	if !hasArtifacts {
		return
	}

	fmt.Fprintln(w)

	artifactCol := "ARTIFACT"
	pathCol := "PATH"
	if uiR != nil {
		artifactCol = uiR.DimStyle().Render(artifactCol)
		pathCol = uiR.DimStyle().Render(pathCol)
	}
	fmt.Fprintf(w, "  %-10s  %s\n", artifactCol, pathCol)

	for _, format := range summary.Formats {
		if format == "terminal" {
			continue
		}
		path := summary.FormatPaths[format]
		if path == "" {
			continue
		}

		paddedFormat := fmt.Sprintf("%-10s", format)
		if uiR != nil {
			paddedFormat = uiR.KeyStyle().Render(paddedFormat)
		}

		absPath, err := filepath.Abs(path)
		if err != nil {
			absPath = path
		}
		fileURL := "file://" + absPath
		clickablePath := terminalHyperlink(fileURL, path)

		fmt.Fprintf(w, "  %s  %s\n", paddedFormat, clickablePath)
	}
}

func severitySummaryParts(counts map[string]int, uiR *ui.Renderer) []string {
	if len(counts) == 0 {
		return nil
	}
	order := []struct {
		key string
		sev model.Severity
	}{
		{key: "critical", sev: model.SeverityCritical},
		{key: "high", sev: model.SeverityHigh},
		{key: "medium", sev: model.SeverityMedium},
		{key: "low", sev: model.SeverityLow},
		{key: "info", sev: model.SeverityInfo},
	}
	parts := []string{}
	for _, item := range order {
		n := counts[item.key]
		if n == 0 {
			continue
		}
		label := fmt.Sprintf("%d %s", n, item.key)
		if uiR != nil {
			label = ui.SeverityStyle(item.sev).Render(label)
		}
		parts = append(parts, label)
	}
	return parts
}

func scanKey(uiR *ui.Renderer, s string) string {
	if uiR != nil {
		return uiR.KeyStyle().Render(s)
	}
	return s
}

func humanDuration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	seconds := float64(ms) / 1000
	return fmt.Sprintf("%.2fs", seconds)
}

func resolveOutputDir(root, configured string, trusted bool) (string, error) {
	if configured == "" {
		configured = "cyberai-reports"
	}
	candidate := configured
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	candidate = filepath.Clean(candidate)
	if trusted {
		return candidate, nil
	}

	rootResolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		rootResolved = filepath.Clean(root)
	}
	candidateResolved, err := resolveWithExistingParents(candidate)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(rootResolved, candidateResolved)
	if err != nil {
		return "", fmt.Errorf("resolve output path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("untrusted output path escapes target root: %s", configured)
	}
	return candidate, nil
}

func resolveWithExistingParents(path string) (string, error) {
	path = filepath.Clean(path)
	tail := []string{}
	current := path
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", fmt.Errorf("resolve symlinks for %s: %w", current, err)
			}
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return filepath.Clean(resolved), nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return path, nil
		}
		tail = append(tail, filepath.Base(current))
		current = parent
	}
}

func terminalHyperlink(url, text string) string {
	return "\x1b]8;;" + url + "\x1b\\" + text + "\x1b]8;;\x1b\\"
}
