package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shfahiim/cyberai/internal/config"
	"github.com/shfahiim/cyberai/internal/llm"
	"github.com/shfahiim/cyberai/internal/project"
	"github.com/shfahiim/cyberai/internal/tools"
	"github.com/shfahiim/cyberai/internal/ui"
)

func newDoctorCmd() *cobra.Command {
	var target string

	cmd := &cobra.Command{
		Use:   "doctor [path]",
		Short: "Check toolchain, config, and project readiness",
		Long: strings.Join([]string{
			"Runs a non-destructive health check before scanning.",
			"",
			"Doctor reports:",
			"  • Managed and system scanner availability",
			"  • Project config (.cyberai.yaml) and suppressions file",
			"  • Git repository status (for --diff / PR scans)",
			"  • LLM API key and model configuration",
			"  • Suggested next commands when something is missing",
			"",
			"Examples:",
			"  cyberai doctor",
			"  cyberai doctor ./services/api",
		}, "\n"),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				target = args[0]
			}
			return runDoctor(cmd, target)
		},
	}

	cmd.Flags().StringVar(&target, "target", ".", "project root to inspect")

	return cmd
}

func runDoctor(cmd *cobra.Command, target string) error {
	uiR := uiFrom(cmd)
	root, err := resolveTarget(target)
	if err != nil {
		return err
	}

	fmt.Fprintln(cmd.OutOrStdout(), renderBrandTitle(uiR, "doctor"))
	fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n\n", doctorKey(uiR, "target:"), root)

	issues := 0

	// Toolchain
	mgr, mgrErr := tools.NewManager()
	if mgrErr != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "%s %v\n", doctorWarn(uiR), mgrErr)
		issues++
	} else {
		rows, err := mgr.List()
		if err != nil {
			return err
		}
		available, missing, manual := 0, []string{}, []string{}
		for _, r := range rows {
			if r.Bundled != nil || r.Probe.Installed {
				available++
				continue
			}
			if mgr.IsInstallable(r.Tool.Name) {
				missing = append(missing, r.Tool.Name)
			} else {
				manual = append(manual, r.Tool.Name)
			}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s %d/%d scanners available\n",
			doctorKey(uiR, "tools:"), available, len(rows))
		if len(missing) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s missing managed tools: %s\n",
				doctorWarn(uiR), strings.Join(missing, ", "))
			fmt.Fprintf(cmd.OutOrStdout(), "  %s cyberai tools install %s\n",
				doctorKey(uiR, "fix:"), strings.Join(missing, " "))
			issues++
		}
		if len(manual) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s manual install: %s (see cyberai tools list)\n",
				doctorHint(uiR), strings.Join(manual, ", "))
		}
	}

	// Config
	cfgPath := filepath.Join(root, config.FileName)
	if _, err := os.Stat(cfgPath); err == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", doctorOK(uiR), cfgPath)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "%s no project config (optional)\n", doctorHint(uiR))
		fmt.Fprintf(cmd.OutOrStdout(), "  %s cyberai setup\n", doctorKey(uiR, "fix:"))
	}

	// Suppressions
	suppPath := filepath.Join(root, ".cyberai-suppressions.yaml")
	if _, err := os.Stat(suppPath); err == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", doctorOK(uiR), suppPath)
	}

	// Git
	if isGitRepo(root) {
		branch := gitOutput(root, "rev-parse", "--abbrev-ref", "HEAD")
		fmt.Fprintf(cmd.OutOrStdout(), "%s git repo on %s\n", doctorOK(uiR), branch)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "%s not a git repository (--diff / --preset pr need git)\n", doctorHint(uiR))
	}

	// LLM
	provider := llm.ResolveProvider("")
	key, source := llm.LookupAPIKey(provider)
	if key != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "%s LLM key configured (%s via %s)\n",
			doctorOK(uiR), provider, source)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "%s LLM disabled (no API key; use cyberai scan --smart after setup --llm)\n", doctorHint(uiR))
	}

	// Project profile snapshot
	profile, err := project.Detect(root)
	if err == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "%s langs=%s docker=%v ci=%v\n",
			doctorKey(uiR, "profile:"),
			strings.Join(profile.Languages, ","),
			profile.HasDocker,
			profile.HasCI)
	}

	fmt.Fprintln(cmd.OutOrStdout())
	if issues == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "%s Ready to scan. Try: cyberai scan\n", doctorOK(uiR))
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s %d issue(s) found. Run cyberai setup to fix most of them.\n", doctorWarn(uiR), issues)
	return nil
}

func isGitRepo(root string) bool {
	cmd := exec.Command("git", "rev-parse", "--is-inside-work-tree")
	cmd.Dir = root
	out, err := cmd.Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

func gitOutput(root string, args ...string) string {
	cmd := exec.Command("git", args...)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func doctorKey(uiR *ui.Renderer, s string) string {
	if uiR != nil {
		return uiR.KeyStyle().Render(s)
	}
	return s
}

func doctorOK(uiR *ui.Renderer) string {
	if uiR != nil {
		return uiR.SuccessStyle().Render("ok")
	}
	return "ok"
}

func doctorWarn(uiR *ui.Renderer) string {
	if uiR != nil {
		return uiR.WarningStyle().Render("warn")
	}
	return "warn"
}

func doctorHint(uiR *ui.Renderer) string {
	if uiR != nil {
		return uiR.DimStyle().Render("info")
	}
	return "info"
}
