package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shfahiim/cyberai/internal/config"
	"github.com/shfahiim/cyberai/internal/project"
	"github.com/shfahiim/cyberai/internal/scanner"
	"github.com/shfahiim/cyberai/internal/tools"
	"github.com/shfahiim/cyberai/internal/ui"
)

type setupOptions struct {
	Target       string
	InstallTools bool
	InitConfig   bool
	EnableLLM    bool
	SkipLLM      bool
}

func newSetupCmd() *cobra.Command {
	opts := &setupOptions{
		InstallTools: true,
		InitConfig:   true,
	}

	cmd := &cobra.Command{
		Use:   "setup [path]",
		Short: "Prepare a project for scanning (tools, config, optional LLM)",
		Long: strings.Join([]string{
			"One-shot onboarding for a project directory.",
			"",
			"By default setup will:",
			"  1. Detect the project stack (languages, Docker, IaC, CI configs)",
			"  2. Install managed scanners that match the stack",
			"  3. Create .cyberai.yaml if it does not exist",
			"  4. Leave LLM routing disabled unless --llm is passed",
			"",
			"After setup, run:",
			"  cyberai scan",
			"  cyberai scan --preset ci -o reports/",
			"",
			"Examples:",
			"  cyberai setup",
			"  cyberai setup ./my-app --llm",
			"  cyberai setup --no-install-tools --init",
		}, "\n"),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.Target = args[0]
			}
			return runSetup(cmd, opts)
		},
	}

	cmd.Flags().BoolVar(&opts.InstallTools, "install-tools", true, "install managed scanners for the detected project stack")
	cmd.Flags().BoolVar(&opts.InitConfig, "init", true, "write .cyberai.yaml when missing")
	cmd.Flags().BoolVar(&opts.EnableLLM, "llm", false, "interactively configure LLM routing and save preferences")
	cmd.Flags().BoolVar(&opts.SkipLLM, "skip-llm", false, "write llm.enabled: false into the generated config")

	return cmd
}

func runSetup(cmd *cobra.Command, opts *setupOptions) error {
	uiR := uiFrom(cmd)
	if uiR != nil {
		printBrandTo(cmd.OutOrStdout(), uiR)
		fmt.Fprintln(cmd.OutOrStdout())
	}

	target, err := resolveTarget(opts.Target)
	if err != nil {
		return err
	}

	profile, err := project.Detect(target)
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", setupKey(uiR, "target:"), profile.Root)
	if len(profile.Languages) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", setupKey(uiR, "languages:"), strings.Join(profile.Languages, ", "))
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s docker=%v k8s=%v terraform=%v ci=%v\n",
		setupKey(uiR, "detected:"), profile.HasDocker, profile.HasK8s, profile.HasTerraform, profile.HasCI)
	fmt.Fprintln(cmd.OutOrStdout())

	if opts.InitConfig {
		cfgPath := filepath.Join(target, config.FileName)
		if _, err := os.Stat(cfgPath); err == nil {
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s (already exists)\n", setupOK(uiR), cfgPath)
		} else if err := writeStarterConfig(target, opts.SkipLLM); err != nil {
			return err
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "%s wrote %s\n", setupOK(uiR), cfgPath)
		}
	}

	if opts.InstallTools {
		if err := installToolsForProfile(cmd, profile); err != nil {
			return err
		}
	}

	if opts.EnableLLM {
		cfg := config.Default()
		cfg.LLM.Enabled = boolPtr(true)
		if err := prepareLLMSession(cmd, cfg, true, false); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s LLM routing enabled for future scans (use cyberai scan --smart)\n", setupOK(uiR))
	} else if !opts.SkipLLM {
		fmt.Fprintf(cmd.OutOrStdout(), "%s LLM routing disabled by default (use cyberai scan --smart or cyberai setup --llm)\n", setupHint(uiR))
	}

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintf(cmd.OutOrStdout(), "%s cyberai scan\n", setupKey(uiR, "next:"))
	fmt.Fprintf(cmd.OutOrStdout(), "%s cyberai doctor\n", setupKey(uiR, "check:"))
	return nil
}

func writeStarterConfig(root string, skipLLM bool) error {
	path := filepath.Join(root, config.FileName)
	example := `# cyberai project config — all keys optional.

# Scanner categories: sast, secrets, sca, iac, license, docker, cicd
# Aliases also work: code, dependencies, infrastructure, containers, pipelines
# scanners:
#   - sast
#   - secrets

# severity_threshold: low

# Save report files with: cyberai scan --save -o cyberai-reports
# output:
#   formats: [sarif, json, markdown, html, terminal]
#   path: cyberai-reports

# Enable smart routing: cyberai scan --smart
# llm:
#   enabled: false
#   provider: gemini
#   model: gemini-3.5-flash

# Policy gates for CI (see cyberai scan --preset ci)
# policies:
#   gates:
#     - name: no-critical
#       fail_on: "severity == critical"
`
	if skipLLM {
		example = strings.Replace(example, "#   enabled: false", "  enabled: false", 1)
	}
	return os.WriteFile(path, []byte(example), 0o644)
}

func installToolsForProfile(cmd *cobra.Command, profile *project.Profile) error {
	mgr, err := tools.NewManager()
	if err != nil {
		return err
	}

	targets := recommendedTools(profile)
	if len(targets) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no managed tools recommended for this project")
		return nil
	}

	var firstErr error
	for _, name := range targets {
		if !mgr.IsInstallable(name) {
			fmt.Fprintf(cmd.OutOrStdout(), "  %-10s  manual install required (cyberai tools list)\n", name)
			continue
		}
		status := tools.Probe(name)
		if status.Installed {
			fmt.Fprintf(cmd.OutOrStdout(), "  %-10s  already available\n", name)
			continue
		}
		progress, live := newToolProgress(cmd)
		progress.Start(name)
		if err := mgr.Install(name, tools.InstallOptions{}); err != nil {
			finishToolProgress(cmd, progress, live, "error", name, err.Error())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		finishToolProgress(cmd, progress, live, "success", name, "installed")
	}
	return firstErr
}

func recommendedTools(profile *project.Profile) []string {
	seen := map[string]bool{}
	add := func(names ...string) {
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
			}
		}
	}
	add("semgrep", "gitleaks", "trivy", "grype", "osv-scanner", "syft")
	if scanner.ProfileHasIaC(profile) {
		add("checkov")
	}
	if profile.HasDocker {
		add("hadolint")
	}
	if profile.HasCI {
		add("zizmor", "actionlint")
	}
	if scanner.HasLanguage(profile, "go") {
		add("govulncheck")
	}
	// Stable order for readable output.
	order := []string{"semgrep", "gitleaks", "trivy", "grype", "osv-scanner", "govulncheck", "checkov", "hadolint", "zizmor", "actionlint", "syft"}
	sorted := []string{}
	for _, name := range order {
		if seen[name] {
			sorted = append(sorted, name)
		}
	}
	return sorted
}

func setupKey(uiR *ui.Renderer, s string) string {
	if uiR != nil {
		return uiR.KeyStyle().Render(s)
	}
	return s
}

func setupOK(uiR *ui.Renderer) string {
	msg := "ok"
	if uiR != nil {
		return uiR.SuccessStyle().Render(msg)
	}
	return msg
}

func setupHint(uiR *ui.Renderer) string {
	msg := "hint"
	if uiR != nil {
		return uiR.DimStyle().Render(msg)
	}
	return msg
}

func boolPtr(v bool) *bool {
	return &v
}
