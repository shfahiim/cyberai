package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/shfahiim/cyberai/internal/baseline"
	"github.com/shfahiim/cyberai/internal/config"
	"github.com/shfahiim/cyberai/internal/enrichment"
	"github.com/shfahiim/cyberai/internal/gitdiff"
	"github.com/shfahiim/cyberai/internal/llm"
	"github.com/shfahiim/cyberai/internal/model"
	"github.com/shfahiim/cyberai/internal/policy"
	"github.com/shfahiim/cyberai/internal/project"
	"github.com/shfahiim/cyberai/internal/reporter"
	"github.com/shfahiim/cyberai/internal/router"
	"github.com/shfahiim/cyberai/internal/scanner"
	"github.com/shfahiim/cyberai/internal/summarizer"
	"github.com/shfahiim/cyberai/internal/suppression"
	"github.com/shfahiim/cyberai/internal/ui"
)

type scannerSelection struct {
	SemgrepRulesets []string
	TrivyScanners   []string
}

// selectRouter returns the appropriate router based on whether LLM is enabled.
func selectRouter(llmEnabled bool, cfg *config.Config, _ *project.Profile) (router.Router, error) {
	if !llmEnabled {
		return router.NewDefault(), nil
	}
	var cache *router.Cache
	if c, err := router.NewCache(""); err == nil {
		cache = c
	}
	return router.NewLLM(cfg.LLM.Provider, cfg.LLM.Model, cache)
}

// scanOptions holds the resolved flag values for the `scan` command.
type scanOptions struct {
	Target            string
	Formats           []string
	OutputDir         string
	Severity          string
	Model             string
	Only              []string
	Preset            string
	NoLLM             bool
	SmartLLM          bool
	PickModel         bool
	CI                bool
	BaselinePath      string
	Verbose           bool
	InstallMissing    bool
	SummaryFormat     string
	Save              bool
	LLMOverride       *bool
	Enrich            bool
	Diff              string
	SuppressHints     bool
}

func newScanCmd() *cobra.Command {
	opts := &scanOptions{}

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a project for security issues",
		Long: strings.Join([]string{
			"Run deterministic security scanners over a project and show results.",
			"",
			"Quick start:",
			"  cyberai scan                     # terminal summary, no LLM, no report files",
			"  cyberai scan --save              # also write SARIF/JSON/HTML under ./cyberai-reports",
			"  cyberai scan --smart             # enable Gemini router + HTML summary",
			"  cyberai scan --preset ci -o out/ # CI: SARIF + JUnit + enrichment, fail on findings",
			"",
			"Presets (bundle common flag combinations):",
			"  quick   Default: fast local scan, terminal output, LLM off",
			"  full    All report formats, EPSS/KEV enrichment, smart routing",
			"  ci      No LLM, SARIF+JUnit+JSON, enrichment, non-zero exit on findings",
			"  pr      Changed files only (--diff origin/HEAD), medium+ severity",
			"",
			"Scanner categories for --only:",
			"  sast, secrets, sca, iac, license, docker, cicd",
			"  Aliases: code, dependencies, infrastructure, containers, pipelines",
			"",
			"CyberAI is read-only: it never modifies source files or git state.",
		}, "\n"),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.Target = args[0]
			}
			if err := applyScanPreset(opts, cmd); err != nil {
				return err
			}
			return runScan(cmd, opts)
		},
	}

	cmd.Flags().StringVarP(&opts.OutputDir, "output", "o", "", "directory for saved reports (implies --save)")
	cmd.Flags().BoolVar(&opts.Save, "save", false, "write report files (default formats unless --format is set)")
	cmd.Flags().StringVar(&opts.Severity, "severity", "", "minimum severity: critical|high|medium|low|info")
	cmd.Flags().StringVar(&opts.Model, "model", "", "LLM model for routing and summaries")
	cmd.Flags().StringSliceVar(&opts.Only, "only", nil, "scanner categories (see help); aliases supported")
	cmd.Flags().StringVar(&opts.Preset, "preset", "", "scan preset: quick|full|ci|pr (default: quick, or ci when --ci is set)")
	cmd.Flags().BoolVar(&opts.SmartLLM, "smart", false, "enable LLM router and HTML summarizer")
	cmd.Flags().BoolVar(&opts.NoLLM, "no-llm", false, "disable LLM router and summarizer")
	cmd.Flags().BoolVar(&opts.PickModel, "pick-model", false, "interactively choose an LLM model (requires --smart)")
	cmd.Flags().BoolVar(&opts.CI, "ci", false, "CI mode: preset ci, JSON summary, non-zero exit on findings")
	cmd.Flags().StringVar(&opts.BaselinePath, "baseline", "", "baseline JSON report; hide findings already in baseline")
	cmd.Flags().BoolVarP(&opts.Verbose, "verbose", "v", false, "show router plan, timings, and per-scanner stats")
	cmd.Flags().BoolVar(&opts.InstallMissing, "install-missing", false, "install missing managed scanners before scanning")
	cmd.Flags().StringVar(&opts.SummaryFormat, "summary", "", "end-of-run summary: pretty|json|off (default: pretty, json in --ci)")
	cmd.Flags().StringArrayVar(&opts.Formats, "format", nil, "report format(s): sarif|json|markdown|html|terminal|junit|csv")
	cmd.Flags().BoolVar(&opts.Enrich, "enrich", false, "fetch EPSS and CISA KEV data; add priority labels")
	cmd.Flags().StringVar(&opts.Diff, "diff", "", "only report findings in files changed vs git ref (e.g. main, HEAD~1)")
	cmd.Flags().BoolVar(&opts.SuppressHints, "suppress-hints", true, "show cyberai suppress … hints under terminal findings")

	return cmd
}

func runScan(cmd *cobra.Command, opts *scanOptions) error {
	uiR := uiFrom(cmd)

	if uiR != nil && !opts.CI {
		printBrandTo(cmd.OutOrStdout(), uiR)
		fmt.Fprintln(cmd.OutOrStdout())
	}

	// 1. Resolve target
	target, err := resolveTarget(opts.Target)
	if err != nil {
		return err
	}

	// 2. Load config (optional .cyberai.yaml at target)
	cfg, err := config.Load(target)
	if err != nil {
		return err
	}

	// 2b. If config has a ui: block, rebuild the renderer so config-driven
	// color/progress choices take effect for the rest of this command.
	if cfg.UI.Color != "" || cfg.UI.Progress != "" || cfg.UI.Unicode != nil {
		mode := ui.ResolveColor(false, ui.ColorMode(cfg.UI.Color))
		prog := ui.ResolveProgress(ui.ProgressMode(cfg.UI.Progress))
		if uiR != nil {
			uiR = ui.NewRenderer(ui.RendererOptions{
				Color:       mode,
				Progress:    prog,
				Unicode:     cfg.UI.Unicode,
				StdoutIsTTY: uiR.StdoutIsTTY(),
				StderrIsTTY: uiR.StderrIsTTY(),
			})
			AttachRenderer(cmd.Root(), uiR)
		}
	}

	// 3. Apply CLI overrides on top of config
	if opts.Severity != "" {
		cfg.SeverityThreshold = model.Severity(strings.ToLower(opts.Severity))
	}
	if opts.Model != "" {
		cfg.LLM.Model = opts.Model
	}
	if len(opts.Only) > 0 {
		normalized, err := normalizeCategories(opts.Only)
		if err != nil {
			return err
		}
		cfg.Scanners = normalized
	}
	if opts.OutputDir != "" {
		cfg.Output.Path = opts.OutputDir
	}
	if opts.NoLLM || opts.CI {
		f := false
		cfg.LLM.Enabled = &f
	}
	if opts.SmartLLM && !opts.NoLLM && !opts.CI {
		f := true
		cfg.LLM.Enabled = &f
	}
	if opts.BaselinePath != "" {
		cfg.BaselinePath = opts.BaselinePath
	}
	cliLLM := opts.LLMOverride
	if opts.SmartLLM && !opts.NoLLM && !opts.CI {
		f := true
		cliLLM = &f
	}
	if opts.NoLLM || opts.CI {
		f := false
		cliLLM = &f
	}

	// 4. Run deterministic project detection
	profile, err := project.Detect(target)
	if err != nil {
		return err
	}

	// 4b. Run the router (LLM or default). The router decides which scanners
	// to enable based on the project; the user's --only flag wins if set.
	llmEnabled := cfg.LLMEnabled(cliLLM)
	if err := prepareLLMSession(cmd, cfg, llmEnabled, opts.PickModel); err != nil {
		return err
	}
	r, err := selectRouter(llmEnabled, cfg, profile)
	if err != nil {
		return err
	}
	plan, err := r.Route(profile)
	if err != nil {
		return fmt.Errorf("router: %w", err)
	}

	// Apply the plan: if user didn't override scanners, use the plan's list.
	// If user passed --only, that wins. The plan still influences everything
	// else (rulesets, severity threshold) — but explicit CLI flags always win
	// over the plan. --severity and --only are user intent; the plan is a
	// suggestion.
	if len(opts.Only) == 0 && len(plan.Scanners) > 0 {
		cfg.Scanners = plan.Scanners
	}
	if opts.Severity == "" && plan.SeverityThreshold != "" {
		cfg.SeverityThreshold = model.Severity(plan.SeverityThreshold)
	}
	if len(plan.IgnorePatterns) > 0 && len(cfg.IgnorePatterns) == 0 {
		cfg.IgnorePatterns = plan.IgnorePatterns
	}
	selection := scannerSelection{
		SemgrepRulesets: plan.SemgrepRulesets,
		TrivyScanners:   plan.TrivyScanners,
	}

	if opts.Verbose {
		key := func(s string) string {
			if uiR != nil {
				return uiR.KeyStyle().Render(s)
			}
			return s
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s %s (source=%s, cached=%v)\n",
			key("router:"), r.Name(), plan.Source, plan.FromCache)
		fmt.Fprintf(cmd.OutOrStdout(), "%s scanners=%v, threshold=%s\n",
			key("plan:"), plan.Scanners, plan.SeverityThreshold)
		fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n",
			key("reasoning:"), plan.Reasoning)
	}

	if opts.Verbose {
		key := func(s string) string {
			if uiR != nil {
				return uiR.KeyStyle().Render(s)
			}
			return s
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", key("target:"), profile.Root)
		fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", key("langs:"), strings.Join(profile.Languages, ", "))
		fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", key("manifests:"), strings.Join(profile.Manifests, ", "))
		fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", key("lockfiles:"), strings.Join(profile.Lockfiles, ", "))
		fmt.Fprintf(cmd.OutOrStdout(), "%s docker=%v  k8s=%v  terraform=%v  ansible=%v\n",
			key("docker:"), profile.HasDocker, profile.HasK8s, profile.HasTerraform, profile.HasAnsible)
		fmt.Fprintf(cmd.OutOrStdout(), "%s %s  monorepo=%v  tests=%v  ci=%v\n",
			key("vcs:"), profile.VCS, profile.IsMonorepo, profile.HasTests, profile.HasCI)
		fmt.Fprintf(cmd.OutOrStdout(), "%s loc=%d  files=%d\n",
			key("loc:"), profile.TotalLOC, profile.FileCount)
		fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", key("hash:"), profile.Hash())
		fmt.Fprintf(cmd.OutOrStdout(), "%s enabled=%v  provider=%s  model=%s\n",
			key("llm:"), cfg.LLMEnabled(cliLLM), cfg.LLM.Provider, llm.ResolveModel(cfg.LLM.Provider, cfg.LLM.Model))
	}

	// 5. Run scanners via the orchestrator (Phase 1.5: Semgrep end-to-end;
	// Phase 1.6 will add Gitleaks + Trivy).
	//
	scanners := buildScanners(cfg, profile, selection)
	var scannerNames []string
	for _, s := range scanners {
		scannerNames = append(scannerNames, s.Name())
	}

	// We wrap the OnProgress callback so the user sees a live spinner when
	// stderr is a TTY (and ui.progress isn't "off"/"plain"). Otherwise we
	// fall back to one-line-per-event output (the existing behavior).
	var progress ui.Progress
	if uiR != nil && uiR.UseSpinner() {
		progress = ui.NewProgress(ui.ProgressOptions{
			Spinner:  true,
			Writer:   cmd.ErrOrStderr(),
			Unicode:  uiR.UnicodeEnabled(),
			Renderer: uiR,
			Names:    scannerNames,
		})
	} else {
		progress = ui.NewProgress(ui.ProgressOptions{
			Spinner: false,
			Writer:  cmd.ErrOrStderr(),
			Names:    scannerNames,
		})
	}
	defer progress.Stop()
	bootstrappedTools, err := ensureScannersAvailable(cmd, scanners, shouldInstallMissingTools(opts, cmd), opts.CI)
	if err != nil {
		return err
	}

	orch := &scanner.Orchestrator{
		Scanners: scanners,
		OnProgress: func(name, status string) {
			if status == "running" {
				progress.Start(name)
				return
			}
			progress.Finish(name, status)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if opts.Verbose {
		msg := "running scanners..."
		if uiR != nil {
			msg = uiR.DimStyle().Render(msg)
		}
		fmt.Fprintln(cmd.OutOrStdout(), msg)
	}
	result, err := orch.Run(ctx, target)
	if err != nil {
		return fmt.Errorf("orchestrator: %w", err)
	}
	progress.Stop()

	// 6. Apply severity filter + ignore patterns + baseline filter
	var filtered []model.Finding
	var skippedByIgnore int
	var baselineSuppressed int
	baselineIDs := map[string]bool{}
	if cfg.BaselinePath != "" {
		base, err := baseline.Load(cfg.BaselinePath)
		if err != nil {
			return fmt.Errorf("load baseline: %w", err)
		}
		for _, f := range base.Findings {
			baselineIDs[f.ID] = true
		}
		if opts.Verbose {
			key := func(s string) string {
				if uiR != nil {
					return uiR.KeyStyle().Render(s)
				}
				return s
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s (%d findings)\n",
				key("baseline:"), cfg.BaselinePath, len(base.Findings))
		}
	}
	for _, f := range result.Aggregate() {
		if !f.MeetsThreshold(cfg.SeverityThreshold) {
			continue
		}
		if cfg.ShouldIgnorePath(f.File) {
			skippedByIgnore++
			continue
		}
		if baselineIDs[f.ID] {
			baselineSuppressed++
			continue
		}
		filtered = append(filtered, f)
	}

	// 6b. Optional enrichment (EPSS + KEV).
	if opts.Enrich {
		enrichClient, err := enrichment.NewClient("")
		if err != nil {
			if opts.Verbose {
				fmt.Fprintf(cmd.ErrOrStderr(), "enrichment: %v\n", err)
			}
		} else {
			filtered = enrichClient.Enrich(filtered)
			if opts.Verbose {
				fmt.Fprintf(cmd.OutOrStdout(), "enrichment: applied EPSS+KEV to %d findings\n", len(filtered))
			}
		}
	}

	// 6c. Policy gate evaluation.
	if len(cfg.Policies.Gates) > 0 {
		gates := make([]policy.Gate, len(cfg.Policies.Gates))
		for i, g := range cfg.Policies.Gates {
			gates[i] = policy.Gate{Name: g.Name, FailOn: g.FailOn}
		}
		violations := policy.Evaluate(gates, filtered)
		if len(violations) > 0 {
			fmt.Fprint(cmd.ErrOrStderr(), policy.FormatViolations(violations))
			if opts.CI {
				return fmt.Errorf("policy: %d gate(s) violated", len(violations))
			}
		}
	}

	// 6d. Git diff filter — restrict to changed files.
	if opts.Diff != "" {
		changed, err := gitdiff.ChangedFiles(profile.Root, opts.Diff)
		if err != nil {
			if opts.Verbose {
				fmt.Fprintf(cmd.ErrOrStderr(), "gitdiff: %v\n", err)
			}
			// Non-fatal: proceed without filtering.
		} else {
			before := len(filtered)
			filtered = gitdiff.FilterFindingsByChanged(filtered, changed)
			if opts.Verbose {
				fmt.Fprintf(cmd.OutOrStdout(), "gitdiff: %d → %d findings (diff ref=%s, changed=%d files)\n",
					before, len(filtered), opts.Diff, len(changed))
			}
		}
	}

	// Apply suppression file filtering (.cyberai-suppressions.yaml).
	{
		sf, sfErr := suppression.Load(profile.Root)
		if sfErr != nil && opts.Verbose {
			msg := fmt.Sprintf("suppressions: %v", sfErr)
			if uiR != nil {
				msg = uiR.WarningStyle().Render(msg)
			}
			fmt.Fprintln(cmd.ErrOrStderr(), msg)
		}
		if sfErr == nil && len(sf.Suppressions) > 0 {
			unsuppressed, suppCount, expiredCount := sf.FilterFindings(filtered)
			filtered = unsuppressed
			if opts.Verbose {
				key := func(s string) string {
					if uiR != nil {
						return uiR.KeyStyle().Render(s)
					}
					return s
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s %d suppressed by .cyberai-suppressions.yaml (%d via expired rules)\n",
					key("suppressions:"), suppCount, expiredCount)
			}
		}
	}

	if opts.Verbose {
		key := func(s string) string {
			if uiR != nil {
				return uiR.KeyStyle().Render(s)
			}
			return s
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s %d total, %d after severity filter, %d suppressed by ignore patterns, %d suppressed by baseline\n",
			key("findings:"), len(result.Aggregate()), len(filtered), skippedByIgnore, baselineSuppressed)
		for _, sr := range result.Results {
			tool := sr.Tool
			if uiR != nil {
				tool = uiR.HeaderStyle().Render(tool)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "  %s: %d findings (skipped=%v err=%q)\n",
				tool, len(sr.Findings), sr.Skipped, sr.Error)
		}
	}

	// 7. Render reports when the user asked to save artifacts.
	saveReports := shouldSaveReports(opts, cmd)
	formats := resolveFormats(opts, cfg, saveReports)
	outputDir := ""
	formatPaths := map[string]string{}

	rep := reporter.NewReport(
		profile.Root, profile.Hash(),
		filtered, result.Results,
		len(result.Aggregate()), skippedByIgnore,
		result.Duration,
	)

	if saveReports {
		var err error
		outputDir, err = resolveOutputDir(profile.Root, cfg.Output.Path, opts.OutputDir != "")
		if err != nil {
			return err
		}
		if err := os.MkdirAll(outputDir, 0o755); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}

		summaryHTML := ""
		if llmEnabled && !opts.CI && hasFormat(formats, "html") {
			sumr, err := summarizer.NewLLM(cfg.LLM.Provider, cfg.LLM.Model)
			if err != nil {
				if opts.Verbose {
					msg := fmt.Sprintf("summarizer setup: %v", err)
					if uiR != nil {
						msg = uiR.WarningStyle().Render(msg)
					}
					fmt.Fprintln(cmd.ErrOrStderr(), msg)
				}
			} else if sum, err := sumr.Summarize(filtered); err != nil {
				if opts.Verbose {
					msg := fmt.Sprintf("summarizer: %v", err)
					if uiR != nil {
						msg = uiR.WarningStyle().Render(msg)
					}
					fmt.Fprintln(cmd.ErrOrStderr(), msg)
				}
			} else if sum != nil {
				summaryHTML = sum.Markdown
				if opts.Verbose {
					key := "summary:"
					if uiR != nil {
						key = uiR.KeyStyle().Render(key)
					}
					fmt.Fprintf(cmd.OutOrStdout(), "%s generated by %s/%s\n", key, cfg.LLM.Provider, cfg.LLM.Model)
				}
			}
		}

		formatPaths, err = writeReports(cmd, outputDir, rep, formats, summaryHTML)
		if err != nil {
			return err
		}
	}

	if !opts.CI && hasFormat(formats, "terminal") {
		term := reporter.NewTerminal()
		term.ShowSuppressHints = opts.SuppressHints
		term.Write(cmd.OutOrStdout(), rep)
	}

	printSkippedScannerSummary(cmd, result.Results)

	summaryPath := formatPaths["json"]
	summary := &scanSummary{
		Phase:             "1.8-summarizer",
		Target:            profile.Root,
		Hash:              profile.Hash(),
		Languages:         profile.Languages,
		Manifests:         profile.Manifests,
		HasDocker:         profile.HasDocker,
		HasK8s:            profile.HasK8s,
		HasTerraform:      profile.HasTerraform,
		IsMonorepo:        profile.IsMonorepo,
		VCS:               profile.VCS,
		Router:            r.Name(),
		PlanSource:        plan.Source,
		PlanCached:        plan.FromCache,
		FindingsCount:     len(filtered),
		SeverityCounts:    countFindingsBySeverity(filtered),
		SummaryPath:       summaryPath,
		OutputDir:         outputDir,
		FormatPaths:       formatPaths,
		Formats:           formats,
		DurationMs:        result.Duration.Milliseconds(),
		LLMEnabled:        cfg.LLMEnabled(cliLLM),
		Threshold:         string(cfg.SeverityThreshold),
		BootstrappedTools: bootstrappedTools,
	}
	if err := writeScanSummary(cmd, opts, summary); err != nil {
		return err
	}

	// 8. CI exit code: non-zero if any finding meets the threshold.
	if opts.CI && len(filtered) > 0 {
		return fmt.Errorf("ci mode: %d findings meet threshold %s", len(filtered), cfg.SeverityThreshold)
	}
	return nil
}

// buildScanners returns the scanners enabled by the user's config + CLI +
// the router's plan.
//
// Trivy is multi-category: it can run as SCA, IaC, or license scanning.
// Secrets are handled by Gitleaks, so `--only secrets` does not implicitly
// pull in Trivy. If no Trivy-relevant categories are enabled, we don't run it.
func buildScanners(cfg *config.Config, profile *project.Profile, selection scannerSelection) []scanner.NormalizingScanner {
	var out []scanner.NormalizingScanner

	if cfg.IsScannerEnabled("sast") {
		// Prefer the router's semgrep rulesets if any; otherwise infer.
		rulesets := selection.SemgrepRulesets
		if len(rulesets) == 0 {
			rulesets = router.DefaultSemgrepRulesets(profile)
		}
		out = append(out, &scanner.Semgrep{
			Configs: rulesets,
		})
	}

	if cfg.IsScannerEnabled("secrets") {
		out = append(out, &scanner.Gitleaks{})
	}

	if cfg.IsScannerEnabled("iac") && projectHasIaC(profile) {
		out = append(out, &scanner.Checkov{})
	}

	if cfg.IsScannerEnabled("docker") && profile.HasDocker {
		out = append(out, &scanner.Hadolint{})
	}

	if cfg.IsScannerEnabled("cicd") && profile.HasCI {
		out = append(out, &scanner.Zizmor{})
		out = append(out, &scanner.Actionlint{})
	}

	if cfg.IsScannerEnabled("sca") {
		out = append(out, &scanner.Grype{})
		out = append(out, &scanner.OSVScanner{})
		if hasLanguage(profile, "go") {
			out = append(out, &scanner.Govulncheck{})
		}
	}

	// Trivy covers SCA, IaC, and license.
	trivyScanners := []string{}
	if cfg.IsScannerEnabled("sca") {
		trivyScanners = append(trivyScanners, "vuln")
	}
	if cfg.IsScannerEnabled("iac") {
		trivyScanners = append(trivyScanners, "misconfig")
	}
	if cfg.IsScannerEnabled("license") {
		trivyScanners = append(trivyScanners, "license")
	}
	// Router may have specified additional trivy scanners; merge them in, but
	// never widen beyond the categories the user/config explicitly enabled.
	for _, s := range selection.TrivyScanners {
		if !trivyScannerAllowed(cfg, s) {
			continue
		}
		found := false
		for _, e := range trivyScanners {
			if e == s {
				found = true
				break
			}
		}
		if !found {
			trivyScanners = append(trivyScanners, s)
		}
	}
	if len(trivyScanners) > 0 {
		out = append(out, &scanner.Trivy{
			Scanners: trivyScanners,
		})
	}

	return out
}

func projectHasIaC(profile *project.Profile) bool {
	if profile == nil {
		return false
	}
	return profile.HasTerraform || profile.HasK8s || profile.HasAnsible || profile.HasDocker || profile.HasCI
}

func hasLanguage(profile *project.Profile, lang string) bool {
	if profile == nil {
		return false
	}
	for _, l := range profile.Languages {
		if strings.EqualFold(l, lang) {
			return true
		}
	}
	return false
}

func resolveTarget(t string) (string, error) {
	if t == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("getwd: %w", err)
		}
		return cwd, nil
	}
	abs, err := filepath.Abs(t)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("stat target: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("target is not a directory: %s", abs)
	}
	return abs, nil
}

// resolveFormats decides which formats to render.
//
// When saveReports is false, only terminal output is produced.
// Precedence when saving: --format flag > config.output.formats > default file formats.
func resolveFormats(opts *scanOptions, cfg *config.Config, saveReports bool) []string {
	if !saveReports {
		return []string{"terminal"}
	}

	var formats []string
	if len(opts.Formats) > 0 {
		for _, f := range opts.Formats {
			for _, part := range strings.Split(f, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					formats = append(formats, part)
				}
			}
		}
	} else {
		cfgFormats := cfg.Output.Formats
		hasFileFormat := false
		for _, f := range cfgFormats {
			if f != "terminal" {
				hasFileFormat = true
				break
			}
		}
		if hasFileFormat {
			formats = append(formats, cfgFormats...)
		} else {
			formats = append(formats, defaultFileFormats...)
		}
	}
	// De-dupe while preserving order.
	seen := map[string]bool{}
	out := []string{}
	for _, f := range formats {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

func trivyScannerAllowed(cfg *config.Config, scannerName string) bool {
	switch scannerName {
	case "vuln":
		return cfg.IsScannerEnabled("sca")
	case "misconfig":
		return cfg.IsScannerEnabled("iac")
	case "license":
		return cfg.IsScannerEnabled("license")
	default:
		return false
	}
}

func countFindingsBySeverity(findings []model.Finding) map[string]int {
	out := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	for _, f := range findings {
		switch f.Severity {
		case model.SeverityCritical:
			out["critical"]++
		case model.SeverityHigh:
			out["high"]++
		case model.SeverityMedium:
			out["medium"]++
		case model.SeverityLow:
			out["low"]++
		case model.SeverityInfo:
			out["info"]++
		}
	}
	return out
}

func hasFormat(formats []string, name string) bool {
	for _, f := range formats {
		if f == name {
			return true
		}
	}
	return false
}

// writeReports renders the report in each requested format and writes the
// file. It returns a map of format -> written path. Errors are aggregated
// so a single failing format doesn't kill the rest.
//
// summaryHTML, when non-empty, is the rendered LLM executive summary that
// the HTML template injects into its "Executive summary" banner. It is
// ignored for all non-HTML formats (SARIF/JSON/Markdown stay clean for CI).
func writeReports(cmd *cobra.Command, outputDir string, rep *reporter.Report, formats []string, summaryHTML string) (map[string]string, error) {
	paths := map[string]string{}
	var firstErr error
	for _, f := range formats {
		// "terminal" is rendered to stdout, not a file - handled in the caller.
		if f == "terminal" {
			continue
		}
		// HTML goes to a styled report. If the LLM summarizer ran, the
		// summaryHTML string is injected as the "Executive summary" banner.
		if f == "html" {
			data, err := reporter.HTML(rep, summaryHTML)
			if err != nil && firstErr == nil {
				firstErr = fmt.Errorf("render %s: %w", f, err)
				continue
			}
			p := filepath.Join(outputDir, "report.html")
			if err := os.WriteFile(p, data, 0o644); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("write %s: %w", f, err)
				continue
			}
			paths[f] = p
			continue
		}

		var (
			data []byte
			err  error
			ext  string
		)
		switch f {
		case "json":
			data, err = reporter.JSON(rep)
			ext = ".json"
		case "markdown":
			ext = ".md"
			data = []byte(reporter.Markdown(rep))
		case "sarif":
			data, err = reporter.SARIF(rep, Version)
			ext = ".sarif.json"
		case "junit":
			data, err = reporter.JUnit(rep)
			ext = ".junit.xml"
		case "csv":
			data, err = reporter.CSV(rep)
			ext = ".csv"
		default:
			firstErr = fmt.Errorf("unknown format: %s", f)
			continue
		}
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("render %s: %w", f, err)
			}
			continue
		}
		p := filepath.Join(outputDir, "report"+ext)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("write %s: %w", f, err)
			}
			continue
		}
		paths[f] = p
		if opts := cmd; opts != nil {
			// Keep cmd referenced for future verbose logging.
			_ = opts
		}
	}
	return paths, firstErr
}
