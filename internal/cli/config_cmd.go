package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/shfahiim/cyberai/internal/config"
	"github.com/shfahiim/cyberai/internal/llm"
	"github.com/shfahiim/cyberai/internal/ui"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect effective CyberAI configuration",
		Long: strings.Join([]string{
			"Show the configuration that would be used for a project.",
			"",
			"Precedence (highest first):",
			"  1. CLI flags on cyberai scan",
			"  2. Project .cyberai.yaml",
			"  3. Global ~/.cyberai/config.json (LLM keys/models only)",
			"  4. Built-in defaults",
			"",
			"Subcommands:",
			"  show   Print merged config for a project path",
		}, "\n"),
	}

	cmd.AddCommand(newConfigShowCmd())
	return cmd
}

func newConfigShowCmd() *cobra.Command {
	var (
		target string
		format string
	)

	cmd := &cobra.Command{
		Use:   "show [path]",
		Short: "Show effective configuration for a project",
		Long: strings.Join([]string{
			"Loads .cyberai.yaml from the project (if present) and prints the",
			"effective settings after defaults are applied.",
			"",
			"Examples:",
			"  cyberai config show",
			"  cyberai config show ./app --format json",
		}, "\n"),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				target = args[0]
			}
			root, err := resolveTarget(target)
			if err != nil {
				return err
			}
			cfg, err := config.Load(root)
			if err != nil {
				return err
			}

			provider := cfg.LLM.Provider
			apiKey, _ := llm.LookupAPIKey(provider)
			effective := map[string]any{
				"project_root":       root,
				"config_file":        configFilePath(root),
				"scanners":           cfg.Scanners,
				"disabled_scanners":  cfg.DisabledScanners,
				"severity_threshold": cfg.SeverityThreshold,
				"ignore_patterns":    cfg.IgnorePatterns,
				"output":             cfg.Output,
				"baseline":           cfg.BaselinePath,
				"policies":           cfg.Policies,
				"ui":                 cfg.UI,
				"llm": map[string]any{
					"provider":        provider,
					"model":           llm.ResolveModel(provider, cfg.LLM.Model),
					"enabled_default": cfg.LLMEnabled(nil),
					"api_key_set":     apiKey != "",
				},
			}

			switch strings.ToLower(format) {
			case "", "yaml":
				data, err := yaml.Marshal(effective)
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
			case "json":
				data, err := json.MarshalIndent(effective, "", "  ")
				if err != nil {
					return err
				}
				uiR := uiFrom(cmd)
				pretty := uiR != nil && uiR.UseColor()
				fmt.Fprintln(cmd.OutOrStdout(), string(ui.MaybePretty(data, pretty)))
			default:
				return fmt.Errorf("unknown format %q (use yaml or json)", format)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&target, "target", ".", "project root directory")
	cmd.Flags().StringVar(&format, "format", "yaml", "output format: yaml|json")

	return cmd
}

func configFilePath(root string) string {
	for _, name := range []string{config.FileName, config.FileNameAlt} {
		path := filepath.Join(root, name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}
