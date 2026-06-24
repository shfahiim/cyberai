package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

const (
	presetQuick = "quick"
	presetFull  = "full"
	presetCI    = "ci"
	presetPR    = "pr"
)

// defaultFileFormats are written when the user asks to save reports without
// specifying explicit formats.
var defaultFileFormats = []string{"sarif", "json", "markdown", "html", "terminal"}

// applyScanPreset mutates opts based on the selected preset. Preset flags only
// fill in values the user did not explicitly override on the CLI.
func applyScanPreset(opts *scanOptions, cmd *cobra.Command) error {
	preset := strings.ToLower(strings.TrimSpace(opts.Preset))
	if preset == "" {
		if opts.CI {
			preset = presetCI
		} else {
			preset = presetQuick
		}
	}

	switch preset {
	case presetQuick, "default":
		if !cmd.Flags().Changed("smart") && !cmd.Flags().Changed("no-llm") && !opts.CI {
			opts.NoLLM = true
		}
	case presetFull:
		if !cmd.Flags().Changed("smart") && !cmd.Flags().Changed("no-llm") {
			opts.SmartLLM = true
		}
		if !cmd.Flags().Changed("enrich") {
			opts.Enrich = true
		}
		if !cmd.Flags().Changed("save") && !cmd.Flags().Changed("output") && len(opts.Formats) == 0 {
			opts.Save = true
		}
		if !cmd.Flags().Changed("format") && len(opts.Formats) == 0 {
			opts.Formats = append([]string(nil), defaultFileFormats...)
		}
	case presetCI:
		opts.CI = true
		opts.NoLLM = true
		if !cmd.Flags().Changed("enrich") {
			opts.Enrich = true
		}
		if !cmd.Flags().Changed("format") && len(opts.Formats) == 0 {
			opts.Formats = []string{"sarif", "junit", "json"}
		}
		if !cmd.Flags().Changed("save") && !cmd.Flags().Changed("output") {
			opts.Save = true
		}
	case presetPR:
		opts.NoLLM = true
		if !cmd.Flags().Changed("diff") && opts.Diff == "" {
			opts.Diff = "origin/HEAD"
		}
		if !cmd.Flags().Changed("severity") {
			opts.Severity = "medium"
		}
	default:
		return fmt.Errorf("unknown preset %q (valid: quick, full, ci, pr)", preset)
	}
	return nil
}

// shouldSaveReports returns true when scan output files should be written.
func shouldSaveReports(opts *scanOptions, cmd *cobra.Command) bool {
	if opts.CI || opts.Save {
		return true
	}
	if cmd.Flags().Changed("output") && opts.OutputDir != "" {
		return true
	}
	if cmd.Flags().Changed("format") && len(opts.Formats) > 0 {
		for _, f := range opts.Formats {
			for _, part := range strings.Split(f, ",") {
				if strings.TrimSpace(part) != "" && strings.TrimSpace(part) != "terminal" {
					return true
				}
			}
		}
	}
	return false
}
