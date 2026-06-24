package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"strings"

	"github.com/shfahiim/cyberai/internal/baseline"
	"github.com/shfahiim/cyberai/internal/ui"
)

func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Compare saved scan reports",
		Long: strings.Join([]string{
			"Operate on JSON reports produced by cyberai scan --save.",
			"",
			"Subcommands:",
			"  compare   Show new and resolved findings between two scan runs",
			"",
			"Examples:",
			"  cyberai report compare --baseline old/report.json --current new/report.json",
			"  cyberai report compare --baseline base.json --current curr.json --format markdown",
		}, "\n"),
	}

	cmd.AddCommand(newReportCompareCmd())

	return cmd
}

func newReportCompareCmd() *cobra.Command {
	var (
		baselinePath string
		currentPath  string
		format       string
	)

	cmd := &cobra.Command{
		Use:   "compare",
		Short: "Diff two saved JSON reports",
		Long: `Prints new findings (in current but not baseline) and resolved
findings (in baseline but not current). Use this to verify a fix
landed, or to check what's been introduced since a prior scan.

Output formats:
  text     - human-readable text (default)
  markdown - GitHub-flavored Markdown
  json     - machine-readable`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			base, err := baseline.Load(baselinePath)
			if err != nil {
				return err
			}
			curr, err := baseline.Load(currentPath)
			if err != nil {
				return err
			}

			d := baseline.Compare(base, curr, baselinePath, currentPath)

			switch format {
			case "", "text":
				printTextDiff(cmd, d)
			case "markdown", "md":
				fmt.Fprint(cmd.OutOrStdout(), d.Markdown())
			case "json":
				enc, _ := json.MarshalIndent(d, "", "  ")
				out := ui.MaybePretty(enc, uiFrom(cmd) != nil && uiFrom(cmd).UseColor())
				fmt.Fprintln(cmd.OutOrStdout(), string(out))
			default:
				return fmt.Errorf("unknown format: %s", format)
			}

			// Exit 1 if there are new critical/high findings (CI semantics).
			if d.NewBySeverity["critical"] > 0 || d.NewBySeverity["high"] > 0 {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&baselinePath, "baseline", "", "baseline report (JSON)")
	cmd.Flags().StringVar(&currentPath, "current", "", "current report (JSON)")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text|markdown|json")
	_ = cmd.MarkFlagRequired("baseline")
	_ = cmd.MarkFlagRequired("current")
	return cmd
}

func printTextDiff(cmd *cobra.Command, d *baseline.Diff) {
	w := cmd.OutOrStdout()
	uiR := uiFrom(cmd)

	key := func(s string) string {
		if uiR != nil {
			return uiR.KeyStyle().Render(s)
		}
		return s
	}
	dim := func(s string) string {
		if uiR != nil {
			return uiR.DimStyle().Render(s)
		}
		return s
	}
	warn := func(s string) string {
		if uiR != nil {
			return uiR.WarningStyle().Render(s)
		}
		return s
	}
	header := func(s string) string {
		if uiR != nil {
			return uiR.HeaderStyle().Render(s)
		}
		return s
	}

	fmt.Fprintf(w, "%s %s (hash %s, %d findings)\n",
		key("Baseline:"), d.BaselinePath, d.BaselineHash, len(d.BaselineFindings))
	fmt.Fprintf(w, "%s %s (hash %s, %d findings)\n",
		key("Current:"), d.CurrentPath, d.CurrentHash, len(d.CurrentFindings))
	if d.BaselineHash != "" && d.CurrentHash != "" && d.BaselineHash != d.CurrentHash {
		fmt.Fprintln(w, warn("⚠️  Project hashes differ — verify the baseline is for this repo."))
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%s\n", header(fmt.Sprintf("New (%d):", len(d.NewFindings))))
	if len(d.NewFindings) == 0 {
		fmt.Fprintln(w, dim("  (none)"))
	} else {
		for _, f := range d.NewFindings {
			tag := ui.SeverityStyle(f.Severity).Render(fmt.Sprintf("[%s]", f.Severity))
			loc := f.File
			if uiR != nil {
				loc = uiR.LocationStyle().Render(loc)
			}
			fmt.Fprintf(w, "  %s %s — %s:%d (%s)\n",
				tag, f.Title, loc, f.StartLine, f.Tool)
		}
		fmt.Fprintf(w, "  %s %d critical, %d high, %d medium, %d low, %d info\n",
			dim("By severity:"),
			d.NewBySeverity["critical"], d.NewBySeverity["high"],
			d.NewBySeverity["medium"], d.NewBySeverity["low"], d.NewBySeverity["info"])
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%s\n", header(fmt.Sprintf("Resolved (%d):", len(d.ResolvedFindings))))
	if len(d.ResolvedFindings) == 0 {
		fmt.Fprintln(w, dim("  (none)"))
	} else {
		for _, f := range d.ResolvedFindings {
			tag := ui.SeverityStyle(f.Severity).Render(fmt.Sprintf("[%s]", f.Severity))
			loc := f.File
			if uiR != nil {
				loc = uiR.LocationStyle().Render(loc)
			}
			fmt.Fprintf(w, "  %s %s — %s:%d (%s)\n",
				tag, f.Title, loc, f.StartLine, f.Tool)
		}
	}
}
