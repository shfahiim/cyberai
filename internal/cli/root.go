// Package cli wires cobra commands. The actual command logic lives in this
// package; subcommand files (scan.go, tools.go, etc.) hold per-command bodies.
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shfahiim/cyberai/internal/tools"
	"github.com/shfahiim/cyberai/internal/ui"
)

const (
	// Version is the cyberai binary version. Set via -ldflags in CI.
	Version = "0.1.0-dev"
)

// cliUIKey is the cobra annotation key under which the *ui.Renderer is
// stored on the root command. Subcommands retrieve it with uiFrom(cmd).
const cliUIKey = "__cyberai_ui_renderer"

// NewRootCmd builds the root `cyberai` command with all subcommands attached.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "cyberai",
		Short: "Security and code analysis CLI",
		Long: strings.Join([]string{
			"CyberAI — local security scanning for software projects.",
			"",
			"Getting started:",
			"  cyberai setup          Prepare tools and project config",
			"  cyberai scan           Quick scan (terminal output)",
			"  cyberai doctor         Check toolchain and config health",
			"",
			"Common workflows:",
			"  cyberai scan --save              Write SARIF/JSON/HTML reports",
			"  cyberai scan --smart             Enable LLM routing + summary",
			"  cyberai scan --preset ci -o out/ CI pipeline scan",
			"  cyberai scan --only secrets      Secrets-only scan",
			"",
			"CyberAI is read-only: it never modifies your source code or git state.",
			"Run cyberai <command> --help for detailed command documentation.",
		}, "\n"),
		Version:      Version,
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// Prepend ~/.cyberai/bin to PATH so child scanner processes
			// resolve to the bundled copy (when one was installed via
			// `cyberai tools install`). System PATH entries still take
			// effect after; we only prepend, not replace.
			//
			// Best-effort: don't fail the command if we can't resolve
			// ~/.cyberai (e.g. $HOME unset). Scanners on the system PATH
			// will still work.
			binDir, err := tools.BinDir()
			if err != nil {
				return nil
			}
			current := os.Getenv("PATH")
			if current == "" {
				_ = os.Setenv("PATH", binDir)
			} else {
				_ = os.Setenv("PATH", binDir+string(filepath.ListSeparator)+current)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	root.SetVersionTemplate("cyberai version {{.Version}}\n")

	// Persistent UI flags. Either --no-color (bool) or --color=auto|always|never
	// may be passed; if both are set, --no-color wins.
	var (
		noColorFlag bool
		colorFlag   string
	)
	root.PersistentFlags().BoolVar(&noColorFlag, "no-color", false,
		"disable colored output (equivalent to NO_COLOR=1)")
	root.PersistentFlags().StringVar(&colorFlag, "color", "",
		"color mode: auto|always|never (default: auto)")

	// Build the default renderer. main.go may have set one already via
	// AttachRenderer — we honor that and only fall back to a fresh one here.
	if _, ok := root.Annotations[cliUIKey]; !ok {
		stdoutTTY := ui.IsTerminal(uintptr(os.Stdout.Fd()))
		stderrTTY := ui.IsTerminal(uintptr(os.Stderr.Fd()))
		r := ui.NewRenderer(ui.RendererOptions{
			Color:       ui.ColorAuto,
			Progress:    ui.ProgressAuto,
			StdoutIsTTY: stdoutTTY,
			StderrIsTTY: stderrTTY,
		})
		AttachRenderer(root, r)
	}

	applyUIFlags := func(cmd *cobra.Command) {
		r := uiFrom(cmd)
		if r == nil {
			return
		}
		if noColorFlag || colorFlag != "" {
			mode := ui.ResolveColor(noColorFlag, ui.ColorMode(colorFlag))
			// Rebuild the renderer with the new color mode. The rest of
			// the options (TTY, progress, unicode) stay the same.
			r2 := ui.NewRenderer(ui.RendererOptions{
				Color:       mode,
				Progress:    r.ProgressMode(),
				Unicode:     nil,
				StdoutIsTTY: r.StdoutIsTTY(),
				StderrIsTTY: r.StderrIsTTY(),
			})
			AttachRenderer(cmd.Root(), r2)
		}
	}

	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		applyUIFlags(cmd)
		printBrand(cmd)
		fmt.Fprintln(cmd.OutOrStdout())
		defaultHelp(cmd, args)
	})

	// Pre-run hook: apply --no-color / --color precedence. Runs after the
	// PATH hook (which we want to keep first).
	root.PersistentPreRunE = chainPreRunE(root.PersistentPreRunE, func(cmd *cobra.Command, _ []string) error {
		applyUIFlags(cmd)
		return nil
	})

	root.AddCommand(
		newSetupCmd(),
		newDoctorCmd(),
		newScanCmd(),
		newToolsCmd(),
		newInitCmd(),
		newConfigCmd(),
		newReportCmd(),
		newSuppressCmd(),
		newSbomCmd(),
		newAnimCmd(),
	)

	return root
}

// AttachRenderer stores r on the cobra root command so subcommands can
// retrieve it via uiFrom. Exported so main.go can wire a custom renderer
// before PersistentPreRunE runs.
func AttachRenderer(root *cobra.Command, r *ui.Renderer) {
	if root.Annotations == nil {
		root.Annotations = map[string]string{}
	}
	if r == nil {
		delete(root.Annotations, cliUIKey)
		return
	}
	// Encode as "<stdoutT>:<stderrT>:<unicode>:<width>:<color>:<progress>".
	// We could store the pointer directly, but cobra annotations are
	// strings, so we round-trip through a side map on the renderer.
	root.Annotations[cliUIKey] = fmt.Sprintf("%v:%v:%v:%d:%s:%s",
		r.StdoutIsTTY(), r.StderrIsTTY(), r.UnicodeEnabled(), r.Width(),
		r.ColorMode(), r.ProgressMode())
	// Side map: key by *cobra.Command pointer.
	rendererRegistry[fmt.Sprintf("%p", root)] = r
}

// uiFrom returns the *ui.Renderer attached to the root command, or nil if
// none. Subcommands call this to get styling for output.
func uiFrom(cmd *cobra.Command) *ui.Renderer {
	root := cmd.Root()
	if root == nil {
		return nil
	}
	if r, ok := rendererRegistry[fmt.Sprintf("%p", root)]; ok {
		return r
	}
	return nil
}

// rendererRegistry is a process-global map from cobra root command pointer
// to *ui.Renderer. We use it because cobra's annotation system only stores
// strings, but we need the renderer pointer accessible from subcommands.
var rendererRegistry = map[string]*ui.Renderer{}

// chainPreRunE combines two PersistentPreRunE hooks. Both run; the second
// only runs if the first returns nil.
func chainPreRunE(first, second func(cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	if first == nil {
		return second
	}
	if second == nil {
		return first
	}
	return func(cmd *cobra.Command, args []string) error {
		if err := first(cmd, args); err != nil {
			return err
		}
		return second(cmd, args)
	}
}

// errf formats an error with the command name as a prefix. Used by
// subcommands to produce consistent error output.
func errf(cmd *cobra.Command, format string, args ...any) error {
	return fmt.Errorf("%s: %s", cmd.Name(), fmt.Sprintf(format, args...))
}
