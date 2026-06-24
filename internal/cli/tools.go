package cli

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shfahiim/cyberai/internal/tools"
	"github.com/shfahiim/cyberai/internal/ui"
)

// toolsOpts are shared flags for the install/update/remove subcommands.
// Subcommands embed this so the same -y/--force/--version flags work uniformly.
type toolsOpts struct {
	Force   bool
	Yes     bool
	Version string
}

func newToolsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tools",
		Short: "Manage scanner tools and the local cyberai toolchain",
		Long: `The tools subcommand manages the external scanners cyberai shells
out to (Semgrep, Gitleaks, Trivy, Checkov, Hadolint, Zizmor).

cyberai keeps managed tools inside ~/.cyberai/bin and prefers them at runtime.
Interactive scans can also bootstrap missing scanners automatically, so this
command is the explicit place to inspect, preinstall, update, or remove that
local toolchain.`,
	}

	cmd.AddCommand(newToolsListCmd())
	cmd.AddCommand(newToolsInstallCmd())
	cmd.AddCommand(newToolsUpdateCmd())
	cmd.AddCommand(newToolsRemoveCmd())

	return cmd
}

func newToolsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show the current scanner toolchain",
		RunE: func(cmd *cobra.Command, _ []string) error {
			mgr, err := tools.NewManager()
			if err != nil {
				return err
			}
			rows, err := mgr.List()
			if err != nil {
				return err
			}
			printToolchain(cmd, mgr, rows)
			return nil
		},
	}
}

func newToolsInstallCmd() *cobra.Command {
	opts := &toolsOpts{}
	cmd := &cobra.Command{
		Use:   "install [tool...]",
		Short: "Install scanner tools into the managed cyberai toolchain",
		Long: `Downloads and installs the named scanners (default: all). Gitleaks,
Trivy, and Hadolint are fetched from GitHub Releases into ~/.cyberai/bin.
Checkov and Zizmor are installed into CyberAI-managed Python virtualenvs and
exposed through ~/.cyberai/bin. Semgrep is installed via pipx (fallback:
python3 -m pip --user).

If a tool is already managed locally, use --force to replace it.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := tools.NewManager()
			if err != nil {
				return err
			}
			targets := args
			if len(targets) == 0 {
				for _, t := range tools.All() {
					targets = append(targets, t.Name)
				}
			}
			installOpts := tools.InstallOptions{Force: opts.Force, Yes: opts.Yes, Version: opts.Version}
			var firstErr error
			for _, name := range targets {
				if err := mgr.Install(name, installOpts); err != nil {
					printToolAction(cmd, "error", name, err.Error())
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
				printToolAction(cmd, "success", name, "ready")
			}
			if firstErr == nil {
				rows, err := mgr.List()
				if err == nil {
					fmt.Fprintln(cmd.OutOrStdout())
					printToolchain(cmd, mgr, rows)
				}
			}
			return firstErr
		},
	}
	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "overwrite an existing managed binary")
	cmd.Flags().BoolVarP(&opts.Yes, "yes", "y", false, "auto-confirm any prompts (reserved)")
	cmd.Flags().StringVar(&opts.Version, "version", "", "pin a specific version (e.g. v8.30.1); default: latest")
	return cmd
}

func newToolsUpdateCmd() *cobra.Command {
	opts := &toolsOpts{}
	cmd := &cobra.Command{
		Use:   "update [tool...]",
		Short: "Refresh managed scanner tools",
		Long: `Re-downloads the latest release for the named tools (default: all)
and overwrites the existing managed copy. Use this when you want cyberai's
local scanner toolchain to catch up with upstream releases.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := tools.NewManager()
			if err != nil {
				return err
			}
			targets := args
			if len(targets) == 0 {
				for _, t := range tools.All() {
					targets = append(targets, t.Name)
				}
			}
			_ = opts
			var firstErr error
			for _, name := range targets {
				if err := mgr.Update(name); err != nil {
					printToolAction(cmd, "error", name, err.Error())
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
				printToolAction(cmd, "success", name, "updated")
			}
			return firstErr
		},
	}
	cmd.Flags().StringVar(&opts.Version, "version", "", "update to a specific version (default: latest)")
	return cmd
}

func newToolsRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove [tool...]",
		Short: "Remove managed scanner binaries",
		Long: `Deletes the managed copy of the named tools (default: all). For
Semgrep, cyberai prints the manual uninstall hint because the package manager
owning that install still needs to remove it.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr, err := tools.NewManager()
			if err != nil {
				return err
			}
			targets := args
			if len(targets) == 0 {
				for _, t := range tools.All() {
					targets = append(targets, t.Name)
				}
			}
			var firstErr error
			for _, name := range targets {
				if err := mgr.Remove(name); err != nil {
					printToolAction(cmd, "error", name, err.Error())
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
				printToolAction(cmd, "success", name, "removed")
			}
			return firstErr
		},
	}
	return cmd
}

func printToolchain(cmd *cobra.Command, mgr *tools.Manager, rows []tools.ListResult) {
	out := cmd.OutOrStdout()
	uiR := uiFrom(cmd)
	fmt.Fprintln(out, renderBrandTitle(uiR, "toolchain"))

	data := make([][]string, 0, len(rows))
	missing := []string{}
	for _, r := range rows {
		active := "missing"
		version := "-"
		source := "-"
		path := "-"
		if r.Bundled != nil {
			active = "bundled"
			version = normalizeVersion(r.Bundled.Version)
			source = string(r.Bundled.Method)
			path = filepath.Join(mgr.BinDir, r.Tool.Binary)
		} else if r.Probe.Installed {
			active = "system"
			version = normalizeVersion(r.Probe.VersionLine())
			source = "path"
			path = r.Probe.Path
		} else {
			missing = append(missing, r.Tool.Name)
		}
		data = append(data, []string{r.Tool.Name, active, truncate(version, 22), source, path})
	}
	ui.RenderTable(out,
		[]string{"TOOL", "ACTIVE", "VERSION", "SOURCE", "PATH"},
		data,
	)

	fmt.Fprintf(out, "\n%s %s\n", toolKey(uiR, "managed dir:"), mgr.BinDir)
	fmt.Fprintf(out, "%s %s\n", toolKey(uiR, "venvs:"), mgr.VenvDir)
	fmt.Fprintf(out, "%s %s\n", toolKey(uiR, "state:"), mgr.State)
	fmt.Fprintf(out, "%s interactive scans can auto-install missing scanners.\n", toolKey(uiR, "bootstrap:"))
	if len(missing) > 0 {
		fmt.Fprintf(out, "%s %s\n", toolKey(uiR, "missing:"), strings.Join(missing, ", "))
	}
}

func printToolAction(cmd *cobra.Command, level, name, status string) {
	uiR := uiFrom(cmd)
	line := fmt.Sprintf("  %s  %s", padToolName(name), status)
	if uiR != nil {
		switch level {
		case "success":
			line = uiR.SuccessStyle().Render(line)
		case "error":
			line = uiR.ErrorStyle().Render(line)
		default:
			line = uiR.KeyStyle().Render(line)
		}
	}
	writer := cmd.OutOrStdout()
	if level == "error" {
		writer = cmd.ErrOrStderr()
	}
	fmt.Fprintln(writer, line)
}

func toolKey(uiR *ui.Renderer, s string) string {
	if uiR != nil {
		return uiR.KeyStyle().Render(s)
	}
	return s
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "unknown"
	}
	return v
}

func padToolName(name string) string {
	if len(name) >= 8 {
		return name
	}
	return name + strings.Repeat(" ", 8-len(name))
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	if n < 1 {
		return ""
	}
	return s[:n-1] + "…"
}
