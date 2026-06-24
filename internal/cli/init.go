package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shfahiim/cyberai/internal/config"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init [path]",
		Short: "Create a starter .cyberai.yaml config file",
		Long: strings.Join([]string{
			"Writes a commented .cyberai.yaml to the target directory (default: current directory).",
			"",
			"Existing files are never overwritten. For a full first-time setup including",
			"scanner installation, prefer:",
			"  cyberai setup",
			"",
			"Examples:",
			"  cyberai init",
			"  cyberai init ./services/api",
		}, "\n"),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}
			abs, err := filepath.Abs(target)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(abs, 0o755); err != nil {
				return err
			}
			path := filepath.Join(abs, config.FileName)
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("%s already exists; refusing to overwrite", path)
			}
			if err := config.WriteExample(path); err != nil {
				return err
			}
			uiR := uiFrom(cmd)
			check := "✓"
			if uiR != nil && !uiR.UnicodeEnabled() {
				check = "ok"
			}
			prefix := fmt.Sprintf("%s wrote", check)
			if uiR != nil {
				prefix = uiR.SuccessStyle().Render(prefix)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", prefix, path)
			return nil
		},
	}
}
