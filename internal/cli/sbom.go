package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/shfahiim/cyberai/internal/tools"
)

func newSbomCmd() *cobra.Command {
	var (
		format string
		enrich bool
		image  string
	)

	cmd := &cobra.Command{
		Use:   "sbom [path]",
		Short: "Generate a Software Bill of Materials (SBOM)",
		Long: strings.Join([]string{
			"Generate an SBOM for a directory or container image using Syft.",
			"",
			"Requires syft on PATH (see cyberai tools list). Use --enrich to attach",
			"vulnerability data from Grype.",
			"",
			"Examples:",
			"  cyberai sbom .",
			"  cyberai sbom --format spdx > sbom.spdx.json",
			"  cyberai sbom --image myapp:latest",
			"  cyberai sbom . --enrich > enriched.cdx.json",
		}, "\n"),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate and resolve format
			syftFormat := "cyclonedx-json"
			switch strings.ToLower(format) {
			case "cyclonedx", "cyclonedx-json":
				syftFormat = "cyclonedx-json"
			case "spdx", "spdx-json":
				syftFormat = "spdx-json"
			default:
				return fmt.Errorf("unsupported format: %s (supported formats: cyclonedx, spdx)", format)
			}

			// Probe syft
			syftStatus := tools.Probe("syft")
			if !syftStatus.Installed {
				t := tools.Tool{
					Name: "syft",
					Install: "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
				}
				for _, tool := range tools.All() {
					if tool.Name == "syft" {
						t = tool
						break
					}
				}
				return fmt.Errorf("syft is not installed but required to generate SBOMs.\nInstall syft: %s", t.Install)
			}

			// Probe grype if enrich is requested
			if enrich {
				grypeStatus := tools.Probe("grype")
				if !grypeStatus.Installed {
					t := tools.Tool{
						Name: "grype",
						Install: "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
					}
					for _, tool := range tools.All() {
						if tool.Name == "grype" {
							t = tool
							break
						}
					}
					return fmt.Errorf("grype is not installed but required for enrichment.\nInstall grype: %s", t.Install)
				}
			}

			// Determine target
			var target string
			if image != "" {
				target = image
			} else {
				path := "."
				if len(args) > 0 {
					path = args[0]
				}
				abs, err := filepath.Abs(path)
				if err != nil {
					return err
				}
				target = "dir:" + abs
			}

			// Execute syft
			syftArgs := []string{target, "-o", syftFormat}
			syftCmd := exec.CommandContext(cmd.Context(), "syft", syftArgs...)
			var syftStdout, syftStderr bytes.Buffer
			syftCmd.Stdout = &syftStdout
			syftCmd.Stderr = &syftStderr

			if err := syftCmd.Run(); err != nil {
				return fmt.Errorf("syft failed: %w (stderr: %s)", err, strings.TrimSpace(syftStderr.String()))
			}

			sbomData := syftStdout.Bytes()

			if !enrich {
				// Output SBOM directly
				_, err := cmd.OutOrStdout().Write(sbomData)
				return err
			}

			// Enrichment: write SBOM to a temp file and run grype on it
			tmpFile, err := os.CreateTemp("", "cyberai-sbom-*.json")
			if err != nil {
				return fmt.Errorf("failed to create temp file for SBOM: %w", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.Write(sbomData); err != nil {
				tmpFile.Close()
				return fmt.Errorf("failed to write SBOM to temp file: %w", err)
			}
			tmpFile.Close()

			if strings.HasPrefix(syftFormat, "cyclonedx") {
				// Grype supports cyclonedx-json output containing vulnerabilities
				grypeArgs := []string{"sbom:" + tmpFile.Name(), "-o", "cyclonedx-json"}
				grypeCmd := exec.CommandContext(cmd.Context(), "grype", grypeArgs...)
				var grypeStdout, grypeStderr bytes.Buffer
				grypeCmd.Stdout = &grypeStdout
				grypeCmd.Stderr = &grypeStderr

				if err := grypeCmd.Run(); err != nil {
					return fmt.Errorf("grype failed: %w (stderr: %s)", err, strings.TrimSpace(grypeStderr.String()))
				}
				_, err = cmd.OutOrStdout().Write(grypeStdout.Bytes())
				return err
			}

			// SPDX format: print SPDX to stdout, and vulnerability list/table to stderr
			grypeArgs := []string{"sbom:" + tmpFile.Name()}
			grypeCmd := exec.CommandContext(cmd.Context(), "grype", grypeArgs...)
			var grypeStdout, grypeStderr bytes.Buffer
			grypeCmd.Stdout = &grypeStdout
			grypeCmd.Stderr = &grypeStderr

			if err := grypeCmd.Run(); err != nil {
				return fmt.Errorf("grype failed: %w (stderr: %s)", err, strings.TrimSpace(grypeStderr.String()))
			}

			// Output original SPDX SBOM to stdout
			if _, err := cmd.OutOrStdout().Write(sbomData); err != nil {
				return err
			}

			// Print vulnerability table to stderr
			fmt.Fprintln(cmd.ErrOrStderr(), "\n--- Vulnerabilities Found ---")
			fmt.Fprintln(cmd.ErrOrStderr(), grypeStdout.String())
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "cyclonedx", "SBOM output format (cyclonedx, spdx)")
	cmd.Flags().BoolVar(&enrich, "enrich", false, "enrich SBOM with vulnerability data using grype")
	cmd.Flags().StringVar(&image, "image", "", "container image to scan (e.g. myapp:latest)")

	return cmd
}
