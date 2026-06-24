package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/shfahiim/cyberai/internal/model"
	"github.com/shfahiim/cyberai/internal/normalizer"
	"github.com/shfahiim/cyberai/internal/tools"
)

// Trivy wraps the trivy CLI. Trivy is a unified scanner for:
//   - Software Composition Analysis (deps via SBOM + CVE matching)
//   - Infrastructure as Code (Terraform, CloudFormation, Dockerfile, k8s)
//   - License compliance
//   - Container image vulns (we skip this - we scan filesystems, not images)
//
// We invoke it with `fs --format json` to scan the local filesystem.
type Trivy struct {
	// Targets is the list of trivy subcommands/scan targets. Default
	// `["fs"]` scans the local filesystem (SCA + IaC + license).
	Targets []string

	// Scanners is the trivy --scanners list: vuln, misconfig, license.
	// Empty = "vuln,misconfig" (license skipped by default; user opts in).
	Scanners []string

	// Severity is the minimum severity trivy reports; empty = all.
	Severity string

	// ExtraArgs is appended verbatim to the trivy invocation.
	ExtraArgs []string

	// Timeout caps the subprocess lifetime. Zero = 5 minutes default.
	Timeout time.Duration
}

func (t *Trivy) Name() string { return "trivy" }
func (t *Trivy) Category() model.Category {
	// Trivy is multi-category; we report SCA by default and let the
	// normalizer upgrade per-finding based on trivy's `Class` field.
	return model.CategorySCA
}

func (t *Trivy) Available() (bool, string) {
	st := tools.Probe("trivy")
	return st.Installed, st.VersionLine()
}

func (t *Trivy) Run(ctx context.Context, target string) ([]byte, error) {
	timeout := t.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	targets := t.Targets
	if len(targets) == 0 {
		targets = []string{"fs"}
	}
	scanners := t.Scanners
	if len(scanners) == 0 {
		scanners = []string{"vuln", "misconfig"}
	}

	args := []string{
		strings.Join(targets, ","),
		"--format", "json",
		"--quiet",
		"--scanners", strings.Join(scanners, ","),
		"--skip-db-update",
	}
	if t.Severity != "" {
		args = append(args, "--severity", t.Severity)
	}
	args = append(args, t.ExtraArgs...)
	args = append(args, target)

	out, err := t.runTrivy(cctx, args)
	if err == nil {
		return out, nil
	}
	if !isTrivyFirstRunDBError(err) {
		return nil, err
	}

	// Trivy cannot use --skip-db-update before its DB has ever been downloaded.
	// Retry once without that flag so first-run installs self-initialize.
	retryArgs := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != "--skip-db-update" {
			retryArgs = append(retryArgs, arg)
		}
	}
	return t.runTrivy(cctx, retryArgs)
}

func (t *Trivy) runTrivy(ctx context.Context, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "trivy", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if stdout.Len() == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("trivy failed: %w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("trivy produced no output (stderr: %s)", strings.TrimSpace(stderr.String()))
	}

	// Trivy may still exit non-zero when it found issues. If we got valid JSON,
	// treat the scan as successful and let the findings speak for themselves.
	var probe map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &probe); err != nil {
		return nil, fmt.Errorf("trivy returned invalid JSON: %w", err)
	}
	return stdout.Bytes(), nil
}

func isTrivyFirstRunDBError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "--skip-db-update cannot be specified on the first run")
}

func (t *Trivy) Normalize(raw []byte) ([]model.Finding, error) {
	return normalizer.Trivy(raw)
}

func (t *Trivy) Scan(ctx context.Context, target string) ([]model.Finding, error) {
	raw, err := t.Run(ctx, target)
	if err != nil {
		return nil, err
	}
	findings, err := t.Normalize(raw)
	if err != nil {
		return nil, fmt.Errorf("normalize trivy: %w", err)
	}
	return findings, nil
}
