package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/shfahiim/cyberai/internal/model"
	"github.com/shfahiim/cyberai/internal/normalizer"
	"github.com/shfahiim/cyberai/internal/tools"
)

// Actionlint wraps the actionlint CLI for GitHub Actions workflow security checks.
// actionlint exits non-zero when it finds issues, so we treat any exit code as
// acceptable as long as we receive parseable output.
type Actionlint struct {
	// ExtraArgs is appended verbatim to the actionlint invocation.
	ExtraArgs []string

	// Timeout caps the subprocess lifetime. Zero = 5 minutes default.
	Timeout time.Duration
}

func (a *Actionlint) Name() string             { return "actionlint" }
func (a *Actionlint) Category() model.Category { return model.CategoryCICD }

func (a *Actionlint) Available() (bool, string) {
	st := tools.Probe("actionlint")
	return st.Installed, st.VersionLine()
}

func (a *Actionlint) Run(ctx context.Context, target string) ([]byte, error) {
	timeout := a.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	workflowsDir := filepath.Join(target, ".github", "workflows")

	// Collect workflow files via glob. If no workflows exist, return empty JSON array.
	ymlFiles, _ := filepath.Glob(filepath.Join(workflowsDir, "*.yml"))
	yamlFiles, _ := filepath.Glob(filepath.Join(workflowsDir, "*.yaml"))
	allFiles := append(ymlFiles, yamlFiles...) //nolint:gocritic
	if len(allFiles) == 0 {
		return []byte("[]"), nil
	}

	args := []string{"-format", "{{json .}}"}
	args = append(args, a.ExtraArgs...)
	args = append(args, allFiles...)

	cmd := exec.CommandContext(cctx, "actionlint", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// actionlint exits non-zero when it finds issues; that is normal behavior.
	// Only treat as an error if stdout is empty and the process truly failed.
	runErr := cmd.Run()
	if stdout.Len() == 0 {
		if runErr != nil {
			// If stderr mentions "no such file" etc., it's a real failure.
			stderrStr := strings.TrimSpace(stderr.String())
			if stderrStr != "" {
				return nil, fmt.Errorf("actionlint failed: %w (stderr: %s)", runErr, stderrStr)
			}
		}
		return []byte("[]"), nil
	}
	if !json.Valid(stdout.Bytes()) {
		if runErr != nil {
			return nil, fmt.Errorf("actionlint returned invalid JSON: %w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("actionlint returned invalid JSON (stderr: %s)", strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (a *Actionlint) Normalize(raw []byte) ([]model.Finding, error) {
	return normalizer.Actionlint(raw)
}

func (a *Actionlint) Scan(ctx context.Context, target string) ([]model.Finding, error) {
	raw, err := a.Run(ctx, target)
	if err != nil {
		return nil, err
	}
	findings, err := a.Normalize(raw)
	if err != nil {
		return nil, fmt.Errorf("normalize actionlint: %w", err)
	}
	return findings, nil
}
