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

// Checkov wraps the checkov CLI for deeper IaC and policy checks.
type Checkov struct {
	ExtraArgs []string
	Timeout   time.Duration
}

func (c *Checkov) Name() string             { return "checkov" }
func (c *Checkov) Category() model.Category { return model.CategoryIaC }

func (c *Checkov) Available() (bool, string) {
	st := tools.Probe("checkov")
	return st.Installed, st.VersionLine()
}

func (c *Checkov) Run(ctx context.Context, target string) ([]byte, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{
		"-d", target,
		"-o", "json",
		"--quiet",
	}
	args = append(args, c.ExtraArgs...)

	cmd := exec.CommandContext(cctx, "checkov", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if stdout.Len() == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("checkov failed: %w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return []byte(`{"results":{"failed_checks":[]}}`), nil
	}
	if !json.Valid(stdout.Bytes()) {
		if runErr != nil {
			return nil, fmt.Errorf("checkov returned invalid JSON: %w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("checkov returned invalid JSON (stderr: %s)", strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (c *Checkov) Normalize(raw []byte) ([]model.Finding, error) {
	return normalizer.Checkov(raw)
}

func (c *Checkov) Scan(ctx context.Context, target string) ([]model.Finding, error) {
	raw, err := c.Run(ctx, target)
	if err != nil {
		return nil, err
	}
	findings, err := c.Normalize(raw)
	if err != nil {
		return nil, fmt.Errorf("normalize checkov: %w", err)
	}
	return findings, nil
}
