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

// Grype wraps the grype CLI for software composition analysis (SCA).
// It scans a directory for known vulnerabilities in dependencies by running
// `grype dir:<target> -o json`.
type Grype struct {
	// ExtraArgs is appended verbatim to the grype invocation.
	ExtraArgs []string

	// Timeout caps the subprocess lifetime. Zero = 5 minutes default.
	Timeout time.Duration
}

func (g *Grype) Name() string             { return "grype" }
func (g *Grype) Category() model.Category { return model.CategorySCA }

func (g *Grype) Available() (bool, string) {
	st := tools.Probe("grype")
	return st.Installed, st.VersionLine()
}

func (g *Grype) Run(ctx context.Context, target string) ([]byte, error) {
	timeout := g.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{
		"dir:" + target,
		"-o", "json",
	}
	args = append(args, g.ExtraArgs...)

	cmd := exec.CommandContext(cctx, "grype", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if stdout.Len() == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("grype failed: %w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return []byte(`{"matches":[]}`), nil
	}
	if !json.Valid(stdout.Bytes()) {
		if runErr != nil {
			return nil, fmt.Errorf("grype returned invalid JSON: %w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("grype returned invalid JSON (stderr: %s)", strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (g *Grype) Normalize(raw []byte) ([]model.Finding, error) {
	return normalizer.Grype(raw)
}

func (g *Grype) Scan(ctx context.Context, target string) ([]model.Finding, error) {
	raw, err := g.Run(ctx, target)
	if err != nil {
		return nil, err
	}
	findings, err := g.Normalize(raw)
	if err != nil {
		return nil, fmt.Errorf("normalize grype: %w", err)
	}
	return findings, nil
}
