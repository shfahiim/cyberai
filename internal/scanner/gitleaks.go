package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/shfahiim/cyberai/internal/model"
	"github.com/shfahiim/cyberai/internal/normalizer"
	"github.com/shfahiim/cyberai/internal/tools"
)

// Gitleaks wraps the gitleaks CLI. Gitleaks is a fast secrets scanner that
// detects hardcoded credentials (AWS keys, GitHub tokens, API keys, ...) by
// running a configurable set of regex + entropy rules.
//
// We invoke it with `detect --no-git --report-path <file>` so it works on
// any directory (not just git repos) and emits JSON we can parse.
type Gitleaks struct {
	// Config is the path to a custom gitleaks config; empty = use the
	// built-in default rule set.
	Config string

	// ExtraArgs is appended verbatim to the gitleaks invocation.
	ExtraArgs []string

	// Timeout caps the subprocess lifetime. Zero = 5 minutes default.
	Timeout time.Duration
}

func (g *Gitleaks) Name() string             { return "gitleaks" }
func (g *Gitleaks) Category() model.Category { return model.CategorySecrets }

func (g *Gitleaks) Available() (bool, string) {
	st := tools.Probe("gitleaks")
	return st.Installed, st.VersionLine()
}

func (g *Gitleaks) Run(ctx context.Context, target string) ([]byte, error) {
	timeout := g.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Gitleaks writes its JSON report to a file, not stdout. We use a
	// temp file, read it, then clean up.
	tmp, err := os.CreateTemp("", "gitleaks-*.json")
	if err != nil {
		return nil, fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	args := []string{
		"detect",
		"--no-git",
		"--source", target,
		"--report-path", tmpPath,
		"--report-format", "json",
		"--exit-code", "0", // findings remain a successful scan
	}
	if g.Config != "" {
		args = append(args, "--config", g.Config)
	}
	args = append(args, g.ExtraArgs...)

	cmd := exec.CommandContext(cctx, "gitleaks", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gitleaks failed: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		// No file = no findings (gitleaks doesn't write a file when clean).
		if os.IsNotExist(err) {
			return []byte("[]"), nil
		}
		return nil, fmt.Errorf("read gitleaks report: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	if len(data) == 0 {
		return []byte("[]"), nil
	}
	return data, nil
}

func (g *Gitleaks) Normalize(raw []byte) ([]model.Finding, error) {
	return normalizer.Gitleaks(raw)
}

func (g *Gitleaks) Scan(ctx context.Context, target string) ([]model.Finding, error) {
	raw, err := g.Run(ctx, target)
	if err != nil {
		return nil, err
	}
	findings, err := g.Normalize(raw)
	if err != nil {
		return nil, fmt.Errorf("normalize gitleaks: %w", err)
	}
	return findings, nil
}
