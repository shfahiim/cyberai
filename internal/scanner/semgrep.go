package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/shfahiim/cyberai/internal/model"
	"github.com/shfahiim/cyberai/internal/normalizer"
	"github.com/shfahiim/cyberai/internal/tools"
)

// Semgrep wraps the semgrep CLI. Semgrep is a SAST tool that supports
// dozens of languages via rule packs (p/python, p/golang, p/javascript, ...).
//
// We invoke it with `--json --quiet --error` to get a stable JSON envelope:
// { "results": [...], "errors": [...], "paths": {...} }.
type Semgrep struct {
	// Configs are Semgrep rulesets / config specs to run, e.g.
	// ["p/python", "p/security-audit", "p/owasp-top-ten"]. Empty = auto.
	Configs []string

	// ExtraArgs is appended verbatim to the semgrep invocation. Use
	// sparingly - most options belong in Configs.
	ExtraArgs []string

	// Timeout caps the subprocess lifetime. Zero = 5 minutes default.
	Timeout time.Duration
}

func (s *Semgrep) Name() string             { return "semgrep" }
func (s *Semgrep) Category() model.Category { return model.CategorySAST }

func (s *Semgrep) Available() (bool, string) {
	st := tools.Probe("semgrep")
	return st.Installed, st.VersionLine()
}

func (s *Semgrep) Run(ctx context.Context, target string) ([]byte, error) {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{
		"scan",
		"--json",
		"--quiet",
		"--no-rewrite-rule-ids",
		"--metrics", "off",
	}
	// Each entry in s.Configs becomes a `--config <name>` pair. Semgrep
	// treats bare positional ruleset names as a target path, which is why
	// the wrapper has to spell out the flag.
	for _, c := range s.Configs {
		args = append(args, "--config", c)
	}
	args = append(args, s.ExtraArgs...)
	args = append(args, target)

	cmd := exec.CommandContext(cctx, "semgrep", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if stdout.Len() == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("semgrep failed: %w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("semgrep produced no output (stderr: %s)", strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (s *Semgrep) Normalize(raw []byte) ([]model.Finding, error) {
	return normalizer.Semgrep(raw)
}

func (s *Semgrep) Scan(ctx context.Context, target string) ([]model.Finding, error) {
	raw, err := s.Run(ctx, target)
	if err != nil {
		return nil, err
	}
	findings, err := s.Normalize(raw)
	if err != nil {
		return nil, fmt.Errorf("normalize semgrep: %w", err)
	}
	return findings, nil
}
