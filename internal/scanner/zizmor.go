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

// Zizmor wraps the zizmor CLI for GitHub Actions security checks.
type Zizmor struct {
	ExtraArgs []string
	Timeout   time.Duration
}

func (z *Zizmor) Name() string             { return "zizmor" }
func (z *Zizmor) Category() model.Category { return model.CategoryCICD }

func (z *Zizmor) Available() (bool, string) {
	st := tools.Probe("zizmor")
	return st.Installed, st.VersionLine()
}

func (z *Zizmor) Run(ctx context.Context, target string) ([]byte, error) {
	timeout := z.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{"--format", "sarif"}
	args = append(args, z.ExtraArgs...)
	args = append(args, target)

	cmd := exec.CommandContext(cctx, "zizmor", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if stdout.Len() == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("zizmor failed: %w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return []byte(`{"runs":[]}`), nil
	}
	if !json.Valid(stdout.Bytes()) {
		if runErr != nil {
			return nil, fmt.Errorf("zizmor returned invalid SARIF: %w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("zizmor returned invalid SARIF (stderr: %s)", strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (z *Zizmor) Normalize(raw []byte) ([]model.Finding, error) {
	return normalizer.SARIF(raw, "zizmor", model.CategoryCICD)
}

func (z *Zizmor) Scan(ctx context.Context, target string) ([]model.Finding, error) {
	raw, err := z.Run(ctx, target)
	if err != nil {
		return nil, err
	}
	findings, err := z.Normalize(raw)
	if err != nil {
		return nil, fmt.Errorf("normalize zizmor: %w", err)
	}
	return findings, nil
}
