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

// OSVScanner wraps the osv-scanner CLI for software composition analysis (SCA).
// osv-scanner exits with a non-zero code when it finds vulnerabilities, so we
// treat any exit code as acceptable as long as we get valid JSON output.
type OSVScanner struct {
	// ExtraArgs is appended verbatim to the osv-scanner invocation.
	ExtraArgs []string

	// Timeout caps the subprocess lifetime. Zero = 5 minutes default.
	Timeout time.Duration
}

func (o *OSVScanner) Name() string             { return "osv-scanner" }
func (o *OSVScanner) Category() model.Category { return model.CategorySCA }

func (o *OSVScanner) Available() (bool, string) {
	st := tools.Probe("osv-scanner")
	return st.Installed, st.VersionLine()
}

func (o *OSVScanner) Run(ctx context.Context, target string) ([]byte, error) {
	timeout := o.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{
		"--recursive",
		"--format", "json",
		target,
	}
	args = append(args, o.ExtraArgs...)

	cmd := exec.CommandContext(cctx, "osv-scanner", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// osv-scanner exits 1 when vulnerabilities are found; treat that as normal.
	// Only fail if we got no output at all and exit was non-zero (real failure).
	runErr := cmd.Run()
	stderrStr := strings.TrimSpace(stderr.String())
	if stdout.Len() == 0 {
		if isNoPackageSources(stderrStr, runErr) {
			return []byte(`{"results":[]}`), nil
		}
		if runErr != nil {
			return nil, fmt.Errorf("osv-scanner failed: %w (stderr: %s)", runErr, stderrStr)
		}
		return []byte(`{"results":[]}`), nil
	}
	if !json.Valid(stdout.Bytes()) {
		if runErr != nil {
			return nil, fmt.Errorf("osv-scanner returned invalid JSON: %w (stderr: %s)", runErr, stderrStr)
		}
		return nil, fmt.Errorf("osv-scanner returned invalid JSON (stderr: %s)", stderrStr)
	}
	return stdout.Bytes(), nil
}

func isNoPackageSources(stderr string, err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(stderr), "no package sources found")
}

func (o *OSVScanner) Normalize(raw []byte) ([]model.Finding, error) {
	return normalizer.OSVScanner(raw)
}

func (o *OSVScanner) Scan(ctx context.Context, target string) ([]model.Finding, error) {
	raw, err := o.Run(ctx, target)
	if err != nil {
		return nil, err
	}
	findings, err := o.Normalize(raw)
	if err != nil {
		return nil, fmt.Errorf("normalize osv-scanner: %w", err)
	}
	return findings, nil
}
