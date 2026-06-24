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

// Govulncheck wraps the govulncheck CLI for Go vulnerability reachability analysis.
type Govulncheck struct {
	Timeout time.Duration
}

func (g *Govulncheck) Name() string             { return "govulncheck" }
func (g *Govulncheck) Category() model.Category { return model.CategorySCA }

func (g *Govulncheck) Available() (bool, string) {
	st := tools.Probe("govulncheck")
	return st.Installed, st.VersionLine()
}

func (g *Govulncheck) Run(ctx context.Context, target string) ([]byte, error) {
	timeout := g.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, "govulncheck", "-json", "./...")
	cmd.Dir = target
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	// Govulncheck exits with code 3 if vulnerabilities are found.
	// It exits with code 0 if none are found.
	// It exits with code 1 or other if execution fails.
	if stdout.Len() == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("govulncheck failed: %w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return []byte(""), nil
	}

	return stdout.Bytes(), nil
}

func (g *Govulncheck) Normalize(raw []byte) ([]model.Finding, error) {
	return normalizer.Govulncheck(raw)
}

func (g *Govulncheck) Scan(ctx context.Context, target string) ([]model.Finding, error) {
	raw, err := g.Run(ctx, target)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	return g.Normalize(raw)
}
