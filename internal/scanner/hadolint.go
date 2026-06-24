package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/shfahiim/cyberai/internal/model"
	"github.com/shfahiim/cyberai/internal/normalizer"
	"github.com/shfahiim/cyberai/internal/tools"
)

// Hadolint wraps the hadolint CLI for Dockerfile linting.
type Hadolint struct {
	ExtraArgs []string
	Timeout   time.Duration
}

func (h *Hadolint) Name() string             { return "hadolint" }
func (h *Hadolint) Category() model.Category { return model.CategoryDocker }

func (h *Hadolint) Available() (bool, string) {
	st := tools.Probe("hadolint")
	return st.Installed, st.VersionLine()
}

func (h *Hadolint) Run(ctx context.Context, target string) ([]byte, error) {
	files, err := findDockerfiles(target)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return []byte("[]"), nil
	}

	timeout := h.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{"--format", "json"}
	args = append(args, h.ExtraArgs...)
	args = append(args, files...)

	cmd := exec.CommandContext(cctx, "hadolint", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if stdout.Len() == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("hadolint failed: %w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return []byte("[]"), nil
	}
	if !json.Valid(stdout.Bytes()) {
		if runErr != nil {
			return nil, fmt.Errorf("hadolint returned invalid JSON: %w (stderr: %s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("hadolint returned invalid JSON (stderr: %s)", strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (h *Hadolint) Normalize(raw []byte) ([]model.Finding, error) {
	return normalizer.Hadolint(raw)
}

func (h *Hadolint) Scan(ctx context.Context, target string) ([]model.Finding, error) {
	raw, err := h.Run(ctx, target)
	if err != nil {
		return nil, err
	}
	findings, err := h.Normalize(raw)
	if err != nil {
		return nil, fmt.Errorf("normalize hadolint: %w", err)
	}
	return findings, nil
}

func findDockerfiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".venv", "venv", "target", "build", "dist", ".terraform", "cyberai-reports":
				return filepath.SkipDir
			}
			return nil
		}
		name := filepath.Base(path)
		if name == "Dockerfile" || strings.HasPrefix(name, "Dockerfile.") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}
