// Package gitdiff provides helpers for restricting scan output to files that
// changed relative to a given git ref (e.g. "HEAD", "main", "origin/main").
package gitdiff

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
)

// ChangedFiles runs `git diff --name-only <ref>` in root and returns the
// absolute paths of changed files. If ref is empty, it diffs the working
// tree against HEAD.
func ChangedFiles(root, ref string) ([]string, error) {
	args := []string{"diff", "--name-only"}
	if ref != "" {
		args = append(args, ref)
	} else {
		args = append(args, "HEAD")
	}

	cmd := exec.Command("git", args...)
	cmd.Dir = root

	var out bytes.Buffer
	var errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git diff: %w\nstderr: %s", err, errBuf.String())
	}

	var files []string
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Make absolute.
		abs := filepath.Join(root, line)
		files = append(files, abs)
	}
	return files, nil
}

// FilterFindingsByChanged returns the subset of findings whose File field is
// in the changedFiles set. Paths are compared after resolving to absolute form
// so that relative/absolute differences don't cause misses.
func FilterFindingsByChanged(findings []model.Finding, changedFiles []string) []model.Finding {
	if len(changedFiles) == 0 {
		return findings
	}
	set := make(map[string]bool, len(changedFiles))
	for _, f := range changedFiles {
		abs, err := filepath.Abs(f)
		if err == nil {
			set[abs] = true
		} else {
			set[f] = true
		}
	}

	var out []model.Finding
	for _, f := range findings {
		abs, err := filepath.Abs(f.File)
		if err != nil {
			abs = f.File
		}
		if set[abs] || set[f.File] {
			out = append(out, f)
		}
	}
	return out
}
