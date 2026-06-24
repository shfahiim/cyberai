package tools

import (
	"fmt"
	"os"
	"path/filepath"
)

// EnvBinDir overrides the bundled scanner directory for tests.
// When set, BinDir() returns this value verbatim (no $HOME expansion).
const EnvBinDir = "CYBERAI_BIN_DIR"

// EnvStateDir overrides the tools-state directory for tests.
const EnvStateDir = "CYBERAI_STATE_DIR"

// EnvVenvDir overrides the managed Python virtualenv root for tests.
const EnvVenvDir = "CYBERAI_VENV_DIR"

// DefaultBinDir is where installed scanner binaries live. Resolved against
// $HOME on Unix; never touches /usr/local/bin or system paths.
const DefaultBinDir = "~/.cyberai/bin"

// DefaultStateDir holds the tools.json file that records installed versions.
const DefaultStateDir = "~/.cyberai/state"

// DefaultVenvDir holds managed Python virtualenvs for Python-based scanners.
const DefaultVenvDir = "~/.cyberai/venvs"

// DefaultStatePath is the JSON file inside DefaultStateDir.
const DefaultStatePath = "~/.cyberai/state/tools.json"

// BinDir returns the directory where cyberai will install scanner binaries.
// Resolves in order: $CYBERAI_BIN_DIR (verbatim), then $HOME + DefaultBinDir.
// Creates the directory (0o755) if it does not yet exist. Idempotent.
func BinDir() (string, error) {
	d, err := resolveDir(EnvBinDir, DefaultBinDir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", fmt.Errorf("create bin dir: %w", err)
	}
	return d, nil
}

// StateDir returns the directory that holds tools.json.
func StateDir() (string, error) {
	d, err := resolveDir(EnvStateDir, DefaultStateDir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", fmt.Errorf("create state dir: %w", err)
	}
	return d, nil
}

// StatePath returns the full path to tools.json.
func StatePath() (string, error) {
	d, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "tools.json"), nil
}

// VenvDir returns the root directory for managed scanner virtualenvs.
func VenvDir() (string, error) {
	d, err := resolveDir(EnvVenvDir, DefaultVenvDir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", fmt.Errorf("create venv dir: %w", err)
	}
	return d, nil
}

// resolveDir returns the override env var if set, otherwise expands the
// default with $HOME.
func resolveDir(envVar, def string) (string, error) {
	if v := os.Getenv(envVar); v != "" {
		return v, nil
	}
	return expandHome(def)
}

// expandHome replaces a leading "~" with $HOME. We avoid os/user to keep
// this package dep-free; we read $HOME directly (set on every Unix system
// and on Windows under WSL/Cygwin).
func expandHome(p string) (string, error) {
	if len(p) == 0 || p[0] != '~' {
		return p, nil
	}
	home := os.Getenv("HOME")
	if home == "" {
		return "", fmt.Errorf("HOME not set; cannot expand %s", p)
	}
	if len(p) == 1 {
		return home, nil
	}
	if p[1] == '/' {
		return home + p[1:], nil
	}
	return home + "/" + p[1:], nil
}
