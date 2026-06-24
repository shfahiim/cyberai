package tools

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// InstalledMethod is how a tool was installed. Values:
//   - "system": already on $PATH (no install action by cyberai)
//   - "github": downloaded from GitHub Releases into ~/.cyberai/bin
//   - "pipx":   installed via pipx (semgrep)
//   - "pip":    installed via python -m pip --user (semgrep fallback)
//   - "venv":   installed into a CyberAI-managed Python virtualenv
type InstalledMethod string

// InstalledTool is one row of ~/.cyberai/state/tools.json.
type InstalledTool struct {
	Version   string          `json:"version"`
	Method    InstalledMethod `json:"method"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// LoadState reads ~/.cyberai/state/tools.json. A missing file returns an
// empty map (not an error) so first-run callers don't have to special-case.
func LoadState(path string) (map[string]InstalledTool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]InstalledTool{}, nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}
	if len(data) == 0 {
		return map[string]InstalledTool{}, nil
	}
	out := map[string]InstalledTool{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	return out, nil
}

// SaveState writes the map to path atomically (write to tmp, rename).
// Atomic write means partial reads never see a half-written JSON.
func SaveState(path string, state map[string]InstalledTool) error {
	if state == nil {
		state = map[string]InstalledTool{}
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write state tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit state: %w", err)
	}
	return nil
}
