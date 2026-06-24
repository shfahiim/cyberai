package router

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultCacheDir is where router plans are stored. Falls back to
// ~/.cyberai/cache/router when empty.
const DefaultCacheDir = "~/.cyberai/cache/router"

// Cache persists ScanPlans keyed by project hash so re-runs on the same
// repo cost zero LLM calls.
//
// Cache files are simple JSON. They're cheap to write, easy to invalidate
// (just delete the dir), and inspectable by humans for debugging.
type Cache struct {
	Dir string
}

// NewCache returns a Cache rooted at dir. Empty dir means the default
// (~/.cyberai/cache/router).
func NewCache(dir string) (*Cache, error) {
	if dir == "" {
		dir = DefaultCacheDir
	}
	expanded, err := expandHome(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(expanded, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	return &Cache{Dir: expanded}, nil
}

// Get loads a plan by project hash. Returns (nil, nil) on miss.
func (c *Cache) Get(hash string) (*ScanPlan, error) {
	p := c.path(hash)
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read cache: %w", err)
	}
	var plan ScanPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("parse cache: %w", err)
	}
	plan.FromCache = true
	plan.Source = "cache"
	return &plan, nil
}

// Put writes a plan to disk, keyed by project hash.
func (c *Cache) Put(plan *ScanPlan) error {
	if plan == nil {
		return fmt.Errorf("nil plan")
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal plan: %w", err)
	}
	return os.WriteFile(c.path(plan.ProjectHash), data, 0o644)
}

func (c *Cache) path(hash string) string {
	// Sanitize hash for filesystem: keep the sha256: prefix but replace
	// any non-alphanumeric chars with underscores. The router's hash is
	// already sanitized ("sha256:abc..."), so this is a no-op in practice.
	safe := make([]rune, 0, len(hash))
	for _, r := range hash {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-' || r == '_' || r == ':':
			safe = append(safe, r)
		default:
			safe = append(safe, '_')
		}
	}
	return filepath.Join(c.Dir, string(safe)+".json")
}

// expandHome replaces a leading "~" with the user's home directory.
// We avoid os/user to keep this package dep-free; we shell out to the
// env var HOME (set on every Unix-like system).
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
