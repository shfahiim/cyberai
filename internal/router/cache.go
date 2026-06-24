package router

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultCacheDir is where router plans are stored. Falls back to
// ~/.cyberai/cache/router when empty.
const DefaultCacheDir = "~/.cyberai/cache/router"

// DefaultTTL is how long a cached ScanPlan is considered valid.
const DefaultTTL = 24 * time.Hour

// Cache persists ScanPlans keyed by a versioned cache key so re-runs on the
// same project/profile/provider/model/policy combination cost zero LLM calls.
type Cache struct {
	Dir string
	// TTL controls how long cached plans are valid. Zero uses DefaultTTL.
	TTL time.Duration
}

// ttl returns the effective TTL, falling back to DefaultTTL.
func (c *Cache) ttl() time.Duration {
	if c.TTL > 0 {
		return c.TTL
	}
	return DefaultTTL
}

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

// Get loads a plan by cache key. Returns (nil, nil) on miss.
func (c *Cache) Get(key string) (*ScanPlan, error) {
	p := c.path(key)
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
	// Evict stale entries.
	if !plan.CachedAt.IsZero() && time.Since(plan.CachedAt) > c.ttl() {
		return nil, nil
	}
	return &plan, nil
}

// Put writes a plan to disk using the supplied cache key.
func (c *Cache) Put(key string, plan *ScanPlan) error {
	if plan == nil {
		return fmt.Errorf("nil plan")
	}
	plan.CachedAt = time.Now().UTC()
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal plan: %w", err)
	}
	return os.WriteFile(c.path(key), data, 0o644)
}

func (c *Cache) path(key string) string {
	safe := make([]rune, 0, len(key))
	for _, r := range key {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-' || r == '_' || r == ':':
			safe = append(safe, r)
		default:
			safe = append(safe, '_')
		}
	}
	return filepath.Join(c.Dir, string(safe)+".json")
}

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
