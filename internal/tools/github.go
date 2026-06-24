package tools

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// LatestReleaseCacheTTL is how long we cache GitHub release lookups. Keeping
// it short means `tools update` sees fresh data without hammering the API.
const LatestReleaseCacheTTL = 1 * time.Hour

// HTTPGetFunc is overridable in tests. The signature mirrors net/http.Get
// but returns a typed *http.Response so tests can serve anything they want.
var HTTPGetFunc = http.Get

// releaseCache is a tiny in-memory cache so `tools update all` makes one
// network call per repo, not one per tool call.
var (
	releaseCacheMu sync.Mutex
	releaseCache   = map[string]releaseCacheEntry{}
)

type releaseCacheEntry struct {
	tag     string
	expires time.Time
}

// releaseCacheLookup returns the cached tag for repo, or "" + false if
// absent/expired. Used by Manager.latestRelease (which uses m.HTTPGet)
// and by the package-level LatestRelease (which uses HTTPGetFunc).
func releaseCacheLookup(repo string) (string, bool) {
	releaseCacheMu.Lock()
	defer releaseCacheMu.Unlock()
	entry, ok := releaseCache[repo]
	if !ok || time.Now().After(entry.expires) {
		return "", false
	}
	return entry.tag, true
}

// releaseCacheStore inserts repo → tag with the standard TTL.
func releaseCacheStore(repo, tag string) {
	releaseCacheMu.Lock()
	releaseCache[repo] = releaseCacheEntry{tag: tag, expires: time.Now().Add(LatestReleaseCacheTTL)}
	releaseCacheMu.Unlock()
}

// LatestRelease returns the latest published tag (e.g. "v8.30.1") for a
// GitHub repository, formatted as "owner/name". Uses the package-level
// HTTPGetFunc — most callers should use Manager.latestRelease instead, so
// tests can substitute HTTPGet per-Manager.
func LatestRelease(repo string) (string, error) {
	if tag, ok := releaseCacheLookup(repo); ok {
		return tag, nil
	}

	url := "https://api.github.com/repos/" + repo + "/releases/latest"
	resp, err := HTTPGetFunc(url)
	if err != nil {
		return "", fmt.Errorf("github: %s: %w", repo, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github: %s: status %d", repo, resp.StatusCode)
	}

	var r struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("github: %s: parse: %w", repo, err)
	}
	if r.TagName == "" {
		return "", fmt.Errorf("github: %s: empty tag_name in response", repo)
	}

	releaseCacheStore(repo, r.TagName)
	return r.TagName, nil
}

// clearReleaseCache wipes the in-memory cache. Tests use this; production
// doesn't.
func clearReleaseCache() {
	releaseCacheMu.Lock()
	releaseCache = map[string]releaseCacheEntry{}
	releaseCacheMu.Unlock()
}
