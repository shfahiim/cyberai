// Package project performs deterministic project detection: walks a repo, parses
// manifests and lockfiles, and produces a ProjectProfile that downstream
// stages (router, scanners) consume.
//
// This package has no LLM dependency. It is the deterministic backbone of
// Phase 1 — the LLM router sits in front of the scanners, but it relies on the
// ProjectProfile produced here to make decisions.
package project

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Profile is a deterministic snapshot of a project's structure, languages,
// dependencies, and tooling. The router consumes this and decides which
// scanners + rulesets to enable.
//
// Profiles are cheap to compute (no external calls, no LLM), so we always
// rebuild one from scratch — but we cache the *hash* of the profile so the
// router's downstream cache key is stable per repo state.
type Profile struct {
	Root         string   `json:"root"`
	Languages    []string `json:"languages"`
	Manifests    []string `json:"manifests"` // package.json, go.mod, requirements.txt, etc.
	HasDocker    bool     `json:"has_docker"`
	HasK8s       bool     `json:"has_k8s"`
	HasTerraform bool     `json:"has_terraform"`
	HasAnsible   bool     `json:"has_ansible"`
	Lockfiles    []string `json:"lockfiles"` // package-lock.json, go.sum, etc.
	FileCount    int      `json:"file_count"`
	TotalLOC     int      `json:"total_loc"` // approximate (counts newlines in source files)
	IsMonorepo   bool     `json:"is_monorepo"`
	VCS          string   `json:"vcs"` // "git" | "none"
	HasTests     bool     `json:"has_tests"`
	HasCI        bool     `json:"has_ci"` // .github/workflows, .gitlab-ci.yml, etc.
}

// Hash returns a stable hash of the profile's structural fields, suitable for
// caching the router's ScanPlan decision.
//
// We deliberately exclude Root (varies by absolute path) and counts
// (FileCount/TotalLOC can drift without semantic change).
func (p *Profile) Hash() string {
	h := sha256.New()
	fmt.Fprintf(h, "languages=%s\n", strings.Join(p.Languages, ","))
	fmt.Fprintf(h, "manifests=%s\n", strings.Join(p.Manifests, ","))
	fmt.Fprintf(h, "has_docker=%t\n", p.HasDocker)
	fmt.Fprintf(h, "has_k8s=%t\n", p.HasK8s)
	fmt.Fprintf(h, "has_terraform=%t\n", p.HasTerraform)
	fmt.Fprintf(h, "has_ansible=%t\n", p.HasAnsible)
	fmt.Fprintf(h, "lockfiles=%s\n", strings.Join(p.Lockfiles, ","))
	fmt.Fprintf(h, "is_monorepo=%t\n", p.IsMonorepo)
	fmt.Fprintf(h, "vcs=%s\n", p.VCS)
	fmt.Fprintf(h, "has_tests=%t\n", p.HasTests)
	fmt.Fprintf(h, "has_ci=%t\n", p.HasCI)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:32]
}

// Detect walks root and builds a Profile. It never panics, never makes network
// calls, never executes the project's code. It does read files (manifests,
// lockfiles, README fragments) to identify language/tooling signatures.
//
// Skipped directories: .git, node_modules, vendor, venv, target, build, dist,
// .next, __pycache__, .gradle, .terraform, .venv, node_modules, and any
// directory whose name starts with '.' other than well-known config dirs.
func Detect(root string) (*Profile, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("root is not a directory: %s", root)
	}

	p := &Profile{Root: root, VCS: "none"}

	// First pass: collect files and identify manifests/lockfiles/docker/k8s/tf.
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Skip permission errors and similar — don't fail the whole walk.
			return nil
		}
		if d.IsDir() {
			// VCS detection: detect .git directory at the root before skipping.
			if d.Name() == ".git" {
				if rel, relErr := filepath.Rel(root, path); relErr == nil && rel == ".git" {
					p.VCS = "git"
				}
				return filepath.SkipDir
			}
			if shouldSkipDir(d.Name(), root, path) {
				return filepath.SkipDir
			}
			return nil
		}
		return classifyFile(path, root, p)
	})
	if err != nil {
		return nil, fmt.Errorf("walk: %w", err)
	}

	// Second pass: count LOC in detected source files. We sample rather than
	// count every byte — good enough for routing, fast for large repos.
	if err := estimateLOC(root, p); err != nil {
		// Non-fatal: profiles are useful even without an LOC estimate.
		p.TotalLOC = -1
	}

	// Fallback language detection: if no manifest declared a language, infer
	// from file extensions. This lets a bare `.go` or `.py` script get
	// classified as Go/Python even when there's no go.mod/requirements.txt.
	if len(p.Languages) == 0 {
		if err := detectLanguagesByExtension(root, p); err != nil {
			// Non-fatal.
		}
	}

	// Dedupe and sort for stable output.
	p.Languages = uniqSorted(p.Languages)
	p.Manifests = uniqSorted(p.Manifests)
	p.Lockfiles = uniqSorted(p.Lockfiles)

	return p, nil
}

// detectLanguagesByExtension walks the tree and adds a language for each
// file extension seen. Used as a fallback when no manifest was found.
//
// Capped at a small sample to stay fast on huge repos; the goal is just
// "is there any Go code here?" not "exactly which languages."
func detectLanguagesByExtension(root string, p *Profile) error {
	const maxFiles = 2000
	exts := make(map[string]int)
	count := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name(), root, path) {
				return filepath.SkipDir
			}
			return nil
		}
		if count >= maxFiles {
			return filepath.SkipAll
		}
		ext := filepath.Ext(path)
		if ext != "" {
			exts[ext]++
		}
		count++
		return nil
	})
	if err != nil {
		return err
	}

	// Map common source extensions to languages.
	for ext, lang := range extToLang() {
		if exts[ext] > 0 {
			p.Languages = addUnique(p.Languages, lang)
		}
	}
	return nil
}

func extToLang() map[string]string {
	return map[string]string{
		".go":    "go",
		".js":    "javascript",
		".jsx":   "javascript",
		".mjs":   "javascript",
		".cjs":   "javascript",
		".ts":    "typescript",
		".tsx":   "typescript",
		".py":    "python",
		".rs":    "rust",
		".java":  "java",
		".kt":    "kotlin",
		".kts":   "kotlin",
		".cs":    "csharp",
		".cpp":   "cpp",
		".cc":    "cpp",
		".cxx":   "cpp",
		".c":     "c",
		".h":     "c",
		".hpp":   "cpp",
		".swift": "swift",
		".dart":  "dart",
		".rb":    "ruby",
		".php":   "php",
	}
}

// classifyFile updates p based on a single file's name.
func classifyFile(path, root string, p *Profile) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	name := filepath.Base(path)

	switch {
	case name == "package.json":
		p.Manifests = append(p.Manifests, rel)
		p.Languages = addUnique(p.Languages, "javascript")
		p.IsMonorepo = p.IsMonorepo || hasMonorepoMarker(root)

	case name == "pnpm-workspace.yaml" || name == "lerna.json" || name == "nx.json" || name == "turbo.json":
		p.IsMonorepo = true

	case name == "package-lock.json" || name == "yarn.lock" || name == "pnpm-lock.yaml":
		p.Lockfiles = append(p.Lockfiles, rel)

	case name == "go.mod":
		p.Manifests = append(p.Manifests, rel)
		p.Languages = addUnique(p.Languages, "go")

	case name == "go.sum":
		p.Lockfiles = append(p.Lockfiles, rel)

	case name == "requirements.txt" || name == "pyproject.toml" || name == "setup.py" || name == "Pipfile":
		p.Manifests = append(p.Manifests, rel)
		p.Languages = addUnique(p.Languages, "python")

	case name == "Pipfile.lock" || name == "poetry.lock" || strings.HasSuffix(name, ".requirements.txt"):
		p.Lockfiles = append(p.Lockfiles, rel)

	case name == "Cargo.toml":
		p.Manifests = append(p.Manifests, rel)
		p.Languages = addUnique(p.Languages, "rust")

	case name == "Cargo.lock":
		p.Lockfiles = append(p.Lockfiles, rel)

	case name == "pom.xml" || name == "build.gradle" || name == "build.gradle.kts":
		p.Manifests = append(p.Manifests, rel)
		p.Languages = addUnique(p.Languages, "java")

	case name == "CMakeLists.txt" || name == "Makefile":
		p.Manifests = append(p.Manifests, rel)
		p.Languages = addUnique(p.Languages, "cpp")

	case strings.HasSuffix(name, ".csproj") || strings.HasSuffix(name, ".sln"):
		p.Manifests = append(p.Manifests, rel)
		p.Languages = addUnique(p.Languages, "csharp")

	case name == "Package.swift":
		p.Manifests = append(p.Manifests, rel)
		p.Languages = addUnique(p.Languages, "swift")

	case name == "pubspec.yaml":
		p.Manifests = append(p.Manifests, rel)
		p.Languages = addUnique(p.Languages, "dart")

	case name == "Gemfile":
		p.Manifests = append(p.Manifests, rel)
		p.Languages = addUnique(p.Languages, "ruby")

	case name == "Gemfile.lock":
		p.Lockfiles = append(p.Lockfiles, rel)

	case name == "composer.json":
		p.Manifests = append(p.Manifests, rel)
		p.Languages = addUnique(p.Languages, "php")

	case name == "composer.lock":
		p.Lockfiles = append(p.Lockfiles, rel)

	case name == "Dockerfile" || strings.HasPrefix(name, "Dockerfile."):
		p.HasDocker = true

	case strings.HasSuffix(name, ".tf") || strings.HasSuffix(name, ".tfvars"):
		p.HasTerraform = true

	case strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml"):
		if isKubernetesManifest(path, root) {
			p.HasK8s = true
		}
		if isAnsibleFile(rel, path) {
			p.HasAnsible = true
		}

	case name == ".gitlab-ci.yml" || rel == ".circleci/config.yml":
		p.HasCI = true

	case strings.HasPrefix(rel, ".github/workflows") && (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")):
		p.HasCI = true
	}

	// Test detection: lightweight — anything under common test dirs or with test suffix.
	if isTestFile(rel) {
		p.HasTests = true
	}

	return nil
}

// estimateLOC walks source files matching detected languages and counts newlines.
// We cap at a reasonable sample size to keep Detect() fast on large repos.
func estimateLOC(root string, p *Profile) error {
	langExts := make(map[string]bool)
	for _, lang := range p.Languages {
		for _, ext := range extensionsFor(lang) {
			langExts[ext] = true
		}
	}
	if len(langExts) == 0 {
		return nil
	}

	const maxFiles = 5000
	count := 0
	p.TotalLOC = 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name(), root, path) {
				return filepath.SkipDir
			}
			return nil
		}
		if count >= maxFiles {
			return filepath.SkipAll
		}
		ext := filepath.Ext(path)
		if !langExts[ext] {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 1_000_000 {
			return nil // skip >1MB files
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		buf := make([]byte, info.Size())
		if _, err := f.Read(buf); err != nil {
			return nil
		}
		p.TotalLOC += countNewlines(buf)
		count++
		return nil
	})

	return err
}

// --- helpers ---

func shouldSkipDir(name, root, full string) bool {
	// Skip hidden dirs at any level EXCEPT well-known config dirs we care about.
	switch name {
	case ".git", "node_modules", "vendor", "venv", ".venv", "target", "build",
		"dist", ".next", "__pycache__", ".gradle", ".terraform",
		"cyberai-reports", "out", "bin":
		return true
	}
	return false
}

func isKubernetesManifest(path, _ string) bool {
	lower := strings.ToLower(path)
	if strings.Contains(lower, "/k8s/") ||
		strings.Contains(lower, "/kubernetes/") ||
		strings.HasSuffix(lower, "k8s.yaml") ||
		strings.HasSuffix(lower, "k8s.yml") {
		return true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if len(data) > 64_000 {
		data = data[:64_000]
	}
	text := strings.ToLower(string(data))
	return strings.Contains(text, "apiversion:") && strings.Contains(text, "kind:")
}

func isAnsibleFile(rel, path string) bool {
	lower := strings.ToLower(rel)
	if strings.Contains(lower, "playbook") || strings.Contains(lower, "/roles/") ||
		strings.Contains(lower, "/tasks/") || strings.Contains(lower, "/ansible/") {
		return true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if len(data) > 32_000 {
		data = data[:32_000]
	}
	text := strings.ToLower(string(data))
	return strings.Contains(text, "hosts:") && (strings.Contains(text, "tasks:") || strings.Contains(text, "roles:"))
}

func hasMonorepoMarker(root string) bool {
	for _, marker := range []string{"pnpm-workspace.yaml", "lerna.json", "nx.json", "turbo.json"} {
		if _, err := os.Stat(filepath.Join(root, marker)); err == nil {
			return true
		}
	}
	return false
}

func isTestFile(rel string) bool {
	lower := strings.ToLower(rel)
	if strings.Contains(lower, "/test/") || strings.Contains(lower, "/tests/") ||
		strings.Contains(lower, "/__tests__/") || strings.Contains(lower, "/spec/") {
		return true
	}
	base := filepath.Base(rel)
	return strings.HasSuffix(base, "_test.go") ||
		strings.HasSuffix(base, ".test.js") || strings.HasSuffix(base, ".test.ts") ||
		strings.HasSuffix(base, ".spec.js") || strings.HasSuffix(base, ".spec.ts") ||
		strings.HasSuffix(base, "_test.py") || strings.HasPrefix(base, "test_")
}

func extensionsFor(lang string) []string {
	switch lang {
	case "go":
		return []string{".go"}
	case "javascript":
		return []string{".js", ".jsx", ".mjs", ".cjs"}
	case "typescript":
		return []string{".ts", ".tsx"}
	case "python":
		return []string{".py"}
	case "rust":
		return []string{".rs"}
	case "java":
		return []string{".java", ".kt", ".scala"}
	case "kotlin":
		return []string{".kt", ".kts"}
	case "csharp":
		return []string{".cs"}
	case "cpp":
		return []string{".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
	case "c":
		return []string{".c", ".h"}
	case "swift":
		return []string{".swift"}
	case "dart":
		return []string{".dart"}
	case "ruby":
		return []string{".rb"}
	case "php":
		return []string{".php"}
	}
	return nil
}

func addUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func uniqSorted(s []string) []string {
	seen := make(map[string]bool, len(s))
	out := make([]string, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func countNewlines(b []byte) int {
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}
