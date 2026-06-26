package tools

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// HTTPGet mirrors net/http.Get but is overridable in tests.
var HTTPGet = http.Get

// ExecRunner is overridable in tests. Default runs commands with the system
// shell. Returns combined stdout+stderr.
var ExecRunner = func(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

// InstallOptions tweaks the Manager.Install behavior.
type InstallOptions struct {
	// Force overwrites an existing binary in ~/.cyberai/bin. Does not
	// affect copies on the system PATH.
	Force bool
	// Yes auto-confirms any prompt. Currently unused (no prompts in v1)
	// but reserved for future interactive flows.
	Yes bool
	// Version pins a specific version (e.g. "v8.30.1" or "8.30.1").
	// Empty = latest from upstream.
	Version string
}

// Manager owns the install/remove/update lifecycle for cyberai's bundled
// scanners. The function-pointer fields (HTTPGet, ExecRunner) are seams for
// unit tests; production callers should use NewManager().
type Manager struct {
	BinDir  string // absolute path to ~/.cyberai/bin
	State   string // absolute path to ~/.cyberai/state/tools.json
	VenvDir string // absolute path to ~/.cyberai/venvs
	HTTPGet func(string) (*http.Response, error)
	Exec    func(name string, args ...string) ([]byte, error)
	// ForcePathLookup is consulted before installing a tool. If it returns
	// a non-empty path AND opts.Force is false, the install is skipped
	// (we use the system copy). nil = use os/exec.LookPath.
	LookPath func(string) (string, error)
}

// NewManager builds a Manager that points at the default locations. Errors
// are returned if BinDir or StateDir cannot be created; the caller decides
// whether to fail the command or proceed.
func NewManager() (*Manager, error) {
	bin, err := BinDir()
	if err != nil {
		return nil, err
	}
	state, err := StatePath()
	if err != nil {
		return nil, err
	}
	venv, err := VenvDir()
	if err != nil {
		return nil, err
	}
	return &Manager{
		BinDir:   bin,
		State:    state,
		VenvDir:  venv,
		HTTPGet:  HTTPGet,
		Exec:     ExecRunner,
		LookPath: exec.LookPath,
	}, nil
}

// ListResult is the merged view of a tool: probe (system PATH) + state
// (~/.cyberai/bin) + declared (tools.All).
type ListResult struct {
	Tool    Tool           // declared metadata
	Probe   Status         // what's on $PATH
	Bundled *InstalledTool // what's in ~/.cyberai/bin (nil if absent)
	BinPath string         // resolved path to the binary we'll actually use
}

// List returns one row per declared tool, merging probe + state.
func (m *Manager) List() ([]ListResult, error) {
	state, err := LoadState(m.State)
	if err != nil {
		return nil, err
	}
	probes := ProbeAll()
	var out []ListResult
	for _, t := range All() {
		st := probes[t.Name]
		installed, hasState := state[t.Name]
		bundledPath := filepath.Join(m.BinDir, t.Binary)
		bundledExists := false
		if _, err := os.Stat(bundledPath); err == nil {
			bundledExists = true
		}
		var bundled *InstalledTool
		if bundledExists {
			if hasState {
				bundled = &installed
			} else {
				bundled = &InstalledTool{Version: "unknown", Method: "github"}
			}
		}
		// Resolution: bundled beats system if both exist. (We prepended
		// bundled to PATH in root.go.)
		binPath := ""
		if bundledExists {
			binPath = bundledPath
		} else if st.Installed {
			binPath = st.Path
		}
		out = append(out, ListResult{
			Tool:    t,
			Probe:   st,
			Bundled: bundled,
			BinPath: binPath,
		})
	}
	return out, nil
}

// IsInstallable returns true if the tool supports automated installation.
func (m *Manager) IsInstallable(name string) bool {
	return IsManagedInstall(name)
}

// Install fetches and installs the named tool. Empty name installs all
// declared tools.
func (m *Manager) Install(name string, opts InstallOptions) error {
	if name == "" {
		var firstErr error
		for _, t := range All() {
			if !m.IsInstallable(t.Name) {
				continue
			}
			if err := m.Install(t.Name, opts); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	switch name {
	case "semgrep":
		return m.installSemgrep(opts)
	case "gitleaks":
		return m.installGitleaks(opts)
	case "trivy":
		return m.installTrivy(opts)
	case "checkov":
		return m.installPythonPackageTool("checkov", "checkov", "checkov", opts)
	case "hadolint":
		return m.installHadolint(opts)
	case "zizmor":
		return m.installPythonPackageTool("zizmor", "zizmor", "zizmor", opts)
	case "grype":
		return m.installGrype(opts)
	case "osv-scanner":
		return m.installOSVScanner(opts)
	case "govulncheck":
		return m.installGovulncheck(opts)
	case "actionlint":
		return m.installActionlint(opts)
	case "syft":
		return m.installSyft(opts)
	default:
		t, ok := findTool(name)
		if ok {
			return fmt.Errorf("tool %s does not support automated installation; please install it manually: %s", name, t.Install)
		}
		return fmt.Errorf("unknown tool: %s", name)
	}
}

// Update re-fetches the latest version of a tool and overwrites the
// existing bundled binary. Empty name = update all.
func (m *Manager) Update(name string) error {
	if name == "" {
		var firstErr error
		for _, t := range All() {
			if err := m.Update(t.Name); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	// For now Update == Install (overwrite). The Force flag is implicit.
	opts := InstallOptions{Force: true}
	return m.Install(name, opts)
}

// Remove deletes the bundled binary and clears the state entry. For
// semgrep (which lives on the system PATH), it prints the manual uninstall
// command and returns nil — we don't try to manage pip/brew packages.
func (m *Manager) Remove(name string) error {
	if name == "" {
		var firstErr error
		for _, t := range All() {
			if err := m.Remove(t.Name); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	t, ok := findTool(name)
	if !ok {
		return fmt.Errorf("unknown tool: %s", name)
	}
	if name == "semgrep" {
		// We didn't put it there; we don't remove it.
		return fmt.Errorf("semgrep is managed by pipx/brew; to remove: pipx uninstall semgrep  (or: brew uninstall semgrep)")
	}
	binPath := filepath.Join(m.BinDir, t.Binary)
	if err := os.Remove(binPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", binPath, err)
	}
	if name == "checkov" || name == "zizmor" {
		_ = os.RemoveAll(filepath.Join(m.VenvDir, name))
	}
	state, err := LoadState(m.State)
	if err != nil {
		return err
	}
	delete(state, name)
	return SaveState(m.State, state)
}

func findTool(name string) (Tool, bool) {
	for _, t := range All() {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// installGitleaks and installTrivy share downloadFromGitHub. semgrep is
// separate because it has no GitHub binary release.

func (m *Manager) installGitleaks(opts InstallOptions) error {
	dest := filepath.Join(m.BinDir, "gitleaks")
	if _, err := os.Stat(dest); err == nil && !opts.Force {
		return m.recordBundledState("gitleaks", "gitleaks", "github")
	}
	p := DetectPlatform()
	ver := opts.Version
	if ver == "" {
		v, err := m.latestRelease("gitleaks/gitleaks")
		if err != nil {
			return err
		}
		ver = v
	}
	_, url, ok := p.GitleaksAsset(ver)
	if !ok {
		return fmt.Errorf("gitleaks: no published binary for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return m.downloadFromGitHub("gitleaks", "gitleaks", url, opts)
}

func (m *Manager) installTrivy(opts InstallOptions) error {
	dest := filepath.Join(m.BinDir, "trivy")
	if _, err := os.Stat(dest); err == nil && !opts.Force {
		return m.recordBundledState("trivy", "trivy", "github")
	}
	p := DetectPlatform()
	ver := opts.Version
	if ver == "" {
		v, err := m.latestRelease("aquasecurity/trivy")
		if err != nil {
			return err
		}
		ver = v
	}
	_, url, ok := p.TrivyAsset(ver)
	if !ok {
		return fmt.Errorf("trivy: no published binary for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return m.downloadFromGitHub("trivy", "trivy", url, opts)
}

func (m *Manager) installHadolint(opts InstallOptions) error {
	dest := filepath.Join(m.BinDir, "hadolint")
	if runtime.GOOS == "windows" {
		dest += ".exe"
	}
	if _, err := os.Stat(dest); err == nil && !opts.Force {
		return m.recordBundledState("hadolint", filepath.Base(dest), "github")
	}
	p := DetectPlatform()
	ver := opts.Version
	if ver == "" {
		v, err := m.latestRelease("hadolint/hadolint")
		if err != nil {
			return err
		}
		ver = v
	}
	_, url, ok := p.HadolintAsset(ver)
	if !ok {
		return fmt.Errorf("hadolint: no published binary for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return m.downloadBinary("hadolint", filepath.Base(dest), url, opts)
}

func (m *Manager) installGrype(opts InstallOptions) error {
	dest := filepath.Join(m.BinDir, "grype")
	if _, err := os.Stat(dest); err == nil && !opts.Force {
		return m.recordBundledState("grype", "grype", "github")
	}
	p := DetectPlatform()
	ver := opts.Version
	if ver == "" {
		v, err := m.latestRelease("anchore/grype")
		if err != nil {
			return err
		}
		ver = v
	}
	_, url, ok := p.GrypeAsset(ver)
	if !ok {
		return fmt.Errorf("grype: no published binary for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return m.downloadFromGitHub("grype", "grype", url, opts)
}

func (m *Manager) installOSVScanner(opts InstallOptions) error {
	binary := "osv-scanner"
	dest := filepath.Join(m.BinDir, binary)
	if runtime.GOOS == "windows" {
		dest += ".exe"
		binary = "osv-scanner.exe"
	}
	if _, err := os.Stat(dest); err == nil && !opts.Force {
		return m.recordBundledState("osv-scanner", filepath.Base(dest), "github")
	}
	p := DetectPlatform()
	ver := opts.Version
	if ver == "" {
		v, err := m.latestRelease("google/osv-scanner")
		if err != nil {
			return err
		}
		ver = v
	}
	_, url, ok := p.OSVScannerAsset(ver)
	if !ok {
		return fmt.Errorf("osv-scanner: no published binary for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return m.downloadBinary("osv-scanner", filepath.Base(dest), url, opts)
}

func (m *Manager) installGovulncheck(opts InstallOptions) error {
	binary := "govulncheck"
	dest := filepath.Join(m.BinDir, binary)
	if runtime.GOOS == "windows" {
		dest += ".exe"
		binary = "govulncheck.exe"
	}
	if _, err := os.Stat(dest); err == nil && !opts.Force {
		return m.recordBundledState("govulncheck", filepath.Base(dest), "go")
	}
	module := "golang.org/x/vuln/cmd/govulncheck"
	spec := module + "@latest"
	if opts.Version != "" {
		spec = module + "@" + opts.Version
	}
	return m.installGoModule("govulncheck", spec, filepath.Base(dest), opts)
}

func (m *Manager) installActionlint(opts InstallOptions) error {
	binary := "actionlint"
	dest := filepath.Join(m.BinDir, binary)
	if runtime.GOOS == "windows" {
		dest += ".exe"
		binary = "actionlint.exe"
	}
	if _, err := os.Stat(dest); err == nil && !opts.Force {
		return m.recordBundledState("actionlint", filepath.Base(dest), "go")
	}
	module := "github.com/rhysd/actionlint/cmd/actionlint"
	spec := module + "@latest"
	if opts.Version != "" {
		spec = module + "@" + opts.Version
	}
	return m.installGoModule("actionlint", spec, filepath.Base(dest), opts)
}

func (m *Manager) installSyft(opts InstallOptions) error {
	dest := filepath.Join(m.BinDir, "syft")
	if _, err := os.Stat(dest); err == nil && !opts.Force {
		return m.recordBundledState("syft", "syft", "github")
	}
	p := DetectPlatform()
	ver := opts.Version
	if ver == "" {
		v, err := m.latestRelease("anchore/syft")
		if err != nil {
			return err
		}
		ver = v
	}
	_, url, ok := p.SyftAsset(ver)
	if !ok {
		return fmt.Errorf("syft: no published binary for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return m.downloadFromGitHub("syft", "syft", url, opts)
}

func (m *Manager) installGoModule(toolName, spec, destName string, opts InstallOptions) error {
	if _, err := m.LookPath("go"); err != nil {
		return fmt.Errorf("%s: go is required on PATH (install Go, then retry)", toolName)
	}
	goBin, err := m.resolveGoBin()
	if err != nil {
		return fmt.Errorf("%s: resolve go bin: %w", toolName, err)
	}
	if _, err := m.Exec("go", "install", spec); err != nil {
		return fmt.Errorf("%s: go install: %w", toolName, err)
	}
	src := filepath.Join(goBin, destName)
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("%s: expected binary at %s after go install: %w", toolName, src, err)
	}
	dest := filepath.Join(m.BinDir, destName)
	if err := linkOrCopy(src, dest); err != nil {
		return fmt.Errorf("%s: expose binary: %w", toolName, err)
	}
	return m.recordBundledState(toolName, destName, "go")
}

func (m *Manager) resolveGoBin() (string, error) {
	out, err := m.Exec("go", "env", "GOBIN")
	if err == nil {
		if bin := strings.TrimSpace(string(out)); bin != "" {
			return bin, nil
		}
	}
	out, err = m.Exec("go", "env", "GOPATH")
	if err != nil {
		return "", err
	}
	gopath := strings.TrimSpace(string(out))
	if gopath == "" {
		return "", fmt.Errorf("empty GOPATH")
	}
	return filepath.Join(gopath, "bin"), nil
}

func (m *Manager) installPythonPackageTool(toolName, packageName, binary string, opts InstallOptions) error {
	dest := filepath.Join(m.BinDir, binary)
	if runtime.GOOS == "windows" {
		dest += ".exe"
	}
	if _, err := os.Stat(dest); err == nil && !opts.Force {
		return m.recordBundledState(toolName, filepath.Base(dest), "venv")
	}

	python := ""
	for _, candidate := range []string{"python3", "python"} {
		if path, _ := m.LookPath(candidate); path != "" {
			python = candidate
			break
		}
	}
	if python == "" {
		return fmt.Errorf("%s: no installer available (need python3 on $PATH)", toolName)
	}

	venvPath := filepath.Join(m.VenvDir, toolName)
	if opts.Force {
		_ = os.RemoveAll(venvPath)
	}
	if _, err := os.Stat(venvPath); os.IsNotExist(err) {
		if _, err := m.Exec(python, "-m", "venv", venvPath); err != nil {
			return fmt.Errorf("%s: create venv: %w", toolName, err)
		}
	}

	venvPython := filepath.Join(venvPath, "bin", "python")
	venvBinary := filepath.Join(venvPath, "bin", binary)
	if runtime.GOOS == "windows" {
		venvPython = filepath.Join(venvPath, "Scripts", "python.exe")
		venvBinary = filepath.Join(venvPath, "Scripts", binary+".exe")
	}

	spec := packageName
	if opts.Version != "" {
		spec = packageName + "==" + strings.TrimPrefix(opts.Version, "v")
	}
	if _, err := m.Exec(venvPython, "-m", "pip", "install", "--upgrade", "pip", spec); err != nil {
		return fmt.Errorf("%s: pip install: %w", toolName, err)
	}
	if _, err := os.Stat(venvBinary); err != nil {
		return fmt.Errorf("%s: expected console script at %s: %w", toolName, venvBinary, err)
	}
	if err := linkOrCopy(venvBinary, dest); err != nil {
		return fmt.Errorf("%s: expose binary: %w", toolName, err)
	}
	return m.recordBundledState(toolName, filepath.Base(dest), "venv")
}

// latestRelease is a Manager-bound version of LatestRelease that uses the
// manager's HTTPGet function. This keeps the test seam working: tests can
// substitute m.HTTPGet and have the GitHub API lookup go through their fake.
func (m *Manager) latestRelease(repo string) (string, error) {
	if tag, ok := releaseCacheLookup(repo); ok {
		return tag, nil
	}
	url := "https://api.github.com/repos/" + repo + "/releases/latest"
	resp, err := m.HTTPGet(url)
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
		return "", fmt.Errorf("github: %s: empty tag_name", repo)
	}
	releaseCacheStore(repo, r.TagName)
	return r.TagName, nil
}

// installSemgrep delegates to pipx (preferred) or python -m pip (fallback).
// We don't put the semgrep binary in ~/.cyberai/bin; it stays on the
// system PATH where pipx puts it.
func (m *Manager) installSemgrep(opts InstallOptions) error {
	// Check if it's already on $PATH.
	if !opts.Force {
		if path, _ := m.LookPath("semgrep"); path != "" {
			return m.recordState("semgrep", "system", opts.Version)
		}
	}
	// Try pipx first.
	if path, _ := m.LookPath("pipx"); path != "" {
		args := []string{"install", "semgrep"}
		if opts.Version != "" {
			args = []string{"install", "semgrep==" + strings.TrimPrefix(opts.Version, "v")}
		}
		if _, err := m.Exec("pipx", args...); err == nil {
			return m.recordState("semgrep", "pipx", opts.Version)
		}
	}
	// Fall back to python -m pip --user.
	if path, _ := m.LookPath("python3"); path != "" {
		args := []string{"-m", "pip", "install", "--user", "semgrep"}
		if opts.Version != "" {
			args = []string{"-m", "pip", "install", "--user", "semgrep==" + strings.TrimPrefix(opts.Version, "v")}
		}
		if _, err := m.Exec("python3", args...); err == nil {
			return m.recordState("semgrep", "pip", opts.Version)
		}
	}
	return fmt.Errorf("semgrep: no installer available (need pipx or python3 on $PATH); try: pipx install semgrep")
}

func (m *Manager) recordState(name, method, version string) error {
	if version == "" {
		// Probe for installed version if caller didn't pin one.
		if path, _ := m.LookPath(name); path != "" {
			if out, err := m.Exec(name, "--version"); err == nil {
				version = firstLine(string(out))
			}
		}
	}
	state, err := LoadState(m.State)
	if err != nil {
		return err
	}
	state[name] = InstalledTool{
		Version:   version,
		Method:    InstalledMethod(method),
		UpdatedAt: time.Now().UTC(),
	}
	return SaveState(m.State, state)
}

func (m *Manager) recordBundledState(name, binary, method string) error {
	dest := filepath.Join(m.BinDir, binary)
	version := "unknown"
	if out, err := m.Exec(dest, "--version"); err == nil {
		version = firstLine(string(out))
	}
	state, err := LoadState(m.State)
	if err != nil {
		return err
	}
	state[name] = InstalledTool{
		Version:   version,
		Method:    InstalledMethod(method),
		UpdatedAt: time.Now().UTC(),
	}
	return SaveState(m.State, state)
}

// downloadFromGitHub fetches a tarball/zip from url, extracts the single
// binary, and writes it to ~/.cyberai/bin/<binary> (mode 0755).
func (m *Manager) downloadFromGitHub(toolName, binary, url string, opts InstallOptions) error {
	dest := filepath.Join(m.BinDir, binary)
	if _, err := os.Stat(dest); err == nil && !opts.Force {
		return fmt.Errorf("%s: already installed at %s (use --force to overwrite)", toolName, dest)
	}
	resp, err := m.HTTPGet(url)
	if err != nil {
		return fmt.Errorf("%s: download: %w", toolName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: download: status %d", toolName, resp.StatusCode)
	}

	if strings.HasSuffix(url, ".tar.gz") {
		if err := extractTarGz(resp.Body, m.BinDir, binary); err != nil {
			return fmt.Errorf("%s: extract: %w", toolName, err)
		}
	} else {
		if err := extractZip(resp.Body, m.BinDir, binary); err != nil {
			return fmt.Errorf("%s: extract: %w", toolName, err)
		}
	}
	if err := os.Chmod(dest, 0o755); err != nil {
		return fmt.Errorf("%s: chmod: %w", toolName, err)
	}

	return m.recordBundledState(toolName, binary, "github")
}

func (m *Manager) downloadBinary(toolName, binary, url string, opts InstallOptions) error {
	dest := filepath.Join(m.BinDir, binary)
	if _, err := os.Stat(dest); err == nil && !opts.Force {
		return fmt.Errorf("%s: already installed at %s (use --force to overwrite)", toolName, dest)
	}
	resp, err := m.HTTPGet(url)
	if err != nil {
		return fmt.Errorf("%s: download: %w", toolName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: download: status %d", toolName, resp.StatusCode)
	}
	tmpDest := dest + ".tmp"
	out, err := os.OpenFile(tmpDest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("%s: create temporary binary: %w", toolName, err)
	}
	defer os.Remove(tmpDest)

	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		return fmt.Errorf("%s: write binary: %w", toolName, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("%s: close binary: %w", toolName, err)
	}
	if err := os.Chmod(tmpDest, 0o755); err != nil {
		return fmt.Errorf("%s: chmod: %w", toolName, err)
	}
	if err := os.Rename(tmpDest, dest); err != nil {
		return fmt.Errorf("%s: rename binary: %w", toolName, err)
	}
	return m.recordBundledState(toolName, binary, "github")
}

func linkOrCopy(src, dest string) error {
	_ = os.Remove(dest)
	if err := os.Symlink(src, dest); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// extractTarGz reads a .tar.gz stream and writes the entry named `binary`
// into destDir. Strips any leading directory components (gitleaks and trivy
// tarballs have a top-level dir in some versions).
func extractTarGz(r io.Reader, destDir, binary string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("%s not found in archive", binary)
		}
		if err != nil {
			return err
		}
		name := filepath.Base(hdr.Name)
		if name != binary {
			continue
		}
		if hdr.FileInfo().IsDir() {
			continue
		}
		tmpDest := filepath.Join(destDir, binary+".tmp")
		out, err := os.OpenFile(tmpDest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		defer os.Remove(tmpDest)
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		return os.Rename(tmpDest, filepath.Join(destDir, binary))
	}
}

// extractZip reads a .zip stream and writes the entry named `binary`.
func extractZip(r io.Reader, destDir, binary string) error {
	// zip needs a ReaderAt + size; buffer the body in memory. Release
	// tarballs are small (10-30 MB), so this is fine.
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytesReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) != binary {
			continue
		}
		src, err := f.Open()
		if err != nil {
			return err
		}
		defer src.Close()
		tmpDest := filepath.Join(destDir, binary+".tmp")
		out, err := os.OpenFile(tmpDest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		defer os.Remove(tmpDest)
		if _, err := io.Copy(out, src); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		return os.Rename(tmpDest, filepath.Join(destDir, binary))
	}
	return fmt.Errorf("%s not found in archive", binary)
}

// bytesReader is a tiny adapter so we can pass a []byte to zip.NewReader.
type bytesReaderImpl struct {
	b   []byte
	pos int64
}

func bytesReader(b []byte) *bytesReaderImpl { return &bytesReaderImpl{b: b} }
func (r *bytesReaderImpl) Read(p []byte) (int, error) {
	if r.pos >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += int64(n)
	return n, nil
}
func (r *bytesReaderImpl) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (r *bytesReaderImpl) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		r.pos = offset
	case io.SeekCurrent:
		r.pos += offset
	case io.SeekEnd:
		r.pos = int64(len(r.b)) + offset
	}
	return r.pos, nil
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
