package tools

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// --- Test helpers --------------------------------------------------------

// newTestManager returns a Manager pointing at t.TempDir() with HTTPGet and
// Exec swapped for test doubles. It does NOT call t.Setenv; tests that need
// to override $HOME / bin dir do that explicitly.
func newTestManager(t *testing.T) (*Manager, *httpClient) {
	t.Helper()
	clearReleaseCache() // avoid stale cache between tests
	binDir := t.TempDir()
	state := filepath.Join(t.TempDir(), "tools.json")
	venvDir := t.TempDir()
	cli := &httpClient{}
	return &Manager{
		BinDir:  binDir,
		State:   state,
		VenvDir: venvDir,
		HTTPGet: cli.Get,
		Exec:    func(name string, args ...string) ([]byte, error) { return []byte(name + " 9.9.9\n"), nil },
		LookPath: func(s string) (string, error) {
			if s == "pipx" || s == "python3" || s == "semgrep" {
				return "", &notFoundError{s: s}
			}
			return "/usr/bin/" + s, nil
		},
	}, cli
}

type notFoundError struct{ s string }

func (e *notFoundError) Error() string { return e.s + ": not found" }

// httpClient is a stub for HTTPGet. Tests register routes; the manager
// calls m.HTTPGet(url) like normal http.Get.
type httpClient struct {
	routes map[string][]byte
	gets   int32
}

func (c *httpClient) Get(url string) (*http.Response, error) {
	atomic.AddInt32(&c.gets, 1)
	body, ok := c.routes[url]
	if !ok {
		// Useful when debugging: print which URL was missed.
		// (Comment out in production; tests run with -v to see this.)
		return &http.Response{
			StatusCode: 404,
			Body:       io.NopCloser(strings.NewReader("not found: " + url)),
		}, nil
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil
}

// makeTarGz builds a real .tar.gz containing one file named `binary` with
// the given content. Used to fake a gitleaks/trivy release.
func makeTarGz(t *testing.T, binary string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{
		Name:     "release/" + binary,
		Mode:     0o755,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// makeGitHubReleaseJSON builds the JSON body returned by GitHub's
// /repos/{owner}/{repo}/releases/latest endpoint.
func makeGitHubReleaseJSON(tag string) []byte {
	body, _ := json.Marshal(map[string]string{"tag_name": tag})
	return body
}

// setGHVersion stubs a single route on the test client: the GitHub
// /releases/latest endpoint returns `tag` for the given repo.
func (c *httpClient) setGHVersion(t *testing.T, repo, tag string) {
	t.Helper()
	if c.routes == nil {
		c.routes = map[string][]byte{}
	}
	c.routes["https://api.github.com/repos/"+repo+"/releases/latest"] = makeGitHubReleaseJSON(tag)
}

// setAsset stubs a release tarball/zip download URL.
func (c *httpClient) setAsset(t *testing.T, url string, body []byte) {
	t.Helper()
	if c.routes == nil {
		c.routes = map[string][]byte{}
	}
	c.routes[url] = body
}

// --- Tests ---------------------------------------------------------------

func TestBinDir_RespectsOverride(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv(EnvBinDir, tmp)
	got, err := BinDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != tmp {
		t.Errorf("BinDir = %q, want %q", got, tmp)
	}
}

func TestBinDir_UsesDefaultWithHome(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv(EnvBinDir, "")
	got, err := BinDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(tmp, ".cyberai", "bin")
	if got != want {
		t.Errorf("BinDir = %q, want %q", got, want)
	}
}

func TestPlatform_GitleaksAsset_Linux(t *testing.T) {
	p := Platform{OS: "linux", Arch: "amd64", Ext: "tar.gz"}
	name, url, ok := p.GitleaksAsset("8.30.1")
	if !ok {
		t.Fatal("expected ok=true for linux/amd64")
	}
	if name != "gitleaks_8.30.1_linux_x64.tar.gz" {
		t.Errorf("filename = %q", name)
	}
	want := "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz"
	if url != want {
		t.Errorf("url = %q", url)
	}
}

func TestPlatform_GitleaksAsset_DarwinARM64(t *testing.T) {
	p := Platform{OS: "darwin", Arch: "arm64", Ext: "tar.gz"}
	name, _, ok := p.GitleaksAsset("v8.30.1")
	if !ok {
		t.Fatal("expected ok=true for darwin/arm64")
	}
	if name != "gitleaks_8.30.1_darwin_arm64.tar.gz" {
		t.Errorf("filename = %q", name)
	}
}

func TestPlatform_TrivyAsset_LinuxARM64(t *testing.T) {
	p := Platform{OS: "linux", Arch: "arm64", Ext: "tar.gz"}
	name, _, ok := p.TrivyAsset("0.71.2")
	if !ok {
		t.Fatal("expected ok=true for linux/arm64")
	}
	if name != "trivy_0.71.2_Linux-ARM64.tar.gz" {
		t.Errorf("filename = %q", name)
	}
}

func TestPlatform_HadolintAsset_Linux(t *testing.T) {
	p := Platform{OS: "linux", Arch: "amd64", Ext: "tar.gz"}
	name, url, ok := p.HadolintAsset("v2.14.0")
	if !ok {
		t.Fatal("expected ok=true for linux/amd64")
	}
	if name != "hadolint-Linux-x86_64" {
		t.Errorf("filename = %q", name)
	}
	want := "https://github.com/hadolint/hadolint/releases/download/v2.14.0/hadolint-Linux-x86_64"
	if url != want {
		t.Errorf("url = %q", url)
	}
}

func TestPlatform_GrypeAsset_Linux(t *testing.T) {
	p := Platform{OS: "linux", Arch: "amd64", Ext: "tar.gz"}
	name, url, ok := p.GrypeAsset("v0.83.0")
	if !ok {
		t.Fatal("expected ok=true for linux/amd64")
	}
	if name != "grype_0.83.0_linux_amd64.tar.gz" {
		t.Errorf("filename = %q", name)
	}
	want := "https://github.com/anchore/grype/releases/download/v0.83.0/grype_0.83.0_linux_amd64.tar.gz"
	if url != want {
		t.Errorf("url = %q", url)
	}
}

func TestPlatform_SyftAsset_Linux(t *testing.T) {
	p := Platform{OS: "linux", Arch: "amd64", Ext: "tar.gz"}
	name, url, ok := p.SyftAsset("v1.45.1")
	if !ok {
		t.Fatal("expected ok=true for linux/amd64")
	}
	if name != "syft_1.45.1_linux_amd64.tar.gz" {
		t.Errorf("filename = %q", name)
	}
	want := "https://github.com/anchore/syft/releases/download/v1.45.1/syft_1.45.1_linux_amd64.tar.gz"
	if url != want {
		t.Errorf("url = %q", url)
	}
}

func TestPlatform_OSVScannerAsset_Linux(t *testing.T) {
	p := Platform{OS: "linux", Arch: "amd64", Ext: "tar.gz"}
	name, url, ok := p.OSVScannerAsset("v2.4.0")
	if !ok {
		t.Fatal("expected ok=true for linux/amd64")
	}
	if name != "osv-scanner_linux_amd64" {
		t.Errorf("filename = %q", name)
	}
	want := "https://github.com/google/osv-scanner/releases/download/v2.4.0/osv-scanner_linux_amd64"
	if url != want {
		t.Errorf("url = %q", url)
	}
}

func TestPlatform_Asset_UnsupportedOS(t *testing.T) {
	p := Platform{OS: "freebsd", Arch: "amd64", Ext: "tar.gz"}
	if _, _, ok := p.GitleaksAsset("1.0.0"); ok {
		t.Error("expected ok=false for freebsd")
	}
	if _, _, ok := p.TrivyAsset("1.0.0"); ok {
		t.Error("expected ok=false for freebsd")
	}
	if _, _, ok := p.HadolintAsset("1.0.0"); ok {
		t.Error("expected ok=false for freebsd")
	}
}

func TestState_LoadMissingReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	got, err := LoadState(filepath.Join(dir, "tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

func TestState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tools.json")
	in := map[string]InstalledTool{
		"gitleaks": {Version: "8.30.1", Method: "github"},
		"semgrep":  {Version: "1.167.0", Method: "system"},
	}
	if err := SaveState(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d entries, want 2", len(out))
	}
	if out["gitleaks"].Version != "8.30.1" || out["gitleaks"].Method != "github" {
		t.Errorf("gitleaks = %+v", out["gitleaks"])
	}
}

func TestState_AtomicOverwrite(t *testing.T) {
	// SaveState should not leave a .tmp file behind on success.
	dir := t.TempDir()
	path := filepath.Join(dir, "tools.json")
	if err := SaveState(path, map[string]InstalledTool{"a": {Version: "1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("expected .tmp to be cleaned up, got err=%v", err)
	}
}

func TestExtractTarGz(t *testing.T) {
	dir := t.TempDir()
	body := makeTarGz(t, "gitleaks", []byte("#!/bin/sh\necho gitleaks\n"))
	if err := extractTarGz(bytes.NewReader(body), dir, "gitleaks"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "gitleaks"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "echo gitleaks") {
		t.Errorf("body = %q", got)
	}
}

func TestExtractTarGz_StripsTopLevelDir(t *testing.T) {
	// Some gitleaks releases ship a `gitleaks/` directory at the top of
	// the tarball. Our extractor should still find `gitleaks` inside.
	dir := t.TempDir()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "gitleaks/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: "gitleaks/bin/gitleaks", Typeflag: tar.TypeReg, Mode: 0o755, Size: 5})
	_, _ = tw.Write([]byte("hello"))
	_ = tw.Close()
	_ = gz.Close()
	if err := extractTarGz(bytes.NewReader(buf.Bytes()), dir, "gitleaks"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "gitleaks")); err != nil {
		t.Errorf("expected gitleaks binary at top of dest dir, got err=%v", err)
	}
}

func TestExtractTarGz_MissingBinary(t *testing.T) {
	dir := t.TempDir()
	body := makeTarGz(t, "semgrep", []byte("x"))
	err := extractTarGz(bytes.NewReader(body), dir, "gitleaks")
	if err == nil {
		t.Error("expected error when binary not in archive")
	}
}

func TestManager_InstallGitleaks_Success(t *testing.T) {
	mgr, cli := newTestManager(t)
	cli.setGHVersion(t, "gitleaks/gitleaks", "v8.30.1")
	p := DetectPlatform()
	_, url, _ := p.GitleaksAsset("v8.30.1")
	cli.setAsset(t, url, makeTarGz(t, "gitleaks", []byte("#!/bin/sh\necho gitleaks\n")))

	if err := mgr.Install("gitleaks", InstallOptions{}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	dest := filepath.Join(mgr.BinDir, "gitleaks")
	if _, err := os.Stat(dest); err != nil {
		t.Errorf("expected binary at %s, got %v", dest, err)
	}
	state, err := LoadState(mgr.State)
	if err != nil {
		t.Fatal(err)
	}
	if state["gitleaks"].Version == "" {
		t.Error("expected state to record gitleaks version")
	}
	if state["gitleaks"].Method != "github" {
		t.Errorf("method = %q, want github", state["gitleaks"].Method)
	}
}

func TestManager_InstallGitleaks_SkipsIfExists(t *testing.T) {
	mgr, cli := newTestManager(t)
	// Pre-create the binary.
	dest := filepath.Join(mgr.BinDir, "gitleaks")
	if err := os.WriteFile(dest, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Install("gitleaks", InstallOptions{}); err != nil {
		t.Fatalf("expected existing binary to be accepted, got %v", err)
	}
	// And we should not have made a network call.
	if atomic.LoadInt32(&cli.gets) != 0 {
		t.Errorf("expected 0 HTTP gets, got %d", atomic.LoadInt32(&cli.gets))
	}
	state, _ := LoadState(mgr.State)
	if state["gitleaks"].Method != "github" {
		t.Errorf("method = %q, want github", state["gitleaks"].Method)
	}
}

func TestManager_InstallGitleaks_ForceOverwrite(t *testing.T) {
	mgr, cli := newTestManager(t)
	dest := filepath.Join(mgr.BinDir, "gitleaks")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	cli.setGHVersion(t, "gitleaks/gitleaks", "v8.30.1")
	p := DetectPlatform()
	_, url, _ := p.GitleaksAsset("v8.30.1")
	cli.setAsset(t, url, makeTarGz(t, "gitleaks", []byte("new")))

	if err := mgr.Install("gitleaks", InstallOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "new" {
		t.Errorf("binary contents = %q, want 'new'", got)
	}
}

func TestManager_InstallGitleaks_PinnedVersion(t *testing.T) {
	mgr, cli := newTestManager(t)
	p := DetectPlatform()
	_, url, _ := p.GitleaksAsset("v8.18.0")
	cli.setAsset(t, url, makeTarGz(t, "gitleaks", []byte("v8.18.0")))

	if err := mgr.Install("gitleaks", InstallOptions{Version: "v8.18.0"}); err != nil {
		t.Fatal(err)
	}
	// LatestRelease should NOT have been called.
	if atomic.LoadInt32(&cli.gets) != 1 {
		t.Errorf("expected exactly 1 HTTP get (asset only), got %d", atomic.LoadInt32(&cli.gets))
	}
}

func TestManager_InstallGitleaks_NetworkError(t *testing.T) {
	mgr, _ := newTestManager(t)
	// No routes registered — HTTPGet returns 404.
	err := mgr.Install("gitleaks", InstallOptions{})
	if err == nil {
		t.Error("expected error when GitHub API returns 404")
	}
}

func TestManager_InstallTrivy_Success(t *testing.T) {
	mgr, cli := newTestManager(t)
	cli.setGHVersion(t, "aquasecurity/trivy", "v0.71.2")
	p := DetectPlatform()
	_, url, _ := p.TrivyAsset("v0.71.2")
	cli.setAsset(t, url, makeTarGz(t, "trivy", []byte("trivy binary")))

	if err := mgr.Install("trivy", InstallOptions{}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	dest := filepath.Join(mgr.BinDir, "trivy")
	if _, err := os.Stat(dest); err != nil {
		t.Errorf("expected trivy at %s: %v", dest, err)
	}
}

func TestManager_InstallHadolint_Success(t *testing.T) {
	mgr, cli := newTestManager(t)
	cli.setGHVersion(t, "hadolint/hadolint", "v2.14.0")
	p := DetectPlatform()
	_, url, _ := p.HadolintAsset("v2.14.0")
	cli.setAsset(t, url, []byte("hadolint binary"))

	if err := mgr.Install("hadolint", InstallOptions{}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mgr.BinDir, "hadolint")); err != nil {
		t.Errorf("expected hadolint binary: %v", err)
	}
	state, _ := LoadState(mgr.State)
	if state["hadolint"].Method != "github" {
		t.Errorf("method = %q, want github", state["hadolint"].Method)
	}
}

func TestManager_InstallGrype_Success(t *testing.T) {
	mgr, cli := newTestManager(t)
	cli.setGHVersion(t, "anchore/grype", "v0.83.0")
	p := DetectPlatform()
	_, url, _ := p.GrypeAsset("v0.83.0")
	cli.setAsset(t, url, makeTarGz(t, "grype", []byte("grype binary")))

	if err := mgr.Install("grype", InstallOptions{}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mgr.BinDir, "grype")); err != nil {
		t.Errorf("expected grype at bin dir: %v", err)
	}
}

func TestManager_InstallOSVScanner_Success(t *testing.T) {
	mgr, cli := newTestManager(t)
	cli.setGHVersion(t, "google/osv-scanner", "v2.4.0")
	p := DetectPlatform()
	_, url, _ := p.OSVScannerAsset("v2.4.0")
	cli.setAsset(t, url, []byte("osv-scanner binary"))

	if err := mgr.Install("osv-scanner", InstallOptions{}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mgr.BinDir, "osv-scanner")); err != nil {
		t.Errorf("expected osv-scanner at bin dir: %v", err)
	}
}

func TestManager_InstallGovulncheck_Success(t *testing.T) {
	mgr, _ := newTestManager(t)
	goBin := filepath.Join(t.TempDir(), "gopath", "bin")
	if err := os.MkdirAll(goBin, 0o755); err != nil {
		t.Fatal(err)
	}
	mgr.LookPath = func(s string) (string, error) {
		if s == "go" {
			return "/usr/bin/go", nil
		}
		return "", &notFoundError{s: s}
	}
	mgr.Exec = func(name string, args ...string) ([]byte, error) {
		if name == "go" && len(args) >= 2 && args[0] == "env" && args[1] == "GOBIN" {
			return []byte("\n"), nil
		}
		if name == "go" && len(args) >= 2 && args[0] == "env" && args[1] == "GOPATH" {
			return []byte(filepath.Dir(goBin) + "\n"), nil
		}
		if name == "go" && len(args) >= 1 && args[0] == "install" {
			if err := os.WriteFile(filepath.Join(goBin, "govulncheck"), []byte("#!/bin/sh\n"), 0o755); err != nil {
				return nil, err
			}
			return []byte("ok\n"), nil
		}
		return []byte("govulncheck version\n"), nil
	}
	if err := mgr.Install("govulncheck", InstallOptions{}); err != nil {
		t.Fatalf("Install govulncheck: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mgr.BinDir, "govulncheck")); err != nil {
		t.Errorf("expected govulncheck at bin dir: %v", err)
	}
}

func TestManager_InstallSyft_Success(t *testing.T) {
	mgr, cli := newTestManager(t)
	cli.setGHVersion(t, "anchore/syft", "v1.45.1")
	p := DetectPlatform()
	_, url, _ := p.SyftAsset("v1.45.1")
	cli.setAsset(t, url, makeTarGz(t, "syft", []byte("syft binary")))

	if err := mgr.Install("syft", InstallOptions{}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mgr.BinDir, "syft")); err != nil {
		t.Errorf("expected syft at bin dir: %v", err)
	}
}

func TestManager_InstallActionlint_Success(t *testing.T) {
	mgr, _ := newTestManager(t)
	goBin := filepath.Join(t.TempDir(), "gopath", "bin")
	if err := os.MkdirAll(goBin, 0o755); err != nil {
		t.Fatal(err)
	}
	mgr.LookPath = func(s string) (string, error) {
		if s == "go" {
			return "/usr/bin/go", nil
		}
		return "", &notFoundError{s: s}
	}
	mgr.Exec = func(name string, args ...string) ([]byte, error) {
		if name == "go" && len(args) >= 2 && args[0] == "env" && args[1] == "GOBIN" {
			return []byte("\n"), nil
		}
		if name == "go" && len(args) >= 2 && args[0] == "env" && args[1] == "GOPATH" {
			return []byte(filepath.Dir(goBin) + "\n"), nil
		}
		if name == "go" && len(args) >= 1 && args[0] == "install" {
			if err := os.WriteFile(filepath.Join(goBin, "actionlint"), []byte("#!/bin/sh\n"), 0o755); err != nil {
				return nil, err
			}
			return []byte("ok\n"), nil
		}
		return []byte("actionlint version\n"), nil
	}
	if err := mgr.Install("actionlint", InstallOptions{}); err != nil {
		t.Fatalf("Install actionlint: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mgr.BinDir, "actionlint")); err != nil {
		t.Errorf("expected actionlint at bin dir: %v", err)
	}
}

func TestManager_InstallPythonPackageTool_ManagedVenv(t *testing.T) {
	mgr, _ := newTestManager(t)
	mgr.LookPath = func(s string) (string, error) {
		if s == "python3" {
			return "/usr/bin/python3", nil
		}
		return "", &notFoundError{s: s}
	}
	mgr.Exec = func(name string, args ...string) ([]byte, error) {
		if len(args) >= 3 && args[0] == "-m" && args[1] == "venv" {
			bin := filepath.Join(args[2], "bin")
			if err := os.MkdirAll(bin, 0o755); err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(bin, "python"), []byte("#!/bin/sh\n"), 0o755); err != nil {
				return nil, err
			}
			return []byte("venv\n"), nil
		}
		if strings.Contains(name, filepath.Join("checkov", "bin", "python")) {
			bin := filepath.Join(mgr.VenvDir, "checkov", "bin")
			if err := os.WriteFile(filepath.Join(bin, "checkov"), []byte("#!/bin/sh\n"), 0o755); err != nil {
				return nil, err
			}
			return []byte("installed\n"), nil
		}
		return []byte("checkov 9.9.9\n"), nil
	}
	if err := mgr.Install("checkov", InstallOptions{}); err != nil {
		t.Fatalf("Install checkov: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mgr.BinDir, "checkov")); err != nil {
		t.Errorf("expected exposed checkov binary: %v", err)
	}
	state, _ := LoadState(mgr.State)
	if state["checkov"].Method != "venv" {
		t.Errorf("method = %q, want venv", state["checkov"].Method)
	}
}

func TestManager_InstallSemgrep_Pipx(t *testing.T) {
	mgr, _ := newTestManager(t)
	// Override the LookPath to claim pipx is available and semgrep is not.
	mgr.LookPath = func(s string) (string, error) {
		if s == "pipx" {
			return "/usr/bin/pipx", nil
		}
		return "", &notFoundError{s: s}
	}
	calls := []string{}
	mgr.Exec = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return []byte("installed\n"), nil
	}
	if err := mgr.Install("semgrep", InstallOptions{}); err != nil {
		t.Fatalf("Install semgrep: %v", err)
	}
	if len(calls) != 1 || !strings.HasPrefix(calls[0], "pipx install") {
		t.Errorf("expected pipx install call, got %v", calls)
	}
	state, _ := LoadState(mgr.State)
	if state["semgrep"].Method != "pipx" {
		t.Errorf("method = %q, want pipx", state["semgrep"].Method)
	}
}

func TestManager_InstallSemgrep_FallbackToPip(t *testing.T) {
	mgr, _ := newTestManager(t)
	calls := []string{}
	mgr.LookPath = func(s string) (string, error) {
		if s == "python3" {
			return "/usr/bin/python3", nil
		}
		return "", &notFoundError{s: s}
	}
	mgr.Exec = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name)
		return []byte("ok\n"), nil
	}
	if err := mgr.Install("semgrep", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != "python3" {
		t.Errorf("expected python3 invocation, got %v", calls)
	}
	state, _ := LoadState(mgr.State)
	if state["semgrep"].Method != "pip" {
		t.Errorf("method = %q, want pip", state["semgrep"].Method)
	}
}

func TestManager_InstallSemgrep_AlreadyOnPath(t *testing.T) {
	mgr, _ := newTestManager(t)
	mgr.LookPath = func(s string) (string, error) {
		if s == "semgrep" {
			return "/usr/bin/semgrep", nil
		}
		return "", &notFoundError{s: s}
	}
	// recordState() probes the semgrep version via Exec; allow that one
	// call but fail if pipx/python3 was invoked.
	installCalls := 0
	mgr.Exec = func(name string, args ...string) ([]byte, error) {
		if name == "pipx" || name == "python3" {
			installCalls++
		}
		return []byte("semgrep 1.167.0\n"), nil
	}
	if err := mgr.Install("semgrep", InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if installCalls != 0 {
		t.Errorf("expected no pipx/python3 install call when semgrep on PATH, got %d", installCalls)
	}
	state, _ := LoadState(mgr.State)
	if state["semgrep"].Method != "system" {
		t.Errorf("method = %q, want system", state["semgrep"].Method)
	}
}

func TestManager_Update_OverwritesBinary(t *testing.T) {
	mgr, cli := newTestManager(t)
	dest := filepath.Join(mgr.BinDir, "gitleaks")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	cli.setGHVersion(t, "gitleaks/gitleaks", "v8.99.0")
	p := DetectPlatform()
	_, url, _ := p.GitleaksAsset("v8.99.0")
	cli.setAsset(t, url, makeTarGz(t, "gitleaks", []byte("new")))

	if err := mgr.Update("gitleaks"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != "new" {
		t.Errorf("contents = %q, want 'new'", got)
	}
}

func TestManager_Remove_DeletesBinary(t *testing.T) {
	mgr, _ := newTestManager(t)
	dest := filepath.Join(mgr.BinDir, "gitleaks")
	if err := os.WriteFile(dest, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mgr.State, []byte(`{"gitleaks":{"version":"8.30.1","method":"github"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Remove("gitleaks"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Errorf("expected binary gone, got err=%v", err)
	}
	state, _ := LoadState(mgr.State)
	if _, ok := state["gitleaks"]; ok {
		t.Error("expected state entry cleared")
	}
}

func TestManager_Remove_SemgrepPrintsHint(t *testing.T) {
	mgr, _ := newTestManager(t)
	err := mgr.Remove("semgrep")
	if err == nil {
		t.Error("expected error for semgrep (we don't manage it)")
	}
	if !strings.Contains(err.Error(), "pipx") {
		t.Errorf("error should mention pipx, got %v", err)
	}
}

func TestManager_Remove_MissingIsNoop(t *testing.T) {
	mgr, _ := newTestManager(t)
	if err := mgr.Remove("gitleaks"); err != nil {
		t.Errorf("expected no error removing missing binary, got %v", err)
	}
}

func TestManager_List_MergesProbeAndState(t *testing.T) {
	mgr, _ := newTestManager(t)
	// Pre-populate state with one tool bundled, one missing.
	if err := SaveState(mgr.State, map[string]InstalledTool{
		"gitleaks": {Version: "8.30.1", Method: "github"},
	}); err != nil {
		t.Fatal(err)
	}
	// Put a binary in binDir so List can find it.
	if err := os.WriteFile(filepath.Join(mgr.BinDir, "gitleaks"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	rows, err := mgr.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(All()) {
		t.Errorf("expected %d rows, got %d", len(All()), len(rows))
	}
	var gitleaksRow *ListResult
	for i := range rows {
		if rows[i].Tool.Name == "gitleaks" {
			gitleaksRow = &rows[i]
		}
	}
	if gitleaksRow == nil {
		t.Fatal("no gitleaks row")
	}
	if gitleaksRow.Bundled == nil || gitleaksRow.Bundled.Version != "8.30.1" {
		t.Errorf("bundled = %+v", gitleaksRow.Bundled)
	}
	if gitleaksRow.BinPath == "" {
		t.Error("expected BinPath to be set when bundled binary exists")
	}
}

func TestManager_Install_AllWhenEmptyName(t *testing.T) {
	mgr, cli := newTestManager(t)
	// Stub all needed URLs.
	cli.setGHVersion(t, "gitleaks/gitleaks", "v8.30.1")
	cli.setGHVersion(t, "aquasecurity/trivy", "v0.71.2")
	cli.setGHVersion(t, "hadolint/hadolint", "v2.14.0")
	cli.setGHVersion(t, "anchore/grype", "v0.83.0")
	cli.setGHVersion(t, "google/osv-scanner", "v2.4.0")
	cli.setGHVersion(t, "anchore/syft", "v1.45.1")
	p := DetectPlatform()
	_, gURL, _ := p.GitleaksAsset("v8.30.1")
	_, tURL, _ := p.TrivyAsset("v0.71.2")
	_, hURL, _ := p.HadolintAsset("v2.14.0")
	_, grURL, _ := p.GrypeAsset("v0.83.0")
	_, osvURL, _ := p.OSVScannerAsset("v2.4.0")
	_, syftURL, _ := p.SyftAsset("v1.45.1")
	cli.setAsset(t, gURL, makeTarGz(t, "gitleaks", []byte("g")))
	cli.setAsset(t, tURL, makeTarGz(t, "trivy", []byte("t")))
	cli.setAsset(t, hURL, []byte("h"))
	cli.setAsset(t, grURL, makeTarGz(t, "grype", []byte("gr")))
	cli.setAsset(t, osvURL, []byte("osv"))
	cli.setAsset(t, syftURL, makeTarGz(t, "syft", []byte("syft")))
	goBin := filepath.Join(t.TempDir(), "gopath", "bin")
	// semgrep: not on PATH in the test manager → would fail; skip by
	// making pipx available. Python is available for checkov/zizmor.
	mgr.LookPath = func(s string) (string, error) {
		switch s {
		case "pipx":
			return "/usr/bin/pipx", nil
		case "python3":
			return "/usr/bin/python3", nil
		case "go":
			return "/usr/bin/go", nil
		}
		return "", &notFoundError{s: s}
	}
	mgr.Exec = func(name string, args ...string) ([]byte, error) {
		if name == "go" && len(args) >= 2 && args[0] == "env" && args[1] == "GOBIN" {
			return []byte("\n"), nil
		}
		if name == "go" && len(args) >= 2 && args[0] == "env" && args[1] == "GOPATH" {
			return []byte(filepath.Dir(goBin) + "\n"), nil
		}
		if name == "go" && len(args) >= 1 && args[0] == "install" {
			if err := os.MkdirAll(goBin, 0o755); err != nil {
				return nil, err
			}
			binName := "govulncheck"
			if len(args) >= 2 && strings.Contains(args[1], "actionlint") {
				binName = "actionlint"
			}
			if err := os.WriteFile(filepath.Join(goBin, binName), []byte("#!/bin/sh\n"), 0o755); err != nil {
				return nil, err
			}
			return []byte("ok\n"), nil
		}
		if len(args) >= 3 && args[0] == "-m" && args[1] == "venv" {
			bin := filepath.Join(args[2], "bin")
			if err := os.MkdirAll(bin, 0o755); err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(bin, "python"), []byte("#!/bin/sh\n"), 0o755); err != nil {
				return nil, err
			}
			return []byte("venv\n"), nil
		}
		for _, tool := range []string{"checkov", "zizmor"} {
			if strings.Contains(name, filepath.Join(tool, "bin", "python")) {
				bin := filepath.Join(mgr.VenvDir, tool, "bin")
				if err := os.WriteFile(filepath.Join(bin, tool), []byte("#!/bin/sh\n"), 0o755); err != nil {
					return nil, err
				}
				return []byte("installed\n"), nil
			}
		}
		return []byte(name + " 9.9.9\n"), nil
	}

	if err := mgr.Install("", InstallOptions{}); err != nil {
		t.Fatalf("Install all: %v", err)
	}
	for _, name := range []string{"gitleaks", "trivy", "hadolint", "checkov", "zizmor", "grype", "osv-scanner", "govulncheck", "actionlint", "syft"} {
		if _, err := os.Stat(filepath.Join(mgr.BinDir, name)); err != nil {
			t.Errorf("expected %s installed, got err=%v", name, err)
		}
	}
}

func TestLatestRelease_CacheHit(t *testing.T) {
	calls := atomic.Int32{}
	origGet := HTTPGetFunc
	HTTPGetFunc = func(url string) (*http.Response, error) {
		calls.Add(1)
		body := makeGitHubReleaseJSON("v1.0.0")
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(body)),
		}, nil
	}
	t.Cleanup(func() {
		HTTPGetFunc = origGet
		clearReleaseCache()
	})
	// First call hits the network.
	if v, err := LatestRelease("foo/bar"); err != nil || v != "v1.0.0" {
		t.Fatalf("first call: v=%q err=%v", v, err)
	}
	// Second call should hit the cache.
	if v, err := LatestRelease("foo/bar"); err != nil || v != "v1.0.0" {
		t.Fatalf("second call: v=%q err=%v", v, err)
	}
	if calls.Load() != 1 {
		t.Errorf("expected 1 network call, got %d", calls.Load())
	}
}

// --- Compile-time guards -------------------------------------------------

// Verify DetectPlatform works on this host.
func TestDetectPlatform_CurrentHost(t *testing.T) {
	p := DetectPlatform()
	if p.OS != runtime.GOOS || p.Arch != runtime.GOARCH {
		t.Errorf("DetectPlatform = %+v, want OS=%s Arch=%s", p, runtime.GOOS, runtime.GOARCH)
	}
}

// suppress unused import warning for httptest in case all uses are removed.
var _ = httptest.NewServer
var _ = http.MethodGet
