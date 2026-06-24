package scanner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSemgrepRun_ReturnsErrorOnFailureWithoutJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script scanner stubs are Unix-only")
	}

	binDir := t.TempDir()
	target := t.TempDir()
	writeFakeExecutable(t, binDir, "semgrep", "#!/bin/sh\necho 'semgrep boom' >&2\nexit 2\n")
	withPrependedPath(t, binDir)

	_, err := (&Semgrep{}).Run(context.Background(), target)
	if err == nil {
		t.Fatal("expected semgrep failure")
	}
	if !strings.Contains(err.Error(), "semgrep failed") {
		t.Fatalf("expected semgrep failure error, got %v", err)
	}
	if !strings.Contains(err.Error(), "semgrep boom") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
}

func TestGitleaksRun_ReturnsErrorOnFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script scanner stubs are Unix-only")
	}

	binDir := t.TempDir()
	target := t.TempDir()
	writeFakeExecutable(t, binDir, "gitleaks", "#!/bin/sh\necho 'gitleaks boom' >&2\nexit 3\n")
	withPrependedPath(t, binDir)

	_, err := (&Gitleaks{}).Run(context.Background(), target)
	if err == nil {
		t.Fatal("expected gitleaks failure")
	}
	if !strings.Contains(err.Error(), "gitleaks failed") {
		t.Fatalf("expected gitleaks failure error, got %v", err)
	}
	if !strings.Contains(err.Error(), "gitleaks boom") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
}

func TestTrivyRun_AllowsNonZeroExitWhenJSONWasProduced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script scanner stubs are Unix-only")
	}

	binDir := t.TempDir()
	target := t.TempDir()
	writeFakeExecutable(t, binDir, "trivy", "#!/bin/sh\necho '{\"Results\":[]}'\nexit 1\n")
	withPrependedPath(t, binDir)

	out, err := (&Trivy{}).Run(context.Background(), target)
	if err != nil {
		t.Fatalf("expected trivy JSON output to be accepted, got %v", err)
	}
	if !strings.Contains(string(out), "\"Results\"") {
		t.Fatalf("expected trivy JSON output, got %q", string(out))
	}
}

func TestTrivyRun_ReturnsErrorOnFailureWithoutJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script scanner stubs are Unix-only")
	}

	binDir := t.TempDir()
	target := t.TempDir()
	writeFakeExecutable(t, binDir, "trivy", "#!/bin/sh\necho 'trivy boom' >&2\nexit 4\n")
	withPrependedPath(t, binDir)

	_, err := (&Trivy{}).Run(context.Background(), target)
	if err == nil {
		t.Fatal("expected trivy failure")
	}
	if !strings.Contains(err.Error(), "trivy failed") {
		t.Fatalf("expected trivy failure error, got %v", err)
	}
	if !strings.Contains(err.Error(), "trivy boom") {
		t.Fatalf("expected stderr in error, got %v", err)
	}
}

func TestTrivyRun_RetriesWithoutSkipDBUpdateOnFirstRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script scanner stubs are Unix-only")
	}

	binDir := t.TempDir()
	target := t.TempDir()
	countFile := filepath.Join(t.TempDir(), "count")
	writeFakeExecutable(t, binDir, "trivy", "#!/bin/sh\n"+
		"count=0\n"+
		"if [ -f '"+countFile+"' ]; then count=$(cat '"+countFile+"'); fi\n"+
		"count=$((count + 1))\n"+
		"printf '%s' \"$count\" > '"+countFile+"'\n"+
		"for arg in \"$@\"; do\n"+
		"  if [ \"$arg\" = \"--skip-db-update\" ]; then\n"+
		"    echo 'Fatal error: --skip-db-update cannot be specified on the first run' >&2\n"+
		"    exit 1\n"+
		"  fi\n"+
		"done\n"+
		"echo '{\"Results\":[]}'\n")
	withPrependedPath(t, binDir)

	out, err := (&Trivy{}).Run(context.Background(), target)
	if err != nil {
		t.Fatalf("expected retry to succeed, got %v", err)
	}
	if !strings.Contains(string(out), "\"Results\"") {
		t.Fatalf("expected trivy JSON output, got %q", string(out))
	}
	got, err := os.ReadFile(countFile)
	if err != nil {
		t.Fatalf("read count: %v", err)
	}
	if string(got) != "2" {
		t.Fatalf("expected trivy to run twice, got %q", string(got))
	}
}

func writeFakeExecutable(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake executable: %v", err)
	}
}

func withPrependedPath(t *testing.T, dir string) {
	t.Helper()
	original := os.Getenv("PATH")
	t.Cleanup(func() {
		_ = os.Setenv("PATH", original)
	})
	_ = os.Setenv("PATH", dir+string(os.PathListSeparator)+original)
}
