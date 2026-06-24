package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveOutputDir_AllowsPathInsideRoot(t *testing.T) {
	root := t.TempDir()

	got, err := resolveOutputDir(root, "cyberai-reports/nested", false)
	if err != nil {
		t.Fatalf("resolveOutputDir: %v", err)
	}

	want := filepath.Join(root, "cyberai-reports", "nested")
	if got != want {
		t.Fatalf("resolveOutputDir = %q, want %q", got, want)
	}
}

func TestResolveOutputDir_RejectsEscapingParentPath(t *testing.T) {
	root := t.TempDir()

	_, err := resolveOutputDir(root, "../outside", false)
	if err == nil {
		t.Fatal("expected escaping output path to fail")
	}
}

func TestResolveOutputDir_RejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	linkPath := filepath.Join(root, "reports-link")
	if err := os.Symlink(outside, linkPath); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}

	_, err := resolveOutputDir(root, "reports-link/out", false)
	if err == nil {
		t.Fatal("expected symlink escape to fail")
	}
}
