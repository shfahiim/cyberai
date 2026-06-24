package project

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetect_GoProject(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module example.com/foo\n\ngo 1.22\n")
	writeFile(t, root, "go.sum", "github.com/stretchr/testify v1.0.0\n")
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	writeFile(t, root, "main_test.go", "package main\n\nimport \"testing\"\n")

	p, err := Detect(root)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !contains(p.Languages, "go") {
		t.Errorf("expected go in languages, got %v", p.Languages)
	}
	if !contains(p.Manifests, "go.mod") {
		t.Errorf("expected go.mod in manifests, got %v", p.Manifests)
	}
	if !contains(p.Lockfiles, "go.sum") {
		t.Errorf("expected go.sum in lockfiles, got %v", p.Lockfiles)
	}
	if !p.HasTests {
		t.Error("expected HasTests=true")
	}
}

func TestDetect_JavaScriptMonorepo(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"name":"root","workspaces":["packages/*"]}`)
	writeFile(t, root, "package-lock.json", "{}")
	writeFile(t, root, "pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n")
	writeFile(t, root, "packages/web/package.json", `{"name":"@org/web"}`)
	writeFile(t, root, "Dockerfile", "FROM node:20\n")

	p, err := Detect(root)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !p.IsMonorepo {
		t.Error("expected IsMonorepo=true")
	}
	if !p.HasDocker {
		t.Error("expected HasDocker=true")
	}
	if !contains(p.Languages, "javascript") {
		t.Errorf("expected javascript, got %v", p.Languages)
	}
}

func TestDetect_TerraformAndK8s(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.tf", `resource "aws_s3_bucket" "x" {}`)
	writeFile(t, root, "k8s/deployment.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: x
`)

	p, err := Detect(root)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !p.HasTerraform {
		t.Error("expected HasTerraform=true")
	}
	if !p.HasK8s {
		t.Error("expected HasK8s=true")
	}
}

func TestDetect_SkipsNodeModules(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"name":"x"}`)
	writeFile(t, root, "node_modules/some-pkg/package.json", `{"name":"some-pkg"}`)
	writeFile(t, root, ".git/HEAD", "ref: refs/heads/main\n")

	p, err := Detect(root)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	// node_modules' package.json should be skipped
	countManifests := 0
	for _, m := range p.Manifests {
		if filepath.Base(m) == "package.json" {
			countManifests++
		}
	}
	if countManifests != 1 {
		t.Errorf("expected exactly 1 package.json, got %d (manifests=%v)", countManifests, p.Manifests)
	}
	if p.VCS != "git" {
		t.Errorf("expected VCS=git, got %s", p.VCS)
	}
}

func TestDetect_NoManifests(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "README.md", "# Hello\n")

	p, err := Detect(root)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(p.Languages) != 0 {
		t.Errorf("expected no languages, got %v", p.Languages)
	}
	if len(p.Manifests) != 0 {
		t.Errorf("expected no manifests, got %v", p.Manifests)
	}
}

func TestDetect_LanguagesFromExtensions(t *testing.T) {
	// No manifests, but source files — should infer languages from extensions.
	root := t.TempDir()
	writeFile(t, root, "script.py", "print('x')\n")
	writeFile(t, root, "main.go", "package main\n")

	p, err := Detect(root)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !contains(p.Languages, "go") {
		t.Errorf("expected go from main.go, got %v", p.Languages)
	}
	if !contains(p.Languages, "python") {
		t.Errorf("expected python from script.py, got %v", p.Languages)
	}
}

func TestProfile_HashStable(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module x\n")
	writeFile(t, root, "main.go", "package main\n")
	writeFile(t, root, "a.go", "package a\n") // extra file shouldn't change hash
	writeFile(t, root, "b.go", "package b\n") // another extra file

	p1, _ := Detect(root)
	p2, _ := Detect(root)

	if p1.Hash() != p2.Hash() {
		t.Errorf("hash not stable: %s vs %s", p1.Hash(), p2.Hash())
	}
}

func TestProfile_HashIgnoresRoot(t *testing.T) {
	// Hash should be the same regardless of absolute root path.
	rootA := t.TempDir()
	rootB := t.TempDir()
	writeFile(t, rootA, "go.mod", "module x\n")
	writeFile(t, rootA, "main.go", "package main\n")
	writeFile(t, rootB, "go.mod", "module x\n")
	writeFile(t, rootB, "main.go", "package main\n")

	pA, _ := Detect(rootA)
	pB, _ := Detect(rootB)

	if pA.Hash() != pB.Hash() {
		t.Errorf("hash should ignore root path: %s vs %s", pA.Hash(), pB.Hash())
	}
}

func TestDetect_RejectsNonDirectory(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Detect(f); err == nil {
		t.Error("expected error when root is a file")
	}
}

func contains(slice []string, v string) bool {
	for _, s := range slice {
		if s == v {
			return true
		}
	}
	return false
}

// Sanity check on the helpers used.
func TestUniqSorted(t *testing.T) {
	got := uniqSorted([]string{"b", "a", "a", "c", "b"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("uniqSorted = %v, want %v", got, want)
	}
}

func TestExtensionsFor(t *testing.T) {
	cases := []struct {
		lang string
		want []string
	}{
		{"go", []string{".go"}},
		{"javascript", []string{".js", ".jsx", ".mjs", ".cjs"}},
		{"python", []string{".py"}},
		{"unknown", nil},
	}
	for _, tc := range cases {
		got := extensionsFor(tc.lang)
		sort.Strings(got)
		want := append([]string(nil), tc.want...)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("extensionsFor(%q) = %v, want %v", tc.lang, got, want)
		}
	}
}
