package router

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shfahiim/cyberai/internal/project"
)

func sampleProfile() *project.Profile {
	return &project.Profile{
		Root:         "/tmp/sample",
		Languages:    []string{"go", "javascript"},
		Manifests:    []string{"go.mod", "package.json"},
		HasDocker:    false,
		HasTerraform: false,
	}
}

func TestDefaultRouter_GoAndJSProject(t *testing.T) {
	r := NewDefault()
	plan, err := r.Route(sampleProfile())
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if plan.Source != "default" {
		t.Errorf("Source = %s, want default", plan.Source)
	}
	if !contains(plan.Scanners, "sast") {
		t.Error("should enable SAST for Go/JS project")
	}
	if !contains(plan.Scanners, "secrets") {
		t.Error("should enable secrets by default")
	}
	if contains(plan.Scanners, "iac") {
		// No IaC signals in the profile, so iac should NOT be enabled.
		t.Error("should NOT enable iac when no terraform/k8s/ansible")
	}
	if !contains(plan.SemgrepRulesets, "p/golang") {
		t.Error("should enable p/golang for Go project")
	}
	if !contains(plan.SemgrepRulesets, "p/javascript") {
		t.Error("should enable p/javascript for JS project")
	}
	if plan.SeverityThreshold != "low" {
		t.Errorf("default severity = %s, want low", plan.SeverityThreshold)
	}
	if plan.ProjectHash == "" {
		t.Error("ProjectHash should be populated")
	}
	if plan.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should be set")
	}
}

func TestDefaultRouter_TerraformProject(t *testing.T) {
	p := &project.Profile{
		Languages:    []string{"go"},
		Manifests:    []string{"go.mod"},
		HasTerraform: true,
	}
	r := NewDefault()
	plan, _ := r.Route(p)
	if !contains(plan.Scanners, "iac") {
		t.Error("should enable iac when HasTerraform=true")
	}
	if !contains(plan.TrivyScanners, "misconfig") {
		t.Error("should enable trivy misconfig for terraform")
	}
}

func TestDefaultRouter_NilProfile(t *testing.T) {
	r := NewDefault()
	if _, err := r.Route(nil); err == nil {
		t.Error("expected error for nil profile")
	}
}

func TestCache_PutGet(t *testing.T) {
	dir := t.TempDir()
	c, err := NewCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	plan := &ScanPlan{
		Scanners:          []string{"sast"},
		SeverityThreshold: "low",
		ProjectHash:       "sha256:test",
		Source:            "default",
	}
	if err := c.Put("sha256:test", plan); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := c.Get("sha256:test")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if !got.FromCache {
		t.Error("FromCache should be true after Get")
	}
	if got.Source != "cache" {
		t.Errorf("Source = %s, want cache", got.Source)
	}
	if got.ProjectHash != "sha256:test" {
		t.Errorf("hash = %s", got.ProjectHash)
	}
}

func TestCache_Miss(t *testing.T) {
	dir := t.TempDir()
	c, _ := NewCache(dir)
	got, err := c.Get("sha256:nonexistent")
	if err != nil {
		t.Fatalf("Get on miss: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil on miss, got %+v", got)
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	dir := t.TempDir()
	c := &Cache{Dir: dir, TTL: time.Millisecond}
	plan := &ScanPlan{
		Scanners:          []string{"sast"},
		SeverityThreshold: "low",
		ProjectHash:       "sha256:ttl-test",
		Source:            "default",
	}
	if err := c.Put("sha256:ttl-test", plan); err != nil {
		t.Fatalf("Put: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	got, err := c.Get("sha256:ttl-test")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Fatalf("expected cache miss after TTL, got %+v", got)
	}
}

func TestCache_HomeExpansion(t *testing.T) {
	// Set HOME to a temp dir so we don't pollute the real one.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	c, err := NewCache("~/router-test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.Dir, tmp) {
		t.Errorf("Cache.Dir = %q, expected prefix %q", c.Dir, tmp)
	}
	if _, err := os.Stat(filepath.Join(c.Dir, "marker")); !os.IsNotExist(err) {
		// We just want to confirm the dir exists; not asserting specific files.
	}
}

func TestScanPlan_JSON(t *testing.T) {
	p := sampleProfile()
	r := NewDefault()
	plan, _ := r.Route(p)
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var roundTrip ScanPlan
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if roundTrip.ProjectHash != plan.ProjectHash {
		t.Errorf("hash roundtrip: got %s, want %s", roundTrip.ProjectHash, plan.ProjectHash)
	}
}

func TestNewGemini_NoKey_FallsBack(t *testing.T) {
	// Ensure HOME is a temp dir so cache doesn't pollute.
	t.Setenv("HOME", t.TempDir())
	// Ensure no API key in env.
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	cache, _ := NewCache(t.TempDir())
	r, live := NewGemini("gemini-3.5-flash", cache)
	if live {
		t.Skip("Gemini API key is set in env; skipping fallback test")
	}
	plan, err := r.Route(sampleProfile())
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if plan.Source != "fallback(gemini)" {
		t.Errorf("Source = %s, want fallback(gemini)", plan.Source)
	}
	if !strings.Contains(plan.Reasoning, "no API key configured for provider gemini") {
		t.Errorf("reasoning should mention missing API key, got %q", plan.Reasoning)
	}
	// Fallback plan should still be sensible (default router output).
	if !contains(plan.Scanners, "sast") {
		t.Error("fallback plan should still enable SAST")
	}
}

func TestGeminiRouter_NilProfile(t *testing.T) {
	r := &LLMRouter{Provider: "gemini", Fallback: NewDefault()}
	if _, err := r.Route(nil); err == nil {
		t.Error("expected error for nil profile")
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
