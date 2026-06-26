package tools

import (
	"strings"
	"testing"
)

func TestProbe_KnownBinary(t *testing.T) {
	// `go` is virtually guaranteed on any Go dev machine, and `true` is in coreutils.
	st := Probe("true")
	if !st.Installed {
		t.Skip("`true` not on $PATH (unusual); skipping")
	}
	if st.VersionLine() == "" {
		t.Errorf("VersionLine empty for installed tool")
	}
}

func TestProbe_MissingBinary(t *testing.T) {
	st := Probe("definitely-not-a-real-binary-zzz-12345")
	if st.Installed {
		t.Errorf("expected Installed=false, got %+v", st)
	}
}

func TestIsSemverish(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1.45.0", true},
		{"v1.45.0", false}, // we strip the 'v' first in VersionLine
		{"1.2", true},
		{"abc", false},
		{"1.2.", false},
		{"", false},
		{"1", false},
	}
	for _, tc := range cases {
		if got := isSemverish(tc.in); got != tc.want {
			t.Errorf("isSemverish(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestIsManagedInstall(t *testing.T) {
	for _, name := range []string{"grype", "osv-scanner", "govulncheck", "trivy", "actionlint", "syft"} {
		if !IsManagedInstall(name) {
			t.Errorf("expected %q to be managed", name)
		}
	}
	if IsManagedInstall("unknown-tool") {
		t.Error("unknown-tool should not be managed")
	}
}

func TestAll_HasExpectedTools(t *testing.T) {
	got := map[string]bool{}
	for _, tool := range All() {
		got[tool.Name] = true
	}
	for _, want := range []string{"semgrep", "gitleaks", "trivy"} {
		if !got[want] {
			t.Errorf("missing tool %q in All()", want)
		}
	}
}

func TestProbeAll_ReturnsAll(t *testing.T) {
	res := ProbeAll()
	for _, tool := range All() {
		if _, ok := res[tool.Name]; !ok {
			t.Errorf("ProbeAll missing %q", tool.Name)
		}
	}
}

func TestStatus_String(t *testing.T) {
	if got := (Status{Installed: false}).String("semgrep"); !strings.Contains(got, "missing") {
		t.Errorf("missing status = %q", got)
	}
	if got := (Status{Installed: true, Version: "1.2.3"}).String("semgrep"); !strings.Contains(got, "installed") {
		t.Errorf("installed status = %q", got)
	}
}
