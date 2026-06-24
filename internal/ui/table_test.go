package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderTable_Basic(t *testing.T) {
	var buf bytes.Buffer
	RenderTable(&buf,
		[]string{"TOOL", "STATUS", "VERSION"},
		[][]string{
			{"semgrep", "bundled", "1.0.0"},
			{"gitleaks", "system", "8.18.0"},
			{"trivy", "missing", "-"},
		})

	out := buf.String()
	// All headers must appear (test invariant from tools_test.go).
	for _, want := range []string{"TOOL", "STATUS", "VERSION", "semgrep", "gitleaks", "trivy"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s\n---", want, out)
		}
	}
}

func TestRenderTable_NoHeader(t *testing.T) {
	var buf bytes.Buffer
	RenderTable(&buf,
		[]string{"HIDDEN"},
		[][]string{{"a", "b", "c"}},
		TableOptions{NoHeader: true})

	out := buf.String()
	if strings.Contains(out, "HIDDEN") {
		t.Errorf("NoHeader=true should suppress header row, got %q", out)
	}
	if !strings.Contains(out, "a") {
		t.Errorf("rows should still appear, got %q", out)
	}
}

func TestRenderTable_CellTextVerbatim(t *testing.T) {
	// Critical: cells must not be wrapped in ANSI codes. This protects the
	// existing tools_test.go substring assertions.
	var buf bytes.Buffer
	RenderTable(&buf,
		[]string{"A", "B"},
		[][]string{{"hello", "world"}})

	out := buf.String()
	if strings.Contains(out, "\033[") {
		t.Errorf("table cells should not contain ANSI, got %q", out)
	}
}

func TestRenderTable_DefaultWriterIsStdout(t *testing.T) {
	// We can't easily redirect stdout in tests, but we can verify the call
	// doesn't panic with a nil writer.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("RenderTable(nil, ...) should fall back to stdout, got panic: %v", r)
		}
	}()
	var buf bytes.Buffer
	_ = buf // unused
	RenderTable(nil, []string{"X"}, [][]string{{"y"}})
}

func TestRenderTable_PerColumnAlign(t *testing.T) {
	var buf bytes.Buffer
	RenderTable(&buf,
		[]string{"L", "R"},
		[][]string{{"aaa", "1"}, {"bbb", "22"}},
		TableOptions{
			ColumnAligns: []TableColumnAlign{AlignLeft, AlignRight},
		})

	out := buf.String()
	if !strings.Contains(out, "L") || !strings.Contains(out, "R") {
		t.Errorf("headers should appear, got %q", out)
	}
	if !strings.Contains(out, "aaa") || !strings.Contains(out, "22") {
		t.Errorf("rows should appear, got %q", out)
	}
}
