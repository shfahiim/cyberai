package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestPlainProgress_PerLine(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(ProgressOptions{Spinner: false, Writer: &buf})

	p.Start("semgrep")
	p.Finish("semgrep", "done — 3 findings")
	p.Stop()

	out := buf.String()
	// Must be two lines, plain text, no spinner, no \r.
	if !strings.Contains(out, "semgrep: running") {
		t.Errorf("expected 'semgrep: running' line, got %q", out)
	}
	if !strings.Contains(out, "semgrep: done") {
		t.Errorf("expected 'semgrep: done' line, got %q", out)
	}
	if strings.Contains(out, "\r") {
		t.Errorf("plain progress should not emit \\r, got %q", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("plain progress should end with newline, got %q", out)
	}
}

func TestPlainProgress_UpdateIgnored(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(ProgressOptions{Spinner: false, Writer: &buf})

	p.Start("a")
	p.Update("a", "intermediate status")
	p.Finish("a", "done")
	p.Stop()

	out := buf.String()
	// Update() in plain mode is a no-op — only Start and Finish print.
	if strings.Contains(out, "intermediate status") {
		t.Errorf("plain Update should be no-op, got %q", out)
	}
	if strings.Count(out, "\n") != 2 {
		t.Errorf("plain should have 2 lines (Start + Finish), got %d in %q",
			strings.Count(out, "\n"), out)
	}
}

func TestSpinnerProgress_DoesNotPanicOnPipeWriter(t *testing.T) {
	// When the writer isn't a TTY, the spinner still works — its output is
	// just text. We just want to ensure Start/Stop don't deadlock.
	var buf bytes.Buffer
	p := NewProgress(ProgressOptions{Spinner: true, Writer: &buf, Unicode: true})

	done := make(chan struct{})
	go func() {
		p.Start("semgrep")
		time.Sleep(50 * time.Millisecond)
		p.Finish("semgrep", "done — 3 findings")
		p.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("spinner Stop() did not return within 2s")
	}
}

func TestSpinnerProgress_AllUnitsFinish_StopsSpinner(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(ProgressOptions{Spinner: true, Writer: &buf, Unicode: true})

	p.Start("a")
	p.Start("b")
	p.Finish("a", "done")
	p.Finish("b", "error: oops")
	p.Stop()

	out := buf.String()
	// Final block should reference both names. Note: when the writer is not
	// a TTY, the spinner's Start() is a no-op, so the PreUpdate hook never
	// fires; but Stop()/Finish() always emit the final state, so the test
	// still sees the names.
	if !strings.Contains(out, "a") {
		t.Errorf("expected 'a' in output, got %q", out)
	}
	if !strings.Contains(out, "b") {
		t.Errorf("expected 'b' in output, got %q", out)
	}
	if !strings.Contains(out, "done") {
		t.Errorf("expected 'done' status, got %q", out)
	}
	if !strings.Contains(out, "error") {
		t.Errorf("expected 'error' status, got %q", out)
	}
}

func TestSpinnerProgress_StopWritesFinalStateOnNonTTY(t *testing.T) {
	// Even when the spinner was never active (non-TTY writer), Stop must
	// still emit the final state block.
	var buf bytes.Buffer
	p := NewProgress(ProgressOptions{Spinner: true, Writer: &buf, Unicode: true})

	p.Start("x")
	p.Update("x", "running")
	p.Finish("x", "done — 7 findings")
	p.Stop()

	out := buf.String()
	if !strings.Contains(out, "x") {
		t.Errorf("expected name 'x' in final state, got %q", out)
	}
	if !strings.Contains(out, "done") {
		t.Errorf("expected final status, got %q", out)
	}
}

func TestLiveProgress_RendersAnimationAndFixedFinishedLines(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(ProgressOptions{Spinner: true, Writer: &buf, Unicode: true})

	p.Start("gitleaks")
	p.Finish("gitleaks", "done — 3 findings")
	p.Start("semgrep")
	p.Finish("semgrep", "done — 1 findings")
	p.Stop()

	out := buf.String()
	if !strings.Contains(out, "CyberAI") {
		t.Fatalf("expected CyberAI animation line in output, got %q", out)
	}
	if !strings.Contains(out, "gitleaks") || !strings.Contains(out, "semgrep") {
		t.Fatalf("expected fixed scanner lines in output, got %q", out)
	}
	if strings.Count(out, "done") < 2 {
		t.Fatalf("expected both scanners to finish, got %q", out)
	}
}

func TestClassifyStatus_UnicodeAndAscii(t *testing.T) {
	cases := []struct {
		status    string
		unicode   bool
		wantGlyph string
	}{
		{"done — 3 findings", true, "\u2713"},
		{"done — 3 findings", false, "ok"},
		{"error: oops", true, "\u2717"},
		{"error: oops", false, "FAIL"},
		{"skipped", true, "\u00b7"},
		{"skipped", false, "skip"},
		{"running", true, "\u25d0"},
		{"running", false, "..."},
	}
	for _, c := range cases {
		got, _ := classifyStatus(c.status, c.unicode)
		if got != c.wantGlyph {
			t.Errorf("classifyStatus(%q, unicode=%v) glyph = %q, want %q",
				c.status, c.unicode, got, c.wantGlyph)
		}
	}
}
