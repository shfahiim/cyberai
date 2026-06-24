package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestSbom_MissingSyft_Errors(t *testing.T) {
	// Set paths to empty temp dirs to ensure no system tools interfere.
	t.Setenv("CYBERAI_BIN_DIR", t.TempDir())
	t.Setenv("CYBERAI_STATE_DIR", t.TempDir())
	t.Setenv("PATH", "") // clear path so syft won't be found

	buf := &bytes.Buffer{}
	cmd := NewRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"sbom", "."})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error since syft is missing")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "syft is not installed but required to generate SBOMs") {
		t.Errorf("unexpected error message: %s", errMsg)
	}
}

func TestSbom_UnsupportedFormat_Errors(t *testing.T) {
	t.Setenv("CYBERAI_BIN_DIR", t.TempDir())
	t.Setenv("CYBERAI_STATE_DIR", t.TempDir())

	buf := &bytes.Buffer{}
	cmd := NewRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"sbom", ".", "--format", "bogus"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "unsupported format") {
		t.Errorf("unexpected error message: %s", errMsg)
	}
}
