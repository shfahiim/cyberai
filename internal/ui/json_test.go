package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestMaybePretty_OnColor(t *testing.T) {
	// Compact JSON in ⇒ pretty JSON out.
	in := []byte(`{"a":1,"b":[1,2,3]}`)
	out := MaybePretty(in, true)
	if !bytes.Contains(out, []byte("\n")) {
		t.Errorf("pretty output should contain newlines, got %q", out)
	}
	if !bytes.Contains(out, []byte("  \"a\"")) {
		t.Errorf("pretty output should have 2-space indent, got %q", out)
	}
	if !bytes.Equal(out, append(bytes.TrimSpace(out), '\n')) {
		t.Errorf("pretty output should end with exactly one trailing newline, got %q", out)
	}
}

func TestMaybePretty_OffColor_ReturnsInput(t *testing.T) {
	in := []byte(`{"a":1}`)
	out := MaybePretty(in, false)
	if !bytes.Equal(in, out) {
		t.Errorf("non-color mode should return input unchanged; got %q want %q", out, in)
	}
}

func TestMaybePretty_MalformedJSON_ReturnInput(t *testing.T) {
	in := []byte(`not json`)
	out := MaybePretty(in, true)
	if !bytes.Equal(in, out) {
		t.Errorf("malformed JSON should return input unchanged; got %q", out)
	}
}

func TestMaybePretty_PreservesContent(t *testing.T) {
	in := []byte(`{"x":"y","z":[true,false,null]}`)
	out := MaybePretty(in, true)
	// Sanity: no keys or values are lost.
	for _, s := range []string{`"x"`, `"y"`, `"z"`, `true`, `false`, `null`} {
		if !strings.Contains(string(out), s) {
			t.Errorf("pretty output lost %q; got %q", s, out)
		}
	}
}
