package scanner

import (
	"errors"
	"strings"
	"testing"
)

func TestIsNoPackageSources(t *testing.T) {
	err := errors.New("exit status 128")
	stderr := "Scanning dir /tmp/foo\nNo package sources found, --help for usage information."
	if !isNoPackageSources(stderr, err) {
		t.Fatal("expected no package sources to be detected")
	}
	if isNoPackageSources("", nil) {
		t.Fatal("nil error should not match")
	}
	if isNoPackageSources("other error", err) {
		t.Fatal("unexpected match on unrelated stderr")
	}
}

func TestIsNoPackageSources_CaseInsensitive(t *testing.T) {
	err := errors.New("exit status 128")
	stderr := strings.ToUpper("no package sources found")
	if !isNoPackageSources(stderr, err) {
		t.Fatal("expected case-insensitive match")
	}
}
