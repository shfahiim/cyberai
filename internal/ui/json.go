package ui

import (
	"bytes"
	"encoding/json"
)

// MaybePretty pretty-prints JSON bytes if useColor is true (a proxy for
// "human is reading this on a terminal"). When false, returns b unchanged
// so piped/redirected JSON is compact and parseable line-by-line.
//
// Callers: prefer this over json.Indent in any user-facing JSON output path.
// Do NOT use for file-based reporters (SARIF/JSON/Markdown) — those must
// stay byte-for-byte identical to the existing emitters.
func MaybePretty(b []byte, useColor bool) []byte {
	if !useColor {
		return b
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, b, "", "  "); err != nil {
		// If we can't indent (malformed JSON, somehow), return input.
		return b
	}
	buf.WriteByte('\n')
	return buf.Bytes()
}
