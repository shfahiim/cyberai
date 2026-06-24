// Package scanner defines the Scanner interface, an availability detector,
// and the orchestrator that runs scanners in parallel and aggregates their
// findings.
//
// A Scanner is a thin wrapper around an external CLI tool (Semgrep, Gitleaks,
// Trivy) that:
//  1. Reports whether the tool is installed (Available).
//  2. Runs the tool against a target directory and returns raw bytes.
//  3. Hands the raw output to a Normalizer to convert it to []model.Finding.
//
// cyberai does not reimplement the scanners. It shells out, normalizes
// their output, and produces a unified report. This keeps the scanning
// itself deterministic, fast, and battle-tested.
package scanner

import (
	"context"

	"github.com/shfahiim/cyberai/internal/model"
)

// Scanner is the contract every scanner implements.
//
// Implementations should be safe for concurrent use (the orchestrator may
// run multiple scanners in parallel).
type Scanner interface {
	// Name returns a stable identifier, e.g. "semgrep".
	Name() string

	// Category returns the scanner's high-level role: "sast", "secrets",
	// "sca", "iac", "license", "docker", "cicd". Must be one of
	// model.Category*.
	Category() model.Category

	// Available reports whether the underlying binary is on $PATH and
	// reachable. The second return is a one-line version string for display.
	Available() (bool, string)

	// Run executes the scanner against target and returns the raw output
	// (typically JSON). The orchestrator passes this to a Normalizer.
	//
	// Run should respect ctx cancellation: if ctx is cancelled, Run must
	// abort the subprocess promptly.
	Run(ctx context.Context, target string) (raw []byte, err error)
}

// Normalizer converts a scanner's raw output to []model.Finding. Each
// scanner has its own Normalizer because output schemas differ; the
// Normalizer is what the orchestrator pairs with the Scanner.
type Normalizer interface {
	// Normalize parses raw and returns findings. Any finding with a fatal
	// parse error is returned along with a non-nil error; the orchestrator
	// treats this as a scanner failure (not "no findings").
	Normalize(raw []byte) ([]model.Finding, error)
}

// NormalizingScanner is the convenience interface combining Scanner +
// Normalizer. Most scanners are NormalizingScanners; the orchestrator only
// uses the Scan() method.
type NormalizingScanner interface {
	Scanner
	Normalizer
	// Scan is Run + Normalize in one call. Implementations may use this
	// to short-circuit (e.g. skip running the binary if Normalize on the
	// cached output is enough).
	Scan(ctx context.Context, target string) ([]model.Finding, error)
}
