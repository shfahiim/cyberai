// Package policy evaluates named gates against a slice of findings and
// produces violations. Gates are user-configurable in .cyberai.yaml under the
// `policies.gates` key.
//
// Expression mini-language (case-insensitive field names):
//
//	severity == critical
//	severity >= high          (uses Severity.Rank ordering)
//	is_in_kev == true
//	epss_score >= 0.5
//	category == secrets
//	priority == P0
//	severity in [critical, high]
//
// Multiple predicates joined with " AND " (all must match).
package policy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/shfahiim/cyberai/internal/model"
)

// Gate is a named policy that fails when FailOn expression matches any finding.
type Gate struct {
	Name   string
	FailOn string
}

// Context supplies optional finding metadata for policy expressions.
type Context struct {
	IsNew        func(model.Finding) bool
	IsSuppressed func(model.Finding) bool
}

// Violation records a gate that failed and the findings that triggered it.
type Violation struct {
	Gate     Gate
	Findings []model.Finding
}

// Evaluate runs each gate against findings and returns the gates that fired.
func Evaluate(gates []Gate, findings []model.Finding, ctx Context) []Violation {
	var violations []Violation
	for _, g := range gates {
		pred, err := parseExpression(g.FailOn)
		if err != nil {
			// Misconfigured gate: treat as non-matching (don't silently block).
			continue
		}
		var matched []model.Finding
		for _, f := range findings {
			if pred(f, ctx) {
				matched = append(matched, f)
			}
		}
		if len(matched) > 0 {
			violations = append(violations, Violation{Gate: g, Findings: matched})
		}
	}
	return violations
}

// FormatViolations renders violations as a human-readable string.
func FormatViolations(violations []Violation) string {
	if len(violations) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("Policy gate violations:\n")
	for _, v := range violations {
		fmt.Fprintf(&sb, "  [FAIL] %s  (fail_on: %q)  — %d finding(s)\n",
			v.Gate.Name, v.Gate.FailOn, len(v.Findings))
		for _, f := range v.Findings {
			loc := f.File
			if f.StartLine > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.StartLine)
			}
			fmt.Fprintf(&sb, "         • %s  %s  [%s]\n", f.ID, loc, f.Title)
		}
	}
	return sb.String()
}

// ─────────────────────────────── expression parser ──────────────────────────

// predicate is a function that returns true if a finding matches.
type predicate func(model.Finding, Context) bool

// parseExpression compiles an expression string into a predicate.
// Supports: simple comparisons and " AND " combinator.
func parseExpression(expr string) (predicate, error) {
	parts := splitAND(expr)
	preds := make([]predicate, 0, len(parts))
	for _, p := range parts {
		pred, err := parseSingle(strings.TrimSpace(p))
		if err != nil {
			return nil, err
		}
		preds = append(preds, pred)
	}
	return func(f model.Finding, ctx Context) bool {
		for _, p := range preds {
			if !p(f, ctx) {
				return false
			}
		}
		return true
	}, nil
}

// splitAND splits on " AND " (case-insensitive).
func splitAND(expr string) []string {
	upper := strings.ToUpper(expr)
	var parts []string
	for {
		idx := strings.Index(upper, " AND ")
		if idx < 0 {
			parts = append(parts, expr)
			break
		}
		parts = append(parts, expr[:idx])
		expr = expr[idx+5:]
		upper = upper[idx+5:]
	}
	return parts
}

// parseSingle compiles a single predicate clause.
// Supported forms:
//
//	field == value
//	field != value
//	field >= value
//	field <= value
//	field > value
//	field < value
//	field in [val1, val2, ...]
func parseSingle(clause string) (predicate, error) {
	clause = strings.TrimSpace(clause)

	// "in" syntax: field in [...]
	if inIdx := indexCaseInsensitive(clause, " in "); inIdx >= 0 {
		field := strings.ToLower(strings.TrimSpace(clause[:inIdx]))
		rest := strings.TrimSpace(clause[inIdx+4:])
		values, err := parseInList(rest)
		if err != nil {
			return nil, fmt.Errorf("policy: invalid 'in' list %q: %w", rest, err)
		}
		return buildInPredicate(field, values)
	}

	// Two-char operators first to avoid prefix collision with single-char.
	for _, op := range []string{"==", "!=", ">=", "<=", ">", "<"} {
		idx := strings.Index(clause, op)
		if idx < 0 {
			continue
		}
		field := strings.ToLower(strings.TrimSpace(clause[:idx]))
		value := strings.TrimSpace(clause[idx+len(op):])
		return buildCompPredicate(field, op, value)
	}

	return nil, fmt.Errorf("policy: cannot parse clause %q", clause)
}

func indexCaseInsensitive(s, sub string) int {
	return strings.Index(strings.ToLower(s), strings.ToLower(sub))
}

// parseInList parses "[val1, val2, ...]" → []string{"val1", "val2", ...}.
func parseInList(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return nil, fmt.Errorf("expected [...], got %q", s)
	}
	inner := s[1 : len(s)-1]
	parts := strings.Split(inner, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			out = append(out, strings.ToLower(v))
		}
	}
	return out, nil
}

// buildInPredicate returns a predicate that matches when the field value is in
// the given set.
func buildInPredicate(field string, values []string) (predicate, error) {
	set := make(map[string]bool, len(values))
	for _, v := range values {
		set[v] = true
	}
	getter, err := fieldGetter(field)
	if err != nil {
		return nil, err
	}
	return func(f model.Finding, ctx Context) bool {
		v := strings.ToLower(getter(f))
		return set[v]
	}, nil
}

// buildCompPredicate builds a comparison predicate.
func buildCompPredicate(field, op, value string) (predicate, error) {
	valueLower := strings.ToLower(value)

	// Numeric comparison fields.
	if field == "epss_score" || field == "cvss" {
		threshold, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return nil, fmt.Errorf("policy: %q must be numeric, got %q", field, value)
		}
		numGetter := func(f model.Finding) float64 {
			if field == "epss_score" {
				return f.EPSSScore
			}
			return f.CVSS
		}
		return func(f model.Finding, ctx Context) bool {
			_ = ctx
			v := numGetter(f)
			switch op {
			case "==":
				return v == threshold
			case "!=":
				return v != threshold
			case ">=":
				return v >= threshold
			case "<=":
				return v <= threshold
			case ">":
				return v > threshold
			case "<":
				return v < threshold
			}
			return false
		}, nil
	}

	// Severity comparison (uses Rank ordering).
	if field == "severity" {
		threshSev := model.Severity(valueLower)
		threshRank := threshSev.Rank()
		return func(f model.Finding, ctx Context) bool {
			_ = ctx
			switch op {
			case "==":
				return strings.ToLower(string(f.Severity)) == valueLower
			case "!=":
				return strings.ToLower(string(f.Severity)) != valueLower
			case ">=": // >= high means rank <= rank(high)
				return f.Severity.Rank() <= threshRank
			case "<=":
				return f.Severity.Rank() >= threshRank
			case ">":
				return f.Severity.Rank() < threshRank
			case "<":
				return f.Severity.Rank() > threshRank
			}
			return false
		}, nil
	}

	// Boolean fields.
	if field == "is_in_kev" || field == "fix_available" || field == "suppressed" ||
		field == "is_new" || field == "verified" || field == "is_reachable" {
		wantTrue := valueLower == "true" || valueLower == "yes" || valueLower == "1"
		getter := func(f model.Finding, ctx Context) bool {
			switch field {
			case "is_in_kev":
				return f.IsInKEV
			case "fix_available":
				return f.FixAvailable
			case "suppressed":
				if ctx.IsSuppressed == nil {
					return false
				}
				return ctx.IsSuppressed(f)
			case "is_new":
				if ctx.IsNew == nil {
					return false
				}
				return ctx.IsNew(f)
			case "verified":
				return strings.EqualFold(f.Metadata["verified"], "true")
			case "is_reachable":
				return f.IsReachable != nil && *f.IsReachable
			}
			return false
		}
		return func(f model.Finding, ctx Context) bool {
			v := getter(f, ctx)
			switch op {
			case "==":
				return v == wantTrue
			case "!=":
				return v != wantTrue
			}
			return false
		}, nil
	}

	// String fields: category, priority, tool, rule_id, confidence.
	getter, err := fieldGetter(field)
	if err != nil {
		return nil, err
	}
	return func(f model.Finding, ctx Context) bool {
		_ = ctx
		v := strings.ToLower(getter(f))
		switch op {
		case "==":
			return v == valueLower
		case "!=":
			return v != valueLower
		}
		return false
	}, nil
}

// fieldGetter returns a function that extracts the named string field from a Finding.
func fieldGetter(field string) (func(model.Finding) string, error) {
	switch field {
	case "category":
		return func(f model.Finding) string { return string(f.Category) }, nil
	case "priority":
		return func(f model.Finding) string { return f.EffectivePriority() }, nil
	case "tool":
		return func(f model.Finding) string { return f.Tool }, nil
	case "rule_id":
		return func(f model.Finding) string { return f.RuleID }, nil
	case "confidence":
		return func(f model.Finding) string { return f.Confidence }, nil
	case "severity":
		return func(f model.Finding) string { return string(f.Severity) }, nil
	default:
		return nil, fmt.Errorf("policy: unknown field %q", field)
	}
}
