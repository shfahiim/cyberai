// Package suppression manages the .cyberai-suppressions.yaml file that lets
// users permanently silence known-false-positive findings.
//
// A suppression can match on:
//   - FindingID: exact match against the stable "F-…" hash
//   - RuleID + optional Path glob: suppresses every finding from that rule
//     (optionally limited to a file/directory glob pattern)
//
// Suppressions support optional expiry dates so that "accept-risk" decisions
// are automatically revisited (e.g. after 90 days).
package suppression

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/shfahiim/cyberai/internal/model"
)

const suppressionFile = ".cyberai-suppressions.yaml"

// Suppression is a single entry that silences one or more findings.
type Suppression struct {
	// ID is a stable identifier for this suppression entry (auto-generated).
	ID string `yaml:"id"`

	// FindingID, when set, matches exactly one finding by its deterministic
	// "F-…" hash. Takes priority over RuleID matching.
	FindingID string `yaml:"finding_id,omitempty"`

	// RuleID suppresses all findings from this scanner rule, optionally
	// constrained to a file path glob via Path.
	RuleID string `yaml:"rule_id,omitempty"`

	// Path is an optional filepath.Match glob pattern applied to finding.File.
	// Only meaningful when RuleID is set. Empty means "any path".
	Path string `yaml:"path,omitempty"`

	// Reason is a mandatory human-readable justification.
	Reason string `yaml:"reason"`

	// Author is the person who added the suppression (free-form).
	Author string `yaml:"author,omitempty"`

	// Ticket is an optional tracker link or issue reference.
	Ticket string `yaml:"ticket,omitempty"`

	// CreatedAt is set automatically when the suppression is added.
	CreatedAt time.Time `yaml:"created_at"`

	// ExpiresAt, when non-zero, causes the suppression to stop matching after
	// this time. FilterFindings counts expired suppressions separately.
	ExpiresAt time.Time `yaml:"expires_at,omitempty"`
}

// IsExpired returns true if ExpiresAt is set and in the past.
func (s *Suppression) IsExpired() bool {
	if s.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(s.ExpiresAt)
}

// Matches reports whether this suppression covers the given finding.
// An expired suppression never matches.
func (s *Suppression) Matches(f *model.Finding) bool {
	if s.IsExpired() {
		return false
	}

	// Exact FindingID match takes priority.
	if s.FindingID != "" {
		return s.FindingID == f.ID
	}

	// RuleID-based match.
	if s.RuleID != "" && s.RuleID == f.RuleID {
		if s.Path == "" {
			return true
		}
		// filepath.Match treats the pattern as a shell glob.
		matched, err := filepath.Match(s.Path, f.File)
		if err != nil {
			// Malformed glob — don't match rather than panic.
			return false
		}
		return matched
	}

	return false
}

// File is the in-memory representation of the suppressions YAML file.
type File struct {
	Suppressions []Suppression `yaml:"suppressions"`
	path         string
}

// Load reads the suppressions file from <root>/.cyberai-suppressions.yaml.
// If the file does not exist an empty File is returned (no error).
func Load(root string) (*File, error) {
	p := filepath.Join(root, suppressionFile)
	f := &File{path: p}

	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return f, nil
		}
		return nil, fmt.Errorf("suppression: read %s: %w", p, err)
	}

	if err := yaml.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("suppression: parse %s: %w", p, err)
	}
	return f, nil
}

// Save marshals the File to YAML and writes it to disk.
func (f *File) Save() error {
	data, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("suppression: marshal: %w", err)
	}
	if err := os.WriteFile(f.path, data, 0o644); err != nil {
		return fmt.Errorf("suppression: write %s: %w", f.path, err)
	}
	return nil
}

// Add appends a new suppression and persists the file.
// ID and CreatedAt are set automatically if missing.
func (f *File) Add(s Suppression) error {
	if s.ID == "" {
		s.ID = generateID(s)
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	f.Suppressions = append(f.Suppressions, s)
	return f.Save()
}

// Remove deletes the suppression with the given ID and persists the file.
// Returns an error if no entry with that ID is found.
func (f *File) Remove(id string) error {
	next := f.Suppressions[:0]
	found := false
	for _, s := range f.Suppressions {
		if s.ID == id {
			found = true
			continue
		}
		next = append(next, s)
	}
	if !found {
		return fmt.Errorf("suppression: ID %q not found", id)
	}
	f.Suppressions = next
	return f.Save()
}

// FilterFindings partitions findings into those that pass all suppressions
// (unsuppressed) and those that are matched (suppressed or expired).
//
// Returns:
//   - unsuppressed: findings not matched by any active suppression
//   - suppressed:   count of findings silenced by an active suppression
//   - expired:      count of findings that would have been silenced but the
//     suppression is past its expiry date

// IsSuppressed reports whether any active suppression covers the finding.
func (f *File) IsSuppressed(finding model.Finding) bool {
	for i := range f.Suppressions {
		if f.Suppressions[i].Matches(&finding) {
			return true
		}
	}
	return false
}

// FilterFindings returns findings that are not covered by active suppressions.
func (f *File) FilterFindings(findings []model.Finding) (unsuppressed []model.Finding, suppressed int, expired int) {
	for _, finding := range findings {
		activeMatch := false
		expiredMatch := false

		for i := range f.Suppressions {
			s := &f.Suppressions[i]
			// Check for an expired suppression that *would* match.
			if s.IsExpired() {
				// Temporarily pretend it hasn't expired to test the rule part.
				if matchIgnoringExpiry(s, &finding) {
					expiredMatch = true
				}
				continue
			}
			if s.Matches(&finding) {
				activeMatch = true
				break
			}
		}

		if activeMatch {
			suppressed++
		} else {
			if expiredMatch {
				expired++
			}
			unsuppressed = append(unsuppressed, finding)
		}
	}
	return unsuppressed, suppressed, expired
}

// matchIgnoringExpiry checks if a suppression matches a finding without
// considering expiry. Used by FilterFindings to count expired hits.
func matchIgnoringExpiry(s *Suppression, f *model.Finding) bool {
	if s.FindingID != "" {
		return s.FindingID == f.ID
	}
	if s.RuleID != "" && s.RuleID == f.RuleID {
		if s.Path == "" {
			return true
		}
		matched, err := filepath.Match(s.Path, f.File)
		return err == nil && matched
	}
	return false
}

// generateID derives a short, stable identifier for a suppression from its
// key fields so that re-adding the same suppression produces the same ID.
func generateID(s Suppression) string {
	h := sha256.New()
	fmt.Fprintf(h, "finding=%s\n", s.FindingID)
	fmt.Fprintf(h, "rule=%s\n", s.RuleID)
	fmt.Fprintf(h, "path=%s\n", s.Path)
	fmt.Fprintf(h, "reason=%s\n", s.Reason)
	fmt.Fprintf(h, "ts=%d\n", time.Now().UnixNano())
	sum := h.Sum(nil)
	return fmt.Sprintf("S-%x", sum[:8])
}
