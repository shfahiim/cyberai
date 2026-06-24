// JUnit reporter — emits an XML file compatible with JUnit / Surefire tooling.
//
// Findings are grouped into <testsuite> elements by category, where each
// finding becomes a <testcase> with a <failure> child. This lets CI systems
// (Jenkins, GitLab, GitHub Actions) render findings as test failures in their
// test result panels.
package reporter

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/shfahiim/cyberai/internal/model"
)

// junitTestSuites is the root element.
type junitTestSuites struct {
	XMLName  xml.Name        `xml:"testsuites"`
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Time     string          `xml:"time,attr"`
	Suites   []junitSuite    `xml:"testsuite"`
}

type junitSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Time      string          `xml:"time,attr"`
	Timestamp string          `xml:"timestamp,attr"`
	Cases     []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	XMLName   xml.Name       `xml:"testcase"`
	Classname string         `xml:"classname,attr"`
	Name      string         `xml:"name,attr"`
	Time      string         `xml:"time,attr"`
	Failure   *junitFailure  `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

// JUnit produces a JUnit-compatible XML report where each finding is a test
// failure, grouped by scanner category into separate <testsuite> elements.
func JUnit(rep *Report) ([]byte, error) {
	// Group findings by category.
	grouped := map[model.Category][]model.Finding{}
	for _, f := range rep.Findings {
		grouped[f.Category] = append(grouped[f.Category], f)
	}

	totalTests := 0
	totalFail := 0
	durationSec := fmt.Sprintf("%.3f", rep.Duration.Seconds())
	ts := rep.GeneratedAt.UTC().Format(time.RFC3339)

	var suites []junitSuite
	for _, cat := range orderedCategories(grouped) {
		findings := grouped[cat]
		cases := make([]junitTestCase, 0, len(findings))
		for _, f := range findings {
			msg := fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Severity)), f.Title)
			content := buildJUnitContent(f)
			cases = append(cases, junitTestCase{
				Classname: string(cat),
				Name:      fmt.Sprintf("%s @ %s:%d", f.RuleID, f.File, f.StartLine),
				Time:      "0.000",
				Failure: &junitFailure{
					Message: msg,
					Type:    string(f.Severity),
					Content: content,
				},
			})
		}
		suites = append(suites, junitSuite{
			Name:      string(cat),
			Tests:     len(cases),
			Failures:  len(cases),
			Time:      durationSec,
			Timestamp: ts,
			Cases:     cases,
		})
		totalTests += len(cases)
		totalFail += len(cases)
	}

	root := junitTestSuites{
		Name:     "cyberai: " + rep.Target,
		Tests:    totalTests,
		Failures: totalFail,
		Time:     durationSec,
		Suites:   suites,
	}

	out, err := xml.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("junit marshal: %w", err)
	}
	return append([]byte(xml.Header), out...), nil
}

func buildJUnitContent(f model.Finding) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "ID:       %s\n", f.ID)
	fmt.Fprintf(&sb, "Tool:     %s\n", f.Tool)
	fmt.Fprintf(&sb, "Severity: %s\n", f.Severity)
	fmt.Fprintf(&sb, "Priority: %s\n", f.Priority)
	fmt.Fprintf(&sb, "File:     %s\n", f.File)
	fmt.Fprintf(&sb, "Line:     %d\n", f.StartLine)
	if len(f.CVE) > 0 {
		fmt.Fprintf(&sb, "CVE:      %s\n", strings.Join(f.CVE, ", "))
	}
	if len(f.CWE) > 0 {
		fmt.Fprintf(&sb, "CWE:      %s\n", strings.Join(f.CWE, ", "))
	}
	if f.CVSS > 0 {
		fmt.Fprintf(&sb, "CVSS:     %.1f\n", f.CVSS)
	}
	if f.EPSSScore > 0 {
		fmt.Fprintf(&sb, "EPSS:     %.4f\n", f.EPSSScore)
	}
	if f.IsInKEV {
		fmt.Fprintf(&sb, "KEV:      true\n")
	}
	if f.Description != "" {
		fmt.Fprintf(&sb, "\n%s\n", f.Description)
	}
	return sb.String()
}

// orderedCategories returns the categories in a stable order for deterministic output.
func orderedCategories(grouped map[model.Category][]model.Finding) []model.Category {
	order := []model.Category{
		model.CategorySAST, model.CategorySecrets, model.CategorySCA,
		model.CategoryIaC, model.CategoryDocker, model.CategoryCICD,
		model.CategoryLicense, model.CategorySBOM, model.CategoryDAST,
	}
	var out []model.Category
	seen := map[model.Category]bool{}
	for _, cat := range order {
		if _, ok := grouped[cat]; ok {
			out = append(out, cat)
			seen[cat] = true
		}
	}
	// Any unlisted categories go at the end.
	for cat := range grouped {
		if !seen[cat] {
			out = append(out, cat)
		}
	}
	return out
}
