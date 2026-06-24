// CSV reporter — emits a flat comma-separated file of findings.
//
// This format is optimized for import into spreadsheets, SIEM dashboards, and
// ad-hoc data analysis. All enrichment fields (EPSS, KEV, priority, compliance
// tags) are included so the exported data is self-contained.
package reporter

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
)

// csvHeaders is the canonical column order for the CSV report.
var csvHeaders = []string{
	"id",
	"severity",
	"priority",
	"category",
	"tool",
	"rule_id",
	"title",
	"file",
	"line",
	"cve",
	"cwe",
	"cvss",
	"epss_score",
	"is_in_kev",
	"fix_version",
	"compliance_tags",
}

// CSV produces a UTF-8 CSV file with one row per finding.
// Columns: id, severity, priority, category, tool, rule_id, title, file,
// line, cve, cwe, cvss, epss_score, is_in_kev, fix_version, compliance_tags.
func CSV(rep *Report) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	if err := w.Write(csvHeaders); err != nil {
		return nil, fmt.Errorf("csv header: %w", err)
	}

	for _, f := range rep.Findings {
		row := []string{
			f.ID,
			string(f.Severity),
			f.Priority,
			string(f.Category),
			f.Tool,
			f.RuleID,
			f.Title,
			f.File,
			strconv.Itoa(f.StartLine),
			strings.Join(f.CVE, ";"),
			strings.Join(f.CWE, ";"),
			formatFloat(f.CVSS),
			formatFloat(f.EPSSScore),
			strconv.FormatBool(f.IsInKEV),
			f.FixVersion,
			strings.Join(f.ComplianceTags, ";"),
		}
		if err := w.Write(row); err != nil {
			return nil, fmt.Errorf("csv row: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("csv flush: %w", err)
	}
	return buf.Bytes(), nil
}

func formatFloat(v float64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}
