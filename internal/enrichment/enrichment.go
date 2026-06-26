// Package enrichment fetches EPSS scores and CISA KEV (Known Exploited
// Vulnerabilities) data and applies them to findings. Results are cached on
// disk to avoid hammering the upstream APIs on every scan.
//
// EPSS cache: 24 hours  (<CacheDir>/epss.json)
// KEV  cache: 6  hours  (<CacheDir>/kev.json)
package enrichment

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shfahiim/cyberai/internal/model"
)

const (
	epssURL = "https://api.first.org/data/v1/epss?cve=%s"
	kevURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	epssCacheTTL = 24 * time.Hour
	kevCacheTTL  = 6 * time.Hour
)

// Client fetches and caches EPSS + KEV enrichment data.
type Client struct {
	CacheDir string
	http     *http.Client
}

// NewClient returns a Client whose cache lives in cacheDir.
// If cacheDir is empty, it defaults to ~/.cyberai/cache/enrichment.
func NewClient(cacheDir string) (*Client, error) {
	if cacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("enrichment: resolve home: %w", err)
		}
		cacheDir = filepath.Join(home, ".cyberai", "cache", "enrichment")
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("enrichment: create cache dir: %w", err)
	}
	return &Client{
		CacheDir: cacheDir,
		http:     &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Enrich fetches EPSS and KEV data for the CVEs present in findings,
// enriches each finding in-place, sets ComplianceTags and Priority, and
// returns the enriched slice.
func (c *Client) Enrich(findings []model.Finding) []model.Finding {
	// Collect unique CVEs.
	cveSet := map[string]bool{}
	for _, f := range findings {
		for _, cve := range f.CVE {
			cveSet[cve] = true
		}
	}

	epssMap := c.fetchEPSS(keys(cveSet))
	kevSet := c.fetchKEV()

	out := make([]model.Finding, len(findings))
	for i, f := range findings {
		// EPSS & KEV
		for _, cve := range f.CVE {
			if e, ok := epssMap[cve]; ok {
				if e.score > f.EPSSScore {
					f.EPSSScore = e.score
					f.EPSSPercentile = e.percentile
				}
			}
			if kevSet[cve] {
				f.IsInKEV = true
			}
		}
		if f.FixVersion != "" {
			f.FixAvailable = true
		}
		f.ComplianceTags = buildComplianceTags(&f)
		f.Priority = f.ComputePriority()
		out[i] = f
	}
	return out
}

// TagCompliance sets ComplianceTags from CWE mappings without network calls.
func TagCompliance(findings []model.Finding) []model.Finding {
	for i := range findings {
		if len(findings[i].ComplianceTags) == 0 {
			findings[i].ComplianceTags = buildComplianceTags(&findings[i])
		}
	}
	return findings
}

// ─────────────────────────────────────── EPSS ───────────────────────────────

type epssEntry struct {
	score      float64
	percentile float64
}

// epssResponse is the JSON shape returned by api.first.org.
type epssResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

func (c *Client) fetchEPSS(cves []string) map[string]epssEntry {
	result := map[string]epssEntry{}
	if len(cves) == 0 {
		return result
	}

	cachePath := filepath.Join(c.CacheDir, "epss.json")
	type cacheFile struct {
		FetchedAt time.Time            `json:"fetched_at"`
		Data      map[string]epssEntry `json:"-"` // marshalled separately
		Raw       epssResponse         `json:"raw"`
	}

	// Try cache first.
	if data, err := os.ReadFile(cachePath); err == nil {
		var cf struct {
			FetchedAt time.Time    `json:"fetched_at"`
			Raw       epssResponse `json:"raw"`
		}
		if json.Unmarshal(data, &cf) == nil && time.Since(cf.FetchedAt) < epssCacheTTL {
			return parseEPSSResponse(&cf.Raw)
		}
	}

	// Fetch fresh.
	url := fmt.Sprintf(epssURL, strings.Join(cves, ","))
	resp, err := c.http.Get(url) //nolint:noctx
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	var parsed epssResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return result
	}

	// Persist to cache.
	type cacheShape struct {
		FetchedAt time.Time    `json:"fetched_at"`
		Raw       epssResponse `json:"raw"`
	}
	if raw, err := json.Marshal(cacheShape{FetchedAt: time.Now(), Raw: parsed}); err == nil {
		_ = os.WriteFile(cachePath, raw, 0o644)
	}

	return parseEPSSResponse(&parsed)
}

func parseEPSSResponse(r *epssResponse) map[string]epssEntry {
	m := make(map[string]epssEntry, len(r.Data))
	for _, item := range r.Data {
		score, _ := strconv.ParseFloat(item.EPSS, 64)
		pct, _ := strconv.ParseFloat(item.Percentile, 64)
		m[item.CVE] = epssEntry{score: score, percentile: pct}
	}
	return m
}

// ─────────────────────────────────────── KEV ────────────────────────────────

type kevResponse struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

func (c *Client) fetchKEV() map[string]bool {
	cachePath := filepath.Join(c.CacheDir, "kev.json")

	// Try cache first.
	if data, err := os.ReadFile(cachePath); err == nil {
		var cf struct {
			FetchedAt time.Time   `json:"fetched_at"`
			Raw       kevResponse `json:"raw"`
		}
		if json.Unmarshal(data, &cf) == nil && time.Since(cf.FetchedAt) < kevCacheTTL {
			return parseKEVResponse(&cf.Raw)
		}
	}

	// Fetch fresh.
	resp, err := c.http.Get(kevURL) //nolint:noctx
	if err != nil {
		return map[string]bool{}
	}
	defer resp.Body.Close()

	var parsed kevResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return map[string]bool{}
	}

	// Persist to cache.
	type cacheShape struct {
		FetchedAt time.Time   `json:"fetched_at"`
		Raw       kevResponse `json:"raw"`
	}
	if raw, err := json.Marshal(cacheShape{FetchedAt: time.Now(), Raw: parsed}); err == nil {
		_ = os.WriteFile(cachePath, raw, 0o644)
	}

	return parseKEVResponse(&parsed)
}

func parseKEVResponse(r *kevResponse) map[string]bool {
	m := make(map[string]bool, len(r.Vulnerabilities))
	for _, v := range r.Vulnerabilities {
		m[v.CVEID] = true
	}
	return m
}

// ─────────────────────────────── Compliance tags ────────────────────────────

// cweComplianceMap maps CWE IDs to one or more compliance/framework tags.
var cweComplianceMap = map[string][]string{
	// OWASP Top 10 2021
	"CWE-79":  {"OWASP:A03-Injection", "CWE-25"},
	"CWE-89":  {"OWASP:A03-Injection", "CWE-25", "PCI-DSS:6.3.2"},
	"CWE-22":  {"OWASP:A01-BrokenAccessControl", "CWE-25"},
	"CWE-78":  {"OWASP:A03-Injection", "CWE-25"},
	"CWE-94":  {"OWASP:A03-Injection"},
	"CWE-502": {"OWASP:A08-SoftwareDataIntegrity"},
	"CWE-20":  {"OWASP:A03-Injection", "CWE-25"},
	"CWE-276": {"OWASP:A01-BrokenAccessControl"},
	"CWE-311": {"OWASP:A02-CryptographicFailures", "HIPAA:§164.312(a)(2)(iv)"},
	"CWE-312": {"OWASP:A02-CryptographicFailures", "HIPAA:§164.312(a)(2)(iv)"},
	"CWE-319": {"OWASP:A02-CryptographicFailures", "PCI-DSS:4.2"},
	"CWE-326": {"OWASP:A02-CryptographicFailures"},
	"CWE-327": {"OWASP:A02-CryptographicFailures", "PCI-DSS:4.2.1"},
	"CWE-330": {"OWASP:A02-CryptographicFailures"},
	"CWE-338": {"OWASP:A02-CryptographicFailures"},
	"CWE-352": {"OWASP:A01-BrokenAccessControl"},
	"CWE-400": {"OWASP:A05-SecurityMisconfiguration"},
	"CWE-434": {"OWASP:A04-InsecureDesign", "CWE-25"},
	"CWE-601": {"OWASP:A10-SSRF"},
	"CWE-611": {"OWASP:A05-SecurityMisconfiguration"},
	"CWE-614": {"OWASP:A02-CryptographicFailures"},
	"CWE-640": {"OWASP:A07-IdentificationAuthenticationFailures"},
	"CWE-732": {"OWASP:A01-BrokenAccessControl"},
	"CWE-798": {"OWASP:A07-IdentificationAuthenticationFailures", "CWE-25", "PCI-DSS:6.3.3"},
	"CWE-918": {"OWASP:A10-SSRF"},
}

// buildComplianceTags returns a deduplicated list of compliance tags for the
// CWE IDs present in the finding.
func buildComplianceTags(f *model.Finding) []string {
	seen := map[string]bool{}
	var tags []string
	for _, cwe := range f.CWE {
		// Normalise: ensure it starts with "CWE-"
		cwe = strings.ToUpper(strings.TrimSpace(cwe))
		if !strings.HasPrefix(cwe, "CWE-") {
			cwe = "CWE-" + cwe
		}
		for _, tag := range cweComplianceMap[cwe] {
			if !seen[tag] {
				seen[tag] = true
				tags = append(tags, tag)
			}
		}
	}
	return tags
}

// ─────────────────────────────────── helpers ────────────────────────────────

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
