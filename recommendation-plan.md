# CyberAI Recommendation Execution Plan

Created: 2026-06-24

This plan converts `recommendations.md` into an execution roadmap for taking CyberAI from a deterministic local security CLI into a broader enterprise-grade vulnerability discovery and triage platform.

## Objective

Increase CyberAI's practical bug-finding coverage and enterprise usefulness while preserving the current product strengths:

- Keep deterministic scanners as the source of truth.
- Keep the default scan read-only against the target project.
- Add active, networked, or validating behavior only behind explicit flags.
- Reduce false-positive fatigue through prioritization, reachability, suppressions, and evidence-based triage.
- Build enterprise workflows around the scanner instead of only adding more findings.

## Current Baseline

CyberAI already has a solid Phase 1 foundation:

- Go CLI with `scan`, `tools`, `init`, and report comparison commands.
- Managed scanner installation and scanner availability checks.
- Current scanners: Semgrep, Gitleaks, and Trivy.
- Normalized finding model with stable fingerprints and report generation.
- Report formats: SARIF, JSON, Markdown, HTML, and terminal.
- Baseline diff support.
- Optional Gemini-based router and HTML report summarizer.
- Benchmark project with vulnerable Python API fixtures.

The next work should build on this rather than replacing it.

## Guiding Decisions

1. Scanner integrations come before advanced agent behavior.
2. Model and configuration changes come before features that depend on them.
3. Prioritization and suppression must land early, because extra scanners will otherwise increase noise.
4. Active scanning, secret validation, cloud scanning, and API fuzzing must require explicit user intent.
5. Draft PR remediation conflicts with the original "find only, never apply fixes" constraint, so it stays out of the default roadmap unless the product boundary is changed deliberately.

## Phase 0 - Stabilize The Core

Target: 1 week

Purpose: Fix known correctness issues and make scanner expansion easier.

### Deliverables

- Formalize scanner registration.
  - Add a scanner registry keyed by scanner name.
  - Support scanner category groups such as `sast`, `sca`, `secrets`, `iac`, `docker`, `cicd`, `sbom`, and `dast`.
  - Allow conditional activation based on project profile.

- Expand the project profile.
  - Detect C/C++, C#/.NET, Swift, Dart/Flutter, Kotlin, Ruby, Java, Node, Python, Rust, Go, Docker, Kubernetes, Terraform, Helm, GitHub Actions, GitLab CI, and Ansible.
  - Replace path-only Kubernetes detection with YAML `apiVersion` and `kind` detection.

- Fix current code-level issues.
  - Allow Semgrep findings to map to `critical` when rule metadata supports it.
  - Improve Gitleaks severity mapping instead of hardcoding every secret to `high`.
  - Add TTL or version invalidation to the router cache.
  - Decide whether `--explain` is implemented now or removed until ready.
  - Replace incomplete HTML sanitization with a hardened sanitizer such as `bluemonday`.
  - Remove or wire currently dead fields such as `HasAnsible`.
  - Avoid package-level mutable scan plan state in `cli/scan.go`.

- Improve test coverage around the existing core.
  - Normalizer fixture tests for Semgrep, Gitleaks, and Trivy.
  - Golden report tests for JSON, SARIF, Markdown, and HTML.
  - Router cache tests, including expiry behavior.
  - Scanner orchestration tests for partial failures.

### Acceptance Criteria

- `go test ./...` passes.
- Existing CLI behavior remains compatible.
- Adding a new scanner requires only a scanner wrapper, normalizer, registry entry, tool metadata, and tests.
- The benchmark still runs end-to-end.

## Phase 1 - High-Yield Scanner Expansion

Target: 2 to 3 weeks

Purpose: Double practical bug discovery with low-to-medium effort scanner integrations.

### Scanner Additions

| Scanner | Category | Priority | Notes |
|---|---|---:|---|
| Checkov | IaC | P0 | Deeper Terraform, Kubernetes, Dockerfile, CloudFormation, Helm, and GitHub Actions coverage than Trivy alone |
| Hadolint | Docker | P0 | Best Dockerfile linting coverage |
| Zizmor | CI/CD security | P0 | Security-focused GitHub Actions scanning |
| Actionlint | CI/CD correctness | P1 | Catches GitHub Actions issues with security impact |
| Grype | SCA | P1 | Second opinion for dependency CVEs |
| OSV-Scanner | SCA/reachability | P1 | OSV-backed dependency scanning, with call graph support where available |

### Implementation Tasks

- Add scanner wrappers and normalizers for each P0 scanner first.
- Add managed tool install metadata for each scanner.
- Add scanner-specific fixture outputs under tests.
- Add benchmark expectations for Dockerfile, IaC, and GitHub Actions findings.
- Add category filters so users can run:

```bash
cyberai scan --only iac
cyberai scan --only docker,cicd
cyberai scan --only sca
```

### Acceptance Criteria

- CyberAI can run at least 6 scanners locally when relevant tools are installed.
- Missing optional scanners are skipped gracefully with clear reasons.
- P0 scanners produce normalized findings in all existing report formats.
- Benchmark output shows improved coverage for Dockerfile, IaC, and GitHub Actions issues.

## Phase 2 - Enterprise Triage And Prioritization

Target: 3 to 5 weeks

Purpose: Make results actionable at enterprise scale.

### Finding Model Enrichment

Add normalized fields for prioritization and triage:

```go
EPSSScore      float64
EPSSPercentile float64
IsInKEV        bool
IsReachable    *bool
FixAvailable   bool
Priority       string
FirstSeen      time.Time
SLADeadline    time.Time
ComplianceTags []string
```

Keep scanner-specific raw fields in metadata when they do not belong in the normalized schema.

### Prioritization Engine

- Fetch EPSS data from FIRST and cache for 24 hours.
- Fetch CISA KEV catalog and cache for 6 hours.
- Calculate priority from severity, EPSS, KEV, reachability, fix availability, and suppression state.
- Suggested default policy:

| Priority | Rule |
|---|---|
| P0 | KEV plus reachable, or EPSS greater than 0.5 plus CVSS at least 9.0 |
| P1 | EPSS greater than 0.1 plus reachable, or CVSS at least 9.0 plus reachable |
| P2 | CVSS at least 7.0 plus reachable |
| P3 | CVSS at least 4.0 or unreachable but relevant |
| P4 | Informational or no known exploit path |

### Suppression Management

Add persistent suppressions:

```bash
cyberai suppress <finding-id> --reason "false positive" --expires 90d
cyberai suppress list
cyberai suppress remove <suppression-id>
```

Use `.cyberai-suppressions.yaml` with:

- fingerprint-based suppressions
- rule and path based suppressions
- author, reason, created date, expiry, and optional ticket
- expired suppression resurfacing
- suppression audit details in reports

### Compliance Mapping

- Add CWE to compliance control mappings.
- Support OWASP Top 10, CWE Top 25, PCI-DSS, SOC 2, HIPAA, ISO 27001, and NIST 800-53 tags.
- Add `cyberai scan --compliance owasp-top-10,pci-dss`.
- Add compliance sections to JSON, Markdown, HTML, and SARIF metadata.

### Policy Gates

Extend `.cyberai.yaml` with pass/fail gates:

```yaml
policies:
  gates:
    - name: no-critical
      fail_on: "severity == critical AND suppressed == false"
    - name: no-new-high
      fail_on: "is_new == true AND severity in [critical, high]"
    - name: no-live-secrets
      fail_on: "category == secrets AND verified == true"
  sla:
    critical: 7d
    high: 30d
    medium: 90d
    low: 180d
```

### Acceptance Criteria

- Reports sort by computed priority, not only severity.
- Suppressed findings are hidden or marked according to user-selected output mode.
- CI can fail on policy violations rather than raw finding count only.
- Compliance tags appear consistently in machine-readable and human reports.

## Phase 3 - Language-Specific Depth And Supply Chain

Target: 4 to 6 weeks

Purpose: Improve accuracy and reachability for common ecosystems.

### Scanner Additions

| Ecosystem | SCA | SAST |
|---|---|---|
| Go | govulncheck | Gosec |
| Python | pip-audit | Bandit |
| JavaScript/TypeScript | npm audit | ESLint security plugins |
| Rust | cargo-audit | N/A |
| Ruby | bundler-audit | Brakeman |
| Java | Dependency scanner as needed | SpotBugs plus Find Security Bugs |

### SBOM Generation

Add Syft-backed SBOM generation:

```bash
cyberai sbom [path]
cyberai sbom --format cyclonedx
cyberai sbom --format spdx
cyberai sbom --enrich
cyberai sbom --image myapp:latest
```

### Malicious Package Signals

Start with lightweight heuristics before paid or hosted services:

- suspicious install scripts
- newly introduced package names similar to popular packages
- dependency confusion indicators
- binary downloads during install
- very young packages in lockfiles

### Acceptance Criteria

- Language-specific scanners only run when project detection says they are relevant.
- Go reachability data from govulncheck affects priority.
- SBOM output validates as CycloneDX or SPDX.
- SCA reports include fix availability when scanners provide it.

## Phase 4 - Enterprise Workflow Integration

Target: 3 to 5 weeks

Purpose: Fit CyberAI into CI, security operations, and vulnerability management workflows.

### Git-Aware Scanning

```bash
cyberai scan --diff main
cyberai scan --diff HEAD~1
cyberai scan --diff origin/main
```

Implementation notes:

- Use `git diff --name-only <ref>` to identify changed files.
- Pass include lists to scanners where supported.
- Report "new findings in changed files" separately from full-project context.

### Additional Formats

- JUnit XML for CI systems.
- CSV for spreadsheet workflows.
- GitLab SAST JSON for GitLab Security Dashboard.
- CycloneDX VDR for vulnerability disclosure reports.
- GitHub annotation output for PR comments.

### Notifications And Integrations

Add webhook outputs with severity and policy filters:

- Slack
- Teams
- Jira
- DefectDojo
- Generic webhook

Config example:

```yaml
notifications:
  slack:
    webhook_url: ${SLACK_WEBHOOK_URL}
    on: [critical, high]
  jira:
    url: ${JIRA_URL}
    project: SEC
    create_on: [critical]
  defectdojo:
    url: ${DEFECTDOJO_URL}
    token: ${DEFECTDOJO_TOKEN}
```

### Acceptance Criteria

- PR scans can focus on changed files while still supporting full scans.
- CI systems can consume CyberAI output without custom adapters.
- Notification integrations are opt-in, environment-variable driven, and do not expose secrets in reports or logs.

## Phase 5 - Active And Runtime Security

Target: 5 to 8 weeks

Purpose: Find bugs static tools miss while keeping active behavior explicit.

### Container Image Scanning

```bash
cyberai scan --image myapp:latest
cyberai scan --image registry.example.com/app:v1.2.3
```

Use Trivy image mode first, then optionally Grype image mode.

### Secret Validation

Add TruffleHog as an optional enhanced secret scanner:

```bash
cyberai scan --verify-secrets
```

Rules:

- Never validate secrets by default.
- Mark validation attempts clearly in the audit trail.
- Avoid printing validated secret material.
- Support offline mode where validation is disabled.

### DAST And API Fuzzing

Add Nuclei first:

```bash
cyberai scan --target-url https://staging.example.com
```

Then add API fuzzing:

```bash
cyberai scan --target-url http://localhost:8080 --openapi openapi.yaml
```

Candidate tools:

- Nuclei for template-based runtime scanning.
- RESTler for stateful OpenAPI fuzzing.
- ffuf for endpoint and parameter discovery.

### CSPM

Add live cloud scanning only as a separate explicit command:

```bash
cyberai cloud-scan --provider aws --profile prod
```

Candidate tools:

- Prowler
- CloudSploit

### Acceptance Criteria

- Active scans require explicit target flags.
- Runtime findings are labeled separately from static findings.
- Network activity is documented in command help and scan summaries.
- Cloud scans never run as part of a default local `cyberai scan`.

## Phase 6 - Agentic Investigation And False-Positive Reduction

Target: after scanner and triage foundations are stable

Purpose: Use the LLM where it adds value: investigation, evidence assembly, and noise reduction.

### Agent Self-Defense

- Treat source files, scanner output, and dependency metadata as untrusted data.
- Wrap file contents in explicit data containers before sending to the model.
- Add prompt-injection and goal-hijack checks before tool execution.
- Keep append-only audit logs for model prompts, tool calls, decisions, and report changes.

### Investigator Behavior

- Trace reachability before escalating findings to high or critical where possible.
- Ask for clarification only when user context materially changes the result.
- Produce remediation plans in reports, without modifying files.
- Link each conclusion to scanner evidence, code paths, or dependency paths.

### False-Positive Reduction

Add two bounded techniques:

- Counterfactual Evidence Reweighting: neutralize variable names and comments, then re-evaluate exploitability.
- Bounded Debate: one agent argues the finding is exploitable, another argues it is a false positive, with a hard two-round limit.

Default behavior:

- If evidence remains weak after review, lower confidence rather than deleting the finding.
- Never suppress automatically without user policy.

### Acceptance Criteria

- Agent conclusions are auditable and grounded in source evidence.
- Prompt-injection attempts inside scanned code do not affect tool behavior.
- Agentic triage reduces noisy high-severity findings in benchmark projects without hiding true positives.

## Product Decision: Draft PR Remediation

`recommendations.md` proposes opt-in draft PR remediation. This is useful, but it conflicts with the original hard rule in `plan.md`: CyberAI finds issues and suggests fixes but does not modify source, git state, or project files.

Recommended handling:

- Keep draft PR remediation out of the main roadmap for now.
- Revisit only after Phase 4 or Phase 5.
- If accepted later, implement as a separate command such as `cyberai fixes draft-pr`, never as part of `cyberai scan`.
- Require explicit confirmation, clean git state checks, branch isolation, and provider-specific authentication.

## Cross-Cutting Engineering Requirements

- Every scanner integration needs fixture-based normalizer tests.
- Every new output format needs golden tests.
- Network-dependent enrichment must be cached and skippable.
- CLI flags must override config file values.
- Reports must clearly distinguish skipped scanners, failed scanners, suppressed findings, and policy failures.
- Managed tools must be versioned and inspectable via `cyberai tools list`.
- Sensitive values must be redacted in logs, reports, and errors.

## Recommended Execution Order

1. Phase 0 core stabilization.
2. Checkov, Hadolint, and Zizmor.
3. EPSS, KEV, and priority scoring.
4. Suppression management.
5. Compliance mapping and policy gates.
6. Grype, OSV-Scanner, and govulncheck.
7. SBOM generation via Syft.
8. Git-aware scanning and CI output formats.
9. Webhooks and vulnerability-management integrations.
10. Active scanning and runtime security.
11. Agentic investigation and debate-based false-positive reduction.

## Success Metrics

| Metric | Baseline | Near-Term Target | Long-Term Target |
|---|---:|---:|---:|
| Scanner count | 3 | 6 to 8 | 15 to 20 |
| Finding categories | 4 | 7 | 12+ |
| Report formats | 5 | 7 to 8 | 10+ |
| Benchmark languages | 1 | 3 | 5+ |
| Prioritization signals | Severity only | Severity, EPSS, KEV | Add reachability, exploitability, business context |
| Enterprise workflow support | Basic CI and SARIF | Policy gates, suppressions, JUnit, CSV | DefectDojo, Jira, Slack, cloud, DAST |

## Immediate Next Sprint

Start with a focused sprint that makes later work easier:

1. Add scanner registry and category grouping.
2. Fix Semgrep critical severity mapping.
3. Fix Gitleaks severity mapping.
4. Add router cache TTL.
5. Replace summarizer HTML sanitization with a stronger sanitizer.
6. Add Checkov wrapper, normalizer, managed install metadata, and tests.
7. Add Hadolint wrapper, normalizer, managed install metadata, and tests.
8. Add Zizmor wrapper, normalizer, managed install metadata, and tests.

Definition of done:

- `go test ./...` passes.
- `cyberai tools list` shows the new scanners.
- `cyberai scan --only iac,docker,cicd` runs the new scanner set when tools are available.
- JSON, SARIF, Markdown, HTML, and terminal reports include normalized findings from the new scanners.
