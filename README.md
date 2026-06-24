# CyberAI

CyberAI is a local CLI security and code-analysis tool. It runs deterministic scanners over a project, normalizes the results, and writes SARIF, JSON, Markdown, HTML, and terminal reports.

The scanner is read-only with respect to the target project. It does not modify source files, lockfiles, configs, or git state.

## Quick Start

```bash
# Build and install the cyberai binary
./setup.sh

# Scan the current directory
cyberai scan

# Scan one scanner category only
cyberai scan --only secrets

# Pick a target and report formats
cyberai scan ./my-app --format sarif,json,html

# CI mode: no LLM, JSON summary, non-zero exit on findings
cyberai scan --ci
```

Running `cyberai` with no subcommand shows the CyberAI ASCII logo, command list, and global flags.

## Install Or Update

Use the setup script from the repo root:

```bash
./setup.sh
```

By default this runs tests, builds the CLI, and installs it to the Go binary directory:

```text
$GOBIN/cyberai
# or, when GOBIN is empty:
$GOPATH/bin/cyberai
# usually:
$HOME/go/bin/cyberai
```

Install to a system path instead:

```bash
./setup.sh --system
```

That installs to `/usr/local/bin/cyberai`. If the directory needs elevated permission, the script uses `sudo install`.

Useful setup flags:

```bash
./setup.sh --skip-tests          # build/install without running tests
./setup.sh --install-tools       # also install managed scanners
./setup.sh --system --install-tools
./setup.sh --prefix "$HOME/.local/bin"
./setup.sh --help
```

After install, verify:

```bash
command -v cyberai
cyberai --version
cyberai tools list
```

## Managed Scanner Tools

CyberAI currently shells out to:

- **Semgrep** for multi-language SAST.
- **Gitleaks** for secret detection.
- **Trivy** for SCA, IaC, and license checks.
- **Checkov** for deeper IaC and policy checks.
- **Hadolint** for Dockerfile linting.
- **Zizmor** for GitHub Actions security checks.

Interactive scans can auto-bootstrap missing scanners. You can also manage them directly:

```bash
cyberai tools list
cyberai tools install
cyberai tools install gitleaks trivy
cyberai tools install checkov hadolint zizmor
cyberai tools update
cyberai tools remove gitleaks
```

Managed binaries live in `~/.cyberai/bin`, and CyberAI prepends that directory to `PATH` at startup. Python-based managed tools use CyberAI-owned virtualenvs under `~/.cyberai/venvs`. Tool state lives in `~/.cyberai/state/tools.json`.

`cyberai tools install` is idempotent: rerunning it refreshes tool state and leaves existing managed binaries in place unless `--force` is used. Trivy initializes its vulnerability database automatically on the first scan when the local DB is missing.

## Scan Output

The normal CLI summary is human-readable:

```bash
cyberai scan
```

Use JSON when another program needs to consume the CLI summary:

```bash
cyberai scan --summary json
```

Suppress the final summary block:

```bash
cyberai scan --summary off
```

Reports land in `./cyberai-reports/` by default. Override with `--output`:

```bash
cyberai scan --output /tmp/cyberai-report
```

Config-file output paths are confined under the scanned project root. A CLI-provided `--output` path is treated as explicit user intent and may point elsewhere.

## Common Commands

```bash
cyberai scan [path]               # run scanners and emit reports
cyberai scan --only secrets       # only run Gitleaks
cyberai scan --only sast,sca      # only run selected categories
cyberai scan --only iac,docker,cicd
cyberai scan --install-missing    # install missing scanners before scanning
cyberai tools list                # show scanner status
cyberai tools install [tool...]   # install scanners
cyberai tools update [tool...]    # refresh scanners
cyberai tools remove [tool...]    # remove managed scanner binaries
cyberai init                      # generate starter .cyberai.yaml
cyberai report compare            # diff two saved JSON reports
```

Run `cyberai <command> --help` for full command-specific flags.

## Report Formats

| Format | Use case |
|---|---|
| SARIF | CI integration, GitHub code scanning, GitLab, and similar systems |
| JSON | Full normalized machine-readable report |
| Markdown | PR or issue comments |
| HTML | Self-contained report with an optional executive summary |
| terminal | Pretty stdout report, skipped in `--ci` |

## Optional LLM Router

When `GEMINI_API_KEY` is set, CyberAI can use Gemini for two narrow tasks:

1. Router: chooses scanners and rulesets from the detected project profile.
2. Summarizer: writes the executive summary for the HTML report.

Disable LLM behavior with:

```bash
cyberai scan --no-llm
```

CI mode also disables it:

```bash
cyberai scan --ci
```

The scanners remain the source of findings. The LLM only routes and summarizes.

## Configuration

Generate a starter config:

```bash
cyberai init
```

CyberAI reads `.cyberai.yaml` or `.cyberai.yml` from the project root. CLI flags override the config file.

Example:

```yaml
scanners:
  - sast
  - secrets
  - sca

severity_threshold: low

output:
  path: cyberai-reports
  formats:
    - sarif
    - json
    - markdown
    - html
    - terminal

ui:
  color: auto
  progress: auto
```

## Development

```bash
go test ./...
go build ./...
go run ./cmd/cyberai --help
```

## Benchmarks

CyberAI includes an intentionally vulnerable Python benchmark app:

```bash
bench/run-python-benchmark.sh
```

The fixture lives at `bench/vulnerable-project/python-api/` and includes FastAPI code bugs, vulnerable dependency pins, fake secret fixtures, Docker issues, Kubernetes issues, Terraform issues, and a dangerous GitHub Actions workflow. Ground truth lives in:

```text
bench/vulnerable-project/python-api/expected-findings.json
```

The benchmark writes reports and score output to:

```text
bench/results/python-api/
```

Current scoring is simple but useful: it matches CyberAI report findings to expected findings by tool, file, and line proximity. This gives us a repeatable baseline while we add better tools and an investigation layer.

Project layout:

```text
cmd/cyberai/main.go          # entrypoint
internal/
  cli/         cobra commands and terminal UX
  config/      .cyberai.yaml loader
  model/       unified Finding schema
  project/     deterministic project detection
  router/      LLM router and default plan
  scanner/     Semgrep, Gitleaks, Trivy wrappers
  normalizer/  tool-specific output to Finding
  reporter/    SARIF, JSON, Markdown, HTML, Terminal
  summarizer/  LLM executive summary
  baseline/    baseline diff
  tools/       scanner probe and installer
```

## Roadmap

The next useful direction is a real triage layer: route discovery, dependency reachability, exploitability scoring, and `cyberai investigate` to confirm or suppress scanner findings with evidence.

Useful future tools to integrate:

- `govulncheck` for Go vulnerability reachability.
- `osv-scanner` or `grype` for dependency coverage.
- `checkov` or `kics` for IaC.
- `hadolint` for Dockerfiles.
- `zizmor` for GitHub Actions security.
- Ecosystem-native audit tools such as `pip-audit` and `npm audit`.
