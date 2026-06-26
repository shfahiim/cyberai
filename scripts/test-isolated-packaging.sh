#!/usr/bin/env bash
# End-to-end packaging smoke test in an isolated HOME + bin dir.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
isolated="$(mktemp -d)"
bin_dir="$isolated/bin"
home_dir="$isolated/home"
log="$isolated/test.log"

cleanup() {
  rm -rf "$isolated"
}
trap cleanup EXIT

exec > >(tee "$log") 2>&1

pass=0
fail=0
note() { printf '  [ok] %s\n' "$*"; pass=$((pass + 1)); }
bad()  { printf '  [FAIL] %s\n' "$*"; fail=$((fail + 1)); }

echo "==> isolated packaging test"
echo "    repo: $repo_root"
echo "    home: $home_dir"
echo "    bin:  $bin_dir"
echo

export HOME="$home_dir"
export XDG_CACHE_HOME="$home_dir/.cache"
mkdir -p "$bin_dir" "$home_dir"

# Minimal PATH: our cyberai binary, pipx-installed tools, then system basics.
export PATH="$bin_dir:$home_dir/.local/bin:/usr/local/go/bin:$(go env GOPATH 2>/dev/null)/bin:/usr/bin:/bin"

echo "==> build cyberai"
cd "$repo_root"
go build -o "$bin_dir/cyberai" ./cmd/cyberai
"$bin_dir/cyberai" --version
note "binary built"

echo
echo "==> fresh tools list (expect missing scanners)"
before=$("$bin_dir/cyberai" tools list 2>&1)
if echo "$before" | grep -q "missing:"; then
  note "tools list shows missing before install"
else
  bad "expected missing tools before install"
fi

echo
echo "==> cyberai tools install (all managed tools)"
if "$bin_dir/cyberai" tools install; then
  note "tools install exited 0"
else
  bad "tools install failed"
  exit 1
fi

echo
echo "==> verify managed binaries"
managed=(
  gitleaks trivy checkov hadolint zizmor
  grype osv-scanner govulncheck actionlint syft
)
for tool in "${managed[@]}"; do
  if [[ -x "$home_dir/.cyberai/bin/$tool" ]]; then
    note "$tool in ~/.cyberai/bin"
  else
    bad "$tool missing from ~/.cyberai/bin"
  fi
done

echo
echo "==> semgrep (pipx/system, not ~/.cyberai/bin)"
if "$bin_dir/cyberai" tools list 2>&1 | grep -E '^ semgrep' | grep -qv 'missing'; then
  note "semgrep available after tools install"
else
  bad "semgrep still missing (need pipx or python3 on PATH)"
fi

echo
echo "==> tools list after install"
after=$("$bin_dir/cyberai" tools list 2>&1)
echo "$after"
if echo "$after" | grep -q "missing:"; then
  bad "tools list still reports missing: $(echo "$after" | grep missing:)"
else
  note "no missing tools in tools list"
fi

echo
echo "==> spot-check versions"
for tool in gitleaks trivy grype syft actionlint govulncheck; do
  if "$home_dir/.cyberai/bin/$tool" --version >/dev/null 2>&1 || \
     "$home_dir/.cyberai/bin/$tool" version >/dev/null 2>&1; then
    note "$tool runs --version"
  else
    bad "$tool --version failed"
  fi
done

echo
echo "==> setup.sh --prefix (packaging path)"
setup_dest="$isolated/setup-prefix/bin"
mkdir -p "$setup_dest"
if "$repo_root/setup.sh" --skip-tests --prefix "$setup_dest" --keep-build; then
  note "setup.sh --prefix succeeded"
else
  bad "setup.sh --prefix failed"
fi
if [[ -x "$setup_dest/cyberai" ]]; then
  note "setup.sh installed cyberai to prefix"
else
  bad "setup.sh did not install binary"
fi

echo
echo "==> doctor on benchmark project"
bench="$repo_root/bench/vulnerable-project/python-api"
if "$bin_dir/cyberai" doctor "$bench" >/dev/null 2>&1; then
  note "doctor ran on benchmark project"
else
  bad "doctor failed on benchmark project"
fi

echo
echo "==> quick scan (no LLM) on benchmark"
if "$bin_dir/cyberai" scan --no-llm --preset quick "$bench" >/dev/null 2>&1; then
  note "scan completed on benchmark"
else
  bad "scan failed on benchmark"
fi

echo
echo "=============================="
printf "results: %d passed, %d failed\n" "$pass" "$fail"
printf "full log: %s\n" "$log"
if [[ "$fail" -gt 0 ]]; then
  exit 1
fi
