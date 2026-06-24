#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="$repo_root/bench/vulnerable-project/python-api"
out_dir="${1:-$repo_root/bench/results/python-api}"

mkdir -p "$out_dir"

printf '==> scanning %s\n' "$target"
cyberai scan "$target" --no-llm --summary json --output "$out_dir" | tee "$out_dir/scan-summary.jsonl"

printf '==> reports written to %s\n' "$out_dir"
printf '==> ground truth: %s\n' "$target/expected-findings.json"
printf '==> scoring report\n'
"$repo_root/bench/score-python-benchmark.py" "$out_dir/report.json" "$target" | tee "$out_dir/score.txt"
