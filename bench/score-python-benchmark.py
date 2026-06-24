#!/usr/bin/env python3
"""Score CyberAI's report against the intentionally vulnerable Python fixture."""

from __future__ import annotations

import json
import sys
from pathlib import Path


DEFAULT_TARGET = Path(__file__).resolve().parent / "vulnerable-project" / "python-api"
DEFAULT_REPORT = Path(__file__).resolve().parent / "results" / "python-api" / "report.json"
LINE_WINDOW = 8


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def relative_to_target(path: str, target: Path) -> str:
    p = Path(path)
    try:
        return p.resolve().relative_to(target.resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def find_line(target: Path, rel_file: str, hint: str) -> int | None:
    path = target / rel_file
    if not hint or not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for i, line in enumerate(lines, start=1):
        if hint in line:
            return i
    return None


def concrete_tools(tools: list[str]) -> set[str]:
    return {tool for tool in tools if not tool.startswith("future-")}


def matches(expected: dict, actual: dict, target: Path) -> bool:
    expected_tools = concrete_tools(expected.get("expected_tools", []))
    if expected_tools and actual.get("tool") not in expected_tools:
        return False

    actual_rel = relative_to_target(actual.get("file", ""), target)
    if actual_rel != expected.get("file"):
        return False

    expected_line = find_line(target, actual_rel, expected.get("line_hint", ""))
    if expected_line is None:
        return True

    actual_line = int(actual.get("start_line") or 0)
    return expected_line <= actual_line <= expected_line + LINE_WINDOW


def main() -> int:
    report_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_REPORT
    target = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_TARGET
    expected_path = target / "expected-findings.json"

    expected = load_json(expected_path)["findings"]
    actual = load_json(report_path).get("findings", [])

    matched: list[tuple[dict, dict]] = []
    missed: list[dict] = []
    used_actual_ids: set[str] = set()

    for exp in expected:
        match = None
        for finding in actual:
            if finding.get("id") in used_actual_ids:
                continue
            if matches(exp, finding, target):
                match = finding
                break
        if match is None:
            missed.append(exp)
        else:
            matched.append((exp, match))
            used_actual_ids.add(match.get("id", ""))

    unexpected = [f for f in actual if f.get("id") not in used_actual_ids]

    recall = (len(matched) / len(expected) * 100) if expected else 100.0
    precision = (len(matched) / len(actual) * 100) if actual else 100.0

    print("CyberAI Python benchmark")
    print(f"report: {report_path}")
    print(f"expected: {len(expected)}")
    print(f"found: {len(actual)}")
    print(f"matched: {len(matched)}")
    print(f"missed: {len(missed)}")
    print(f"unexpected: {len(unexpected)}")
    print(f"recall: {recall:.1f}%")
    print(f"precision: {precision:.1f}%")

    if matched:
        print("\nmatched")
        for exp, finding in matched:
            print(f"  {exp['id']} <- {finding['tool']} {finding['rule_id']}")

    if missed:
        print("\nmissed")
        for exp in missed:
            tools = ",".join(exp.get("expected_tools", []))
            print(f"  {exp['id']} [{tools}] {exp['file']} :: {exp['line_hint']}")

    if unexpected:
        print("\nunexpected")
        for finding in unexpected:
            rel = relative_to_target(finding.get("file", ""), target)
            print(f"  {finding['tool']} {finding['rule_id']} {rel}:{finding.get('start_line')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
