#!/usr/bin/env python3
"""Emit deterministic, synthetic examples for advisory-analysis gate policy.

This script does not run an analyzer, compiler, build, or test suite.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SCENARIOS: dict[str, dict[str, Any]] = {
    "finding-only": {
        "diagnostics": {"state": "findings", "tool_exit": 0, "finding_ids": ["FIXTURE-SA-001"]},
        "build": "passed",
        "tests": "passed",
    },
    "clean": {
        "diagnostics": {"state": "clean", "tool_exit": 0, "finding_ids": []},
        "build": "passed",
        "tests": "passed",
    },
    "unsupported": {
        "diagnostics": {"state": "unsupported", "tool_exit": None, "finding_ids": []},
        "build": "passed",
        "tests": "passed",
    },
    "tool-error": {
        "diagnostics": {"state": "tool-error", "tool_exit": 127, "finding_ids": []},
        "build": "passed",
        "tests": "passed",
    },
    "build-failure": {
        "diagnostics": {"state": "findings", "tool_exit": 0, "finding_ids": ["FIXTURE-SA-001"]},
        "build": "failed",
        "tests": "not-run",
    },
    "test-failure": {
        "diagnostics": {"state": "findings", "tool_exit": 0, "finding_ids": ["FIXTURE-SA-001"]},
        "build": "passed",
        "tests": "failed",
    },
}


def evaluate(scenario: str) -> dict[str, Any]:
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario: {scenario}")
    data = SCENARIOS[scenario]
    core_failed = data["build"] == "failed" or data["tests"] == "failed"
    diagnostic_state = data["diagnostics"]["state"]
    finding_records = [
        {
            "id": finding_id,
            "triage_owner": "fixture-maintainer (synthetic)",
            "disposition": "triaged-fixture-only",
            "upstream_route": "not-applicable: synthetic fixture finding has no upstream component",
            "applicability_rationale": "Synthetic policy example only; not a real third-party diagnostic result.",
        }
        for finding_id in data["diagnostics"]["finding_ids"]
    ]
    diagnostics = {
        **data["diagnostics"],
        "gate": "advisory",
        "finding_alone_blocks": False,
        "invocation_problem_is_visible": diagnostic_state in {"unsupported", "tool-error"},
        "finding_records": finding_records,
        "triage_summary": {
            "triage_owner": "fixture-maintainer (synthetic)",
            "disposition": "triaged-fixture-only" if finding_records else "no-findings",
            "upstream_route": "not-applicable: synthetic fixture is not upstream evidence",
            "applicability_rationale": "This fixture demonstrates policy only; it is not an analyzer report.",
        },
    }
    return {
        "schema_version": 1,
        "fixture_only": True,
        "product_claim": False,
        "scenario": scenario,
        "diagnostics": diagnostics,
        "build": {"status": data["build"], "gate": "blocking"},
        "tests": {"status": data["tests"], "gate": "blocking"},
        "overall": "failed" if core_failed else "passed",
        "exit_code": 1 if core_failed else 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), required=True)
    parser.add_argument("--output", type=Path, help="write the JSON fixture report to this path")
    args = parser.parse_args()
    report = evaluate(args.scenario)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
