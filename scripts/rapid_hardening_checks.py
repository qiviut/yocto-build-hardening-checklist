#!/usr/bin/env python3
"""Run the fast, local-only assurance gates for the rolling hardening model.

This orchestrates traceability validation, unit tests, and product-neutral
fixtures. It does not fetch sources, build a product, or promote a candidate.
The optional third-party analyzer remains a separate, revision-pinned advisory
lane.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]


def doorstop_command() -> str | None:
    candidates = [
        Path(sys.executable).parent / "doorstop",
        ROOT / ".venv-doorstop/bin/doorstop",
        ROOT / ".ci-venv/bin/doorstop",
    ]
    found = shutil.which("doorstop")
    if found:
        candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def output_excerpt(text: str, limit: int = 20) -> list[str]:
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return lines[-limit:]


def run_command(name: str, command: list[str], timeout: int = 180) -> tuple[dict[str, Any], subprocess.CompletedProcess[str] | None]:
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ({"name": name, "status": "failed", "command": command,
                 "error": str(exc)}, None)
    text = completed.stdout + completed.stderr
    stage: dict[str, Any] = {
        "name": name,
        "status": "passed" if completed.returncode == 0 else "failed",
        "command": command,
        "exit_code": completed.returncode,
        "output_excerpt": output_excerpt(text),
    }
    return stage, completed


def add_command_stage(stages: list[dict[str, Any]], name: str, command: list[str], timeout: int = 180) -> tuple[dict[str, Any], subprocess.CompletedProcess[str] | None]:
    stage, result = run_command(name, command, timeout)
    stages.append(stage)
    return stage, result


def add_json_stage(
    stages: list[dict[str, Any]],
    name: str,
    command: list[str],
    output_path: Path,
    check: Callable[[dict[str, Any]], list[str]],
) -> dict[str, Any]:
    stage, result = run_command(name, command)
    problems: list[str] = []
    report: dict[str, Any] | None = None
    if result is not None and result.returncode == 0:
        try:
            stdout_report = json.loads(result.stdout)
            disk_report = json.loads(output_path.read_text(encoding="utf-8"))
            if not isinstance(stdout_report, dict) or not isinstance(disk_report, dict):
                problems.append("CLI report must be a JSON object")
            elif stdout_report != disk_report:
                problems.append("stdout report differs from the --output artifact")
            else:
                report = disk_report
                problems.extend(check(report))
        except (OSError, json.JSONDecodeError) as exc:
            problems.append(f"invalid or missing JSON report: {exc}")
    if report is not None:
        stage["report"] = {
            key: report[key]
            for key in ("status", "overall", "state", "candidate_status", "promotes_candidate", "product_claim")
            if key in report
        }
    if problems:
        stage["status"] = "failed"
        stage["assertion_errors"] = problems
    stages.append(stage)
    return stage


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--openssl-archive",
        type=Path,
        help="optional local archive for the bounded, non-blocking GCC analyzer pass",
    )
    parser.add_argument(
        "--refresh-evidence",
        action="store_true",
        help="write fixture reports to their documented evidence/ paths instead of a temporary directory",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="optional path for the aggregate JSON run summary",
    )
    args = parser.parse_args()
    stages: list[dict[str, Any]] = []

    doorstop = doorstop_command()
    if doorstop:
        stage, result = add_command_stage(stages, "doorstop", [doorstop, "-j", ".", "-F", "-C"])
        if result is not None:
            warnings = [line for line in (result.stdout + result.stderr).splitlines() if re.match(r"\s*WARNING:", line)]
            stage["warning_count"] = len(warnings)
            stage["warning_categories"] = {
                "unreviewed_changes": sum("unreviewed changes" in line.lower() for line in warnings),
                "suspect_links": sum("suspect link:" in line.lower() for line in warnings),
                "other": sum("unreviewed changes" not in line.lower() and "suspect link:" not in line.lower() for line in warnings),
            }
            stage["warning_examples"] = warnings[:3]
    else:
        stages.append({"name": "doorstop", "status": "failed", "error": "Doorstop executable not found; use the project validation virtualenv"})

    lint_stage, lint_result = add_command_stage(
        stages, "traceability-linter", [sys.executable, "scripts/lint_traceability.py"]
    )
    if lint_result is not None:
        text = lint_result.stdout + lint_result.stderr
        match = re.search(r"traceability errors:\s*(\d+); completeness warnings:\s*(\d+)", text)
        if match:
            lint_stage["traceability_errors"] = int(match.group(1))
            lint_stage["completeness_warnings"] = int(match.group(2))
            if lint_stage["traceability_errors"]:
                lint_stage["status"] = "failed"
        else:
            lint_stage["status"] = "failed"
            lint_stage["assertion_errors"] = ["traceability error/completeness summary was not emitted"]

    with tempfile.TemporaryDirectory(prefix="yocto-rapid-checks-") as temporary:
        temporary_out = Path(temporary)
        py = sys.executable

        def report_path(name: str, relative: str) -> Path:
            path = ROOT / relative if args.refresh_evidence else temporary_out / name
            path.parent.mkdir(parents=True, exist_ok=True)
            return path

        reference_report = report_path("reference.json", "evidence/rolling-intake-validation.json")
        add_json_stage(
            stages, "reference-manifest",
            [py, "scripts/rolling_manifest.py", "validate", "fixtures/rolling-intake/reference-snapshot.json", "--output", str(reference_report)],
            reference_report,
            lambda r: [] if r.get("status") == "passed" and r.get("candidate_status") == "not-promoted" and r.get("promotes_candidate") is False else ["reference fixture must validate without promoting"],
        )
        failed_report = report_path("failed-intake.json", "evidence/failed-intake-validation.json")
        add_json_stage(
            stages, "failed-intake-preserves-candidate",
            [py, "scripts/rolling_manifest.py", "validate", "fixtures/rolling-intake/failed-intake-example.json", "--output", str(failed_report)],
            failed_report,
            lambda r: [] if r.get("status") == "passed" and r.get("candidate_status") == "not-promoted" and r.get("promotes_candidate") is False else ["failed intake must remain valid and unpromoted"],
        )
        replay_report = report_path("replay.json", "evidence/rolling-intake-replay.json")
        add_json_stage(
            stages, "local-exact-sha-replay",
            [py, "scripts/rolling_manifest.py", "replay-fixture", "--output", str(replay_report)],
            replay_report,
            lambda r: [] if r.get("status") == "passed" and r.get("network_used") is False and r.get("promotes_candidate") is False and re.fullmatch(r"[0-9a-f]{40}", str(r.get("revision", ""))) else ["replay must pass locally at an exact SHA without promotion"],
        )
        advisory_report = report_path("advisory.json", "evidence/advisory-lane-fixture.json")
        add_json_stage(
            stages, "advisory-finding-policy",
            [py, "scripts/advisory_lane_fixture.py", "--scenario", "finding-only", "--output", str(advisory_report)],
            advisory_report,
            lambda r: [] if r.get("overall") == "passed" and r.get("diagnostics", {}).get("finding_alone_blocks") is False and r.get("exit_code") == 0 else ["diagnostic-only finding must remain advisory"],
        )
        cve_report = report_path("cve.json", "evidence/cve/cve-fixture-validation.json")
        add_json_stage(
            stages, "cve-disposition-fixture",
            [py, "scripts/cve_disposition_fixture.py", "fixtures/cve/rolling-cve-fixture.json", "--output", str(cve_report)],
            cve_report,
            lambda r: [] if r.get("status") == "passed" and r.get("fixture_only") is True and r.get("product_claim") is False else ["CVE fixture must remain product-neutral"],
        )
        runtime_report = report_path("runtime.json", "evidence/runtime-containment-reference.json")
        add_json_stage(
            stages, "runtime-containment-fixture",
            [py, "scripts/runtime_containment_fixture.py", "--output", str(runtime_report)],
            runtime_report,
            lambda r: [] if r.get("status") == "passed" and r.get("product_claim") is False and r.get("kernel_configuration", {}).get("status") == "not-run" and r.get("runtime_enforcement", {}).get("status") == "not-run" else ["runtime fixture must not upgrade missing product evidence"],
        )
        if args.openssl_archive:
            analyzer_report = report_path("openssl.json", "evidence/advisory-openssl-4.0.2-gcc-analyzer.json")
            add_json_stage(
                stages, "optional-bounded-openssl-analyzer",
                [py, "scripts/run_openssl_gcc_analyzer.py", "--archive", str(args.openssl_archive), "--output", str(analyzer_report)],
                analyzer_report,
                lambda r: [] if r.get("state") in {"clean", "findings"} else ["analyzer invocation was not a completed clean/findings result"],
            )

    _, test_result = add_command_stage(
        stages,
        "unit-tests",
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        timeout=180,
    )
    test_stage = stages[-1]
    if test_result is not None:
        test_output = test_result.stdout + test_result.stderr
        match = re.search(r"Ran (\d+) tests? in ([0-9.]+)s", test_output)
        if match:
            test_stage["tests_run"] = int(match.group(1))
            test_stage["duration_seconds"] = float(match.group(2))
        if test_result.returncode == 0 and ("OK" not in test_output or not match):
            test_stage["status"] = "failed"
            test_stage["assertion_errors"] = ["unittest did not report its complete passing summary"]

    compile_stage, _ = add_command_stage(
        stages, "compileall", [sys.executable, "-m", "compileall", "-q", "scripts", "tests"]
    )

    report = {
        "schema_version": 1,
        "status": "passed" if all(stage.get("status") == "passed" for stage in stages) else "failed",
        "promotion_authorized": False,
        "product_build_claim": False,
        "optional_lanes": {
            "bounded_openssl_gcc_analyzer": "run" if args.openssl_archive else "not-run",
        },
        "stages": stages,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output_path = args.output if args.output.is_absolute() else ROOT / args.output
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
