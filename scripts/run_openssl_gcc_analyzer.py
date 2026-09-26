#!/usr/bin/env python3
"""Run a bounded advisory GCC analyzer pass over pinned OpenSSL source.

The archive must be supplied locally. It is SHA-256 checked before safe
extraction. No configure, build-system script, compiler link, or product test
is executed; one C translation unit is compiled to an object with GCC's
-fanalyzer. Analyzer findings/errors are recorded and never fail the primary
build/test gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

EXPECTED_ARCHIVE_SHA256 = "736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8"
RECIPE_REVISION = "f94ae3d6ba49aef86f497998c0e0232a5039510a"
SOURCE_RELATIVE = Path("crypto/sha/keccak1600.c")
EXPECTED_SOURCE_SHA256 = "c22abcd9106bfc0b4a4726281f1ab366bec3984100b2a3952a487454fbb85cf7"
MAX_ARCHIVE_BYTES = 100_000_000
MAX_UNPACKED_BYTES = 512_000_000
TRIAGE_FIELDS = ("triage_owner", "disposition", "upstream_route", "applicability_rationale")


def triage_record_errors(record: Any) -> list[str]:
    if not isinstance(record, dict):
        return ["triage record must be an object"]
    errors = []
    for field in TRIAGE_FIELDS:
        value = record.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field} must be non-empty text")
        elif value.strip().lower() in {"pending", "unassigned", "todo", "tbd"}:
            errors.append(f"{field} must be triaged, not left pending")
    return errors


def build_finding_records(
    warnings: list[str],
    *,
    triage_owner: str | None = None,
    finding_disposition: str | None = None,
    upstream_route: str | None = None,
    applicability_rationale: str | None = None,
) -> list[dict[str, str]]:
    return [
        {
            "id": f"GCC-FANALYZER-{index:03d}",
            "message": warning,
            "triage_owner": triage_owner or "unassigned",
            "disposition": finding_disposition or "pending",
            "upstream_route": upstream_route or "pending",
            "applicability_rationale": applicability_rationale or "pending",
        }
        for index, warning in enumerate(warnings, start=1)
    ]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_extract(archive: Path, destination: Path) -> Path:
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive exceeds the 100 MB fixture bound")
    if not hasattr(tarfile, "data_filter"):
        raise ValueError("Python tarfile data filter is unavailable; safe extraction is unsupported")
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as tf:
        members = tf.getmembers()
        if sum(member.size for member in members if member.isfile()) > MAX_UNPACKED_BYTES:
            raise ValueError("archive exceeds the 512 MB unpacked fixture bound")
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"unsafe archive path: {member.name}")
        tf.extractall(destination, filter="data")
    source_root = destination / "openssl-4.0.2"
    source = source_root / SOURCE_RELATIVE
    if not source.is_file():
        raise ValueError(f"expected source file missing: {SOURCE_RELATIVE.as_posix()}")
    return source_root


def run(
    archive: Path,
    compiler: str = "gcc",
    *,
    triage_owner: str | None = None,
    finding_disposition: str | None = None,
    upstream_route: str | None = None,
    applicability_rationale: str | None = None,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": 1,
        "analysis_scope": "pinned-third-party-source",
        "product_claim": False,
        "primary_gate": "unaffected-by-diagnostic-findings",
        "component": {
            "name": "OpenSSL",
            "version": "4.0.2",
            "recipe_metadata_revision": RECIPE_REVISION,
            "recipe_source_uri": "http://www.openssl.org/source/openssl-4.0.2.tar.gz",
            "retrieval_uri": "https://www.openssl.org/source/openssl-4.0.2.tar.gz",
            "expected_archive_sha256": EXPECTED_ARCHIVE_SHA256,
            "source_file": SOURCE_RELATIVE.as_posix(),
            "expected_source_file_sha256": EXPECTED_SOURCE_SHA256,
        },
        "tool": {"name": "GCC -fanalyzer", "command": compiler, "flags": ["-fanalyzer", "-Wall", "-Wextra"]},
        "finding_records": [],
        "triage_summary": {
            "triage_owner": "operator executing this bounded analysis",
            "disposition": "not-run",
            "upstream_route": "not-applicable: no finding is available to route",
            "applicability_rationale": "No completed diagnostic result is available yet.",
        },
    }
    if not archive.is_file():
        report["state"] = "not-run"
        report["reason"] = f"source archive not found: {archive}"
        report["tool_exit"] = None
        return report

    actual_archive_sha = sha256(archive)
    report["component"]["observed_archive_sha256"] = actual_archive_sha
    if actual_archive_sha != EXPECTED_ARCHIVE_SHA256:
        report["state"] = "tool-error"
        report["reason"] = "source archive SHA-256 does not match the pinned recipe"
        report["triage_summary"]["disposition"] = "tool-error-no-analysis-result"
        report["triage_summary"]["applicability_rationale"] = "The input identity failed before analysis; no finding was produced."
        report["tool_exit"] = None
        return report

    try:
        with tempfile.TemporaryDirectory(prefix="openssl-advisory-") as temporary:
            temp = Path(temporary)
            source_root = safe_extract(archive, temp / "source")
            source_file = source_root / SOURCE_RELATIVE
            source_sha = sha256(source_file)
            report["component"]["source_file_sha256"] = source_sha
            if source_sha != EXPECTED_SOURCE_SHA256:
                raise ValueError("selected source file SHA-256 does not match this fixture")
            generated_include = temp / "generated-include" / "openssl"
            generated_include.mkdir(parents=True)
            (generated_include / "configuration.h").write_text(
                """#ifndef OPENSSL_CONFIGURATION_H
#define OPENSSL_CONFIGURATION_H
#define OPENSSL_CONFIGURED_API 40000
#endif
""",
                encoding="utf-8",
            )
            (generated_include / "opensslv.h").write_text(
                """#ifndef OPENSSL_OPENSSLV_H
#define OPENSSL_OPENSSLV_H
#define OPENSSL_VERSION_MAJOR 4
#define OPENSSL_VERSION_MINOR 0
#define OPENSSL_VERSION_PATCH 2
#define OPENSSL_VERSION_STR "4.0.2"
#define OPENSSL_FULL_VERSION_STR "OpenSSL 4.0.2"
#define OPENSSL_VERSION_TEXT "OpenSSL 4.0.2"
#define OPENSSL_VERSION_NUMBER 0x40000020L
#endif
""",
                encoding="utf-8",
            )
            obj = temp / "keccak1600.o"
            command = [
                compiler,
                "-fanalyzer",
                "-Wall",
                "-Wextra",
                "-fdiagnostics-color=never",
                "-fdiagnostics-show-option",
                "-c",
                f"-I{temp / 'generated-include'}",
                f"-I{source_root / 'include'}",
                f"-I{source_root / 'include/internal'}",
                f"-I{source_root / 'crypto/include'}",
                f"-I{source_root}",
                str(source_file),
                "-o",
                str(obj),
            ]
            version = subprocess.run(
                [compiler, "--version"], text=True, capture_output=True, check=False, timeout=10
            )
            if version.returncode != 0:
                report.update(state="tool-error", tool_exit=version.returncode, tool_output=version.stderr.strip())
                report["triage_summary"]["disposition"] = "tool-error-no-analysis-result"
                report["triage_summary"]["applicability_rationale"] = "The compiler version query failed; no finding was produced."
                return report
            result = subprocess.run(
                command, cwd=source_root, text=True, capture_output=True, check=False, timeout=120
            )
            output = (result.stdout + result.stderr).strip()
            warnings = re.findall(r"^.*\bwarning:.*$", output, flags=re.MULTILINE)
            safe_warnings = [line.replace(str(temp), "<TMP>") for line in warnings]
            report["tool"].update(version=version.stdout.splitlines()[0] if version.stdout else "unknown")
            report["command"] = [part.replace(str(temp), "<TMP>") for part in command]
            report["tool_exit"] = result.returncode
            report["output"] = output.replace(str(temp), "<TMP>")
            report["finding_lines"] = safe_warnings
            report["finding_records"] = build_finding_records(
                safe_warnings,
                triage_owner=triage_owner,
                finding_disposition=finding_disposition,
                upstream_route=upstream_route,
                applicability_rationale=applicability_rationale,
            )
            if result.returncode != 0:
                report["state"] = "tool-error"
                report["reason"] = "bounded compiler/analyzer invocation did not complete"
                report["triage_summary"]["disposition"] = "tool-error-no-analysis-result"
                report["triage_summary"]["applicability_rationale"] = "The analyzer invocation failed; no completed finding set is available."
            else:
                report["state"] = "findings" if warnings else "clean"
                report["finding_count"] = len(warnings)
                if warnings:
                    report["triage_summary"] = {
                        "status": "required-per-finding",
                        "finding_count": len(warnings),
                    }
                else:
                    report["triage_summary"] = {
                        "triage_owner": triage_owner or "operator executing this bounded analysis",
                        "disposition": "no-findings",
                        "upstream_route": "not-applicable: no findings",
                        "applicability_rationale": "The completed bounded pass emitted no analyzer warnings.",
                    }
                report["limitations"] = [
                    "one C translation unit only",
                    "minimal configuration header; not the recipe's effective target configuration",
                    "no full OpenSSL build, ASan/UBSan run, recipe ptest, or product image",
                ]
            return report
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as exc:
        report["state"] = "tool-error"
        report["tool_exit"] = None
        report["reason"] = f"bounded diagnostic setup failed: {type(exc).__name__}: {exc}"
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True, help="local OpenSSL 4.0.2 source archive")
    parser.add_argument("--compiler", default="gcc", help="GCC executable or approved absolute path")
    parser.add_argument("--triage-owner", help="responsible owner when analyzer warnings are found")
    parser.add_argument("--finding-disposition", help="triage disposition for analyzer warnings")
    parser.add_argument("--upstream-route", help="issue/patch route or reason no upstream route applies")
    parser.add_argument("--applicability-rationale", help="why each warning does or does not apply")
    parser.add_argument("--output", type=Path, help="write report JSON to this path as well as stdout")
    args = parser.parse_args()
    report = run(
        args.archive,
        args.compiler,
        triage_owner=args.triage_owner,
        finding_disposition=args.finding_disposition,
        upstream_route=args.upstream_route,
        applicability_rationale=args.applicability_rationale,
    )
    if report.get("finding_records") and args.applicability_rationale:
        for finding in report["finding_records"]:
            finding["applicability_rationale"] = args.applicability_rationale
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
