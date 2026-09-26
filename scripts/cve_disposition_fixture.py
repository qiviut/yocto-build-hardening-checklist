#!/usr/bin/env python3
"""Validate a synthetic Yocto CVE disposition fixture.

This checks a documented workflow shape, not an actual image SBOM or CVE result.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_STATES = {"Patched", "Unpatched", "Ignored"}


def validate(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        return ["fixture must be a schema_version 1 JSON object"]
    if document.get("scope") != "synthetic-product-neutral-fixture":
        errors.append("scope must explicitly identify a synthetic product-neutral fixture")
    if document.get("product_evidence") != "not-run":
        errors.append("product_evidence must remain not-run")
    manifest_sha = document.get("candidate_manifest_sha256")
    if not isinstance(manifest_sha, str) or not SHA256.fullmatch(manifest_sha):
        errors.append("candidate_manifest_sha256 must be a full SHA-256 digest")
    else:
        manifest = ROOT / "fixtures/rolling-intake/reference-snapshot.json"
        try:
            source = json.loads(manifest.read_text(encoding="utf-8"))
            if source.get("manifest_sha256") != manifest_sha:
                errors.append("candidate_manifest_sha256 does not match the referenced fixture manifest")
        except (OSError, json.JSONDecodeError):
            errors.append("referenced rolling intake manifest is unavailable or invalid")
    records = document.get("records")
    if not isinstance(records, list):
        errors.append("records must be a list")
        records = []
    states: set[str] = set()
    ids: set[str] = set()
    for index, record in enumerate(records):
        label = f"records[{index}]"
        if not isinstance(record, dict):
            errors.append(f"{label} must be an object")
            continue
        cve_id = record.get("cve")
        state = record.get("report_status")
        if not isinstance(cve_id, str) or not CVE_ID.fullmatch(cve_id) or cve_id in ids:
            errors.append(f"{label}.cve must be a unique CVE identifier")
        else:
            ids.add(cve_id)
        if state not in REQUIRED_STATES:
            errors.append(f"{label}.report_status must be Patched, Unpatched, or Ignored")
        else:
            states.add(state)
        required = ("package", "version", "mapping_note", "applicability", "evidence", "owner", "action", "recheck")
        for field in required:
            if not isinstance(record.get(field), str) or not record[field].strip():
                errors.append(f"{label}.{field} must be non-empty")
        if state == "Ignored" and not (isinstance(record.get("ignore_rationale"), str) and record["ignore_rationale"].strip()):
            errors.append(f"{label}.ignore_rationale is required for Ignored")
        evidence_ref = record.get("evidence_ref")
        if not isinstance(evidence_ref, str) or not evidence_ref.strip():
            errors.append(f"{label}.evidence_ref must identify inspectable fixture evidence")
        elif not (ROOT / evidence_ref).is_file():
            errors.append(f"{label}.evidence_ref does not exist in the repository")
    if states != REQUIRED_STATES:
        errors.append(f"fixture must cover exactly these report states: {sorted(REQUIRED_STATES)}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=Path, default=ROOT / "fixtures/cve/rolling-cve-fixture.json")
    parser.add_argument("--output", type=Path, help="write the JSON validation report to this path")
    args = parser.parse_args()
    try:
        document = json.loads(args.fixture.read_text(encoding="utf-8"))
        errors = validate(document)
    except (OSError, json.JSONDecodeError) as exc:
        errors = [str(exc)]
    result = {
        "fixture_only": True,
        "status": "failed" if errors else "passed",
        "product_claim": False,
        "errors": errors,
        "input": str(args.fixture),
    }
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
