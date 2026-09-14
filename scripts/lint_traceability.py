#!/usr/bin/env python3
"""Validate the Doorstop-backed security analysis data model.

Doorstop owns document-tree/link integrity. This sidecar owns the domain schema:
stable record kinds, required fields, enumerations, source references, and the
separate warning-only completeness assessment.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - exercised by CI setup failure
    raise SystemExit("PyYAML is required; install requirements-dev.txt") from exc

ROOT = Path(__file__).resolve().parents[1]
TRACEABILITY = ROOT / "traceability"

DOC_SPECS = {
    "requirements": {"prefix": "REQ", "parent": None, "kind": "requirement"},
    "entrypoints": {"prefix": "EP", "parent": "REQ", "kind": "entrypoint"},
    "risks": {"prefix": "RISK", "parent": "EP", "kind": "risk"},
    "controls": {"prefix": "CTRL", "parent": "RISK", "kind": "control"},
    "verification": {"prefix": "VER", "parent": "CTRL", "kind": "verification"},
}

BASE_FIELDS = {
    "active",
    "derived",
    "header",
    "level",
    "links",
    "normative",
    "ref",
    "reviewed",
    "text",
}
REQUIRED_FIELDS = {
    "requirements": {"record_type", "status", "source_refs"},
    "entrypoints": {
        "record_type",
        "kind",
        "status",
        "disposition",
        "source",
        "representation",
        "sink",
        "trust_boundary",
        "code_refs",
    },
    "risks": {
        "record_type",
        "finding_id",
        "risk_status",
        "severity",
        "confidence",
        "evidence_class",
        "preconditions",
        "impact",
        "evidence",
        "remediation",
        "regression",
        "residual_uncertainty",
        "code_refs",
        "evidence_refs",
    },
    "controls": {
        "record_type",
        "control_status",
        "control_type",
        "implementation",
        "operational_mitigation",
        "evidence_needed",
    },
    "verification": {
        "record_type",
        "verification_status",
        "method",
        "command",
        "expected",
        "observed",
        "evidence_refs",
    },
}
ENUMS = {
    "requirements.status": {"active", "partial", "closed"},
    "entrypoints.status": {"covered", "partial", "unverified"},
    "entrypoints.disposition": {
        "trust-contract",
        "finding",
        "hypothesis",
        "control",
        "gap",
        "unverified",
    },
    "entrypoints.kind": {
        "metadata",
        "uri",
        "archive",
        "git",
        "submodule",
        "npm",
        "lockfile",
        "cache",
        "stamp",
        "sstate",
        "environment",
        "worker",
        "later-task",
        "evidence",
        "release",
    },
    "risks.risk_status": {
        "confirmed",
        "source-supported",
        "hypothesis",
        "operational-risk",
        "open-gap",
    },
    "risks.severity": {"critical", "high", "medium", "low"},
    "risks.confidence": {"high", "medium", "low"},
    "risks.evidence_class": {
        "fixture-confirmed",
        "source-confirmed",
        "source-supported",
        "hypothesis",
        "not-run",
    },
    "controls.control_status": {"proposed", "partial", "operational", "verified"},
    "controls.control_type": {
        "code",
        "test",
        "operational",
        "process",
        "code-and-test",
        "code-and-operational",
        "process-and-operational",
        "operational-and-process",
    },
    "verification.verification_status": {
        "passed",
        "observed",
        "planned",
        "not-run",
        "blocked",
        "partial",
    },
    "verification.method": {
        "source-review",
        "fixture",
        "integration",
        "operational",
        "release",
    },
}
UID_RE = re.compile(r"^[A-Z]+[0-9]{3}$")
LINE_RE = re.compile(r"^[0-9]+(?:-[0-9]+)?$")
REVISION_RE = re.compile(r"^(?:[0-9a-f]{40}|worktree)$")


class UniqueSafeLoader(yaml.SafeLoader):
    """SafeLoader variant that rejects duplicate mapping keys."""


def _construct_mapping(loader: UniqueSafeLoader, node: yaml.MappingNode, deep: bool = False):
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.YAMLError(f"duplicate YAML key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def load_yaml(path: Path, errors: list[str]) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return yaml.load(handle, Loader=UniqueSafeLoader)
    except (OSError, yaml.YAMLError) as exc:
        errors.append(f"{path.relative_to(ROOT)}: invalid YAML: {exc}")
        return None


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def link_uid(link: Any) -> str | None:
    """Return the UID from Doorstop's string or {UID: fingerprint} form."""
    if isinstance(link, str):
        return link
    if isinstance(link, dict) and len(link) == 1:
        candidate = next(iter(link))
        if isinstance(candidate, str):
            return candidate
    return None


def validate_links(path: Path, links: Any, errors: list[str]) -> list[str]:
    if not isinstance(links, list):
        errors.append(f"{rel(path)}: links must be a list")
        return []
    uids: list[str] = []
    for link in links:
        uid = link_uid(link)
        if uid is None or not UID_RE.fullmatch(uid):
            errors.append(f"{rel(path)}: links must contain UID strings or Doorstop mappings")
        else:
            uids.append(uid)
    return uids


def validate_code_refs(path: Path, value: Any, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append(f"{rel(path)}: code_refs must be a non-empty list")
        return
    expected = {"repository", "path", "lines", "revision"}
    for index, reference in enumerate(value):
        label = f"{rel(path)}: code_refs[{index}]"
        if not isinstance(reference, dict):
            errors.append(f"{label} must be a mapping")
            continue
        missing = expected - set(reference)
        extra = set(reference) - expected
        if missing:
            errors.append(f"{label} missing keys: {sorted(missing)}")
        if extra:
            errors.append(f"{label} unknown keys: {sorted(extra)}")
        if not nonempty(reference.get("repository")):
            errors.append(f"{label}.repository must be non-empty")
        ref_path = reference.get("path")
        if (
            not isinstance(ref_path, str)
            or not ref_path.strip()
            or ref_path.startswith("/")
            or ".." in Path(ref_path).parts
        ):
            errors.append(f"{label}.path must be a relative repository path")
        if not isinstance(reference.get("lines"), str) or not LINE_RE.fullmatch(
            reference["lines"]
        ):
            errors.append(f"{label}.lines must look like N or N-M")
        if not isinstance(reference.get("revision"), str) or not REVISION_RE.fullmatch(
            reference["revision"]
        ):
            errors.append(f"{label}.revision must be a 40-hex revision or worktree")


def validate_string_list(path: Path, key: str, value: Any, errors: list[str]) -> None:
    if not isinstance(value, list) or not value or not all(nonempty(v) for v in value):
        errors.append(f"{rel(path)}: {key} must be a non-empty list of strings")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict-completeness",
        action="store_true",
        help="turn completeness warnings into a non-zero result (not used by CI)",
    )
    args = parser.parse_args()

    errors: list[str] = []
    warnings: list[tuple[Path | None, str]] = []
    records: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)

    if not TRACEABILITY.is_dir():
        errors.append("traceability: missing Doorstop root directory")
        return report(errors, warnings, args.strict_completeness)

    expected_dirs = set(DOC_SPECS)
    actual_dirs = {path.name for path in TRACEABILITY.iterdir() if path.is_dir()}
    for missing in sorted(expected_dirs - actual_dirs):
        errors.append(f"traceability: missing document directory {missing}")
    for extra in sorted(actual_dirs - expected_dirs):
        errors.append(f"traceability: unexpected document directory {extra}")

    for dirname, spec in DOC_SPECS.items():
        directory = TRACEABILITY / dirname
        if not directory.is_dir():
            continue
        config_path = directory / ".doorstop.yml"
        config = load_yaml(config_path, errors)
        if not isinstance(config, dict):
            continue
        settings = config.get("settings")
        if not isinstance(settings, dict):
            errors.append(f"{rel(config_path)}: settings must be a mapping")
        else:
            if settings.get("prefix") != spec["prefix"]:
                errors.append(f"{rel(config_path)}: wrong prefix")
            if settings.get("parent") != spec["parent"] and not (
                spec["parent"] is None and "parent" not in settings
            ):
                errors.append(f"{rel(config_path)}: wrong parent")
            if settings.get("digits") != 3:
                errors.append(f"{rel(config_path)}: digits must be 3")
            if settings.get("itemformat") != "yaml":
                errors.append(f"{rel(config_path)}: itemformat must be yaml")
        attributes = config.get("attributes")
        if not isinstance(attributes, dict) or not isinstance(attributes.get("reviewed"), list):
            errors.append(f"{rel(config_path)}: attributes.reviewed must be a list")

        seen_levels: dict[str, Path] = {}
        for item_path in sorted(directory.glob("*.yml")):
            if item_path.name == ".doorstop.yml":
                continue
            item = load_yaml(item_path, errors)
            if not isinstance(item, dict):
                continue
            uid = item_path.stem
            expected_uid = f"{spec['prefix']}{uid[len(spec['prefix']):]}"
            if not UID_RE.fullmatch(uid) or not uid.startswith(spec["prefix"]):
                errors.append(f"{rel(item_path)}: filename is not a {spec['prefix']}### UID")
            if uid != expected_uid:
                errors.append(f"{rel(item_path)}: UID does not match its filename")
            records[dirname][uid] = item

            allowed = BASE_FIELDS | set(REQUIRED_FIELDS[dirname])
            unknown = set(item) - allowed
            if unknown:
                errors.append(f"{rel(item_path)}: unknown fields: {sorted(unknown)}")
            missing = REQUIRED_FIELDS[dirname] - set(item)
            if missing:
                errors.append(f"{rel(item_path)}: missing fields: {sorted(missing)}")

            for field in ("active", "derived", "normative"):
                if not isinstance(item.get(field), bool):
                    errors.append(f"{rel(item_path)}: {field} must be boolean")
            if not nonempty(item.get("header")) or not nonempty(item.get("text")):
                errors.append(f"{rel(item_path)}: header and text must be non-empty strings")
            validate_links(item_path, item.get("links"), errors)
            if item.get("reviewed") is not None and not isinstance(item.get("reviewed"), str):
                errors.append(f"{rel(item_path)}: reviewed must be null or a string")
            level = item.get("level")
            level_key = str(level)
            if not isinstance(level, (int, float, str)) or not re.fullmatch(
                r"^[0-9]+(?:\.[0-9]+)+$", level_key
            ):
                errors.append(f"{rel(item_path)}: level must be numeric dotted notation")
            elif level_key in seen_levels:
                errors.append(
                    f"{rel(item_path)}: duplicate level {level_key}; already used by "
                    f"{rel(seen_levels[level_key])}"
                )
            else:
                seen_levels[level_key] = item_path

            for field in REQUIRED_FIELDS[dirname] - {"record_type", "source_refs", "code_refs", "evidence_refs"}:
                value = item.get(field)
                if field in {"kind", "status", "disposition", "risk_status", "severity", "confidence", "evidence_class", "control_status", "control_type", "verification_status", "method"}:
                    allowed_values = ENUMS.get(f"{dirname}.{field}", set())
                    if value not in allowed_values:
                        errors.append(
                            f"{rel(item_path)}: {field}={value!r} is not one of "
                            f"{sorted(allowed_values)}"
                        )
                elif field == "finding_id":
                    if not isinstance(value, str) or not re.fullmatch(r"F-[0-9]{3}", value):
                        errors.append(f"{rel(item_path)}: finding_id must be F-###")
                elif not nonempty(value):
                    errors.append(f"{rel(item_path)}: {field} must be non-empty text")
            for field in ("source_refs", "evidence_refs"):
                if field in REQUIRED_FIELDS[dirname]:
                    validate_string_list(item_path, field, item.get(field), errors)
            if "code_refs" in REQUIRED_FIELDS[dirname]:
                validate_code_refs(item_path, item.get("code_refs"), errors)
            if item.get("record_type") != spec["kind"]:
                errors.append(
                    f"{rel(item_path)}: record_type must be {spec['kind']!r}"
                )

    # Check parent-link syntax and target existence after all records are loaded.
    by_uid: dict[str, tuple[str, dict[str, Any], Path]] = {}
    for dirname, items in records.items():
        for uid, item in items.items():
            by_uid[uid] = (dirname, item, TRACEABILITY / dirname / f"{uid}.yml")
    for dirname, spec in DOC_SPECS.items():
        for uid, item in records.get(dirname, {}).items():
            path = TRACEABILITY / dirname / f"{uid}.yml"
            links = item.get("links", [])
            for raw_link in links:
                link = link_uid(raw_link)
                if link is None or not UID_RE.fullmatch(link):
                    errors.append(f"{rel(path)}: links must contain UID strings or Doorstop mappings")
                    continue
                target = by_uid.get(link)
                if target is None:
                    errors.append(f"{rel(path)}: link target {link} does not exist")
                elif spec["parent"] is None or not link.startswith(spec["parent"]):
                    errors.append(
                        f"{rel(path)}: link {link} must target document prefix {spec['parent']}"
                    )
            if spec["parent"] is None and links:
                errors.append(f"{rel(path)}: root requirements must not have parent links")
            if spec["parent"] is not None and not links:
                errors.append(f"{rel(path)}: active child record must have a parent link")

    # Deterministic warning-only completeness checks.
    child_dirs = {
        "requirements": "entrypoints",
        "entrypoints": "risks",
        "risks": "controls",
        "controls": "verification",
    }
    for parent_dir, child_dir in child_dirs.items():
        child_items = records.get(child_dir, {})
        linked_parents = {
            link_uid(link)
            for item in child_items.values()
            for link in item.get("links", [])
            if link_uid(link) is not None
        }
        for uid, item in records.get(parent_dir, {}).items():
            if item.get("active") and uid not in linked_parents:
                warnings.append(
                    (TRACEABILITY / parent_dir / f"{uid}.yml", f"no linked child record in {child_dir}")
                )

    for uid, item in records.get("entrypoints", {}).items():
        if item.get("active") and item.get("status") != "covered":
            warnings.append(
                (TRACEABILITY / "entrypoints" / f"{uid}.yml", "entry point is not marked covered")
            )
    for uid, item in records.get("risks", {}).items():
        if item.get("active") and item.get("evidence_class") not in {"fixture-confirmed"}:
            warnings.append(
                (
                    TRACEABILITY / "risks" / f"{uid}.yml",
                    "risk lacks fixture-confirmed or product-specific evidence",
                )
            )
    for uid, item in records.get("verification", {}).items():
        if item.get("active") and item.get("verification_status") != "passed":
            warnings.append(
                (
                    TRACEABILITY / "verification" / f"{uid}.yml",
                    f"verification status is {item.get('verification_status')!r}, not passed",
                )
            )

    return report(errors, warnings, args.strict_completeness, records)


def report(
    errors: list[str],
    warnings: list[tuple[Path | None, str]],
    strict_completeness: bool,
    records: dict[str, dict[str, dict[str, Any]]] | None = None,
) -> int:
    for message in errors:
        print(f"ERROR: {message}", file=sys.stderr)
    for path, message in warnings:
        if path is None:
            print(f"WARNING: {message}")
        else:
            print(f"::warning file={rel(path)}::{message}")
    if records is not None:
        counts = " ".join(f"{name}={len(records.get(name, {}))}" for name in DOC_SPECS)
        print(f"traceability records: {counts}")
    print(f"traceability errors: {len(errors)}; completeness warnings: {len(warnings)}")
    if errors:
        return 1
    if strict_completeness and warnings:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
