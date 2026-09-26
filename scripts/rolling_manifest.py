#!/usr/bin/env python3
"""Validate rolling Yocto input manifests and exercise a local replay fixture.

The replay path is synthetic and never builds or certifies a product image.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_manifest(document: Any, root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["manifest must be a JSON object"]
    if document.get("schema_version") != 1:
        errors.append("schema_version must equal 1")
    candidate = document.get("candidate")
    if not isinstance(candidate, dict):
        errors.append("candidate must be an object")
    else:
        if candidate.get("ref") != "master":
            errors.append("candidate.ref must record the moving intake ref 'master'")
        status = candidate.get("status")
        if status not in {"not-promoted", "promoted"}:
            errors.append("candidate.status must be not-promoted or promoted")
        if not isinstance(candidate.get("reason"), str) or not candidate["reason"].strip():
            errors.append("candidate.reason must explain the promotion decision")
        promotion = candidate.get("promotion_evidence")
        if status == "promoted":
            if not isinstance(promotion, dict):
                errors.append("promoted candidates require promotion_evidence")
            else:
                if not isinstance(promotion.get("decision_owner"), str) or not promotion["decision_owner"].strip():
                    errors.append("promotion_evidence.decision_owner must be non-empty text")
                gates = promotion.get("gates")
                required_gates = ("parse", "build", "tests", "security")
                if not isinstance(gates, dict):
                    errors.append("promotion_evidence.gates must record parse, build, tests, and security")
                else:
                    for gate_name in required_gates:
                        gate = gates.get(gate_name)
                        label = f"promotion_evidence.gates.{gate_name}"
                        if not isinstance(gate, dict):
                            errors.append(f"{label} must contain passed status and evidence identity")
                            continue
                        if gate.get("status") != "passed":
                            errors.append(f"{label}.status must be passed before promotion")
                        if not isinstance(gate.get("evidence_ref"), str) or not gate["evidence_ref"].strip():
                            errors.append(f"{label}.evidence_ref must identify retained gate evidence")
                        if not isinstance(gate.get("evidence_sha256"), str) or not SHA256.fullmatch(gate["evidence_sha256"]):
                            errors.append(f"{label}.evidence_sha256 must be a full lowercase SHA-256")
        elif promotion is not None:
            errors.append("not-promoted candidates must not carry promotion_evidence")

    intake_outcome = document.get("intake_outcome")
    if intake_outcome is not None:
        if not isinstance(intake_outcome, dict):
            errors.append("intake_outcome must be an object")
        elif intake_outcome.get("status") == "rejected":
            if not isinstance(candidate, dict) or candidate.get("status") != "not-promoted":
                errors.append("a rejected intake must remain not-promoted")
            if intake_outcome.get("gate_result") not in {"failed", "incomplete"}:
                errors.append("a rejected intake must name a failed or incomplete gate")
            if not isinstance(intake_outcome.get("failed_gate"), str) or not intake_outcome["failed_gate"].strip():
                errors.append("a rejected intake must identify failed_gate")
            if not isinstance(intake_outcome.get("evidence_ref"), str) or not intake_outcome["evidence_ref"].strip():
                errors.append("a rejected intake must retain its gate evidence reference")
            previous = intake_outcome.get("previous_candidate")
            if not isinstance(previous, dict) or previous.get("retained_unchanged") is not True:
                errors.append("a rejected intake must record the prior candidate as retained unchanged")
            else:
                identity = previous.get("identity")
                identity_sha = previous.get("identity_sha256")
                if not isinstance(identity, dict) or not isinstance(identity_sha, str) or not SHA256.fullmatch(identity_sha) or canonical_digest(identity) != identity_sha:
                    errors.append("the retained prior candidate needs a canonical identity SHA-256")
        elif intake_outcome.get("status") == "accepted":
            if not isinstance(candidate, dict) or candidate.get("status") != "promoted":
                errors.append("accepted intake_outcome requires candidate.status promoted")
        elif intake_outcome.get("status") == "not-run":
            if isinstance(candidate, dict) and candidate.get("status") == "promoted":
                errors.append("not-run intake_outcome cannot accompany a promoted candidate")
        else:
            errors.append("intake_outcome.status must be accepted, rejected, or not-run")

    repositories = document.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        errors.append("repositories must be a non-empty list")
        repositories = []
    names: set[str] = set()
    repositories_by_name: dict[str, dict[str, Any]] = {}
    for index, repo in enumerate(repositories):
        label = f"repositories[{index}]"
        if not isinstance(repo, dict):
            errors.append(f"{label} must be an object")
            continue
        name, url, revision, role = (repo.get(k) for k in ("name", "url", "revision", "role"))
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{label}.name must be non-empty text")
        elif name in names:
            errors.append(f"{label} duplicates repository name {name!r}")
        else:
            names.add(name)
            repositories_by_name[name] = repo
        if not isinstance(url, str) or not url.strip() or not isinstance(role, str) or not role.strip():
            errors.append(f"{label} needs non-empty url and role")
        if not isinstance(revision, str) or not SHA40.fullmatch(revision):
            errors.append(f"{label}.revision must be a full lowercase 40-hex commit")

    layers = document.get("selected_layers")
    if not isinstance(layers, list):
        errors.append("selected_layers must be a list")
        layers = []
    for index, layer in enumerate(layers):
        if not isinstance(layer, dict):
            errors.append(f"selected_layers[{index}] must be an object")
            continue
        layer_repository = layer.get("repository")
        layer_revision = layer.get("revision")
        selected_repo = repositories_by_name.get(layer_repository) if isinstance(layer_repository, str) else None
        if selected_repo is None:
            errors.append(f"selected_layers[{index}].repository must name an evaluated repository")
        elif layer_revision != selected_repo.get("revision"):
            errors.append(f"selected_layers[{index}].revision must match its named repository SHA")
        if not isinstance(layer.get("path"), str) or not layer["path"].strip():
            errors.append(f"selected_layers[{index}].path must be non-empty")

    recipes = document.get("recipe_sources")
    if not isinstance(recipes, list) or not recipes:
        errors.append("recipe_sources must contain at least one revision-bound recipe source")
        recipes = []
    for index, recipe in enumerate(recipes):
        label = f"recipe_sources[{index}]"
        if not isinstance(recipe, dict):
            errors.append(f"{label} must be an object")
            continue
        metadata_repository = recipe.get("metadata_repository")
        metadata_revision = recipe.get("metadata_revision")
        metadata_repo = repositories_by_name.get(metadata_repository) if isinstance(metadata_repository, str) else None
        if metadata_repo is None:
            errors.append(f"{label}.metadata_repository must name an evaluated repository")
        elif metadata_revision != metadata_repo.get("revision"):
            errors.append(f"{label}.metadata_revision must match its named repository SHA")
        if not all(isinstance(recipe.get(k), str) and recipe[k].strip() for k in ("recipe", "version", "source_uri")):
            errors.append(f"{label} needs recipe, version, and source_uri")
        source_kind = recipe.get("source_kind")
        if source_kind == "archive":
            if recipe.get("integrity_algorithm") != "sha256" or not isinstance(recipe.get("integrity"), str) or not SHA256.fullmatch(recipe["integrity"]):
                errors.append(f"{label} archive source must carry a full SHA-256 integrity value")
        elif source_kind == "git":
            source_repo = recipe.get("source_repository")
            source_revision = recipe.get("source_revision")
            selected_source_repo = repositories_by_name.get(source_repo) if isinstance(source_repo, str) else None
            if selected_source_repo is None or not isinstance(source_revision, str) or not SHA40.fullmatch(source_revision):
                errors.append(f"{label} Git source must name a repository and full commit SHA")
            elif source_revision != selected_source_repo.get("revision"):
                errors.append(f"{label}.source_revision must match its named repository SHA")
        else:
            errors.append(f"{label}.source_kind must be archive or git")

    configuration = document.get("configuration")
    if not isinstance(configuration, dict):
        errors.append("configuration must be an object")
    else:
        files = configuration.get("files")
        if not isinstance(files, list) or not files:
            errors.append("configuration.files must be a non-empty list")
            files = []
        for index, item in enumerate(files):
            label = f"configuration.files[{index}]"
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                errors.append(f"{label} needs a repository-relative path")
                continue
            relative = Path(item["path"])
            if relative.is_absolute() or ".." in relative.parts:
                errors.append(f"{label}.path must remain within the repository")
                continue
            target = (root / relative).resolve()
            if not target.is_relative_to(root.resolve()) or not target.is_file():
                errors.append(f"{label}.path must resolve to an existing repository file")
                continue
            expected = item.get("sha256")
            if not isinstance(expected, str) or not SHA256.fullmatch(expected):
                errors.append(f"{label}.sha256 must be 64 lowercase hex characters")
            elif file_digest(target) != expected:
                errors.append(f"{label}.sha256 does not match {item['path']}")
        if not all(isinstance(configuration.get(k), str) and configuration[k].strip() for k in ("machine", "distro")):
            errors.append("configuration.machine and configuration.distro must be non-empty strings")
        identity = configuration.get("identity_sha256")
        payload = {k: v for k, v in configuration.items() if k != "identity_sha256"}
        if not isinstance(identity, str) or not SHA256.fullmatch(identity) or canonical_digest(payload) != identity:
            errors.append("configuration.identity_sha256 does not match the canonical configuration record")

    toolchain = document.get("toolchain")
    if not isinstance(toolchain, dict):
        errors.append("toolchain must be an object")
    else:
        if not isinstance(toolchain.get("host"), dict) or not toolchain["host"]:
            errors.append("toolchain.host must identify the build host/tool versions")
        target = toolchain.get("target")
        if not isinstance(target, dict) or target.get("status") not in {"observed", "not-run"}:
            errors.append("toolchain.target.status must be observed or not-run")
        if isinstance(target, dict) and target.get("status") == "not-run" and not (isinstance(target.get("reason"), str) and target["reason"].strip()):
            errors.append("an unbuilt target toolchain needs a not-run reason")
        identity = toolchain.get("identity_sha256")
        payload = {k: v for k, v in toolchain.items() if k != "identity_sha256"}
        if not isinstance(identity, str) or not SHA256.fullmatch(identity) or canonical_digest(payload) != identity:
            errors.append("toolchain.identity_sha256 does not match the canonical toolchain record")

    digest = document.get("manifest_sha256")
    payload = {k: v for k, v in document.items() if k != "manifest_sha256"}
    if not isinstance(digest, str) or not SHA256.fullmatch(digest) or canonical_digest(payload) != digest:
        errors.append("manifest_sha256 does not match the canonical manifest content")
    return errors


def run_git(
    args: list[str], cwd: Path, env_overrides: dict[str, str] | None = None
) -> str:
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
    result = subprocess.run(
        ["git", *args], cwd=cwd, env=env, text=True, capture_output=True,
        check=False, timeout=20,
    )
    if result.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def replay_fixture() -> dict[str, Any]:
    """Create and replay a local-only source snapshot at its immutable SHA."""
    with tempfile.TemporaryDirectory(prefix="yocto-manifest-replay-") as temporary:
        root = Path(temporary)
        source = root / "source"
        checkout = root / "checkout"
        source.mkdir()
        run_git(["init", "-q"], source)
        run_git(["config", "user.name", "Manifest Fixture"], source)
        run_git(["config", "user.email", "fixture@example.invalid"], source)
        content = b"product-neutral recipe input\n"
        (source / "recipe.conf").write_bytes(content)
        run_git(["add", "recipe.conf"], source)
        run_git(
            ["commit", "-q", "-m", "fixture source"],
            source,
            {
                "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
                "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
            },
        )
        revision = run_git(["rev-parse", "HEAD"], source)
        run_git(["clone", "-q", "--no-hardlinks", str(source), str(checkout)], root)
        run_git(["checkout", "-q", "--detach", revision], checkout)
        actual_revision = run_git(["rev-parse", "HEAD"], checkout)
        actual_digest = file_digest(checkout / "recipe.conf")
        expected_digest = hashlib.sha256(content).hexdigest()
        if actual_revision != revision or actual_digest != expected_digest:
            raise RuntimeError("replayed source does not match its manifest identity")
        return {
            "fixture_only": True,
            "network_used": False,
            "status": "passed",
            "revision": revision,
            "content_sha256": actual_digest,
            "promotes_candidate": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate", help="validate a manifest and its file identities")
    validate_parser.add_argument("manifest", type=Path)
    validate_parser.add_argument("--root", type=Path, default=ROOT)
    validate_parser.add_argument("--output", type=Path, help="write the JSON validation report to this path")
    replay_parser = subparsers.add_parser("replay-fixture", help="exercise exact-SHA replay with a local disposable Git repository")
    replay_parser.add_argument("--output", type=Path, help="write the JSON replay report to this path")
    args = parser.parse_args()
    try:
        if args.command == "validate":
            document = json.loads(args.manifest.read_text(encoding="utf-8"))
            errors = validate_manifest(document, args.root)
            candidate = document.get("candidate")
            purpose = document.get("purpose")
            report = {
                "fixture_only": purpose == "product-neutral-reference" or (isinstance(purpose, str) and purpose.startswith("synthetic-")),
                "status": "failed" if errors else "passed",
                "errors": errors,
                "manifest": str(args.manifest),
                "candidate_status": candidate.get("status") if isinstance(candidate, dict) else "invalid",
                "promotes_candidate": False,
                "promotion_validation": "schema-only; this command never authorizes or performs promotion",
            }
        else:
            report = replay_fixture()
            errors = []
        rendered = json.dumps(report, sort_keys=True, indent=2) + "\n"
        if getattr(args, "output", None):
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        print(rendered, end="")
        return 1 if errors else 0
    except (OSError, json.JSONDecodeError, RuntimeError) as exc:
        print(json.dumps({"status": "failed", "errors": [str(exc)]}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
