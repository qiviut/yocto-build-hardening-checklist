#!/usr/bin/env python3
"""Expand the pinned OE-Core reference and mitigation profiles.

This command performs parse-only configuration evidence. It never builds an
image, fetches a source, or modifies either component checkout.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

EXPECTED_REVISIONS = {
    "bitbake": "046a90b0e9b7b914b7a95aec579cdc3fc9c7617a",
    "openembedded-core": "f94ae3d6ba49aef86f497998c0e0232a5039510a",
}
PROFILE_FILES = {
    "reference": Path("baseline/reference/local.conf"),
    "mitigation": Path("baseline/mitigation/offline-and-signed-sstate.conf"),
}
REPORT_VARIABLES = (
    "MACHINE",
    "DISTRO",
    "BB_NO_NETWORK",
    "BB_STRICT_CHECKSUM",
    "SSTATE_VERIFY_SIG",
)
ASSIGNMENT = re.compile(r"^([A-Z][A-Z0-9_]*)\s*(?:\?=|\+=|=)\s*(.*)$")


def source_revision(root: Path, name: str) -> str:
    if not (root / ".git").exists():
        raise RuntimeError(f"{name} is not a Git checkout: {root}")
    revision = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    expected = EXPECTED_REVISIONS[name]
    if revision != expected:
        raise RuntimeError(f"{name} revision {revision} != expected {expected}")
    status = subprocess.check_output(
        ["git", "-C", str(root), "status", "--short"], text=True
    ).strip()
    if status:
        raise RuntimeError(f"{name} checkout is not clean: {status}")
    return revision


def parse_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def parse_environment(output: str) -> dict[str, str | None]:
    values: dict[str, str | None] = {}
    for line in output.splitlines():
        match = ASSIGNMENT.match(line)
        if match and match.group(1) in REPORT_VARIABLES:
            values[match.group(1)] = parse_value(match.group(2))
    return {name: values.get(name) for name in REPORT_VARIABLES}


def make_probe_shims(directory: Path) -> list[str]:
    missing = [name for name in ("chrpath", "diffstat") if shutil.which(name) is None]
    for name in missing:
        path = directory / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
    return missing


def run_profile(
    repo_root: Path,
    bitbake_root: Path,
    oe_root: Path,
    profile: str,
    skip_sanity: bool,
) -> dict[str, Any]:
    profile_path = repo_root / PROFILE_FILES[profile]
    with tempfile.TemporaryDirectory(prefix=f"yocto-{profile}-") as temporary:
        temp = Path(temporary)
        build = temp / "build"
        shims = temp / "hosttool-shims"
        shims.mkdir()
        postread = temp / "postread.conf"
        postread.write_text(
            'INHERIT:remove = "sanity"\n' if skip_sanity else "",
            encoding="utf-8",
        )
        shimmed = make_probe_shims(shims) if skip_sanity else []
        environment = os.environ.copy()
        path_entries = [str(bitbake_root / "bin")]
        if shimmed:
            path_entries.insert(0, str(shims))
        environment["PATH"] = os.pathsep.join(path_entries + [environment["PATH"]])
        shell = r'''set -e
source "$1/oe-init-build-env" "$2" >"$3"
expected_bitbake=$(readlink -f "$7/bin/bitbake")
actual_bitbake=$(readlink -f "$(command -v bitbake)")
if [ "$actual_bitbake" != "$expected_bitbake" ]; then
    printf 'BitBake path mismatch: expected %s, got %s\n' "$expected_bitbake" "$actual_bitbake" >&2
    exit 1
fi
cat "$4" >> "$2/conf/local.conf"
if [ "$6" = "1" ]; then
    bitbake -R "$5" -e core-image-minimal
else
    bitbake -e core-image-minimal
fi
'''
        result = subprocess.run(
            [
                "bash",
                "-lc",
                shell,
                "baseline-probe",
                str(oe_root),
                str(build),
                str(temp / "setup.log"),
                str(profile_path),
                str(postread),
                "1" if skip_sanity else "0",
                str(bitbake_root),
            ],
            cwd=repo_root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        report: dict[str, Any] = {
            "profile": profile,
            "status": "passed" if result.returncode == 0 else "blocked",
            "returncode": result.returncode,
            "sanity_skipped": skip_sanity,
            "temporary_hosttool_shims": shimmed,
            "effective_variables": parse_environment(result.stdout),
        }
        if result.returncode:
            report["stdout_tail"] = result.stdout.splitlines()[-12:]
            report["stderr_tail"] = result.stderr.splitlines()[-8:]
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitbake-root", required=True, type=Path)
    parser.add_argument("--oe-root", required=True, type=Path)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="analysis repository root (defaults to this script's repository)",
    )
    parser.add_argument(
        "--skip-sanity",
        action="store_true",
        help="remove OE-Core's sanity class for parse-only host evidence",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    bitbake_root = args.bitbake_root.resolve()
    oe_root = args.oe_root.resolve()
    revisions = {
        "bitbake": source_revision(bitbake_root, "bitbake"),
        "openembedded-core": source_revision(oe_root, "openembedded-core"),
    }
    profiles = [
        run_profile(repo_root, bitbake_root, oe_root, name, args.skip_sanity)
        for name in ("reference", "mitigation")
    ]
    output = {
        "source_revisions": revisions,
        "profiles": profiles,
        "scope": "parse-only configuration expansion; no image build or source fetch",
    }
    encoded = json.dumps(output, indent=2, sort_keys=True) + "\n"
    if args.output:
        destination = args.output if args.output.is_absolute() else repo_root / args.output
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if all(item["status"] == "passed" for item in profiles) else 1


if __name__ == "__main__":
    raise SystemExit(main())
