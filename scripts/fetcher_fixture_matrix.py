#!/usr/bin/env python3
"""Run deterministic, local-only BitBake fetch/unpack boundary fixtures."""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import importlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable


def add_tar_member(
    archive: tarfile.TarFile,
    name: str,
    kind: str = "file",
    content: bytes = b"marker\n",
    linkname: str = "",
) -> None:
    info = tarfile.TarInfo(name)
    if kind == "file":
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    elif kind == "fifo":
        info.type = tarfile.FIFOTYPE
        info.mode = 0o644
        archive.addfile(info)
    elif kind == "symlink":
        info.type = tarfile.SYMTYPE
        info.linkname = linkname
        archive.addfile(info)
    elif kind == "hardlink":
        info.type = tarfile.LNKTYPE
        info.linkname = linkname
        archive.addfile(info)
    else:
        raise ValueError(f"unsupported tar member kind: {kind}")


def make_tar(path: Path) -> None:
    with tarfile.open(path, "w:gz") as archive:
        add_tar_member(archive, "../traversal.txt")
        add_tar_member(archive, "/absolute.txt")
        add_tar_member(archive, "link", "symlink", linkname="../outside")
        add_tar_member(archive, "link/symlink-escaped.txt")
        add_tar_member(archive, "source.txt")
        add_tar_member(
            archive,
            "hard",
            "hardlink",
            linkname="../outside/hardlink-escaped.txt",
        )
        add_tar_member(archive, "fifo", "fifo")


def make_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in ("../zip-traversal.txt", "/zip-absolute.txt", "safe.txt"):
            archive.writestr(name, b"marker\n")
        symlink = zipfile.ZipInfo("zip-link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(symlink, b"../outside")


def make_deb_or_ipk(path: Path, suffix: str) -> None:
    data = path.parent / "data.tar.gz"
    control = path.parent / "control.tar.gz"
    with tarfile.open(data, "w:gz") as archive:
        add_tar_member(archive, f"../{suffix}-traversal.txt")
        add_tar_member(archive, f"{suffix}-safe.txt")
        add_tar_member(archive, f"{suffix}-fifo", "fifo")
    with tarfile.open(control, "w:gz") as archive:
        add_tar_member(archive, "control")
    binary = path.parent / "debian-binary"
    binary.write_text("2.0\n")
    subprocess.run(
        ["ar", "rc", str(path), binary.name, control.name, data.name],
        cwd=path.parent,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def make_npm_package(path: Path) -> None:
    with tarfile.open(path, "w:gz") as archive:
        package_json = {
            "name": "fixture-package",
            "version": "1.0.0",
            "scripts": {"postinstall": "touch lifecycle-marker"},
        }
        for name, payload in {
            "package/package.json": json.dumps(package_json).encode() + b"\n",
            "package/index.js": b"module.exports = 'fixture';\n",
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def list_entries(root: Path) -> list[str]:
    entries: list[str] = []
    for current, directories, files in os.walk(root, followlinks=False):
        for name in sorted(directories + files):
            entries.append(str((Path(current) / name).relative_to(root)))
    return sorted(entries)


def tool_version(command: str) -> str | None:
    if shutil.which(command) is None:
        return None
    try:
        result = subprocess.run(
            [command, "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "available (version query failed)"
    return result.stdout.splitlines()[0] if result.stdout else result.stderr.splitlines()[0]


def run_archive_case(
    bb: Any,
    base: Path,
    name: str,
    suffix: str,
    maker: Callable[[Path], None],
    outside_name: str,
) -> dict[str, Any]:
    case = base / name
    case.mkdir()
    source = case / f"fixture.{suffix}"
    maker(source)
    root = case / "root"
    root.mkdir()
    data = bb.data.init()
    data.setVar("DL_DIR", str(case / "download"))
    data.setVar("FILESPATH", str(case))
    data.setVar("PERSISTENT_DIR", str(case / "persistent"))
    data.setVar("PATH", os.environ["PATH"])
    data.setVar("BB_NO_NETWORK", "1")
    result: dict[str, Any] = {"format": name, "suffix": suffix}
    try:
        fetcher = bb.fetch.Fetch([f"file://fixture.{suffix}"], data)
        fetcher.download()
        fetcher.unpack(str(root))
        result["outcome"] = "returned"
    except Exception as exc:  # The result itself is the fixture observation.
        result["outcome"] = type(exc).__name__
        result["error"] = str(exc)
    outside = case / outside_name
    result["outside_traversal"] = outside.exists()
    result["root_entries"] = list_entries(root)
    result["root_fifo"] = any(
        stat.S_ISFIFO(os.lstat(root / entry).st_mode)
        for entry in result["root_entries"]
        if os.path.lexists(root / entry)
    )
    return result


def run_npmsw_case(bb: Any, base: Path, location: str, package: Path) -> dict[str, Any]:
    name = "normal" if "../" not in location else "traversal"
    case = base / f"npm-{name}"
    case.mkdir()
    shrinkwrap = case / "npm-shrinkwrap.json"
    shrinkwrap.write_text(
        json.dumps(
            {
                "packages": {
                    "": {},
                    location: {
                        "version": "1.0.0",
                        "resolved": f"file://{package}",
                    },
                }
            }
        )
        + "\n"
    )
    data = bb.data.init()
    data.setVar("DL_DIR", str(case / "download"))
    data.setVar("PERSISTENT_DIR", str(case / "persistent"))
    data.setVar("PATH", os.environ["PATH"])
    data.setVar("BB_NO_NETWORK", "1")
    root = case / "root"
    root.mkdir()
    result: dict[str, Any] = {"location": location}
    try:
        fetcher = bb.fetch.Fetch([f"npmsw://{shrinkwrap}"], data)
        # The dependency is a local file: URI; downloading is not needed.
        fetcher.unpack(str(root))
        result["outcome"] = "returned"
    except Exception as exc:  # The result itself is the fixture observation.
        result["outcome"] = type(exc).__name__
        result["error"] = str(exc)
    normal_file = root / "node_modules" / "fixture-package" / "index.js"
    outside = case / "escaped.js"
    result["normal_package_extracted"] = normal_file.exists()
    result["normal_package_content"] = normal_file.read_text().strip() if normal_file.exists() else None
    result["outside_root_path"] = outside.exists()
    result["lifecycle_marker_created"] = (root / "lifecycle-marker").exists()
    result["root_entries"] = list_entries(root)
    return result


def run_npm_lifecycle_case(base: Path, mode: str) -> dict[str, Any]:
    case = base / f"npm-lifecycle-{mode}"
    case.mkdir()
    dependency = case / "dependency"
    dependency.mkdir()
    marker = case / "lifecycle-marker"
    (dependency / "package.json").write_text(
        json.dumps(
            {
                "name": "fixture-package",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": (
                        "node -e \"require('fs').writeFileSync("
                        "process.env.FIXTURE_MARKER, 'ran\\n')\""
                    ),
                },
            }
        )
        + "\n"
    )
    project = case / "project"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps(
            {
                "name": "fixture-consumer",
                "version": "1.0.0",
                "private": True,
                "dependencies": {"fixture-package": f"file:{dependency}"},
            }
        )
        + "\n"
    )
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(case / "home"),
            "NPM_CONFIG_USERCONFIG": "/dev/null",
            "npm_config_cache": str(case / "cache"),
            "npm_config_audit": "false",
            "npm_config_fund": "false",
            "npm_config_update_notifier": "false",
            "FIXTURE_MARKER": str(marker),
        }
    )
    approval_returncode: int | None = None
    bootstrap_returncode: int | None = None
    if mode == "approved":
        bootstrap = subprocess.run(
            [
                "npm",
                "install",
                "--offline",
                "--no-audit",
                "--no-fund",
                "--ignore-scripts",
            ],
            cwd=project,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        bootstrap_returncode = bootstrap.returncode
        approval = subprocess.run(
            ["npm", "install-scripts", "approve", "fixture-package", "--json"],
            cwd=project,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        approval_returncode = approval.returncode
        shutil.rmtree(project / "node_modules")
        (project / "package-lock.json").unlink(missing_ok=True)

    command = ["npm", "install", "--offline", "--no-audit", "--no-fund"]
    if mode == "ignore":
        command.append("--ignore-scripts")
    elif mode == "explicit-allow":
        command.append("--ignore-scripts=false")
    result = subprocess.run(
        command,
        cwd=project,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    return {
        "mode": mode,
        "bootstrap_returncode": bootstrap_returncode,
        "approval_returncode": approval_returncode,
        "returncode": result.returncode,
        "marker_created": marker.exists(),
        "stderr_tail": result.stderr.splitlines()[-3:],
    }


def run_npm_lifecycle(base: Path) -> dict[str, Any]:
    return {
        "npm_version": tool_version("npm"),
        "cases": [
            run_npm_lifecycle_case(base, mode)
            for mode in ("default", "ignore", "explicit-allow", "approved")
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bitbake-root",
        required=True,
        type=Path,
        help="path to the read-only BitBake checkout under review",
    )
    args = parser.parse_args()
    bitbake_root = args.bitbake_root.resolve()
    lib = bitbake_root / "lib"
    if not (lib / "bb").is_dir():
        parser.error(f"not a BitBake checkout: {bitbake_root}")
    sys.path.insert(0, str(lib))
    bb: Any = importlib.import_module("bb")
    importlib.import_module("bb.data")
    importlib.import_module("bb.fetch")
    npm_integrity = importlib.import_module("bb.fetch.npm").npm_integrity

    source_revision = subprocess.check_output(
        ["git", "-C", str(bitbake_root), "rev-parse", "HEAD"], text=True
    ).strip()
    with tempfile.TemporaryDirectory(prefix="bb-fetch-fixtures-") as temp:
        base = Path(temp)
        package = base / "npm-package.tgz"
        make_npm_package(package)
        digest = hashlib.sha512(package.read_bytes()).digest()
        integrity = "sha512-" + base64.b64encode(digest).decode()
        checksum_name, checksum_value = npm_integrity(integrity)
        archives = [
            run_archive_case(bb, base, "tar", "tar.gz", make_tar, "traversal.txt"),
            run_archive_case(bb, base, "zip", "zip", make_zip, "zip-traversal.txt"),
            run_archive_case(
                bb,
                base,
                "deb",
                "deb",
                lambda path: make_deb_or_ipk(path, "deb"),
                "deb-traversal.txt",
            ),
            run_archive_case(
                bb,
                base,
                "ipk",
                "ipk",
                lambda path: make_deb_or_ipk(path, "ipk"),
                "ipk-traversal.txt",
            ),
        ]
        npm = {
            "sri": {
                "checksum_name": checksum_name,
                "integrity_matches_bytes": checksum_value == hashlib.sha512(package.read_bytes()).hexdigest(),
            },
            "cases": [
                run_npmsw_case(bb, base, "node_modules/fixture-package", package),
                run_npmsw_case(bb, base, "node_modules/../../escaped.js", package),
            ],
            "lifecycle": run_npm_lifecycle(base),
        }
        output = {
            "bitbake_revision": source_revision,
            "tools": {
                command: tool_version(command)
                for command in ("tar", "unzip", "ar", "cpio", "7z", "7za", "rpm2cpio.sh", "zstd", "lzip")
            },
            "archives": archives,
            "npm": npm,
            "network": "disabled (BB_NO_NETWORK=1; file:// and local npmsw inputs only)",
        }
        print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
