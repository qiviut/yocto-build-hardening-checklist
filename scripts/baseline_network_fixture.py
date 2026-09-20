#!/usr/bin/env python3
"""Prove the fetcher-level effect of the reference and offline profiles.

The only network endpoint is a temporary HTTP server bound to loopback. The
fixture is deliberately below the BitBake task boundary: it proves fetcher
behavior, not host-level egress denial or product reachability.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.server
import importlib
import io
import json
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

EXPECTED_BITBAKE = "046a90b0e9b7b914b7a95aec579cdc3fc9c7617a"


class FixtureServer(http.server.SimpleHTTPRequestHandler):
    requests: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        self.requests.append(self.path)
        super().do_GET()

    def log_message(self, format: str, *_args: object) -> None:
        return


def source_revision(bitbake_root: Path) -> str:
    if not (bitbake_root / ".git").exists():
        raise RuntimeError(f"BitBake is not a Git checkout: {bitbake_root}")
    revision = subprocess.check_output(
        ["git", "-C", str(bitbake_root), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != EXPECTED_BITBAKE:
        raise RuntimeError(f"BitBake revision {revision} != expected {EXPECTED_BITBAKE}")
    status = subprocess.check_output(
        [
            "git",
            "-C",
            str(bitbake_root),
            "status",
            "--short",
            "--untracked-files=all",
        ],
        text=True,
    ).strip()
    if status:
        raise RuntimeError(f"BitBake checkout is not clean: {status}")
    return revision


def profile_data(bb: Any, root: Path, network: str) -> Any:
    data = bb.data.init()
    data.setVar("DL_DIR", str(root / "downloads"))
    data.setVar("PERSISTENT_DIR", str(root / "persistent"))
    data.setVar("FILESPATH", str(root))
    data.setVar("PATH", os.environ["PATH"])
    data.setVar("BB_NO_NETWORK", network)
    data.setVar("BB_STRICT_CHECKSUM", "1")
    data.setVar("HOME", str(root / "home"))
    return data


def run_case(bb: Any, root: Path, no_network: str, expected: str) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    payload = b"reference-baseline fixture\n"
    fixture = root / "fixture.txt"
    fixture.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    FixtureServer.requests = []
    handler = lambda *args, **kwargs: FixtureServer(*args, directory=str(root), **kwargs)
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler) as server:
        server.daemon_threads = True
        port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{port}/fixture.txt;sha256sum={digest}"
            data = profile_data(bb, root, no_network)
            fetcher = bb.fetch.Fetch([url], data)
            outcome = "returned"
            localpath: Path | None = None
            try:
                fetcher.download()
                localpath = Path(data.getVar("DL_DIR")) / "fixture.txt"
            except Exception as exc:  # The exception class is the observed result.
                outcome = type(exc).__name__
            downloaded = localpath is not None and localpath.exists()
            bytes_match = bool(downloaded and localpath is not None and localpath.read_bytes() == payload)
            result = {
                "BB_NO_NETWORK": no_network,
                "expected_outcome": expected,
                "outcome": outcome,
                "server_requests": len(FixtureServer.requests),
                "downloaded_bytes_match": bytes_match,
            }
        finally:
            server.shutdown()
            thread.join(timeout=5)
    validate_case(result, expected)
    return result


def validate_case(result: dict[str, Any], expected: str) -> None:
    if result["outcome"] != expected:
        raise AssertionError(result)
    expected_requests = 1 if expected == "returned" else 0
    if result["server_requests"] != expected_requests:
        raise AssertionError(result)
    expected_bytes_match = expected == "returned"
    if result["downloaded_bytes_match"] is not expected_bytes_match:
        raise AssertionError(result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitbake-root", required=True, type=Path)
    args = parser.parse_args()
    bitbake_root = args.bitbake_root.resolve()
    lib = bitbake_root / "lib"
    if not (lib / "bb").is_dir():
        parser.error(f"not a BitBake checkout: {bitbake_root}")
    revision = source_revision(bitbake_root)
    sys.path.insert(0, str(lib))
    bb = importlib.import_module("bb")
    importlib.import_module("bb.data")
    importlib.import_module("bb.fetch")
    with tempfile.TemporaryDirectory(prefix="yocto-baseline-network-") as temporary:
        root = Path(temporary)
        downloader_output = io.StringIO()
        with contextlib.redirect_stdout(downloader_output):
            reference = run_case(bb, root / "reference", "0", "returned")
            mitigation = run_case(bb, root / "mitigation", "1", "NetworkAccess")
        if downloader_output.getvalue():
            print(downloader_output.getvalue(), file=sys.stderr, end="")
    output = {
        "bitbake_revision": revision,
        "scope": "fetcher-level loopback-only fixture; no external network",
        "reference": reference,
        "mitigation": mitigation,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
