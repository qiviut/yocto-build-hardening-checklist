#!/usr/bin/env python3
"""Run local-only worker, environment, and sstate-signature probes."""
# pyright: reportMissingImports=false
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def source_revision(path: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
    ).strip()


def network_child(bitbake_root: Path) -> int:
    sys.path.insert(0, str(bitbake_root / "lib"))
    import bb.utils  # pylint: disable=import-outside-toplevel

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    port = listener.getsockname()[1]
    before = os.readlink("/proc/self/ns/net")
    result: dict[str, Any] = {"loopback_port": port, "network_namespace_before": before}
    try:
        bb.utils.disable_network()
        result["helper_outcome"] = "returned"
    except Exception as exc:  # A helper failure is the behavior under review.
        result["helper_outcome"] = type(exc).__name__
    result["network_namespace_after"] = os.readlink("/proc/self/ns/net")
    try:
        probe = socket.create_connection(("127.0.0.1", port), timeout=1)
        probe.close()
        result["loopback_probe"] = "connected"
    except OSError as exc:
        result["loopback_probe"] = type(exc).__name__
    finally:
        listener.close()
    print(json.dumps(result, sort_keys=True))
    return 0


def run_network_probe(bitbake_root: Path, oe_root: Path) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(bitbake_root / "lib")
    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--oe-root",
            str(oe_root),
            "--network-child",
            "--bitbake-root",
            str(bitbake_root),
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode:
        raise RuntimeError(f"network child failed: {result.stderr}")
    return json.loads(result.stdout.strip().splitlines()[-1])


def run_environment_probe(bitbake_root: Path) -> dict[str, Any]:
    sys.path.insert(0, str(bitbake_root / "lib"))
    import bb.data  # pylint: disable=import-outside-toplevel
    import bb.fetch  # pylint: disable=import-outside-toplevel

    with tempfile.TemporaryDirectory(prefix="bb-environment-fixture-") as temp:
        data = bb.data.init()
        data.setVar("PATH", os.environ["PATH"])
        data.setVar("PERSISTENT_DIR", temp)
        os.environ["FIXTURE_AMBIENT"] = "ambient"
        output = bb.fetch.runfetchcmd(
            [
                sys.executable,
                "-c",
                (
                    "import json, os; print(json.dumps({"
                    "'ambient': os.environ.get('FIXTURE_AMBIENT'),"
                    "'approved': os.environ.get('FIXTURE_APPROVED'),"
                    "'pseudo_disabled': os.environ.get('PSEUDO_DISABLED')}))"
                ),
            ],
            data,
            extraenv={"FIXTURE_APPROVED": "approved"},
        )
    return json.loads(output.strip())


def gpg_direct_verify(gpg: str, home: Path, signature: Path, payload: Path | None) -> dict[str, Any]:
    command = [gpg, "--batch", "--status-fd", "1", "--verify", str(signature)]
    if payload is not None:
        command.append(str(payload))
    environment = os.environ.copy()
    environment["GNUPGHOME"] = str(home)
    result = subprocess.run(
        command,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    statuses = result.stdout.splitlines()
    return {
        "returncode": result.returncode,
        "goodsig": any(" GOODSIG " in line for line in statuses),
        "validsig": any(" VALIDSIG " in line for line in statuses),
        "badsig": any(" BADSIG " in line for line in statuses),
    }


def run_gpg_probe(oe_root: Path) -> dict[str, Any]:
    gpg = shutil.which("gpg")
    if not gpg:
        return {"gpg": None, "status": "unavailable"}
    sys.path.insert(0, str(oe_root / "meta" / "lib"))
    sys.path.insert(0, os.environ["BITBAKE_LIB"])
    import bb.data  # pylint: disable=import-outside-toplevel
    from oe.gpg_sign import LocalSigner  # pylint: disable=import-outside-toplevel

    with tempfile.TemporaryDirectory(prefix="sstate-gpg-fixture-") as temp:
        base = Path(temp)
        home = base / "gnupg"
        home.mkdir(mode=0o700)
        payload = base / "payload"
        payload.write_text("sstate fixture payload\n")
        signature = base / "payload.sig"
        environment = os.environ.copy()
        environment["GNUPGHOME"] = str(home)
        generate = subprocess.run(
            [
                gpg,
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Fixture <fixture@example.invalid>",
                "rsa2048",
                "sign",
                "1d",
            ],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        if generate.returncode:
            raise RuntimeError(f"gpg key generation failed: {generate.stderr}")
        listing = subprocess.check_output(
            [gpg, "--batch", "--with-colons", "--list-secret-keys"],
            env=environment,
            text=True,
        )
        fingerprint = next(
            row.split(":")[9]
            for row in listing.splitlines()
            if row.startswith("fpr:")
        )
        sign = subprocess.run(
            [
                gpg,
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--local-user",
                fingerprint,
                "--detach-sign",
                "--output",
                str(signature),
                str(payload),
            ],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        if sign.returncode:
            raise RuntimeError(f"gpg signing failed: {sign.stderr}")
        tampered = base / "tampered"
        tampered.write_text("tampered payload\n")
        actual = LocalSigner.__new__(LocalSigner)
        actual.gpg_cmd = [gpg]
        actual.gpg_path = str(home)

        fake = base / "fake-gpg"
        fake.write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  --version) printf 'gpg (GnuPG) 2.4.8\\n' ;;\n"
            "  *) printf '[GNUPG:] GOODSIG 0123456789ABCDEF Fixture\\n'; exit 7 ;;\n"
            "esac\n"
        )
        fake.chmod(stat.S_IRWXU)
        branch = LocalSigner.__new__(LocalSigner)
        branch.gpg_cmd = [str(fake)]
        branch.gpg_path = None
        return {
            "gpg_version": subprocess.check_output([gpg, "--version"], text=True).splitlines()[0],
            "direct_valid_payload": gpg_direct_verify(gpg, home, signature, payload),
            "direct_tampered_payload": gpg_direct_verify(gpg, home, signature, tampered),
            "local_signer_empty_allow_list": actual.verify(str(signature), ""),
            "local_signer_matching_key_without_data": actual.verify(str(signature), fingerprint),
            "local_signer_fake_goodsig_nonzero_matching_key": branch.verify(
                str(signature), "0123456789ABCDEF"
            ),
            "local_signer_fake_goodsig_nonzero_empty_allow_list": branch.verify(str(signature), ""),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitbake-root", type=Path, required=True)
    parser.add_argument("--oe-root", type=Path, required=True)
    parser.add_argument("--network-child", action="store_true")
    args = parser.parse_args()
    bitbake_root = args.bitbake_root.resolve()
    oe_root = args.oe_root.resolve()
    if args.network_child:
        return network_child(bitbake_root)
    if not (bitbake_root / "lib" / "bb").is_dir():
        parser.error(f"not a BitBake checkout: {bitbake_root}")
    if not (oe_root / "meta" / "lib" / "oe").is_dir():
        parser.error(f"not an OE-Core checkout: {oe_root}")
    os.environ["BITBAKE_LIB"] = str(bitbake_root / "lib")
    print(
        json.dumps(
            {
                "bitbake_revision": source_revision(bitbake_root),
                "oe_revision": source_revision(oe_root),
                "network": run_network_probe(bitbake_root, oe_root),
                "environment": run_environment_probe(bitbake_root),
                "gpg": run_gpg_probe(oe_root),
                "tools": {
                    command: shutil.which(command)
                    for command in ("gpg", "git", "python3")
                },
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
