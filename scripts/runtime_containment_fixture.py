#!/usr/bin/env python3
"""Check a product-neutral systemd unit fixture, never start the service."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "fixtures/runtime/yocto-hardening-fixture.service"
KSPP_CONTROLS = (
    ("CONFIG_STRICT_KERNEL_RWX", "Separate writable data from executable kernel text", "https://github.com/torvalds/linux/blob/v6.17/Documentation/security/self-protection.rst"),
    ("CONFIG_STRICT_MODULE_RWX", "Apply strict text/data permissions to modules", "https://github.com/torvalds/linux/blob/v6.17/Documentation/security/self-protection.rst"),
    ("CONFIG_RANDOMIZE_BASE", "Kernel address-space layout randomization", "https://github.com/torvalds/linux/blob/v6.17/Documentation/security/self-protection.rst"),
    ("CONFIG_HARDENED_USERCOPY", "Harden usercopy boundary checks", "https://github.com/torvalds/linux/blob/v6.17/Documentation/security/self-protection.rst"),
    ("CONFIG_STACKPROTECTOR_STRONG", "Compiler stack-protector instrumentation for the kernel", "https://github.com/torvalds/linux/blob/v6.17/arch/Kconfig"),
    ("CONFIG_INIT_ON_ALLOC_DEFAULT_ON", "Initialize allocated pages by default", "https://github.com/torvalds/linux/blob/v6.17/mm/Kconfig"),
    ("CONFIG_INIT_ON_FREE_DEFAULT_ON", "Initialize freed pages by default", "https://github.com/torvalds/linux/blob/v6.17/mm/Kconfig"),
    ("CONFIG_FORTIFY_SOURCE", "Compile-time/runtime fortified kernel operations", "https://github.com/torvalds/linux/blob/v6.17/lib/Kconfig"),
    ("CONFIG_BPF_UNPRIV_DEFAULT_OFF", "Disable unprivileged BPF by default", "https://github.com/torvalds/linux/blob/v6.17/kernel/bpf/Kconfig"),
    ("CONFIG_PAGE_TABLE_CHECK", "Page-table integrity checking", "https://github.com/torvalds/linux/blob/v6.17/mm/Kconfig"),
    ("CONFIG_SLAB_FREELIST_HARDENED", "Harden slab freelist pointers", "https://github.com/torvalds/linux/blob/v6.17/mm/Kconfig"),
    ("CONFIG_SLAB_FREELIST_RANDOM", "Randomize slab freelist order", "https://github.com/torvalds/linux/blob/v6.17/mm/Kconfig"),
    ("CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT", "Randomize kernel stack offset by default", "https://github.com/torvalds/linux/blob/v6.17/arch/Kconfig"),
)
REQUIRED = {
    "User": "61101",
    "Group": "61101",
    "NoNewPrivileges": "yes",
    "CapabilityBoundingSet": "",
    "AmbientCapabilities": "",
    "PrivateTmp": "yes",
    "PrivateDevices": "yes",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "ProtectKernelTunables": "yes",
    "ProtectKernelModules": "yes",
    "ProtectControlGroups": "yes",
    "RestrictAddressFamilies": "AF_UNIX",
    "RestrictNamespaces": "yes",
    "RestrictSUIDSGID": "yes",
    "SystemCallFilter": "@system-service",
    "SystemCallErrorNumber": "EPERM",
    "MemoryMax": "128M",
    "TasksMax": "64",
}


def read_service(text: str) -> dict[str, str]:
    section = ""
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section != "Service" or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def verify_policy(text: str) -> list[str]:
    values = read_service(text)
    errors = []
    for key, expected in REQUIRED.items():
        if values.get(key) != expected:
            errors.append(f"{key} must be {expected!r}, got {values.get(key)!r}")
    if not re.fullmatch(r"/[A-Za-z0-9_./+-]+", values.get("ExecStart", "")):
        errors.append("ExecStart must be an absolute, simple executable path in this fixture")
    return errors


def systemd_check(unit_text: str) -> dict[str, Any]:
    binary = shutil.which("systemd-analyze")
    if binary is None:
        return {"status": "not-run", "reason": "systemd-analyze is unavailable"}
    with tempfile.TemporaryDirectory(prefix="yocto-unit-verify-") as directory:
        path = Path(directory) / "yocto-hardening-fixture.service"
        path.write_text(unit_text, encoding="utf-8")
        result = subprocess.run(
            [binary, "verify", str(path)], text=True, capture_output=True,
            check=False, timeout=20,
        )
    version = subprocess.run([binary, "--version"], text=True, capture_output=True, check=False, timeout=10)
    return {
        "status": "passed" if result.returncode == 0 else "failed",
        "command": "systemd-analyze verify <temporary-fixture-unit>",
        "exit_code": result.returncode,
        "version": version.stdout.splitlines()[0] if version.stdout else "unknown",
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def kernel_reference_snapshot() -> dict[str, Any]:
    release = platform.release()
    config_path = Path("/boot") / f"config-{release}"
    base = {
        "reference_name": f"analysis-host Linux {release} ({platform.machine()})",
        "scope": "host configuration reference only; not a Yocto target or product kernel",
        "upstream_kconfig_baseline": "Linux v6.17 source references; downstream vendor source identity was not inspected",
        "config_path": str(config_path),
        "product_kernel_status": "not-run",
        "runtime_enforcement_status": "not-run",
    }
    if not config_path.is_file():
        return {
            **base,
            "status": "not-run",
            "reason": "no matching host /boot/config file is available",
            "controls": [
                {
                    "symbol": symbol,
                    "description": description,
                    "observed_value": None,
                    "reference_status": "not-run",
                    "product_status": "not-run",
                    "source": source,
                }
                for symbol, description, source in KSPP_CONTROLS
            ],
        }

    raw = config_path.read_bytes()
    lines = raw.decode("utf-8", errors="replace").splitlines()
    configured = {
        line.split("=", 1)[0]: line.split("=", 1)[1]
        for line in lines
        if line.startswith("CONFIG_") and "=" in line
    }
    disabled = {
        line.removeprefix("# ").removesuffix(" is not set")
        for line in lines
        if line.startswith("# CONFIG_") and line.endswith(" is not set")
    }
    controls = []
    for symbol, description, source in KSPP_CONTROLS:
        if symbol in configured:
            value = configured[symbol]
            state = "enabled" if value in {"y", "m"} else "configured"
        elif symbol in disabled:
            value = "not-set"
            state = "disabled"
        else:
            value = "absent"
            state = "not-in-config; support not established"
        controls.append({
            "symbol": symbol,
            "description": description,
            "observed_value": value,
            "reference_status": state,
            "product_status": "not-run",
            "source": source,
        })
    return {
        **base,
        "status": "observed-host-config-only",
        "architecture": platform.machine(),
        "config_sha256": hashlib.sha256(raw).hexdigest(),
        "controls": controls,
        "limitations": [
            "the packaged host config is not proof of effective runtime behavior",
            "Linux v6.17 links are version-specific upstream reference sources, not the vendor source tree for this host build",
            "no product kernel config, QEMU image, target boot, or enforcement test was run",
        ],
    }


def evaluate() -> dict[str, Any]:
    text = UNIT.read_text(encoding="utf-8")
    errors = verify_policy(text)
    negative_text = "\n".join(line for line in text.splitlines() if not line.strip().startswith("NoNewPrivileges="))
    negative_errors = verify_policy(negative_text)
    syntax = systemd_check(text)
    return {
        "fixture_only": True,
        "product_claim": False,
        "service_started": False,
        "unit": str(UNIT.relative_to(ROOT)),
        "static_policy": {"status": "passed" if not errors else "failed", "errors": errors},
        "negative_policy_test": {
            "status": "passed" if any(error.startswith("NoNewPrivileges ") for error in negative_errors) else "failed",
            "mutation": "removed NoNewPrivileges=yes from a temporary copy",
            "detected_errors": negative_errors,
        },
        "systemd_syntax": syntax,
        "kernel_reference": kernel_reference_snapshot(),
        "kernel_configuration": {"status": "not-run", "reason": "No selected target Yocto kernel .config is available; host reference evidence is separate."},
        "runtime_enforcement": {"status": "not-run", "reason": "The fixture was not started; no product/QEMU image or service workload is available"},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write the JSON evidence report to this path")
    args = parser.parse_args()
    try:
        report = evaluate()
    except (OSError, subprocess.TimeoutExpired) as exc:
        report = {"fixture_only": True, "status": "failed", "errors": [str(exc)]}
    failures = []
    for field in ("static_policy", "negative_policy_test", "systemd_syntax"):
        if report.get(field, {}).get("status") not in {"passed", "not-run"}:
            failures.append(field)
    report["status"] = "failed" if failures else "passed"
    report["failed_checks"] = failures
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
