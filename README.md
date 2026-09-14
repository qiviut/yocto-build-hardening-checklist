# Yocto Build Hardening Checklist

A practical, evidence-oriented hardening checklist for Yocto/OpenEmbedded build environments that produce safety- and security-relevant embedded products.

> **Status:** working draft. This project is not part of the Yocto Project, is not a compliance certification, and does not by itself establish IEC 62304, IEC 62443, or regulatory conformity.

## Why this exists

Yocto provides strong build composition, source pinning, checksums, mirroring, and reproducibility mechanisms. It is not, by itself, a sandbox against:

- malicious or compromised layers;
- hostile recipes and classes;
- compromised upstream projects;
- package-manager lifecycle scripts;
- poisoned download or shared-state caches; or
- a compromised build host.

The checklist turns those trust assumptions into reviewable controls and retained evidence. It is intentionally aimed at production and medtech build assurance, while remaining useful for any security-sensitive embedded product.

## Quick-start posture

For a serious product build, start here:

1. Pin BitBake, OE-Core, BSP, every layer, the toolchain, host image, and build configuration to reviewed immutable revisions.
2. Treat every layer and recipe as executable code, not declarative data.
3. Resolve and fetch sources in a controlled intake lane, then compile from a frozen local mirror with `BB_NO_NETWORK = "1"`.
4. Enforce network denial at the VM/container/firewall boundary. BitBake attempts namespace isolation for non-network tasks, but that helper is defense in depth and can fail open.
5. Use disposable, non-root workers with no signing keys, cloud credentials, SSH agent, home npm configuration, or broad host mounts.
6. Protect `DL_DIR` and `SSTATE_DIR` as supply-chain inputs; require provenance or signatures for promoted cache objects.
7. Disable npm lifecycle scripts by default. Isolate and explicitly approve exceptions.
8. Reject unpack destinations that escape the task root, including relative traversal, sibling-prefix paths, symlink ancestors, and unsafe Git/npm shrinkwrap paths.
9. Keep build, test, provenance generation, and release signing in separate trust lanes.
10. Retain source manifests, layer approvals, build logs, SBOMs, provenance, reproducibility results, and verification records.

The maintained analysis is now organized as a Doorstop tree so claims can be
reviewed and extended without losing source links:

- [Traceability process](docs/traceability-process.md) — schema, evidence,
  validation, warning policy, and Astra handoff.
- [Doorstop analysis](traceability/) — the canonical `REQ → EP → RISK → CTRL → VER`
  result.
- [Fixture evidence](evidence/fetcher-fixtures-2026-09-14.md) — retained local
  observations and their limits.
- [CI data-model linter](scripts/lint_traceability.py) — blocking schema checks
  plus warning-only completeness checks.

Run the same gates locally with the pinned tools in
[`requirements-dev.txt`](requirements-dev.txt):

```sh
python3 -m venv .venv-doorstop
.venv-doorstop/bin/python -m pip install --no-cache-dir -r requirements-dev.txt
.venv-doorstop/bin/doorstop -j . -F -C
.venv-doorstop/bin/python scripts/lint_traceability.py
```

The Doorstop tree is an evidence-oriented working analysis, not a trusted-build
or regulatory conclusion. Open verification records are intentionally visible
as CI warnings.

## Contents

- [CHECKLIST.md](CHECKLIST.md) — the operational checklist with evidence expectations.
- [docs/threat-model.md](docs/threat-model.md) — actors, trust boundaries, and attack paths.
- [docs/review-yocto-do-unpack.md](docs/review-yocto-do-unpack.md) — the narrow source review that seeded this project.
- [docs/astra-second-pass.md](docs/astra-second-pass.md) — the runtime-verified Astra second-pass review and its additional cache/network findings.
- [docs/remediation-roadmap.md](docs/remediation-roadmap.md) — prioritized fixes and verification work.
- [SECURITY.md](SECURITY.md) — safe handling of security reports.

## Review baseline

The initial review used clean `master` checkouts matching these local `origin/master` revisions:

- BitBake: `046a90b0e9b7b914b7a95aec579cdc3fc9c7617a`
- OpenEmbedded-Core: `f94ae3d6ba49aef86f497998c0e0232a5039510a`
- meta-yocto: `7e41504cd63b099b214f10d92cfdaf358ab98c5f`
- yocto-docs: `e35e86e9aea4e4ae12e8e0ba8a6391f2b2555b63`

Source references in the documents use upstream repository-relative paths and line numbers from that snapshot. Line numbers must be rechecked whenever the baseline changes.

## How to use it

Copy the checklist into the product's secure-development evidence system, then attach an owner, status, due date, and evidence reference to every applicable item. Do not mark a control complete because a variable is present in configuration: verify the effective task behavior in a clean build and retain the result.

The intended stopping condition is not "Yocto is trusted." It is an explicit, reviewable statement of:

- which inputs are trusted and why;
- which inputs remain executable or hostile;
- where containment is enforced;
- what evidence proves the controls; and
- what residual risk is accepted by the product organization.
