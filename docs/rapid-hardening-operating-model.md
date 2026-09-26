# Rolling Yocto Hardening Operating Model

> This document implements a local operating policy for the Yocto Build Hardening Checklist. It is not a Yocto Project policy, product build, release approval, or deployment-security claim. Each candidate retains exact immutable inputs even though intake follows the moving development line.

## Policy boundary and evidence vocabulary

This program follows upstream `master` for routine intake, evaluates untagged commits, and does not maintain an LTS/backport lane. Yocto also runs release and stable/LTS processes; avoiding those lanes is our choice, not an upstream recommendation.[1]

Use these evidence labels consistently:

- **source review**: pinned metadata/docs were inspected; no build or runtime claim follows.
- **product-neutral fixture**: a deterministic local fixture exercised a bounded contract; it is not a product build.
- **reference build**: an explicitly named, pinned generic configuration was built or parsed; it is not product evidence.
- **product/deployment evidence**: only product configuration and execution can support these claims.
- **not-run**: name the missing input, exact downstream procedure, and evidence required; do not silently treat absence as a pass.

The repository's product-release preflight found no product `bblayers.conf`, `local.conf`, or `kas*.yml`. No product image, release dry run, or device runtime test is claimed. Preserve those gaps as open in the traceability model.

## 1. Rolling development-head intake and immutable manifests

### Routine intake

1. Observe the current upstream development refs (normally `master`); record ref, retrieval time, and full resolved commit SHA before deciding whether to evaluate it. A branch name is an intake pointer, never a candidate identity.
2. Resolve every evaluated component and layer: BitBake, OE-Core, meta-yocto, BSP/vendor layers, additional layers, submodules, recipe Git `SRCREV`s, and archive checksums. Record omitted/unselected repositories and why they are not in the candidate.
3. Bind configuration files and their hashes, `MACHINE`, `DISTRO`, image/target, build-tool identity, host environment, and generated target-toolchain identity to the manifest. For `SRC_URI`, retain resolved Git revisions and strong archive checksums; include lockfiles and generated inputs where used.
4. Freeze the manifest and its canonical digest before parse/build/test. Every later stage consumes that frozen input set rather than resolving moving refs again.
5. Promote only after declared parse/build/tests and security review succeed. A failed or incomplete intake remains `not-promoted`; record the failed gate and evidence. Do not move a candidate pointer in place.

The schema and deterministic validator are `scripts/rolling_manifest.py`; `fixtures/rolling-intake/reference-snapshot.json` is a source-only example tied to exact local reference pins and checked-in configuration hashes. The validator binds selected layer and recipe metadata revisions to the SHA of the named repository and rejects a `promoted` status without parse/build/test/security evidence identities. This is schema validation only: it does not verify every referenced external result, authorize promotion, or perform promotion. `fixtures/rolling-intake/failed-intake-example.json` is a synthetic failed-build example that records a canonical prior-candidate identity and remains `not-promoted`; it is not an actual Yocto failure. `python3 scripts/rolling_manifest.py validate <manifest> --output <report.json>` validates one manifest, and `python3 scripts/rolling_manifest.py replay-fixture --output <report.json>` replays one synthetic exact-SHA checkout offline. Neither command proves a Yocto product build.

For actual builds, capture the resolved output of the selected BitBake metadata (for example, `bitbake -e <recipe>` for `SRC_URI`, `SRCREV`, `PACKAGECONFIG`, compiler and linker variables), the exact config/toolchain inputs, and the builder/container identity. If a source cannot be pinned or a required artifact is missing, fail the intake promotion decision and preserve the prior manifest unchanged.

## 2. Advisory third-party diagnostics

For C/C++ recipes, use compiler diagnostics plus a language-appropriate analyzer; do not imply one tool covers all languages or configurations. GCC `-fanalyzer` was selected for the revision-pinned OpenSSL C source available here: GCC describes it as path-sensitive bug finding that may have false positives and false negatives, not a correctness proof.[9] The real bounded run is recorded in `evidence/advisory-openssl-4.0.2-gcc-analyzer.json`: OpenSSL 4.0.2 source archive SHA-256 matched the recipe, and GCC 15.2.0 analyzed one `crypto/sha/keccak1600.c` translation unit with zero warnings. That is `clean` for this file/pass only, not for the recipe or product. ASan/UBSan, a full package build, ptests, and broader analyzer coverage remain not-run.

Each run record includes component/recipe, full source SHA or archive digest, tool and version, flags/configuration, run state, finding identifiers, raw report artifact, triage owner, applicability/false-positive rationale, disposition, and upstream issue/patch route. States distinguish `clean`, `findings`, `unsupported`, `not-run`, and `tool-error`. When findings are present, pass `--triage-owner`, `--finding-disposition`, `--upstream-route`, and `--applicability-rationale` to the bounded runner; absent fields remain explicitly pending and do not close triage. Preserve unresolved findings instead of suppressing them. Address confirmed upstream defects through the component's documented contribution and review process.[8]

A finding alone is advisory: it does not flip the ordinary build/test gate. Ordinary build or functional-test failures remain failures. A missing or broken analyzer invocation is visible as a diagnostic-lane problem, not a claim of a clean scan. `scripts/advisory_lane_fixture.py` emits a separate synthetic finding case at `evidence/advisory-lane-fixture.json`; it demonstrates that findings alone do not block and that ordinary failures do, but it does not replace the real bounded OpenSSL result.

## 3. Minimize recipe features and validate build hardening

For each third-party recipe, inventory optional features, plugins, tools, examples, tests, services, and dependencies. Prefer that recipe's supported `PACKAGECONFIG` or equivalent configure/build-system options.[4] Record each feature as required, disabled, not offered, or undecided, with the product owner and compatibility evidence. Do not remove a feature merely because it is optional upstream.

Use the selected revision's supported security defaults and exceptions. For example, the pinned OE-Core reference source `f94ae3d6ba49aef86f497998c0e0232a5039510a` has `meta/conf/distro/include/security_flags.inc`: it defines stack protector, PIE, fortify, format-security, and RELRO/NOW defaults, and documents recipe-specific exceptions in the same file. Confirm effective values for the tested branch/recipe before adding overrides; flags are not universal.[2]

The pinned recipe metadata exposes OpenSSL `4.0.2` options `legacy`, `tls1`, `tls1_1`, `manpages`, and `fips`, and systemd options including `networkd`, `resolved`, `hostnamed`, and `seccomp`. The source review records explicit enabled/disabled/required profile decisions and compatibility rationale in `evidence/recipe-hardening-source-review-2026-09-25.md`; this synthetic profile is not a product `PACKAGECONFIG` selection. The exact source files and commits are recorded in the fixture evidence.

Evaluate dead-code and binary-size reduction using the actual compiler/linker and generated link command (for example, section-level garbage collection where supported); do not infer that a linker brand removes unused code. Retain debug symbols through a deliberate package/provenance path. For any claimed output change, compare buildhistory or equivalent package/image manifests before and after, run relevant ptests/runtime checks, and check reproducibility.

This repository has no product layer/configuration. Therefore output comparison and product ptest results are **not-run** here. The downstream procedure is: pin the product manifest; save effective `PACKAGECONFIG`, compile/link flags, and task environment; build the baseline and candidate in clean workspaces with identical inputs except the named change; compare package/image manifests and buildhistory; run recipe ptests and product integration tests; inspect debug artifacts and reproducibility; archive commands and outputs. Do not present source review or this procedure as an actual build result.

## 4. Kernel and per-service runtime containment

Map each proposed control to a named kernel revision/configuration, init system/version, service, and workload. Linux v6.17 Kernel Self-Protection documentation is a design guide, not evidence that a product kernel enabled a setting.[10] `evidence/runtime/kernel-hardening-reference.md` and `evidence/runtime-containment-reference.json` record a versioned **analysis-host config snapshot** with a control-by-control matrix; every product-target state remains `not-run`. For systemd units, assess a dedicated `User=`/`Group=`, filesystem read/write boundaries, capabilities, `NoNewPrivileges=`, syscall filtering, namespaces, and resource/cgroup limits. `systemd.exec` and `systemd.resource-control` document these as versioned execution/resource controls; directive presence does not prove the running service is confined.[6][7]

The local systemd unit fixture is in `fixtures/runtime/`; `scripts/runtime_containment_fixture.py --output evidence/runtime-containment-reference.json` records its syntax/policy checks and the analysis-host config snapshot. It does not start the service. The target kernel configuration and effective product runtime enforcement remain `not-run` because no selected Yocto kernel/config or product service image is available.

Downstream verification must: capture the exact kernel source SHA and `.config`; map each KSPP control to supported Kconfig/help text for that kernel; inspect the actual init/service version and effective unit/drop-ins; verify user, filesystem, capabilities, seccomp, namespace and cgroup policy from the running target; demonstrate denied operations with negative tests; and run service functionality/regression tests. Unsupported controls and compatibility exceptions stay visible. Do not transfer host/QEMU fixture results to deployed devices.

## 5. Rolling CVE/SBOM intake and disposition

Run CVE review on each promoted candidate and on urgent advisories relevant to included components. Keep known-vulnerability/product decisions separate from static-analyzer findings. Record the exact manifest SHA, report generator/database snapshot, report artifact digest, package-to-source mapping, applicability rationale, owner, action, due/recheck point, and escalation.

The selected OE-Core reference source `f94ae3d6ba49aef86f497998c0e0232a5039510a` contains `meta/classes-recipe/sbom-cve-check.bbclass` and the `core/yocto/sbom-cve-check` fragment. The fragment sets both CVE database recipe `SRCREV`s to `${AUTOREV}`. The class runs `sbom-cve-check` in offline mode and defines SPDX3, CVE JSON, and human-readable summary export variables; however, `SBOM_CVE_CHECK_EXPORT_VARS` defaults only to SPDX3 and CVECHECK, so the summary file is **not exported by default**. To retain that artifact, explicitly add `SBOM_CVE_CHECK_EXPORT_SUMMARY` to the export list. `SBOM_CVE_CHECK_SHOW_WARNINGS` defaults to `1` and can emit BitBake warnings for Unpatched items in the CVE JSON; those log messages are not the text-summary artifact. Offline scan execution does not freeze database revisions fetched by preceding tasks. For reproducible rolling candidates, bind the resolved full Git SHA for each CVE database input into the manifest (the manifest validator supports Git `SRCREV`s as well as archive checksums), or retain a digest-addressed database snapshot and its provenance. If the selected recipe/revision does not provide those identities, leave CVE status not-run and do not claim a reproducible scan. No CVE databases were fetched or analyzed for this source-only fixture.[3]

For a synthetic report-state example, run `python3 scripts/cve_disposition_fixture.py fixtures/cve/rolling-cve-fixture.json --output evidence/cve/cve-fixture-validation.json`. For a real candidate, classify applicability using the actual recipe source and patches, distinguish an upstream `master` fix from a constrained local patch, assign an owner and recheck, and preserve justified `Ignored` rationale. Confirmed applicable issues enter the product's explicit security/release decision path; no universal release gate is prescribed by this framework. The absence of a product SBOM/CVE report here is **not-run**, not clean. Source-level details and line references are recorded in `evidence/cve/cve-workflow-source-review.md`.

## 6. Integration, traceability, and closure

The traceability chain is `REQ006 → EP016 → RISK011 → CTRL011 → VER012`; the verification links each fixture, source review, and the bounded OpenSSL analyzer artifact. The only remaining warnings are explicit open/not-run product evidence and pre-existing coverage records.[truncated]
A bead may close when the documented framework, fixture, and tests pass, with product-only controls explicitly left `not-run` and the required downstream evidence named. It may not close by claiming product readiness or by turning a diagnostic warning into a build result.

## Sources

[1] https://docs.yoctoproject.org/dev/ref-manual/release-process.html
[2] https://docs.yoctoproject.org/dev/security-manual/securing-images.html
[3] https://docs.yoctoproject.org/dev/security-manual/vulnerabilities.html
[4] https://docs.yoctoproject.org/dev/ref-manual/variables.html
[6] https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
[7] https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html
[8] https://docs.yoctoproject.org/dev/contributor-guide/submit-changes.html
[9] https://gcc.gnu.org/onlinedocs/gcc/Static-Analyzer-Options.html — GCC Static Analyzer Options
[10] https://github.com/torvalds/linux/blob/v6.17/Documentation/security/self-protection.rst — Linux v6.17 Kernel Self-Protection
