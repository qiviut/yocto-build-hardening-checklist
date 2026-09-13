# Yocto Build Hardening Checklist

Use one copy of this checklist per product, release train, or build-platform change. Mark an item complete only when the evidence field points to an inspectable artifact.

Suggested record fields for every item: **Owner · Status · Evidence · Date · Exception/risk acceptance**.

## 0. Scope and assurance statement

- [ ] Define the product, release, supported machines, build entry point, and exact build configuration under review.
- [ ] Record whether the build is for development, verification, production release, or field-update artifacts.
- [ ] Define the safety/security impact of a compromised build: incorrect clinical function, unsafe defaults, disabled security controls, update compromise, data exposure, or loss of traceability.
- [ ] Map applicable quality and security processes, including SOUP/dependency review, change control, verification, release approval, and incident response.
- [ ] State explicitly that this checklist is evidence for the product process, not a compliance certificate.

## 1. Layer, metadata, and governance intake

Treat every layer, recipe, class, configuration file, handler, and anonymous Python block as executable code.

- [ ] Inventory `BBLAYERS`, layer priorities, `BBPATH`, `BBFILES`, `BBFILE_COLLECTIONS`, and effective `bblayers.conf`/`local.conf`.
- [ ] Pin BitBake, OE-Core, BSP, vendor layers, toolchain layers, and every other layer to reviewed immutable commits.
- [ ] Record repository URLs, commit IDs, signed-tag/signature status, maintainer, license, and approval decision for every layer.
- [ ] Review layer `conf/layer.conf`, classes, `.bbappend` files, anonymous Python, task functions, `inherit` statements, and `INHERIT` changes.
- [ ] Treat changes to `SRC_URI`, `SRCREV`, lockfiles, fetcher code, classes, build scripts, and packaging metadata as security-significant changes.
- [ ] Require independent review for new layers, layer priority changes, new overrides, and changes that broaden `BBPATH` or executable search paths.
- [ ] Run `bitbake-layers show-layers`, `show-recipes`, and `show-appends`; retain the output for the release.
- [ ] Check for duplicate recipe providers, unexpected appends, masked recipes, and provider changes.
- [ ] Do not use a layer's reputation as a substitute for reviewing the exact revision and effective metadata.

## 2. Source and dependency intake

- [ ] Generate a source manifest containing every URI, fetcher type, revision/version, checksum/integrity value, mirror, and intended license/provenance.
- [ ] Ban `AUTOREV`, mutable branch-only sources, mutable release tags, and floating package labels in release builds unless a documented exception is approved.
- [ ] Require exact Git revisions for repositories and verify submodule revisions as part of the manifest.
- [ ] Require SHA-256 or stronger for downloaded archives and package-manager artifacts; reject MD5/SHA-1 for new release inputs.
- [ ] Set `BB_STRICT_CHECKSUM = "1"` and fail the build on missing or mismatched checksums.
- [ ] Resolve package-manager lockfiles before the build and review lockfile changes as dependency changes.
- [ ] Verify that package-manager integrity values bind to the exact downloaded bytes, not merely a registry response or mutable metadata.
- [ ] Review dependency names, publishers, registries, scopes, repository ownership, and maintainer/takeover risk separately from CVE status.
- [ ] Inspect generated, vendored, bundled, and transitive dependencies; do not rely only on declared top-level manifests.
- [ ] Freeze the resolved input set in an immutable manifest before compilation.

## 3. Fetch and offline transition

- [ ] Perform networked source intake in a distinct, observable lane.
- [ ] Prefer an internally controlled mirror populated only after checksum, revision, license, and provenance checks.
- [ ] Set `BB_NO_NETWORK = "1"` for the compile/test/release lanes after intake is complete.
- [ ] Use `BB_ALLOWED_NETWORKS` and `PREMIRRORS`/`MIRRORS` to constrain the intake lane to approved hosts.
- [ ] Prove with a clean build that all expected sources are present before disabling network access.
- [ ] Retain fetch logs and the source manifest; alert on unexpected upstream access.
- [ ] Do not treat BitBake's `do_fetch`/`do_unpack` network convention as OS-level egress enforcement.
- [ ] Enforce network denial with a firewall, network namespace, VM policy, or equivalent kernel/host control for every non-intake task.
- [ ] Test direct sockets, DNS, `curl`/`wget`, Git, npm, Python, and native helper egress from the build worker.

## 4. Host and build-worker isolation

- [ ] Use a disposable, reproducible VM/container image with a documented digest and patch level.
- [ ] Run as a non-root user; remove unnecessary capabilities, setuid helpers, device access, and host mounts.
- [ ] Keep release signing keys, update credentials, cloud credentials, package-publishing tokens, and SSH agents out of the build worker.
- [ ] Use a minimal environment allow-list. Do not pass ambient `AWS_*`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK`, proxy credentials, or similar secrets to untrusted build code.
- [ ] Keep `HOME` and user configuration isolated; do not use a developer's home `.npmrc`, `.gitconfig`, SSH config, or credential helper in release builds.
- [ ] Use resource limits and workspace quotas to contain disk, process, memory, inode, and log exhaustion.
- [ ] Use host controls such as namespaces, seccomp, LSM policy, and filesystem permissions where available; record the effective policy, not just intended configuration.
- [ ] Destroy workers after builds or after a security-significant failure.
- [ ] Keep the release-signing and artifact-publication lane separate from compilation and tests.

## 5. `do_unpack` and path-confinement controls

- [ ] Record the effective `UNPACKDIR`, `WORKDIR`, `S`, and all source destination parameters for each release recipe.
- [ ] Require canonical destination checks for common `subdir`, Git `subdir`, Git `destsuffix`, npm `destsuffix`, and npm shrinkwrap dependency locations.
- [ ] Reject absolute paths unless they resolve below the intended root using a component-aware `commonpath` check.
- [ ] Reject relative `..` traversal, empty path components, backslashes where POSIX paths are expected, and sibling-prefix paths such as `/work/root2` for `/work/root`.
- [ ] Reject or safely stage archives containing absolute members, `..` members, symlink ancestors, hardlinks, device nodes, FIFOs, and unsafe permissions.
- [ ] Extract into a temporary directory, validate the resulting tree, then promote it atomically where the threat model requires it.
- [ ] Add regression tests for tar, zip/jar, rpm/deb/ipk, npm, Git, gitsm, and npmsw paths.
- [ ] Use argument arrays for decompression and extraction commands; eliminate shell-string filename interpolation.
- [ ] Test filenames containing spaces, quotes, newlines, `$()`, backticks, semicolons, and glob characters.
- [ ] Re-run the tests with the actual host versions of tar, unzip, Git, npm, and any 7z/lzip/zstd tools used in production.
- [ ] Re-run all fetcher tests after every fetcher hardening change.

## 6. Package-manager and build-script policy

- [ ] Classify every package-manager lifecycle hook, code generator, native extension build, configure step, and custom build command as executable code.
- [ ] Disable npm lifecycle scripts by default for packages that do not require them.
- [ ] Maintain an explicit exception list for packages that require `preinstall`, `install`, `postinstall`, `prepare`, or equivalent hooks.
- [ ] Build approved exceptions in a separate disposable worker with no secrets, no signing authority, no host mounts, and enforced network denial.
- [ ] Review all transitive npm dependencies and scripts, not only the top-level package.
- [ ] Prefer lockfiles with strong integrity values and exact versions; reject `latest` and weak integrity algorithms for release inputs.
- [ ] Ensure npm cache contents are derived from the approved manifest and are not silently replaced by a shared writable cache.
- [ ] Apply the same policy to Cargo build scripts, Python setup/build hooks, Go generators, CMake/Meson configure logic, Autotools, Makefiles, Gradle/Maven plugins, and vendor tooling.
- [ ] Record whether build scripts are permitted, why they are needed, what they can access, and how their outputs are verified.

## 7. `DL_DIR`, `SSTATE_DIR`, and cache integrity

- [ ] Treat download and shared-state caches as supply-chain inputs, not mere performance optimizations.
- [ ] Use dedicated per-product or per-trust-domain cache namespaces.
- [ ] Restrict cache write access and prevent untrusted jobs from publishing objects consumed by release jobs.
- [ ] Verify cache objects by digest/signature/provenance before promotion.
- [ ] Keep a manifest of cache objects used for each release build.
- [ ] Confirm that cache and done-stamp permissions prevent another worker or user from replacing inputs between fetch, unpack, and build.
- [ ] Do not assume a done stamp proves current bytes are safe if the cache is writable by an attacker.
- [ ] Configure signed sstate or equivalent artifact verification where available.
- [ ] Invalidate and rebuild caches after a worker compromise or unexplained integrity failure.

## 8. Build, test, and release separation

- [ ] Build from an immutable source/input manifest and record its digest.
- [ ] Keep test execution separate from the immutable artifact that will be signed or published.
- [ ] Run tests on copies or throwaway artifacts when instrumentation mutates files.
- [ ] Generate SBOM, license, dependency, and provenance records from the exact build inputs and outputs.
- [ ] Bind artifact digests to source revisions, layer revisions, configuration, toolchain, builder identity, and relevant environment parameters.
- [ ] Require reproducibility evidence for release candidates; investigate unexplained differences.
- [ ] Sign artifacts in a separate lane after build and verification, using an explicit approval.
- [ ] Verify signatures/provenance at every promotion and installation boundary; producing an attestation is not enough.
- [ ] Ensure the exact tested SHA is the exact signed and published SHA.
- [ ] Retain build logs, manifests, test reports, SBOMs, provenance, signatures, approvals, and exceptions for the product record.

## 9. Monitoring and incident response

- [ ] Alert on layer, recipe, class, fetcher, lockfile, toolchain, and build-container changes.
- [ ] Capture unexpected network attempts, package-manager script execution, external process launches, and access to protected paths.
- [ ] Define triage for compromised upstream, layer takeover, registry compromise, cache poisoning, and builder compromise.
- [ ] Have a documented cache quarantine and rebuild procedure.
- [ ] Rotate any credential that may have entered a build worker; assume an executed build script could read it.
- [ ] Rebuild from a clean worker and independently re-verify source, cache, provenance, and artifact digests.
- [ ] Preserve evidence before destroying a worker when the product incident process requires forensic retention.

## 10. Evidence review gate

A release should not pass this checklist if any of these statements is false:

- [ ] Every executable input is identified and has an owner and review decision.
- [ ] Every source and dependency is bound to an approved immutable identity.
- [ ] Non-intake build tasks cannot reach the network through the host controls.
- [ ] Build workers have no unnecessary credentials or release authority.
- [ ] Unpack destinations and archive contents are confined to the intended workspace.
- [ ] Caches are access-controlled and provenance-checked.
- [ ] Build/test/sign/publish lanes are separated according to consequence.
- [ ] The exact release artifact is traceable to its source, configuration, builder, tests, and approvals.
- [ ] Residual risk and any accepted exceptions are signed by the product owner and quality/security authority.
