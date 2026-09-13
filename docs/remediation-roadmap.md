# Remediation Roadmap

This roadmap separates framework changes from deployment controls. Do not close a deployment control because a framework patch exists, and do not treat a sandbox as permission to admit unreviewed metadata.

## P0 — before trusting a production release build

### 1. Remove consequence from the ordinary build worker

- Disposable VM/container.
- Non-root user and minimal mounts/capabilities.
- No signing keys, update credentials, cloud credentials, SSH agent, or home npm configuration.
- Host-enforced, fail-closed network denial outside the intake lane; BitBake namespace isolation is only defense in depth.
- Separate test and signing/publishing lanes.

**Verification:** execute a fixture package script that attempts direct DNS/socket access and reads known sentinel environment variables; prove the attempts fail and the sentinels are absent. Run the check from the effective build task environment, not only from an interactive shell.

Also exercise the unsupported-isolation case and verify the release lane rejects it rather than relying on the helper's debug-only fallback.

### 2. Freeze and review the complete input set

- Immutable revisions for all layers and toolchains.
- SHA-256/SHA-512 checksums for archives and package artifacts.
- Exact Git and submodule revisions.
- Reviewed lockfiles and transitive dependency inventory.
- Controlled mirror and offline build.

**Verification:** build from a clean worker with `BB_NO_NETWORK=1`, compare the resolved manifest to the approved manifest, and retain the digest plus fetch logs.

### 3. Establish an npm lifecycle-script policy

- Disable scripts by default where product compatibility permits.
- Explicitly isolate exceptions.
- Review all transitive scripts and native build hooks.

**Verification:** a fixture dependency's install hook must not run in the default lane; the same hook may run only in an exception worker whose network, environment, and filesystem assertions pass.

## P1 — framework hardening and regression coverage

### 4. Centralize destination confinement

Add one reusable component-aware path-validation helper and apply it to:

- common fetcher `subdir`;
- Git `subdir` and `destsuffix`;
- npm `destsuffix`;
- npm shrinkwrap locations and dependency destinations;
- gitsm module checkout paths.

Reject absolute paths outside the root, relative traversal, sibling-prefix paths, symlink ancestors, backslashes in POSIX metadata, and unsafe special files as appropriate.

**Verification:** add deterministic tests for `../escape`, `/root2` versus `/root`, encoded/normalized forms, nested package locations, and symlink races/staging behavior.

### 5. Eliminate shell-string extractor commands

Replace decompressor and RPM pipeline strings with argument arrays or safe temporary-file stages.

**Verification:** run the fetcher test suite with shell-metacharacter filenames and assert no marker command executes.

### 6. Normalize and allow-list shrinkwrap proxy URLs

Discard embedded BitBake URI parameters from `resolved` values and rebuild only the intended scheme, source, filename, and verified integrity parameters.

**Verification:** lockfile fixtures containing `subdir`, `destsuffix`, credentials, alternate schemes, and semicolon parameters must either be rejected or produce a confined, approved request.

### 7. Reject weak new npm integrity algorithms

Make SHA-256 or stronger mandatory for production policy. Provide an explicit migration path for older recipes rather than silently changing bytes.

**Verification:** a SHA-1-only fixture fails in production policy and a SHA-512 fixture passes.

### 7.1. Remove executable cache metadata

Replace fetcher done-stamp pickle serialization with a strictly parsed non-executable format. Until that lands, make cache write access a hard trust boundary and quarantine caches after any cross-domain write.

**Verification:** feed a crafted done-stamp fixture to the fetcher and prove it is rejected as data without invoking code; verify the accepted record is bound to the intended artifact and recipe identity.

## P2 — assurance and operational maturity

### 8. Cache promotion and provenance

- Per-trust-domain cache namespaces.
- Signed/provenance-bound sstate promotion.
- Per-build cache manifest.
- Quarantine/rebuild process after compromise.

**Verification:** attempt to consume an unsigned or cross-domain cache object and prove the release lane rejects it.

### 9. Reproducibility and release traceability

- Exact source/config/toolchain/builder manifest.
- SBOM and license records.
- Reproducible-build comparison.
- Artifact signature and consumer-side verification.

**Verification:** rebuild from a clean worker and prove the signed artifact digest is bound to the tested source SHA and approved input manifest.

### 10. Expand beyond npm

Apply the same threat model to Cargo build scripts, Python packaging hooks, Go generators, CMake/Meson/Autotools, Makefiles, Gradle/Maven plugins, vendor SDK installers, and container/toolchain bootstrap scripts.

**Verification:** maintain a package-manager/build-hook inventory with an explicit execution and isolation decision for every ecosystem used by the product.

## Framework defect versus deployment gap

| Area | Framework change | Deployment/process control |
| --- | --- | --- |
| Unpack path escape | Add canonical confinement and tests | Keep workers and workspaces isolated |
| Shell interpolation | Use argument arrays | Restrict metadata admission |
| npm scripts | Add an explicit policy/option and tests | Isolate exceptions and remove secrets |
| Network | Improve diagnostics and fail-closed policy for unsupported isolation | Enforce egress below BitBake |
| Done-stamp metadata | Replace pickle with non-executable serialization and bind records to inputs | Protect cache writers and quarantine after compromise |
| Cache trust | Add manifests/signature hooks where practical | Protect namespaces and promotion |
| Malicious layers | Cannot be solved by `do_unpack` alone | Review, pin, isolate, and separate signing |
