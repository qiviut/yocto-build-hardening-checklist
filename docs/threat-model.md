# Yocto Build Threat Model

## Scope

This model covers a Yocto/OpenEmbedded build that turns layer metadata and upstream sources into firmware, operating-system images, packages, SBOMs, provenance, and update artifacts for a medtech product.

The central question is not whether a source has a CVE. It is whether an actor can influence the build, the resulting artifact, the evidence attached to it, or the release credentials.

## Actors and inputs

### Potentially hostile or semi-trusted inputs

- Layer repositories and their maintainers/contributors.
- Recipes, `.bbappend` files, classes, configuration, handlers, and anonymous Python.
- Git repositories, tags, submodules, Git LFS objects, and `.gitmodules` files.
- HTTP archives, mirrors, package registries, npm lockfiles, bundled dependencies, and generated sources.
- Download and shared-state caches.
- Host tools, container images, compilers, interpreters, and package managers.
- Build and test scripts, code generators, plugins, and native extensions.
- CI configuration, artifact stores, reusable actions, and provenance generators.

### Higher-consequence assets

- Source and layer credentials.
- SSH agents and cloud tokens.
- Signing keys and update publication authority.
- Other builds' workspaces and caches.
- Release artifacts, SBOMs, provenance, and approval records.
- Developer or CI host files reachable through mounts or ambient permissions.

## Trust boundaries

1. **Repository intake:** networked acquisition becomes a frozen, reviewed source set.
2. **Metadata parser:** BitBake parses metadata that can contain executable Python and task definitions.
3. **Fetcher/unpacker:** source bytes and metadata-derived paths become files in the build workspace.
4. **Build worker:** source and build scripts execute with the worker's OS privileges and environment.
5. **Cache boundary:** `DL_DIR` and `SSTATE_DIR` become reusable inputs to later builds.
6. **Test boundary:** tests may execute artifacts or mutate them.
7. **Release boundary:** verified immutable outputs are signed and published.
8. **Installation/update boundary:** consumers verify the artifact and its provenance before use.

A boundary is only real if it is enforced by a lower-level mechanism. A convention in a recipe, a task flag, or a comment is not sufficient against code already executing as the build user.

## Main attack paths

### A. Malicious layer provider

A layer can influence metadata parsing, task definitions, `SRC_URI`, overrides, classes, `PATH`, package-manager configuration, and release-facing variables. A malicious layer should therefore be assumed to have code-execution capability within an ordinary BitBake build.

**Controls:** independent layer review, immutable revisions, a restricted layer allow-list, disposable workers, no secrets, no signing authority, host-enforced network denial, and separate release signing.

### B. Compromised upstream project

A pinned commit or archive checksum identifies bytes; it does not prove that the bytes are benign. A compromised approved revision can introduce build scripts, native code, unsafe install behavior, malicious `.gitmodules`, lockfile changes, or runtime backdoors.

**Controls:** review source and build-system changes, inspect transitive dependencies, retain provenance, run static/dynamic analysis in isolated lanes, and require product-owner acceptance for residual supply-chain risk.

### C. Package-manager lifecycle attack

The package manager can execute scripts from a direct or transitive dependency. npm is particularly relevant because `npm install` may run lifecycle hooks. A package-manager setting such as offline mode does not stop a script from opening a socket or launching another installed program.

**Controls:** disable scripts by default, explicitly approve exceptions, isolate exceptions, remove ambient credentials, and enforce egress denial below the package manager.

### D. Unpack path escape

URI parameters, Git submodule metadata, npm lockfiles, and archive members can influence filesystem destinations. A path-confinement bug can pollute sibling workspaces, overwrite other build inputs, or create a bridge to a higher-consequence location.

**Controls:** component-aware canonical path checks, rejection of traversal and unsafe link/device members, staging and validation, safe command construction, and hostile fixture tests.

### E. Cache poisoning

A writable download or shared-state cache can replace an input after initial verification or introduce an object consumed by a later build. Done stamps and cache hits are not equivalent to provenance verification when the cache trust boundary is compromised.

**Controls:** access control, per-trust-domain namespaces, signed/provenance-bound promotion, cache manifests, quarantine and rebuild procedures, and no shared writable cache between untrusted and release jobs.

### F. Build-host compromise or contamination

Yocto assumes a secure host and does not make a hostile host trustworthy. Host tools, environment variables, mounts, kernel vulnerabilities, user namespaces, container escapes, and stale workspaces can affect the build or leak credentials.

**Controls:** patched disposable images, least privilege, host LSM/namespace policy, minimal environment, no secrets, resource limits, clean rebuild after incidents, and independent verification of release artifacts.

## Security properties to prove

For a production build, the team should be able to demonstrate:

- **Input identity:** every source/dependency is tied to an approved immutable identity.
- **Input completeness:** the build uses the reviewed source set, including transitive and generated inputs.
- **Execution containment:** hostile build code cannot reach release secrets, unrelated workspaces, or the network except through an approved intake lane.
- **Filesystem confinement:** fetching and unpacking cannot escape the intended task workspace.
- **Cache integrity:** reusable objects are access-controlled and provenance-checked.
- **Artifact integrity:** signed outputs correspond to the exact tested source and configuration.
- **Evidence integrity:** SBOMs, provenance, logs, and approvals describe the exact artifact being released.

## Residual-risk statement

Even after these controls, the organization still trusts the reviewed source, the toolchain, the host kernel, the verification process, and the humans approving changes. The correct outcome is an explicit residual-risk decision, not an unqualified statement that Yocto or an upstream package is safe.
