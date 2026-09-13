# Second-pass Astra review

## Scope and provenance

A replacement Astra lane performed a bounded, read-only second-pass review after the provider rate limit reset. The runtime log records `model=gpt-6-astra provider=openai-codex` for the review session. It was given the prior source-review notes, the medtech/Sec-T background, the threat model, and the initial public checklist.

The parent review independently re-read the cited source locations before recording the findings below. This is a review note, not an upstream security advisory or a claim that a malicious layer has been observed in the wild.

Baseline:

- BitBake: `046a90b0e9b7b914b7a95aec579cdc3fc9c7617a`
- OpenEmbedded-Core: `fe7a24bc67118e7e184b5f5247258715e3904e7c`
- meta-yocto: `7e41504cd63b099b214f10d92cfdaf358ab98c5f`
- yocto-docs: `e35e86e9aea4e4ae12e8e0ba8a6391f2b2555b63`

## Astra’s conclusion

Yocto is not a malicious-input sandbox. `do_unpack` is a thin task orchestrator; the effective attack surface includes BitBake parsing and task execution, fetcher-specific unpackers, package-manager hooks, caches, and the build host. Yocto can support a trustworthy medtech build process only when the surrounding admission, isolation, cache, reproducibility, and release controls are treated as part of the security boundary.

## Findings from the second pass

### A-001 — Ordinary task network isolation can fail open

**Evidence:**

- OE-Core marks `do_fetch[network] = "1"` in `openembedded-core/meta/classes-global/base.bbclass:165–171`.
- `do_unpack` has no network-enabled flag in the task definition at `:185–211`.
- `bitbake/bin/bitbake-worker:283–305` parses the recipe before checking the task’s `network` flag, and for a non-network task attempts `bb.utils.disable_network()` only when the task UID is local.
- `bitbake/lib/bb/utils.py:2046–2075` calls `unshare(CLONE_NEWNET | CLONE_NEWUSER)`, but logs at debug level and returns when `unshare()` fails.

**Preconditions:** the build relies on BitBake’s namespace helper as its main non-fetch network control, and the production host disallows unprivileged user/network namespaces or the task UID is not treated as local.

**Impact:** a task expected to be offline can retain host network access. A compromised recipe, layer, or package build hook can exfiltrate data or fetch mutable code. The risk is especially material for a medtech release worker, but this is not a claim that every default build is network-enabled.

**Remediation:** enforce egress denial below BitBake with a VM, firewall, or equivalent fail-closed control; test the effective task namespace; treat BitBake’s helper as defense in depth; add diagnostics and a policy gate for unsupported isolation rather than silently accepting the fallback.

### A-002 — Done stamps use Python pickle in the trusted cache path

**Evidence:** `bitbake/lib/bb/fetch/__init__.py:715–720` loads a done stamp with `pickle.Unpickler(...).load()`. The exception is caught at `:721–728`, so a successful pickle payload can execute before the error-handling path. The same file writes checksum dictionaries using `pickle.Pickler` at `:732–737` and `:765–770`.

**Preconditions:** an attacker can replace or inject a fetcher done stamp in a cache/workspace that a later build trusts, and the file is newer than the local artifact or the artifact is a directory. The upstream archive alone does not write this stamp; cache or worker write access is required.

**Impact:** arbitrary Python code execution in the BitBake process before normal build work, with the build worker’s permissions. This makes cache write separation a code-execution control, not just an integrity optimization.

**Remediation:** replace pickle with a strictly parsed, non-executable format such as a canonical JSON or fixed binary checksum record; bind it to the exact local artifact and recipe identity; reject untrusted or unsigned cache metadata; quarantine caches after any cross-trust-domain write.

### A-003 — npm lifecycle scripts remain an executable-code path

**Evidence:** `openembedded-core/meta/classes-recipe/npm.bbclass:322–325` runs `npm install` without an `ignore-scripts` setting. The npm environment invokes `bitbake/lib/bb/fetch/npm.py:127–153`, which delegates through `runfetchcmd()`. `bitbake/lib/bb/fetch/__init__.py:894–924,961–966` carries selected environment values, including SSH-agent, cloud, proxy, Git, and GitHub-token variables when present in the datastore or original environment. `npm.py:118–124` also has an explicit `BB_USE_HOME_NPMRC` path.

**Preconditions:** a recipe uses this class and a direct or transitive package supplies an install hook or native build hook.

**Impact:** a Mini Shai-Hulud-style dependency can run code during the build, alter outputs, attempt direct network access, or read credentials exposed to the worker. npm offline configuration is not kernel-level egress control.

**Remediation:** disable scripts by default where compatible; make exceptions explicit, reviewed, and isolated; remove credentials and SSH agents; keep signing outside the build worker; add a fixture that proves default and exception-lane behavior.

### A-004 — Path and command hardening remain defense-in-depth priorities

The earlier findings remain valid for the reviewed snapshot:

- common and Git destination handling need component-aware confinement rather than string-prefix checks and unchecked relative joins;
- npm shrinkwrap package locations require canonical validation and symlink-aware staging;
- shell-string extractor commands should be replaced with argument arrays;
- SHA-1 should not be accepted for new production npm integrity policy.

These controls reduce damage from hostile metadata and malformed package layouts, but they do not turn a malicious layer into safe data. A layer provider can define Python and shell tasks by design.

## What this review does not establish

- It does not identify an upstream CVE or prove exploitation against a production configuration.
- It does not show that a compromised upstream archive can directly write a BitBake done stamp; the cache-writer precondition matters.
- It does not establish that every host fails network isolation. A direct probe on this review host accepted user-plus-network namespaces; production images must be tested independently.
- It does not validate every archive tool, filesystem race, package ecosystem, or external layer.
- It is not an IEC 62304, IEC 62443, or regulatory conformity assessment.

## Priority order

1. Put release builds in disposable, least-privilege workers with host-enforced network denial and no signing/cloud/SSH credentials.
2. Freeze and review layers, recipes, source revisions, lockfiles, toolchains, and cache provenance; build from a controlled mirror with `BB_NO_NETWORK = "1"` after intake.
3. Remove pickle from cache metadata and fail closed when required isolation is unavailable.
4. Make npm lifecycle execution an explicit exception and extend the same policy to every ecosystem’s build hooks.
5. Land component-aware path validation, safe archive staging, shell-free extractor invocation, and regression tests upstream or in the maintained product fork.
6. Keep build, test, SBOM/provenance, signing, and publication in separate trust domains with exact-SHA verification.
