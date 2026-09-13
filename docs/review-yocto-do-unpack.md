# Narrow Review: Yocto `do_unpack`

## Review baseline

The review used clean `master` checkouts matching these local `origin/master` revisions:

- BitBake: `046a90b0e9b7b914b7a95aec579cdc3fc9c7617a`
- OpenEmbedded-Core: `fe7a24bc67118e7e184b5f5247258715e3904e7c`
- meta-yocto: `7e41504cd63b099b214f10d92cfdaf358ab98c5f`
- yocto-docs: `e35e86e9aea4e4ae12e8e0ba8a6391f2b2555b63`

The checkouts were clean after updating from `origin/master`. This document records a source review and local reproductions; it is not an upstream security advisory.

## Definition and call chain

OpenEmbedded defines the task in:

`openembedded-core/meta/classes-global/base.bbclass`

- `185`: `addtask unpack after do_fetch`
- `186`: `do_unpack[cleandirs] = "${UNPACKDIR}"`
- `188–210`: `python base_do_unpack()`
- `195`: reads `SRC_URI`
- `200`: reads `UNPACKDIR`
- `207–208`: creates `bb.fetch.Fetch` and calls `fetcher.unpack(UNPACKDIR)`

The dispatcher is:

`bitbake/lib/bb/fetch/__init__.py:2010–2037`

The common archive path is:

`bitbake/lib/bb/fetch/__init__.py:1523–1661`

Fetcher-specific paths reviewed:

- Git: `bitbake/lib/bb/fetch/git.py:660–799`
- Git submodules: `bitbake/lib/bb/fetch/gitsm.py:37–148,210–255`
- npm: `bitbake/lib/bb/fetch/npm.py:84–89,335–340`
- npm shrinkwrap: `bitbake/lib/bb/fetch/npmsw.py:37–60,81–192,251–280`

## Findings

### F-001 — BitBake is an execution engine, not a malicious-layer sandbox

**Severity:** architecture / high consequence

**Evidence:**

- `yocto-docs/documentation/security-manual/build-process-security.rst:22–50` says the host is assumed secure, `DL_DIR` and `SSTATE_DIR` are trusted, BitBake executes code during parsing and builds, and build environments should be disposable.
- `openembedded-core/meta/classes-global/base.bbclass:165–171` explicitly enables network for `do_fetch`; `do_unpack` has no network-enabled flag at `:185–211`.
- `bitbake/bin/bitbake-worker:283–305` parses the recipe before attempting to disable networking for a non-network task, and only attempts it for a local UID.
- `bitbake/lib/bb/utils.py:2046–2075` returns after a failed `unshare()` after only a debug log, so the namespace helper is not a fail-closed boundary.
- `bitbake/lib/bb/fetch/README:5–18` documents the fetcher network convention and its limitations.

**Precondition:** an untrusted or compromised layer, recipe, class, build script, or tool is admitted to the build.

**Impact:** code executes with the build worker's OS permissions. It can alter outputs, attempt network access, read ambient credentials, poison caches, or attack the host. For a medtech product this affects artifact integrity, traceability, and potentially product safety.

**Disposition:** not a defect that can be solved by changing only `do_unpack`. Use disposable least-privilege workers, lower-level network/filesystem controls, review/approval of layers, and a separate signing lane.

### F-002 — npm `install` can run dependency lifecycle scripts

**Severity:** high in a credentialed or networked worker

**Evidence:** `openembedded-core/meta/classes-recipe/npm.bbclass:273–325` runs `npm install`. The configuration at `67–77` sets npm offline mode, but the invocation does not set `ignore-scripts`.

**Precondition:** a recipe uses the npm class and a package or transitive dependency contains an install lifecycle script.

**Impact:** the script runs in the build worker. Offline npm configuration does not stop direct sockets or other binaries. `bitbake/lib/bb/fetch/__init__.py:894–924` includes credential- and agent-related variables such as `GITHUB_TOKEN`, AWS credentials, and `SSH_AUTH_SOCK` in the fetcher environment. Any such ambient value increases impact.

**Remediation:** disable scripts by default; explicitly isolate and approve exceptions; remove credentials and SSH agents; enforce network denial outside intake; sign only in a separate lane.

**Caveat:** some packages genuinely need build hooks or native compilation. The safe answer is a reviewed exception lane, not an untested global switch that silently breaks products.

### F-003 — Common and Git unpack destination checks allow traversal classes

**Severity:** medium/high depending on worker permissions

**Evidence:**

- Common unpacker: `bitbake/lib/bb/fetch/__init__.py:1538–1547` checks absolute paths with a string `startswith` and joins relative paths without a containment check.
- Git unpacker: `bitbake/lib/bb/fetch/git.py:672–683` repeats the behavior and also joins `destsuffix` directly.
- Existing tests at `bitbake/lib/bb/tests/fetch.py:824–831` cover a valid absolute subdirectory and an obvious `/bin/sh` rejection, but not sibling-prefix or relative traversal cases.

**Local reproduction:** invoking the current common unpack method in an isolated temporary directory allowed:

- `subdir=../escape` to extract outside the root;
- an absolute sibling destination such as `/tmp/root2` to pass the `/tmp/root` prefix check.

**Remediation:** use canonical component-aware `commonpath` checks for every destination parameter; reject traversal and unsafe links; stage and validate where stronger guarantees are needed; add regression tests.

**Threat-model caveat:** malicious layer metadata already has code-execution power. This finding is still valuable defense-in-depth and matters when untrusted package/lockfile metadata reaches a fetcher path without granting the source author a direct task body.

### F-004 — npm shrinkwrap locations are used as destination suffixes without confinement

**Severity:** medium/high depending on cache and workspace layout

**Evidence:**

- `bitbake/lib/bb/fetch/npmsw.py:37–60` iterates package-lock `packages` locations and only checks `startswith('node_modules/')`.
- `npmsw.py:176–184` retains the location as `destsuffix`.
- `npmsw.py:269–280` joins the dependency suffix and extracts/copies into it.

A location beginning with `node_modules/` can still contain `..` components. The resulting destination is not canonicalized against the unpack root.

**Remediation:** parse locations as bounded relative POSIX paths; reject absolute paths, `..`, backslashes, empty components, and symlink ancestors; use component-aware root checks and hostile lockfile fixtures.

### F-005 — Resolved shrinkwrap URLs are not normalized like direct npm proxy URLs

**Severity:** review gap / medium-confidence hypothesis

**Evidence:**

- `npmsw.py:105–111` and `132–138` construct a `URI` directly from the shrinkwrap `resolved` value and retain its parsed parameters while adding download filename and checksum.
- The direct npm fetcher deliberately discards stored URL parameters before rebuilding the proxy URI: `bitbake/lib/bb/fetch/npm.py:281–292`.
- Generic unpack uses URI parameters such as `subdir`: `bitbake/lib/bb/fetch/__init__.py:1538–1547`.

A hostile lockfile URL containing BitBake-style parameters may be able to influence extraction behavior. The exact reachable combinations need a regression test across URI parsing, proxy fetch construction, and unpack.

**Remediation:** allow-list the scheme, host, path, and required package parameters for shrinkwrap dependencies; discard all embedded parameters before adding only generated download filename and verified integrity; reject non-HTTPS registry sources unless explicitly approved.

### F-006 — Shell-string extraction commands create avoidable injection exposure

**Severity:** medium-confidence hardening finding

**Evidence:** `bitbake/lib/bb/fetch/__init__.py:1551–1557` runs string commands through `shell=True`. Filename interpolation occurs at `1580–1598`, and RPM pipelines at `1609–1616`. Other code paths use argument arrays, demonstrating the safer pattern.

The usual attacker would need influence over URI/local-cache metadata, so exploitability depends on how that metadata is admitted. Nevertheless, shell parsing is unnecessary for decompression and extraction.

**Remediation:** use argument arrays and temporary files for every extractor; add filenames containing shell metacharacters, whitespace, and newlines to the test suite.

### F-007 — Direct npm integrity accepts SHA-1

**Severity:** medium cryptographic hygiene finding

**Evidence:** `bitbake/lib/bb/fetch/npm.py:49–50` lists `sha1sum` as an accepted checksum, and `162–207` requires exactly one checksum but does not reject SHA-1.

**Impact:** SHA-1 is not an appropriate new release integrity primitive for a medtech supply-chain policy. Collision attacks are not the normal registry substitution path, but accepting a broken algorithm weakens the policy and creates avoidable migration debt.

**Remediation:** require SHA-256 or SHA-512 for new recipes, warn or fail on SHA-1 in production policy, and migrate existing recipes with controlled source changes.

### F-008 — Download and shared-state caches are explicitly trusted

**Severity:** high if cache write access crosses trust domains

**Evidence:** `yocto-docs/documentation/security-manual/build-process-security.rst:30–36` says `DL_DIR` artifacts are not repeatedly re-verified and that `SSTATE_DIR`/mirrors are assumed safe. Fetch checksum verification and done-stamp handling are in `bitbake/lib/bb/fetch/__init__.py:590–747`, but `do_unpack` itself dispatches extraction at `2010–2037`.

**Remediation:** protect caches, separate trust domains, bind promotion to signatures/provenance, retain per-build cache manifests, and rebuild after compromise.

### F-009 — Fetcher done stamps deserialize Python pickle from the cache

**Severity:** high if a cache writer or worker can replace done stamps

**Evidence:** `bitbake/lib/bb/fetch/__init__.py:715–720` loads an existing done stamp with `pickle.Unpickler(...).load()`. The same file writes checksum dictionaries with `pickle.Pickler` at `:732–737` and `:765–770`.

**Precondition:** an attacker can write or replace a done stamp in a cache/workspace later consumed by BitBake. A downloaded upstream archive does not itself write this stamp; the cache-writer precondition is essential.

**Impact:** a crafted pickle can execute Python in the BitBake process before normal build work, with build-worker privileges. This turns cache write separation into an execution-boundary requirement.

**Remediation:** replace pickle with a strictly parsed canonical checksum record, bind it to the exact artifact and recipe identity, and reject or quarantine untrusted cache metadata. Add a regression fixture proving malformed and hostile records are treated as data and never invoked.

## Positive controls observed

- Fixed Git revisions and submodule revisions are supported.
- `BB_NO_NETWORK`, `BB_ALLOWED_NETWORKS`, mirrors, and fetcher URL checks exist.
- Non-network tasks attempt user/network-namespace isolation, but the current helper can fall back after `unshare()` failure; host enforcement remains required.
- Direct npm rejects `latest` and requires a recipe-provided checksum.
- Direct npm proxy setup discards embedded resolved URL parameters and injects the recipe checksum.
- The npm class avoids `npm pack` lifecycle hooks during its tar packaging step.
- Existing fetcher tests cover some absolute destination, archive format, checksum, and quoted-filename cases.

## Screenshot pointer: `lfs=1` versus `lfs=True`

The attached pointer described an operational submodule LFS parameter issue, not a security vulnerability. In the reviewed snapshot:

- `gitsm.py:124–128` emits numeric `lfs=1` or `lfs=0`.
- `git.py:867–868` enables LFS only when the value is exactly the string `"1"`.

A manually supplied `lfs=True` is therefore treated as disabled, but the current gitsm-generated parameter uses the numeric form. This should remain a compatibility regression test, not a security finding.

## Trust conclusion

Yocto is suitable as part of a controlled, reproducible product build system. It should not be described as a sandbox or as proof that upstream source is safe. The minimum credible medtech posture is pinned and reviewed inputs, a controlled offline transition, disposable lower-privilege builders, host-enforced network denial, protected caches, explicit package-script policy, path-confinement tests, separated signing, and retained traceability evidence.
