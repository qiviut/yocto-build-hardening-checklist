# Upstream reference baseline evidence (2026-09-19)

This is a product-neutral control experiment against the pinned BitBake and
OpenEmbedded-Core checkouts. It is not a product build, a host-isolation proof,
or a release-signing result.

## Source and repository state

- Analysis repository: `yocto-build-hardening-checklist` at the clean
  generation revision `20987fe1c8bbc4d26f199d3bafa6025903a28739`.
- BitBake: `046a90b0e9b7b914b7a95aec579cdc3fc9c7617a`, clean checkout.
- OpenEmbedded-Core: `f94ae3d6ba49aef86f497998c0e0232a5039510a`, clean checkout.

The machine-readable artifact records the clean-before-run state, the generator
SHA-256 `51dc1739b2b8581e5967c556d6e9702d4ff9fab0e317e61fed3ca1bc65afe429`,
and SHA-256 hashes for the three profile inputs. The verifier rejects a
modified analysis checkout, a different component `HEAD`, or a dirty component
checkout, and does not modify either component checkout.

## Reference setup and effective configuration

The command was:

```text
python3 scripts/reference_baseline.py \
  --bitbake-root ../yocto-components/bitbake \
  --oe-root ../yocto-components/openembedded-core \
  --skip-sanity \
  --output evidence/reference-baseline-2026-09-19.json
```

The command uses OE-Core's own `oe-init-build-env`, generated
`conf/local.conf`/`conf/bblayers.conf`, and `core-image-minimal` parse-only
expansion. The explicit `--skip-sanity` is a host limitation, not a build
mitigation: it removes the `sanity` class only for this parse probe. The host
also lacked `chrpath` and `diffstat`, so the probe used temporary no-op shims
for those two host-tool links. No shim, build directory, or component checkout
was retained.

The canonical machine-readable result is
`evidence/reference-baseline-2026-09-19.json`. The following is a selected,
reshaped projection of that artifact (not a literal copy); the expected and
effective maps, provenance, return codes, and shim list remain canonical in the
JSON file.

```json
{
  "source_revisions": {
    "bitbake": "046a90b0e9b7b914b7a95aec579cdc3fc9c7617a",
    "openembedded-core": "f94ae3d6ba49aef86f497998c0e0232a5039510a"
  },
  "reference": {
    "status": "passed",
    "sanity_skipped": true,
    "effective_variables": {
      "MACHINE": "qemux86-64",
      "DISTRO": "nodistro",
      "BB_NO_NETWORK": null,
      "BB_STRICT_CHECKSUM": "1",
      "SSTATE_VERIFY_SIG": "0",
      "SSTATE_MIRROR_ALLOW_NETWORK": null
    }
  },
  "mitigation": {
    "status": "passed",
    "sanity_skipped": true,
    "effective_variables": {
      "MACHINE": "qemux86-64",
      "DISTRO": "nodistro",
      "BB_NO_NETWORK": "1",
      "BB_STRICT_CHECKSUM": "1",
      "SSTATE_VERIFY_SIG": "1",
      "SSTATE_MIRROR_ALLOW_NETWORK": "0"
    }
  }
}
```

`BB_NO_NETWORK=null` and `SSTATE_MIRROR_ALLOW_NETWORK=null` mean the
reference fragment leaves both upstream defaults unset; the fetcher fixture
represents the former default as `0`. The mitigation profile explicitly sets
both `BB_NO_NETWORK=1` and `SSTATE_MIRROR_ALLOW_NETWORK=0`, preventing the
sstate mirror exception from deleting the network guard. `BB_STRICT_CHECKSUM`
is already `1` in the pinned `nodistro` configuration, so the mitigation
profile makes that existing policy explicit rather than claiming a before/after
change. The verifier removes inherited report-variable overrides and
`BB_ENV_PASSTHROUGH` additions before sourcing OE-Core, then fails if any
reported effective value differs from its expected profile map.

For comparison, running the same verifier without `--skip-sanity` exited `1`
and refused to parse because the host lacks the required `chrpath` and
`diffstat` tools. That is an intentional fail-closed result.

## Before/after fetcher fixture

The command was:

```text
python3 scripts/baseline_network_fixture.py \
  --bitbake-root ../yocto-components/bitbake
```

It created a temporary HTTP server bound only to `127.0.0.1`, served one
checksummed file, and ran the same URI through the reference and mitigation
profiles. It never contacted an external host. The fixture now rejects a dirty
BitBake checkout, asserts the downloaded-byte result, and emits standalone JSON
on stdout; downloader progress is kept on stderr.

Observed result:

```json
{
  "bitbake_revision": "046a90b0e9b7b914b7a95aec579cdc3fc9c7617a",
  "reference": {
    "BB_NO_NETWORK": "0",
    "outcome": "returned",
    "server_requests": 1,
    "downloaded_bytes_match": true
  },
  "mitigation": {
    "BB_NO_NETWORK": "1",
    "outcome": "NetworkAccess",
    "server_requests": 0,
    "downloaded_bytes_match": false
  }
}
```

This is `fixture-confirmed-at-sink` evidence for the BitBake fetcher path. It is
not end-to-end recipe/task reachability, and it does not prove that arbitrary
task code, DNS, npm, Git helpers, or sstate `_setscene` work cannot open a
socket. Those require the host/worker boundary in `CTRL002`.

## Source basis

- `openembedded-core/oe-init-build-env:11-12,38-48` — official setup entry
  point and template generation path.
- `openembedded-core/meta/conf/templates/default/local.conf.sample:17-29,260-262`
  — machine selection and configuration version.
- `openembedded-core/meta/conf/templates/default/bblayers.conf.sample:1-10`
  — single `meta` layer template.
- `openembedded-core/meta/conf/machine/qemux86-64.conf:1-8` — reference QEMU
  machine.
- `openembedded-core/meta/conf/distro/include/default-distrovars.inc:52-53`
  — strict checksum default;
- `openembedded-core/meta/classes-global/sstate.bbclass:734-756` — sstate
  mirror network exception and detached-signature fetch path;
- `bitbake/lib/bb/fetch/__init__.py:1011-1021` — `BB_NO_NETWORK` fetcher gate;
- `bitbake/doc/bitbake-user-manual/bitbake-user-manual-ref-variables.rst:575-582`
  — documented `BB_NO_NETWORK` semantics.
- `yocto-docs/documentation/security-manual/sstate-signing.rst:119-147` —
  separate signed-sstate configuration and key-material boundary.

## Remaining limits and stopping condition

The baseline phase is complete for source/configuration expansion and the
bounded fetcher fixture. It must not be promoted to product assurance. The
following remain open and are intentionally not marked passed:

- normal OE-Core sanity and a successful image build on this host;
- host-enforced egress denial and the unsupported-user-namespace release gate;
- signed sstate generation/restore with a real reviewed keyring;
- product layers, package lifecycle policy, cache ownership, signing, and
  tested-to-published artifact correspondence.
