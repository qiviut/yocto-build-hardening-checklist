# Upstream reference baseline evidence (2026-09-19)

This is a product-neutral control experiment against the pinned BitBake and
OpenEmbedded-Core checkouts. It is not a product build, a host-isolation proof,
or a release-signing result.

## Source and repository state

- Analysis repository: `yocto-build-hardening-checklist` at the pre-change
  checkpoint `233c3dee81909a5a48da514455b193cb1d9e2fea`.
- BitBake: `046a90b0e9b7b914b7a95aec579cdc3fc9c7617a`, clean checkout.
- OpenEmbedded-Core: `f94ae3d6ba49aef86f497998c0e0232a5039510a`, clean checkout.

The verifier rejects a different component `HEAD` and does not modify either
component checkout.

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

The normalized result in `evidence/reference-baseline-2026-09-19.json` was:

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
      "SSTATE_VERIFY_SIG": "0"
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
      "SSTATE_VERIFY_SIG": "1"
    }
  }
}
```

`BB_NO_NETWORK=null` means the reference fragment leaves the upstream default
unset; the fetcher fixture represents that default as `0`. `BB_STRICT_CHECKSUM`
is already `1` in the pinned `nodistro` configuration, so the mitigation profile
makes that existing policy explicit rather than claiming a before/after change.

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
profiles. It never contacted an external host.

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
  — strict checksum default.
- `bitbake/lib/bb/fetch/__init__.py:1011-1021` — `BB_NO_NETWORK` fetcher gate.
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
