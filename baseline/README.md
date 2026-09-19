# Reproducible upstream reference baseline

This directory is a product-neutral control experiment for the pinned
BitBake/OE-Core sources. It is not a product build configuration and does not
establish worker isolation, cache trust, signing, or release assurance.

## Source pins

- BitBake: `046a90b0e9b7b914b7a95aec579cdc3fc9c7617a`
- OpenEmbedded-Core: `f94ae3d6ba49aef86f497998c0e0232a5039510a`

The verifier rejects a different `HEAD` rather than silently changing the
experiment. The component checkouts are inputs and are not modified.

## Reference setup

`oe-init-build-env` is the upstream entry point. It creates `conf/local.conf`
and `conf/bblayers.conf` from the pinned OE-Core templates. The verifier then
appends [`reference/local.conf`](reference/local.conf), which selects:

- the upstream `qemux86-64` machine;
- the upstream `nodistro` configuration;
- only the pinned OE-Core `meta` layer.

[`reference/bblayers.conf.in`](reference/bblayers.conf.in) is an inspectable
copy of the template with `##OEROOT##` retained as its documented placeholder.
The generated file is still produced by OE-Core itself during each run.

The upstream anchors are:

- `openembedded-core/oe-init-build-env:11-12,38-48`;
- `openembedded-core/meta/conf/templates/default/local.conf.sample:17-29,260-262`;
- `openembedded-core/meta/conf/templates/default/bblayers.conf.sample:1-10`;
- `openembedded-core/meta/conf/machine/qemux86-64.conf:1-8`;
- `openembedded-core/meta/conf/distro/include/default-distrovars.inc:52-53`.

## Mitigation profile

[`mitigation/offline-and-signed-sstate.conf`](mitigation/offline-and-signed-sstate.conf)
adds three bounded settings:

- `BB_NO_NETWORK = "1"` rejects fetcher network access after intake;
- `BB_STRICT_CHECKSUM = "1"` makes the checksum requirement explicit;
- `SSTATE_VERIFY_SIG = "1"` requires signed shared-state reuse.

The last setting is not a complete signing configuration. A reviewed public
key setup and signed artifact are required to exercise it; no key material is
stored here. The profile also cannot replace a host firewall or network policy:
BitBake task code can open sockets outside the fetcher, and sstate/
`_setscene` tasks have distinct network metadata.

## Verification commands

From this repository, using the pinned checkouts:

```sh
python3 scripts/reference_baseline.py \
  --bitbake-root ../yocto-components/bitbake \
  --oe-root ../yocto-components/openembedded-core \
  --skip-sanity \
  --output evidence/reference-baseline-2026-09-19.json

python3 scripts/baseline_network_fixture.py \
  --bitbake-root ../yocto-components/bitbake
```

`--skip-sanity` is explicit and is only for configuration expansion on hosts
where the normal OE-Core sanity event cannot run. It removes the `sanity`
class for the parse-only probe and may create temporary no-op `chrpath` and
`diffstat` shims when the host lacks those required tools. It does **not** make
a build valid, and the evidence must retain that limitation. Without this flag,
the verifier fails rather than bypassing the host gate.

The network fixture starts a local loopback HTTP server and exercises the same
fetch input twice. It must show one request under the reference profile and
zero requests plus `NetworkAccess` under the offline profile. It never contacts
an external host.

## Evidence boundary

The artifacts prove:

- the pinned source revisions and generated upstream build setup;
- effective configuration expansion for the selected variables;
- the fetcher-level effect of `BB_NO_NETWORK` on one harmless local fixture.

They do not prove:

- a successful normal build on a host that fails OE-Core sanity;
- direct task-socket denial or DNS/firewall containment;
- signed sstate generation or restore with a real product keyring;
- npm lifecycle policy, product layer behavior, or release artifact binding.
