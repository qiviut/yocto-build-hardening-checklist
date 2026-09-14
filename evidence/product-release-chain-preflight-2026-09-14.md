# Product release-chain preflight — 2026-09-14

## Scope

This is an evidence-availability check for the product-specific release-chain
phase of the Yocto/OpenEmbedded assurance review. It is not a product build,
release approval, or deployment verification.

## Search result

The local search covered `/home/operator` for product build entry points and
configuration names. No product `bblayers.conf`, `local.conf`, or `kas*.yml`
was found. The only `bblayers.conf` located was BitBake's own testdata:

```text
/home/operator/.openclaw/workspace/yocto-components/bitbake/lib/layerindexlib/tests/testdata/build/conf/bblayers.conf
```

It is source-component testdata, not product configuration, and was not treated
as release evidence. The `.wks` files found under the read-only Yocto component
checkouts are upstream image-layout fixtures/templates, not a product release
configuration.

The analysis repository contains the checklist and source-grounded records, but
no product-specific evidence for:

- layer, machine, distro, image, release, and exact revision selection;
- CI worker definitions, mounts, identity, network enforcement, or credential
  policy;
- `DL_DIR`, mirror, `SSTATE_DIR`, cache ownership, signer, keyring, or
  `SSTATE_VERIFY_SIG` deployment policy;
- generated test reports, SBOM/SPDX, provenance, manifests, or approvals;
- signing requests, artifact-store promotion, publication, installation, update
  channels, or consumer verification.

No full product build, release dry run, signing operation, publication, install,
or update was performed. No credentials were retained.

## Gate decision

**Blocked pending product evidence.** The release-chain records must remain
`unverified`/`planned` and RISK010 must remain an open gap. Source review,
upstream selftests, and harmless local fixtures cannot establish tested-to-signed
byte correspondence or product deployment controls.

## Required next evidence bundle

Provide or point the review at an approved, secret-free evidence bundle
containing at least:

1. immutable layer/machine/distro/image configuration and component revisions;
2. effective worker environment, mounts, identity, egress policy, and credential
   absence assertions;
3. mirror/download/cache ownership and signature/keyring policy;
4. test, SBOM, provenance, manifest, approval, and artifact-digest records;
5. a dry run proving that substitution after testing is rejected before signing,
   publication, installation, or update acceptance.
