# Independent review of the pinned baseline checkpoint

## Historical disposition

The exact checkpoint `52acd55891e3dbeca77692630cda3bd954508b50` was reviewed by
three bounded, read-only lanes after the initial timeout was explicitly treated
as `UNKNOWN`. All three completed lanes returned `REQUEST_CHANGES`; none was
approval for the checkpoint.

The review scope was the product-neutral parse-only baseline, the loopback
fetcher fixture, the retained evidence, and the traceability/CI harness. It was
not a product-build, deployment, cache-trust, signing, or release-artifact
sign-off.

## Confirmed findings and remediation

- **Effective configuration was not verified.**
  `scripts/reference_baseline.py` at the reviewed checkpoint marked a profile
  passed from the BitBake return code alone (`:139-150`, `:177-192`) and
  inherited caller policy variables through the environment. The remediation
  in `20987fe1c8bbc4d26f199d3bafa6025903a28739` adds sanitized environment
  construction and exact expected/effective-value comparison in
  `scripts/reference_baseline.py:31-66`, `:96-159`, and `:230-248`.

- **The offline profile did not explicitly close the sstate mirror exception.**
  The reviewed `baseline/mitigation/offline-and-signed-sstate.conf` set
  `BB_NO_NETWORK` but not `SSTATE_MIRROR_ALLOW_NETWORK`. The repaired profile
  sets `SSTATE_MIRROR_ALLOW_NETWORK = "0"`; the README and VER011 retain the
  separate public-key and `SSTATE_VALID_SIGS` deployment boundary.

- **The network fixture attributed behavior to a pinned checkout without
  checking cleanliness.** The repaired
  `scripts/baseline_network_fixture.py:38-61` rejects tracked or untracked
  checkout changes before importing BitBake.

- **The fixture reported byte comparison without enforcing it.** The repaired
  `scripts/baseline_network_fixture.py:109-126` requires the expected request
  count and `downloaded_bytes_match` result for both cases, with unit coverage
  in `tests/test_baseline_artifacts.py:56-77`.

- **The fixture's stdout was not standalone JSON.** BitBake downloader progress
  could precede the JSON object. The repaired
  `scripts/baseline_network_fixture.py:139-153` redirects downloader progress
  to stderr; the real pinned fixture run now parses stdout with `json.loads`.

- **Evidence provenance was bound to the parent checkpoint and the Markdown
  excerpt was mislabeled as the JSON artifact.** The regenerated
  `evidence/reference-baseline-2026-09-19.json` records the full clean
  generation SHA, generator hash, and profile-input hashes. The corresponding
  Markdown note labels its embedded data as a selected projection and points to
  the canonical JSON.

- **CI did not execute the dynamic evidence path.**
  `.github/workflows/traceability.yml:65-107` now fetches the exact pinned
  BitBake/OE-Core commits and runs both probes, validating their JSON contracts;
  `tests/test_baseline_artifacts.py:35-77` covers the fail-closed helper logic.

- **Strict-checksum and signed-sstate scope needed sharper wording.**
  `baseline/README.md:40-59` now limits `BB_STRICT_CHECKSUM` to
  checksum-capable fetch methods and requires a reviewed key setup plus a
  non-empty `SSTATE_VALID_SIGS` signer allow-list for signed-sstate exercise.

## Follow-up state

The repaired behavior is committed at
`20987fe1c8bbc4d26f199d3bafa6025903a28739`. Local tests, Doorstop, the
traceability linter, the loopback fixture, and the parse-only reference probe
pass against the pinned component revisions. A fresh independent review of this
new exact SHA remains required before closing the review bead or unblocking the
dependent deployment-boundary work.

The evidence remains deliberately bounded: it does not prove host/kernel
network denial, arbitrary task-socket containment, signed-sstate generation or
restore with a real keyring, product-layer behavior, cache ownership, or
release-artifact correspondence.
