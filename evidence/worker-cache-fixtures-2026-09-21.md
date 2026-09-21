# Worker and cache boundary fixture evidence — 2026-09-21

## Decision

This is a fresh, local-only evidence pass for the deployment-boundary follow-up. It is **fixture-confirmed-at-sink**, not deployment-verified. No external host, product build, production cache, credential, signing key, or artifact was used.

The evidence does not close the deployment gap. `CTRL002` (host-enforced egress), `CTRL006` (secretless worker), and `CTRL008` (cache provenance/signatures) remain partial.

## Exact scope and provenance

- Analysis repository revision: `926cc51726edf62ca20f6cad137c7c54ebb07ec9`
- BitBake: `046a90b0e9b7b914b7a95aec579cdc3fc9c7617a`
- OpenEmbedded-Core: `f94ae3d6ba49aef86f497998c0e0232a5039510a`
- The analysis, BitBake, and OE-Core worktrees were clean before and after the probes.
- Machine-readable projection: `evidence/worker-cache-fixtures-2026-09-21.json`

## Probes run

1. `scripts/worker_cache_fixture_matrix.py` with the pinned BitBake and OE-Core roots, using the repository Doorstop virtualenv.
2. A disposable Python probe importing the pinned BitBake `bb.utils`, binding only to `127.0.0.1`, and testing Python, curl, wget, Git, npm, and local hostname resolution. The probe recorded only return codes, byte counts, request paths, and environment-name presence; it did not record secret values.

Both commands exited `0`. GPG emitted only temporary trust-database diagnostics on stderr.

## Observed results

### Network helper and direct tool behavior

The repository fixture’s network child reported:

- `disable_network()` outcome: `PermissionError` while setting up the child mapping;
- network namespace changed;
- post-helper loopback probe: `OSError`.

The direct loopback probe showed a different, important path:

- `disable_network()` returned;
- network namespace did not change;
- Python direct socket and Python subprocess connected to the temporary loopback server;
- curl, wget, and npm returned success against that server;
- Git attempted the local HTTP endpoint and returned `128` after the server observed the request;
- local `localhost` resolution succeeded;
- observed request paths were `/probe`, `/probe`, `/probe/repo.git/info/refs?service=git-upload-pack`, and `/probe/-/ping`.

These were all local requests. They do not demonstrate access to an external host, but they do demonstrate that the BitBake helper is not a sufficient host-level egress boundary in the direct-process fallback path.

### Environment and worker identity

The probe ran as a non-root UID/GID, but it was not a product release worker:

- `HOME` was not an isolated temporary home;
- the process reported 46 mounts;
- `SSH_AUTH_SOCK` was present in the environment (the socket value was not collected);
- no product worker allow-list, mount policy, credential policy, or host firewall policy was available.

Therefore `CTRL006` is not deployment-verified, and the current host must not be described as secretless.

### Cache and signature fixture

The disposable GPG fixture recorded:

- valid payload: return code `0`, `GOODSIG`, `VALIDSIG`, no `BADSIG`;
- tampered payload: return code `1`, `BADSIG`, no `GOODSIG`/`VALIDSIG`;
- actual valid signature with an empty allow-list: `LocalSigner.verify()` returned `true`;
- fake `GOODSIG` with a non-zero exit and a matching key: returned `true`;
- fake `GOODSIG` with a non-zero exit and an empty allow-list: returned `false`.

This confirms the fixture behavior and the need for an explicit product signer allow-list plus successful GPG-status policy. It does not verify a product keyring, `SSTATE_VALID_SIGS`, cache ownership, signed-sstate generation, restore, or provenance promotion.

## Source mapping

The pinned source explains the boundary:

- `bitbake/lib/bb/utils.py:2046-2075`: `disable_network()` returns after `unshare()` failure rather than failing the task itself; mapping failures can occur after the namespace change.
- `bitbake/bin/bitbake-worker:290-295`: the worker calls the helper only for tasks without the `network` flag and skips it for non-local UIDs.
- `openembedded-core/meta/classes-global/sstate.bbclass:150-160`: every `SSTATETASKS` task and its `_setscene` form receives `network=1`.
- `bitbake/lib/bb/fetch/__init__.py:894-935,961-972`: fetch command environments can carry selected proxy, Git, SSH-agent, cloud, and token variables from metadata or the original environment.
- `openembedded-core/meta/lib/oe/gpg_sign.py:125-151`: empty `valid_sigs` accepts any successful GPG verification; a non-empty allow-list is matched against `GOODSIG` values without independently rejecting a non-zero exit in the tested branch.
- `openembedded-core/meta/classes-recipe/npm.bbclass:322-325`: the class invokes `npm install`; package lifecycle behavior remains an executable-code path requiring worker controls.

## Unavailable deployment evidence

The following remain explicitly unavailable and must stay open:

- a product-like disposable worker with effective task flags and host/kernel/firewall egress denial;
- direct socket, DNS, HTTP(S), Git, npm/Python, and native-helper results from that product worker rather than this host-local loopback fixture;
- effective environment, process identity, mounts, SSH-agent/cloud-credential absence, and helper configuration from the release worker;
- `DL_DIR`/`SSTATE_DIR` ownership and writer/reader separation;
- production keyring, `SSTATE_VERIFY_SIG`, `SSTATE_VALID_SIGS`, signed-sstate restore, and provenance promotion;
- full product build, SBOM/provenance, signing, publication, installation, and update reachability.

## Traceability disposition

- `VER002`: local fixture path observed; host-enforced denial and product `_setscene` behavior remain unverified.
- `VER006`: local environment behavior observed; secretless product-worker state remains unverified.
- `VER008`: local signature/tamper behavior observed; product cache ownership, keyring, signer allow-list, and restore decisions remain unverified.
- `VER011`: the parse/fetcher baseline remains bounded and must not be promoted to deployment assurance.

Stopping condition: the local evidence surface is exercised and recorded; further closure requires an approved product-worker evidence bundle, not more host-local loopback probes.
