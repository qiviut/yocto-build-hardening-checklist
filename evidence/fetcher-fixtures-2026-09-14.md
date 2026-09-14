# Fetcher fixture evidence (2026-09-14)

These are harmless local observations from the reviewed BitBake checkout. They
used temporary directories only, no network, no credentials, and no production
build artifacts. They prove behavior at the common sinks; they do not by
themselves prove that a normal upstream URI or product configuration reaches
every sink.

## Source baseline

- BitBake: `046a90b0e9b7b914b7a95aec579cdc3fc9c7617a`
- OpenEmbedded-Core: `f94ae3d6ba49aef86f497998c0e0232a5039510a`

## Destination containment

The fixture invoked the current `bb.fetch.FetchMethod.unpack` with a synthetic
file and `rootdir`.

- `ud.parm['subdir'] = '../escape'` resulted in
  `escape_file_exists=True` outside the intended root.
- An absolute sibling destination (`root2` while the root was `root`) resulted
  in `sibling_file_exists=True`.

The corresponding implementation is
`bitbake/lib/bb/fetch/__init__.py:1523-1557`; the absolute check uses a string
prefix and relative paths are joined without a containment check.

## Done-stamp deserialization

The fixture created a newer `.done` file containing a pickle whose reduce
callable wrote a marker, then passed it to `verify_donestamp`.

```text
marker_exists_after_verify=True
outcome=AttributeError
```

The marker was created before the harness reported an AttributeError. The
fixture did not isolate that exception's precise cause, so it must not be
attributed to a particular checksum-map failure. This proves unsafe
deserialization at the sink; cache writer access is still a required deployment
precondition.

## Shell-sensitive filename

The fixture passed a gzip file named `input;touch marker;#.gz` as the local path
to the common unpack method. The result was:

```text
marker_exists=True
outcome=returned
```

The marker was created in the unpack root. The corresponding implementation is
`bitbake/lib/bb/fetch/__init__.py:1551-1557` and `:1566-1616`, where string
commands are executed with `shell=True`. The format matrix below covers the
available local extractor branches; rpm, 7z, and lzip remain unavailable on
this host.

## Fetch/unpack fixture matrix

The retained runner is `scripts/fetcher_fixture_matrix.py`. It imports the
read-only BitBake checkout selected by `--bitbake-root`, creates all inputs in
a temporary directory, sets `BB_NO_NETWORK=1`, and uses only `file://` or local
`npmsw` inputs. Re-run it from this repository root with:

```text
.venv-doorstop/bin/python scripts/fetcher_fixture_matrix.py \
  --bitbake-root ../yocto-components/bitbake
```

Observed at BitBake revision
`046a90b0e9b7b914b7a95aec579cdc3fc9c7617a` on GNU tar 1.35, GNU ar 2.45,
GNU cpio 2.15, zstd 1.5.7, and Python 3.11.15:

- tar.gz: `UnpackError`; no outside traversal marker; `absolute.txt`, a
  symlink entry, ordinary content, and a FIFO remained in the staging tree.
- zip: `UnpackError`; no outside traversal marker; unzip stripped the absolute
  and parent components and left sanitized entries in the staging tree.
- deb and ipk: `UnpackError`; no outside traversal marker; their data tar
  extraction left ordinary content and a FIFO before rejecting the parent
  member.
- npm shrinkwrap with `node_modules/fixture-package`: returned; the package
  extracted under the requested module directory and the package's
  `postinstall` field did not execute during fetch/unpack.
- npm shrinkwrap with `node_modules/../../escaped.js`: returned and created a
  path outside the intended unpack root, demonstrating the parser-to-sink
  reachability in `npmsw.py:51-60` and `:251-280`.
- The package's SRI `sha512-...` value mapped to `sha512sum` and matched the
  exact tarball bytes.
- With npm 12.0.2, default install, explicit `--ignore-scripts=false`, and
  `--ignore-scripts` all returned zero without creating the marker; default and
  explicit-allow emitted npm's untrusted-install-script warning. After a local
  `npm install-scripts approve fixture-package` decision, reinstall returned
  zero and created the marker. This demonstrates both the executable hook and
  the version/configuration-specific approval gate; it is not evidence that
  OE-Core's effective product policy is configured safely.

The archive result is not a claim that rejection makes extraction safe: all
four tested formats can leave partial output, and tar/deb/ipk can leave a
special file before returning an error. The control must stage, validate, and
discard on error. `7z`, `7za`, `rpm2cpio.sh`, and `lzip` were unavailable and
were not counted as tested.

The pinned upstream tests also passed without network access:

```text
BB_SKIP_NETTESTS=yes ./bin/bitbake-selftest \
  bb.tests.fetch.FetcherLocalTest bb.tests.fetch.FetcherNoNetworkTest -v
Ran 30 tests ... OK

BB_SKIP_NETTESTS=yes ./bin/bitbake-selftest \
  bb.tests.fetch.NPMTest -k npmsw_no_network_no_tarball -v
Ran 1 test ... OK

BB_SKIP_NETTESTS=yes ./bin/bitbake-selftest \
  bb.tests.fetch.GitShallowTest -k submodule -v
Ran 2 tests ... OK

BB_SKIP_NETTESTS=yes ./bin/bitbake-selftest \
  bb.tests.fetch.GitLfsTest -k gitsm_lfs -v
Ran 2 tests ... OK
```

These tests cover local archive/Git behavior, no-network done-stamp/cache
handling, local gitsm shallow submodules and LFS behavior, and the no-network
shrinkwrap guard. They do not exercise remote registry resolution, an
OE-Core recipe's npm install lifecycle policy, or unavailable extractor tools.

## Worker and cache fixture evidence

The repository-native worker/cache runner was executed against the pinned source
revisions with temporary directories only:

```text
.venv-doorstop/bin/python scripts/worker_cache_fixture_matrix.py \
  --bitbake-root ../yocto-components/bitbake \
  --oe-root ../yocto-components/openembedded-core
```

Source boundaries exercised:

- `yocto-components/bitbake/lib/bb/utils.py`: `disable_network()`;
- `yocto-components/bitbake/lib/bb/fetch/__init__.py`: `runfetchcmd()`;
- `yocto-components/openembedded-core/meta/lib/oe/gpg_sign.py`:
  `LocalSigner.verify()`.

Observed results:

- The network child changed its network namespace, then raised `PermissionError`
  while completing user-namespace setup. A loopback connection attempted after
  the helper failed with `OSError`. This demonstrates the helper's behavior on
  this host; it is not evidence of a worker firewall, outbound-egress policy,
  or a successful isolated product build.
- The fetch command child received both an ambient marker and an explicitly
  supplied marker, and `PSEUDO_DISABLED=1` was present. This confirms the
  inspected `runfetchcmd()` environment inheritance semantics; it does not
  prove that a product worker sanitizes its environment.
- Ephemeral real-GPG evidence accepted a valid detached signature with its
  payload (`returncode=0`, `GOODSIG`, `VALIDSIG`) and rejected the same
  signature over a tampered payload (`returncode=1`, `BADSIG`, no `VALIDSIG`).
- The same source-level signer was tested with a disposable fake GPG executable.
  A non-zero fake GPG exit carrying `GOODSIG` and a matching allowed key made
  `LocalSigner.verify()` return `True`; a non-zero exit with an empty allow-list
  returned `False`. This is a deterministic control-flow finding, not fake
  cryptographic evidence. A real detached signature passed to `verify()` without
  its payload returned `False` even with the matching key.

The runner retains no key material, signatures, payloads, or credentials.

## Evidence limits

- These observations are not an upstream CVE claim.
- They do not establish a production exploit chain.
- npm lifecycle policy, remote registry resolution, remote/product LFS object retrieval,
  cache/sstate restore, worker egress, and exact release binding remain open
  verification work.
- The GPG fixture validates actual local cryptographic behavior and the
  `LocalSigner` branch handling, but does not validate a product's keyring,
  signature policy, cache ownership, or sstate deployment.
- Archive evidence is limited to tar, zip, deb, and ipk with the host tools
  listed above; rpm, 7z, and lzip behavior remains untested.
