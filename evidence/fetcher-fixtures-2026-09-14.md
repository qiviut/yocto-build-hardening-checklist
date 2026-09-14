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

The marker was created before the later checksum-map error. The corresponding
implementation is `bitbake/lib/bb/fetch/__init__.py:685-747`, especially
`:718-720`. This proves unsafe deserialization at the sink; cache writer access
is still a required deployment precondition.

## Shell-sensitive filename

The fixture passed a gzip file named `input;touch marker;#.gz` as the local path
to the common unpack method. The result was:

```text
marker_exists=True
outcome=returned
```

The marker was created in the unpack root. The corresponding implementation is
`bitbake/lib/bb/fetch/__init__.py:1551-1557` and `:1566-1616`, where string
commands are executed with `shell=True`. Normal URI-to-localpath reachability
and the other format branches remain to be tested.

## Evidence limits

- These observations are not an upstream CVE claim.
- They do not establish a production exploit chain.
- `npmsw` parser-to-sink behavior remains a hypothesis and needs its own fixture.
- Git pruning, hostile archive members, npm lifecycle policy, cache/sstate
  restore, worker egress, and exact release binding remain open verification
  work.
