# Traceability analysis process

This repository uses [Doorstop](https://github.com/doorstop-dev/doorstop) as the
version-controlled system of record for the living Yocto/OpenEmbedded build
threat model. The model is defensive analysis, not an upstream advisory,
compliance certificate, or claim that a product build is safe.

## Authority and layout

The canonical chain is:

```text
REQ (assurance contract)
  -> EP (unique source/trust-boundary entry point)
    -> RISK (source-to-sink risk)
      -> CTRL (mitigation/control)
        -> VER (verification evidence)
```

The documents live under `traceability/`:

- `requirements/` — scope, assets, traceability, evidence, and closure rules.
- `entrypoints/` — stable `EP###` identifiers for every material input or
  trust-boundary crossing.
- `risks/` — stable `RISK###` records. Every active risk must link to one or
  more entry points; the link is the authoritative risk-to-entry-point edge.
- `controls/` — proposed or implemented controls linked to risks.
- `verification/` — tests, fixtures, operational probes, and release dry runs
  linked to controls.

The older narrative files in `docs/` retain review history. New claims and
status changes belong in the Doorstop tree first; narrative documents must not
silently override it.

## Record contract

Doorstop validates YAML syntax, document hierarchy, item UIDs, parent links,
link targets, levels, and fingerprints. `scripts/lint_traceability.py` adds
the project data model:

- required fields and enumerations for each document;
- exactly one `REQ###`, `EP###`, `RISK###`, `CTRL###`, or `VER###` filename;
- Doorstop links in either native `{UID: fingerprint}` or initial string form;
- non-empty `code_refs` with repository-relative paths, line ranges, and exact
  40-hex revisions (or the explicit `worktree` marker);
- explicit preconditions, impact, evidence class, remediation, regression, and
  residual uncertainty for every risk;
- explicit expected/observed evidence for every verification record.

Custom fields listed in each `.doorstop.yml` `attributes.reviewed` section are
included in Doorstop fingerprints. The Doorstop `reviewed` field records the
fingerprint/review state of an item; it is not an approval that the security
risk is closed. The domain status fields are authoritative for evidence and
closure.

## Local validation

From the repository root:

```sh
python3 -m venv .venv-doorstop
.venv-doorstop/bin/python -m pip install --no-cache-dir -r requirements-dev.txt
.venv-doorstop/bin/doorstop -j . -F -C
.venv-doorstop/bin/python scripts/lint_traceability.py
```

`-F` prevents validation from rewriting item files. `-C` disables Doorstop's
nested reverse-child check; Doorstop 3.2 calculates that check incorrectly for
this five-level tree. The sidecar linter performs the reverse-link check using
the actual document graph and emits a deterministic warning when a parent has
no child. Native Doorstop validation still checks YAML, item structure, target
UIDs, and other integrity errors.

For a local completeness gate, which is intentionally stricter than CI:

```sh
.venv-doorstop/bin/python scripts/lint_traceability.py --strict-completeness
```

The normal CI command returns zero when the model is valid, even if it emits
GitHub Actions warnings for open evidence. Syntax errors and data-model errors
return non-zero and block the pipeline. This distinction prevents an honest
`planned`, `observed`, or `hypothesis` record from being hidden while still
making malformed traceability fail closed.

## Iteration workflow

1. **Pin the baseline.** Record the exact repository and revision for every
   source citation. Re-read line references after a baseline change.
2. **Add or update the entry point.** Give it one stable UID, representation,
   boundary, sink, status, and exact first code references.
3. **Add or update risks.** Link every risk to its EP item. Keep behavior,
   reachability, product configuration, and release impact separate.
4. **Add controls and verification.** A control is not evidence. A verification
   record must state the method, command or procedure, expected result, and
   observed result. Use `planned`, `not-run`, `observed`, or `blocked` honestly.
5. **Run both validators.** Fix all errors. Review warnings and leave them in
   the model until the evidence is actually closed.
6. **Inspect the diff.** Check that Doorstop fingerprints and links changed only
   as expected. Do not use `doorstop review` as a substitute for human review
   of the security claim.
7. **Commit a coherent checkpoint.** Include model, process, evidence, and
   verifier changes together when they describe one state. Do not include
   credentials, private source, patient data, or live exploit material.

## Astra review workflow

Astra is an independent review lane, not the source of truth. Run it only after
the local Doorstop and sidecar gates pass. Give Astra the repository path and
point it to this process document, `traceability/`, and
`scripts/lint_traceability.py`; do not duplicate the entire result in the
prompt.

A code-changing Astra run must:

1. start from a clean, known commit in an isolated worktree;
2. read this process and the current Doorstop records;
3. verify claims against the cited source or label them as hypotheses;
4. modify only the analysis/evidence documentation unless a separate task
   explicitly authorizes framework remediation;
5. run both local validators;
6. create focused Git commits with descriptive messages; and
7. report commit IDs, changed paths, validator output, and residual uncertainty.

The integrating agent must inspect the diff and commit, rerun the validators on
the integrated tree, and only then merge/push. A model response, launched
process, timeout, or claimed edit is not evidence without the commit and test
results.

## Completeness warning policy

The sidecar emits warnings, rather than failures, for:

- active entry points without a linked risk;
- entry points not marked `covered`;
- risks without fixture or product evidence;
- verification records not marked `passed`; and
- any missing reverse edge in the REQ → EP → RISK → CTRL → VER chain.

This is the deliberate stopping signal. The analysis is not complete until each
warning is either closed with inspectable evidence, rejected with a documented
reason, or accepted as residual risk by the appropriate owner.

## Security and assurance boundary

The analysis must not claim that checksums prove benign content, that a pinned
revision proves publisher trust, or that BitBake is a sandbox. It must keep
layer metadata, upstream content, lockfiles/submodules, caches, host
configuration, worker isolation, tests/SBOM, signing, and publication as
separate trust questions. It is not an IEC 62304, IEC 62443, or regulatory
conformity assessment.
