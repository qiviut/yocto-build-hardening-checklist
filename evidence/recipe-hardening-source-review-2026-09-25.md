# Pinned recipe hardening source review

## Scope and pins

This is a metadata/source review, not an effective build or product assessment.
The local component checkouts were clean and at these full commits on their
`master` refs during review:

- BitBake: `046a90b0e9b7b914b7a95aec579cdc3fc9c7617a`
- OE-Core: `f94ae3d6ba49aef86f497998c0e0232a5039510a`
- meta-yocto: `7e41504cd63b099b214f10d92cfdaf358ab98c5f`

The example recipe statements below are read from the pinned OE-Core Git
objects with `git -C ../yocto-components/openembedded-core show
f94ae3d6ba49aef86f497998c0e0232a5039510a:<path>`. No BitBake parse, compile,
image build, ptest, package-size comparison, or runtime test was run.

## Observations

| Source | Pinned source observation | Decision/evidence boundary |
|---|---|---|
| `meta/conf/distro/include/security_flags.inc:1-67` | Describes non-universal security flags and recipe exceptions; defines stack-protector, PIE, fortify, format-security, RELRO/NOW defaults and targeted exceptions. | Inspect the selected branch's effective values and exceptions before adding policy overrides. This file is not proof every recipe receives every flag. |
| `meta/recipes-connectivity/openssl/openssl_4.0.2.bb:21-38` | Archive SHA-256 is declared; `PACKAGECONFIG` default is empty; recipe exposes `legacy`, `tls1`, `tls1_1`, `manpages`, and `fips`. | These are supported option names, not a product selection. A separate bounded run verified the archive digest for a single OpenSSL source translation unit; see `evidence/advisory-openssl-4.0.2-gcc-analyzer.json`. |
| `meta/recipes-core/systemd/systemd_261.2.bb:50-103,113-211` | Recipe enables a broad default feature set influenced by `DISTRO_FEATURES` and removes some options for `libc-musl`/`mipsarch`; features have Meson arguments/dependency effects. | Candidate feature removals require product service/dependency analysis and a clean reference/product build; no blanket removal is recommended. |

## Explicit reference-profile feature decisions

The following decisions define a **synthetic minimal-service reference profile**, not an actual product's `PACKAGECONFIG`. “Disabled” means default-off in that profile; the owning product must opt in only with a named use case and compatibility evidence. Compatibility/build/ptest evidence is `not-run` because no product layer or workload was supplied.

| Recipe option | Profile decision | Compatibility rationale / required exception evidence |
|---|---|---|
| OpenSSL `legacy` | **disabled** | Avoid shipping the legacy provider by default. Re-enable only for a named consumer that cannot migrate; test its real algorithm/provider calls and record the accepted exposure. |
| OpenSSL `tls1` | **disabled** | Do not expose TLS 1.0 by default. Re-enable only for a documented peer requirement after protocol inventory and interoperability/security review. |
| OpenSSL `tls1_1` | **disabled** | Do not expose TLS 1.1 by default. Re-enable only for a documented peer requirement after protocol inventory and interoperability/security review. |
| OpenSSL `manpages` | **disabled in runtime image** | Documentation is not needed by target runtime processes; preserve it in the developer/documentation artifact if selected. Check package split/consumer expectations before removal. |
| OpenSSL `fips` | **disabled** | Do not build/configure the FIPS module absent an explicit validated-module requirement and operational validation plan. Enabling the option alone is not a compliance claim. |
| systemd `networkd` | **disabled** | The reference profile assigns network configuration to an external manager; re-enable only if target network ownership, required units, and interface behavior are specified and tested. |
| systemd `resolved` | **disabled** | The reference profile assigns resolver configuration outside systemd; re-enable only with a concrete stub/resolver integration and DNS regression tests. |
| systemd `hostnamed` | **disabled** | No reference-profile service needs runtime hostname-management APIs; re-enable only for a named consumer with D-Bus/API compatibility tests. |
| systemd `seccomp` | **required** | Build support is required by the reference service-containment policy because units use `SystemCallFilter=`. Effective syscall policy and workload compatibility still require target execution tests. |

These are explicit profile decisions with compatibility gates, not observations of an effective Yocto build. The recipe’s defaults and architecture/libc exceptions remain as inspected above; a downstream product must record its own enabled/disabled/required/exception decision from the resolved `bitbake -e` data and close compatibility tests before promotion.

## Repeatable source inspection

```sh
git -C ../yocto-components/openembedded-core rev-parse HEAD
# Must print f94ae3d6ba49aef86f497998c0e0232a5039510a.
git -C ../yocto-components/openembedded-core show \
  f94ae3d6ba49aef86f497998c0e0232a5039510a:meta/conf/distro/include/security_flags.inc
git -C ../yocto-components/openembedded-core show \
  f94ae3d6ba49aef86f497998c0e0232a5039510a:meta/recipes-connectivity/openssl/openssl_4.0.2.bb
git -C ../yocto-components/openembedded-core show \
  f94ae3d6ba49aef86f497998c0e0232a5039510a:meta/recipes-core/systemd/systemd_261.2.bb
```

## Downstream build/ptest comparison — not run

No product `bblayers.conf`, `local.conf`, `kas*.yml`, target image, or product
ptest environment is available in this repository. For a downstream product:

1. record the immutable manifest and product config/toolchain identities;
2. capture baseline effective `PACKAGECONFIG`, `EXTRA_OECONF`/Meson arguments,
   compiler and linker commands for each selected recipe;
3. apply one feature or hardening change at a time in a clean, otherwise
   identical build;
4. compare package/image contents, SBOM, buildhistory, ELF program headers and
   size; retain debug packages/provenance intentionally;
5. run affected recipe ptests, product integration/runtime tests, and a clean
   reproducibility comparison; and
6. retain commands, tool versions, output hashes, exceptions, and an explicit
   pass/fail/not-run disposition.

No output reduction, dead-code removal, supported linker result, runtime
compatibility, or product hardening is claimed from this source review.
