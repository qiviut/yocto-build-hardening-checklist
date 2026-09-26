# Host KSPP configuration reference snapshot

## Scope and identity

This is a **host reference snapshot**, not a Yocto reference image, product kernel, or claim of effective runtime enforcement. The captured host release was `6.17.0-41-generic` (`x86_64`); the inspected configuration file was `/boot/config-6.17.0-41-generic`, SHA-256 `60323562e64ea6f73b62035b6a166b4c89ebb4c551150fca6a9b959fac2575f7`. Machine-readable rows and the separate target `not-run` state are in `evidence/runtime-containment-reference.json`.

The option references below are pinned to upstream Linux **v6.17** documentation/Kconfig paths, for version-specific symbol meaning and applicability—not to the downstream Ubuntu kernel source commit. The packaged config file records configured values only; it does not prove the running kernel's effective behavior. `product_status` is `not-run` for every row because no selected Yocto kernel, `.config`, QEMU image, target boot, or enforcement test exists here.[10]

## Control-by-control matrix

| Control | Host config value | Host-reference status | Product status | Rationale / version-specific reference |
|---|---:|---|---|---|
| `CONFIG_STRICT_KERNEL_RWX` | `y` | enabled | **not-run** | Kernel text/data permission separation; upstream v6.17 self-protection guidance.[10] |
| `CONFIG_STRICT_MODULE_RWX` | `y` | enabled | **not-run** | Module text/data permission separation; upstream v6.17 self-protection guidance.[10] |
| `CONFIG_RANDOMIZE_BASE` | `y` | enabled | **not-run** | Kernel base randomization is configuration- and boot-dependent; v6.17 self-protection and x86 Kconfig references.[10][15] |
| `CONFIG_HARDENED_USERCOPY` | `y` | enabled | **not-run** | Host config selects the control; product architecture/config support and runtime behavior remain unverified.[10] |
| `CONFIG_STACKPROTECTOR_STRONG` | `y` | enabled | **not-run** | Kernel compiler hardening option; v6.17 architecture Kconfig reference.[12] |
| `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` | `y` | enabled | **not-run** | Default initialization-on-allocation option; v6.17 memory-management Kconfig reference.[13] |
| `CONFIG_INIT_ON_FREE_DEFAULT_ON` | not set | disabled | **not-run** | This host reference does not enable initialization-on-free; it is not a product recommendation.[13] |
| `CONFIG_FORTIFY_SOURCE` | `y` | enabled | **not-run** | Fortification option in the v6.17 library Kconfig; compiler/architecture support must be checked for a target.[14] |
| `CONFIG_BPF_UNPRIV_DEFAULT_OFF` | `y` | enabled | **not-run** | v6.17 BPF Kconfig describes disabling unprivileged BPF by default.[11] |
| `CONFIG_PAGE_TABLE_CHECK` | not set | disabled | **not-run** | Host reference does not enable page-table checking; target cost/applicability is not assessed.[13] |
| `CONFIG_SLAB_FREELIST_HARDENED` | `y` | enabled | **not-run** | Host config selects slab freelist hardening; target allocator/config applicability remains open.[13] |
| `CONFIG_SLAB_FREELIST_RANDOM` | `y` | enabled | **not-run** | Host config selects slab freelist randomization; target allocator/config applicability remains open.[13] |
| `CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT` | `y` | enabled | **not-run** | Host config selects default kernel-stack offset randomization; v6.17 architecture Kconfig reference.[12] |

The runtime fixture separately records systemd 257 syntax validation and static service directives; it does not start the service. No row above closes the product kernel gate. For a downstream target, capture its exact source revision and `.config`, distinguish unsupported symbols from symbols absent in the config, inspect boot parameters and effective runtime state, and run target-specific negative/security and workload-compatibility tests before recording a product disposition.

## Sources

[10] https://github.com/torvalds/linux/blob/v6.17/Documentation/security/self-protection.rst — Linux v6.17 Kernel Self-Protection
[11] https://github.com/torvalds/linux/blob/v6.17/kernel/bpf/Kconfig — Linux v6.17 BPF Kconfig
[12] https://github.com/torvalds/linux/blob/v6.17/arch/Kconfig — Linux v6.17 Architecture Kconfig
[13] https://github.com/torvalds/linux/blob/v6.17/mm/Kconfig — Linux v6.17 Memory Management Kconfig
[14] https://github.com/torvalds/linux/blob/v6.17/lib/Kconfig — Linux v6.17 Library Kconfig
[15] https://github.com/torvalds/linux/blob/v6.17/arch/x86/Kconfig — Linux v6.17 x86 Kconfig
