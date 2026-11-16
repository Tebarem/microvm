# Linux kernel patches

The `0001`–`0040` patch files in this directory modify the Linux kernel.
They are **licensed GPL-2.0-only**, as derivative works of Linux (which is
GPL-2.0-only; the kernel's `COPYING` file applies). Unlike the rest of this
repository, which is MIT-licensed (see the top-level `LICENSE`), these files
are not MIT. Each patch is a diff against the upstream kernel source, and
only the kernel's own licence terms apply to it. The GPL-2.0 text is in
`LICENSES/GPL-2.0-only.txt`, and the top-level `NOTICE` lists it.

## How the patches are applied

`guest/kernel/build.sh` (step 2) downloads the upstream `linux-$KVER.tar.xz`
(default `KVER=6.18.60`) from kernel.org, checks it against `KSHA256` or
kernel.org's published sums, extracts it, and then applies every
`patches/*.patch` in lexical order with `patch -d SRC -p1 --forward`. The
build records a hash of all the patch files in `SRC/.microvm-patched` and
re-extracts the tree whenever that hash changes, so the built tree always
equals the tarball plus these patches.

Patch 0019 and patch 0026 depend on work done at build time. After the
kernel is built, `guest/kernel/prepatch.py` (step 5 of `build.sh`) pre-patches
the return sites in the `vmlinux` image (for patch 0019), and
`tools/prepatch-alternatives.sh` / `.ps1` (and `prepatch.py --alternatives`)
pre-patch the alternatives for a given CPU (for patch 0026). `prepatch.py`
also sorts the static-call table, which patch 0021 relies on finding sorted.
These steps need the patches to be applied exactly as they are, so do not
edit the patch files.

## The patches

- `0001-x86-hyperv-trust-invariant-tsc-cpuid.patch`: x86/hyperv: keep the TSC when CPUID reports it invariant
- `0002-x86-alternatives-serialize-once-after-boot-patching.patch`: x86/alternatives: serialize once after boot-time patching
- `0003-x86-mm-skip-poisoning-freed-kernel-image-pages.patch`: x86/mm: don't poison freed kernel image pages unless init_on_free
- `0004-x86-boot-skip-clearing-bss-decrypted-padding.patch`: x86/boot: don't clear the padding in front of .bss..decrypted
- `0005-x86-cpuid-stop-hypervisor-scan-at-empty-range.patch`: x86/cpuid: stop the hypervisor signature scan at an empty range
- `0006-x86-sparsemem-use-32mb-sections.patch`: x86/sparsemem: use 32 MB memory sections
- `0007-x86-add-noroms-to-skip-rom-probing.patch`: x86: add "noroms" to skip legacy BIOS/option ROM probing
- `0008-x86-alternatives-decode-rel32-sites-directly.patch`: x86/alternatives: decode rel32 return/retpoline sites directly
- `0009-kobject-skip-uevents-without-receivers.patch`: kobject: don't build uevents nobody can receive
- `0010-x86-alternatives-prefetch-sites.patch`: x86/alternatives: prefetch return/retpoline sites
- `0011-x86-early_printk-add-microvm-console.patch`: x86/early_printk: add the microvm console port
- `0012-x86-rtc-boot-wallclock-from-cmdline.patch`: x86/rtc: take the boot wall clock from the command line
- `0013-x86-alternatives-skip-unchanged-text-poke.patch`: x86/alternatives: don't rewrite unchanged text at boot
- `0014-x86-alternatives-decode-less-in-optimize-nops.patch`: x86/alternatives: decode less in optimize_nops()
- `0015-x86-amd-no-s5-reset-reason-in-guest.patch`: x86/CPU/AMD: don't read the S5 reset reason in a guest
- `0016-x86-cpu-query-scattered-cpuid-leaves-once.patch`: x86/cpu: query each scattered CPUID leaf once
- `0017-x86-mm-optionally-keep-kernel-image-gaps.patch`: x86/mm: optionally keep the kernel image's alignment gaps
- `0018-x86-ibt-no-endbr-sealing-without-ibt.patch`: x86/ibt: don't seal ENDBRs on CPUs without IBT
- `0019-x86-alternatives-accept-prepatched-return-sites.patch`: x86/alternatives: accept return sites pre-patched in the image
- `0020-params-no-strlen-per-entry.patch`: params: don't strlen() every table entry per boot option
- `0021-static-call-skip-sorted-sort.patch`: static_call: don't re-sort sites that are already sorted
- `0022-x86-mm-one-e820-scan.patch`: x86/mm/init: one E820 scan for the slots past the end of RAM
- `0023-x86-mm-free-init-one-cpa-pass.patch`: x86/mm: free init pages with one CPA pass, not two
- `0024-x86-apic-skip-isr-scan-in-vm.patch`: x86/apic: don't scan a virtual LAPIC's ISR/IRR for stale bits
- `0025-x86-reduced-hw-boot-option.patch`: x86: "reduced_hw" boot option for platforms without PIT and PIC
- `0026-x86-alternatives-accept-prepatched-text.patch`: x86/alternatives: accept an image whose text is pre-patched
- `0027-x86-cpa-batch-4k-ptes.patch`: x86/mm/cpa: change a run of 4k PTEs in one step
- `0028-printk-drop-suppressed.patch`: printk: option to not log what the console suppresses
- `0029-mm-inline-struct-page-init.patch`: mm: inline struct page init into memmap_init_range
- `0030-init-skip-empty-level-param-pass.patch`: init: skip the per-level param pass when no param has that level
- `0031-init-match-setup-entries-inline.patch`: init: match boot options against __setup entries inline
- `0032-x86-cpa-run-protections-once.patch`: x86/mm/cpa: compute a 4k run's protections once
- `0033-x86-e820-reserve-late-without-pci.patch`: x86/e820: insert the non-busy ranges without PCI as well
- `0034-libnvdimm-sync-before-init.patch`: libnvdimm: finish registering boot-time devices before /init
- `0035-libnvdimm-pmem-selects-nd-claim.patch`: libnvdimm: the pmem driver needs ND_CLAIM on its own
- `0036-iomap-no-write-reserves-at-boot.patch`: iomap: don't allocate write-path reserves at boot
- `0037-vsock-no-credit-update-per-read.patch`: vsock/virtio: don't send a credit update after every read
- `0038-ipconfig-no-settle-sleep-for-static-address.patch`: ipconfig: don't sleep 10 ms for a static address
- `0039-random-vmfork-wipe-on-restore.patch`: random: RNDVMFORK, for a VM restored from a snapshot
- `0040-mm-page-reporting-flush.patch`: mm/page_reporting: drain the per-CPU lists; vm.page_reporting_flush
