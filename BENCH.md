# Cold-start benchmarks

Host: AMD Ryzen 5 7600X, Windows 11 (WHP), single vCPU, 64 MiB guest RAM ceiling.
(The production target is Linux / KVM: see [Linux / KVM](#linux--kvm-the-production-target).)
Guest: Linux 6.18.60 LTS, `tinyconfig` + `guest/kernel/config.fragment`, built-in
uncompressed initramfs with the freestanding `/init`. Each number is the p50 of
15–20 fresh processes (`tools/bench.ps1`). "total" runs from `main()` entry to the
guest's exit-status write from `/init`.

| step | total | VMM setup | guest → /init | guest RAM touched |
|---|---:|---:|---:|---:|
| first boot, full console output | 54.5 ms | 3.1 ms | 51.4 ms | — |
| `--quiet` (~13k → 317 VM exits) | 21.4 ms | 3.1 ms | 18.2 ms | 12.2 MB |
| + `--ws` working-set prefault | 9.7 ms | 4.0 ms | 5.8 ms | 12.2 MB |
| + 0001 TSC patch (TSC clocksource instead of 10 ms jiffies) | 9.9 ms | 4.1 ms | 5.8 ms | 12.2 MB |
| + MP table I/O-interrupt entry (no "BIOS bug" warning: 317 → 151 exits) | 9.0 ms | 3.7 ms | 5.3 ms | 12.2 MB |
| + 0002 serialize once after boot-time patching | 7.9 ms | 3.6 ms | 4.4 ms | 12.2 MB |
| + RDSEED hidden from the guest (`CpuidResultList2`) | 7.9 ms | 3.7 ms | 4.2 ms | 12.2 MB |
| + kernel copied on a second thread, overlapping partition setup | 7.0 ms | 2.8 ms | 4.2 ms | 12.2 MB |
| + VMM sandbox (seccomp/Landlock or job/Low IL/mitigation policies) | 7.2 ms | 2.9 ms | 4.3 ms | 12.2 MB |
| + memory diet: 0003/0004, zero pages skipped on load, 16 KB printk ring, no call-depth padding | 6.7 ms | 2.6 ms | 4.0 ms | 8.3 MB |
| + 0005 hypervisor CPUID scan stops early, 0006 32 MB memory sections, 0007 `noroms` | 6.5 ms | 2.6 ms | 3.9 ms | 7.1 MB |
| + 0008 rel32 patch sites decoded directly | 6.4 ms | 2.6 ms | 3.7 ms | 7.1 MB |
| + 0009 no uevent environments when nothing can receive them | 6.0 ms | 2.6 ms | 3.3 ms | 7.1 MB |
| + 0010 prefetch patch sites | 5.9 ms | 2.6 ms | 3.2 ms | 7.1 MB |
| + Unix98 PTYs instead of 256 legacy PTY pairs | 5.5 ms | 2.6 ms | 2.9 ms | 6.7 MB |
| + `/init`'s line on the console port, 4 bytes per exit (93 exits) | 5.2 ms | 2.6 ms | 2.7 ms | 6.7 MB |
| + 0011 kernel log on the console port, no 8250 driver, `io_delay=none` (53 exits) | 5.2 ms | 2.6 ms | 2.6 ms | 6.7 MB |
| + 0012 boot wall clock on the command line, no CMOS RTC read (31 exits) | 5.0 ms | 2.5 ms | 2.5 ms | 6.7 MB |
| + 0013 unchanged text not rewritten, 0014 `optimize_nops()` decodes less | 4.9 ms | 2.6 ms | 2.2 ms | 6.7 MB |
| + 0015 no S5 reset-reason MMIO read in a guest, 0016 each scattered CPUID leaf read once (30 exits) | 4.6 ms | 2.5 ms | 2.1 ms | 6.7 MB |
| + 0017 `keep_image_gaps`: the kernel image's 2 MB alignment padding isn't freed | 4.4 ms | 2.5 ms | 1.8 ms | 6.7 MB |
| + 0018 no ENDBR sealing on CPUs without IBT | 4.3 ms | 2.5 ms | 1.7 ms | 6.7 MB |
| + 0019 return sites pre-patched in the image (`prepatch.py`) | 4.2 ms | 2.5 ms | 1.7 ms | 6.7 MB |
| + 0020–0024 boot options parsed without per-entry `strlen`, static calls sorted at build time, one E820 scan, one CPA pass for init memory, no ISR scan (guest −163 µs vs 0019) | 4.1 ms | 2.6 ms | 1.6 ms | 6.7 MB |
| + 0025 `reduced_hw` (16 exits); only the working set mapped before the guest starts, the rest while it boots (setup −0.42 ms) | 3.8 ms | 2.2 ms | 1.6 ms | 6.7 MB |
| + 0026 all alternatives pre-patched for this CPU (`tools/prepatch-alternatives.ps1`) | 3.55 ms | 2.2 ms | 1.34 ms | 6.7 MB |
| + 0027 page attributes changed a page table at a time, not a 4k page at a time | 3.5 ms | 2.2 ms | 1.28 ms | 6.7 MB |
| + 0028 `--quiet` also stops the kernel logging the messages it hides (`printk_drop_suppressed`) | 3.4 ms | 2.2 ms | 1.19 ms | 6.7 MB |
| + 0029 struct page init inlined into its per-page loop | 3.3 ms | 2.2 ms | 1.11 ms | 6.7 MB |
| + 0030, 0031 boot options parsed once per level that has params, and matched against `__setup` entries inline | 3.3 ms | 2.2 ms | 1.08 ms | 6.7 MB |
| + working set from the guest's first touches; kernel pages it never touches mapped from the file, shared | 3.2 ms | 2.1 ms | 1.1 ms | 4.7 MB |
| + `/init`'s line in one `rep outsb` exit, done by the VMM rather than the WHP emulator (`/init` 43 → 25 µs, 16 → 8 exits) | 3.1 ms | 2.1 ms | 1.07 ms | 4.7 MB |
| + 0032 a 4k CPA run's protections computed once, its PTEs by increment (guest −59 µs + −15 µs, CPA samples 121 → ~60) | **2.9 ms** | 1.9 ms | 1.02 ms | 4.7 MB |
| + root filesystem support built in (block layer, pmem, EROFS; 0033–0036, no I/O schedulers or partition parsers), plain boot without `--rootfs` (guest +59 µs) | 3.0 ms | 1.9 ms | 1.07 ms | 5.0 MB |
| **container run**: `--rootfs IMAGE -- /bin/probe` (mount, chroot, fork, exec, output, exit status; image pages in the working set) | **3.3 ms** | 2.1 ms | 1.18 ms | 5.2 MB |
| (experiment) `mitigations=off` in the guest, before 0002 | 8.8 ms | 4.3 ms | 4.4 ms | 12.2 MB |
| (experiment) prefault *all* 64 MiB | 13.3 ms | 7.3 ms | 5.8 ms | 64 MB |
| (experiment) `--map-kernel`: copy-on-write kernel views | 11.5 ms | 5.4 ms | 6.3 ms | 9.6 MB |

Later rows use `tools/ab.ps1`, which interleaves the two configurations being
compared so clock-speed and background-load drift hit both equally.

Hello guest (5 port writes, no kernel): 1.2 ms total, of which `WHvCreatePartition` +
`WHvSetupPartition` take 0.9 ms. Windows process creation adds ~8 ms of wall time on
top of every number here (`wall_us` in the bench output). On this host that
is the machine, not the VMM: an empty C program takes 9–10 ms from process
creation to `main()` (probably antivirus scanning new processes), and the
VMM 7 ms. Ending with `TerminateProcess` instead of returning saves only
~0.2 ms of teardown.

## Linux / KVM (the production target)

Host: AMD Ryzen 9 7950X (16 cores / 32 threads), 128 GB, Debian 13, kernel
6.12.111+deb13 (`kvm_amd`, TDP MMU), transparent huge pages on `always`
(Debian's default), bare metal, other services idle. The VMM runs as
`nobody` with only the `kvm` group (`setpriv --reuid=nobody --regid=nogroup
--groups=kvm --inh-caps=-all --bounding-set=-all --no-new-privs`), sandbox
on. Kernel pre-patched for the KVM CPU view (`tools/prepatch-alternatives.sh`
on the host), working sets recorded on KVM. p50 of 40 interleaved runs
(`tools/bench.sh -c ... -c ...`):

| run | total | VMM setup | guest | touched | shared |
|---|---:|---:|---:|---:|---:|
| hello guest (5 port writes, no kernel) | 0.39 ms | 0.31 ms | 0.08 ms | 32 KB | — |
| boot to `/init`, `--map-kernel --ws` | **3.2 ms** | 1.8 ms | 1.40 ms | 5.0 MB | 1.5 MB |
| **container run**: `--rootfs IMAGE -- /bin/probe`, `--map-kernel --ws` | **3.5 ms** | 1.9 ms | 1.72 ms | 5.2 MB | 1.5 MB |
| boot, `--ws`, kernel copied in | 3.6 ms | 2.3 ms | 1.34 ms | 6.9 MB | 0 |
| boot, no working set | ~6.1 ms | 2.2 ms | 3.8 ms | 6.9 MB | 0 |
| (experiment) boot, `--ws`, THP left on for guest RAM | 2.6 ms | 1.2 ms | 1.34 ms | 16.5 MB | 0 |

Same order of magnitude as WHP (2.9 / 3.3 ms), but not the same work: WHP
gives its guests no speculation controls, so there the guest reported SSB
and SRSO as vulnerable and fell back to retpolines. Under KVM it gets the
real mitigations (SSBD, Safe RET for SRSO, VERW for TSA, AutoIBRS + IBPB),
and they stay on.

Parallel starts (`mvm-parlaunch`, `tools/parlaunch_posix.c`; `result` is
launch until the VMM's exit-status line, i.e. when a caller has its answer,
including the ~1 ms `setpriv` + `exec` before `main()`):

| N in flight | answers/s | result p50 | result p90 | VMM total p50 | guest p50 |
|---:|---:|---:|---:|---:|---:|
| 1 | — | 4.4 ms | — | 3.2 ms | 1.3 ms |
| 16 | ~1550 | 8.3 ms | 8.7 ms | 7.2 ms | 3.8 ms |
| 64 | ~2300 | 9.9 ms | 11.3 ms | 7.5 ms | 3.7 ms |
| 128 | ~2150 | 11.7 ms | 15.1 ms | 8.4 ms | 3.8 ms |
| 256 | ~1600–2000 | 10–12.5 ms | 14–30 ms | 7.8–9.3 ms | 3.6–3.8 ms |
| 512 | ~1850 | 11.0 ms | 15.9 ms | 8.0 ms | 3.7 ms |
| 128 container runs (`/bin/probe`) | ~1950 | 14.5 ms | 20.2 ms | 11.4 ms | 4.4 ms |

About 8x the Windows box (230–250 VMs/s, capped by process creation) and
13x Firecracker's published 150 microVMs/s per host. Process creation is
no bottleneck here: `pre` stays 1.0–1.4 ms p50 at every N.

What we found on KVM:

- **KVM's teardown runs in the exiting VMM and waits for RCU.** The guest's
  exit status is known at `total` (3.2 ms), but the process is reaped only
  ~45–50 ms later, 100–150 ms with 64+ in flight. The VMM's last thread out
  (KVM's `kvm-nx-lpage-recovery` worker, which belongs to the process) drops
  the last VM reference, and `kvm_destroy_vm()` → `kvm_mmu_uninit_vm()` →
  `rcu_barrier()` waits for every CPU's pending RCU callbacks. It sleeps;
  it doesn't burn CPU. A service must take results from the VMM (its
  output), not from `waitpid()`. Guest memory is freed only at the very end,
  so with N VMs/s about N × 50 ms worth of VMs sit in teardown.
- **`RLIMIT_NPROC = 0` made every `KVM_RUN` fail.** Since 6.13 (and in
  6.12 stable) KVM starts that worker on the first `KVM_RUN` as a task of
  the calling process, charged to its uid. With NPROC at 0 it can't, and
  `KVM_RUN` returns EAGAIN, forever. Our run loop treated EAGAIN as
  "retry", so the VMM spun at 100% with the guest never entered (0 exits
  in KVM's debugfs stats). NPROC is gone from the sandbox; seccomp already
  kills fork/clone/clone3. Only EINTR is retried now.
- **The CPU template.** KVM's supported CPUID includes its paravirt leaf
  and a PMU. Through `KVM_CPUID_FEATURES` the guest switched to kvm-clock,
  enabled steal time, async page faults and others. Each of those swaps
  `pv_ops` at boot, which made the alternatives pre-patch refuse the
  image. Now only PV EOI is offered (an EOI without an exit). There's no
  PMU (CPUID, plus `KVM_CAP_PMU_CAPABILITY` disables it in KVM): it would
  be a cross-tenant side channel, and the guest's perf probe cost boot
  time. `HWCR.TscFreqSel` is set, so the guest stops warning about the TSC.
- **Pre-patching for KVM** needed two fixes. `prepatch.py` sized a retpoline
  site with a CS prefix (`2e e8 rel32`, from `-mindirect-branch-cs-prefix`)
  as 5 bytes, not 6; it never mattered on WHP, where retpolines stay. And
  KVM's view rewrites every retpoline site, so 0026's undo table grew from
  16 to 48 KiB (`__initdata`, freed after boot). One image is pre-patched
  for one CPU view: production builds should pre-patch on the KVM host
  type. Any other view still boots, just patching as before.
- **Prefault on KVM must populate host pages first.** `KVM_PRE_FAULT_MEMORY`
  faults like a guest read. On anonymous memory nothing has touched yet,
  it maps the host's zero page read-only, and the next write (the guest's,
  or the kernel loader thread's, which runs concurrently) throws that
  mapping away again. With `--ws`, guest time went *up*, 1.8 → 5.0 ms.
  `MADV_POPULATE_WRITE` (or `_READ` for read-only pages) before the KVM
  call fixes it: guest 1.3 ms. The prefault is now the biggest setup step
  (~1.4 ms for 5 MB: ~1.0 ms host populate, ~0.5 ms stage-2), and the next
  thing to attack.
- **Huge pages: off for guest RAM.** With THP on `always`, each first touch
  faulted in 2 MiB: a hello guest touched 2 MB, a boot 16.5 MB. `MADV_NOHUGEPAGE`
  brings that to 32 KB and 5.0 MB, the same as on WHP, at +0.5 ms total.
  Memory per VM wins.
- **`--map-kernel` pays off on KVM.** Read-only kernel pages are the host's
  page-cache pages, shared by every VM (1.5 MB here), and the loader copies
  less (0.5 vs 1.6 ms), for the same guest time once the image is
  pre-patched for this view. With a WHP-pre-patched image the guest
  rewrites text at boot, and every rewritten page is a copy-on-write
  fault: guest 2.6 ms.

### Under `microvm-jail`

`microvm-jail` started as root, a uid per VM (3000*i*), the kernel and
working set bind-mounted in. Compared with plain `setpriv`, same box, p50 of
5 runs per cell, `pre` = launch → VMM `main()`:

| | pre, N=1 | pre, N=64 | pre, N=256 | result, N=256 |
|---|---:|---:|---:|---:|
| `setpriv` (no jail) | 0.8 ms | 1.2 ms | 1.3 ms | 10.0 ms |
| jail | 1.3 ms | 8–12 ms | 16–21 ms | 25–29 ms |
| jail + cgroup (created per VM) | 1.2 ms | 9–13 ms | 15–28 ms | 22–34 ms |
| jail + `--base` | 1.0 ms | 3–11 ms | 3.8–5.0 ms | 12–13 ms |
| jail + `--base` + cgroup from a pool | 1.4 ms | 3.8–5.9 ms | 4.0–5.8 ms | 12–14 ms |

On its own, one VM pays ~0.3–0.5 ms for the jail. With many in flight, the
cost is global kernel locks, found by timing each step inside the jail:

- **Moving a process into a cgroup: ~27 ms**, even for a single VM. Writing
  `cgroup.procs` waits for an RCU grace period (`cgroup_threadgroup_rwsem`).
  The VM's first process is now created in its cgroup instead (`clone3` with
  `CLONE_INTO_CGROUP`, all namespaces in the same call), and the waiter
  stays outside. That costs 0.
- **The host's mount table, copied and detached per VM.** The step that
  mounts the new root took 5 ms p50 at N=64, against 0.05 ms alone. Each
  VM's mount namespace is a copy of the host's 48 mounts. `pivot_root`
  then detaches them all, and both hold `namespace_sem`, one lock for the
  whole host. With `--base`, each VM copies a namespace holding one empty
  tmpfs. An experiment that used `chroot` instead of `pivot_root` + detach
  gained little more on top of `--base`, so the full detach stays.
- **Creating the cgroup**: `cgroup_mutex`, with the memory controller's
  per-CPU state allocated under it. That adds 5–8 ms at N=256. Pre-created
  cgroups (`--cgroup` reuses an empty one) remove that cost.
- The network namespace costs ~1 ms under load (`rtnl_lock`). It stays.

Throughput is ~1300–1700 results/s with the jail, against 1800–2400 without.
The waiter costs 64 KB private (616 KB PSS, mostly its static binary, which
all waiters share).

**`--net` and invocations through the jail.** Same box, one VM at a time,
the jail started by `nobody` (a user namespace, no `--base`, no cgroup):

| | direct (`setpriv`) | through `microvm-jail` |
|---|---:|---:|
| agent: restore → connected, p50 / p90 (50 runs) | 1.43 / 1.61 ms | 2.14 / 2.41 ms |
| agent: restore → first response, p50 / p90 | 2.11 / 2.26 ms | 2.81 / 3.09 ms |
| agent: invocation round trip, 0 B / 64 KiB / 1 MiB, p50 | 50 / 130 / 1480 µs | 47 / 114 / 1497 µs |
| net: guest connected to the host after spawn (boot included, 1 run) | 8.9 ms | 9.7 ms (as root, VM uid 65534: 10.2 ms) |
| net: 1-byte round trip / 8 MiB bulk each way | 40 µs / 1048 MiB/s | 38 µs / 1383 MiB/s |

The jail adds its ~0.7 ms of setup to the restore, as for any VM; once the
guest runs, nothing on the data path changes. The network helper the jail
forks for `--net` has 12 KB of private dirty memory; its other 508 KB
resident are pages of the jail's binary, which VMs share (Pss 298 KB with
one VM).

### virtio-vsock (`--vsock`)

Same box, as `nobody` with the sandbox on, kernel pre-patched for KVM,
`--map-kernel`, running `/bin/probe` from the test image. p50 of 60 runs:

| | guest | setup | total | exits | idle private dirty |
|---|---:|---:|---:|---:|---:|
| kernel without NET / VSOCK | 4.32 ms | 0.57 ms | 4.92 ms | 47 | — |
| kernel with them, no device | 4.60 ms | 0.60 ms | 5.25 ms | 47 | 3.70 MB |
| `--vsock` | 5.11 ms | 0.63 ms | 5.76 ms | 123 | 3.90 MB |

`tests/test_vsock.c --bench` against `/bin/vsock-echo` in the guest:

| | |
|---|---:|
| 1-byte round trip, host → guest → host | 32.5–33 µs (64–73 µs before the changes below) |
| MMIO exits per round trip | 1 (8 before) |
| bulk echo (64 MiB through, both directions at once) | 1.36–1.68 GiB/s each way (650–860 MiB/s before) |
| host socket connected and answered, from spawn | ~9 ms (the test retries every 0.1 ms until the guest listens) |

- **The receive queue size is guest memory.** Linux's vsock driver fills
  the whole receive queue with 4 KiB buffers when it probes the device.
  With the 256 entries the transport offered at first, that was 1.2 MB
  private per VM and 1.2 ms of boot. Each device now sets its own queue
  maximum: vsock receive 32 (128 KiB), transmit 64, events 8. That gives
  +0.2 MB and +0.5 ms, and bulk throughput didn't change.
- **The remaining 0.5 ms is mostly the probe's 76 MMIO exits.** These are
  the transport registers, three queues' setup, the config space, the
  I/O APIC entry, and the first kicks. On this AMD host each exit to
  userspace is several µs with the host's mitigations.
- **A round trip took 8 MMIO exits; two causes made 5 of them.** An MMIO
  histogram of 2000 round trips showed them:
  - **The guest sent a credit update after every read.** The vsock
    transport sends one when the receive queue holds less than
    `SO_RCVLOWAT`, and with the default of 1 that is true every time a
    read empties it. Each update is a transmit packet, a kick, and a
    completion interrupt. Patch 0037 keeps that test for
    `SO_RCVLOWAT` > 1 only. The free-space test still sends an update
    before the sender can run out of credit, and 8 MiB bulk transfers
    with half-closes still pass.
  - **Every transmit completion had an interrupt of its own**, with the
    driver's ISR read and acknowledge: 3 exits just to let the guest free
    a buffer. The device now holds it back until the next receive
    interrupt, because one interrupt has Linux's driver look at every
    queue. It waits 500 µs at most, or less once half the transmit ring
    is waiting. A one-way sender gets an interrupt every 32 packets
    instead of every packet.
- **Interrupt acknowledgements don't exit.** The guest's driver reads the
  interrupt status and writes it back to acknowledge it, on every
  interrupt. On KVM the write now goes into KVM's coalesced-MMIO ring and
  is applied when the vCPU next exits, which is always before the driver
  reads the status again. A bit raised for new work in between survives
  the late acknowledgement. Round trip 35 → 30 µs, 3 → 2 exits.
- **Transmit kicks ring a doorbell instead of exiting.** On KVM the
  notify register is a `KVM_IOEVENTFD` on the vsock I/O thread's eventfd,
  and that thread takes the transmit queue itself. Every kick already woke
  it. The vCPU no longer stops while packets are copied to host sockets:
  bulk went from 1.10 to 1.36–1.68 GiB/s each way. A round trip now waits
  for that thread to wake, so it went from 29.7 to 32.7 µs (4 runs each,
  A/B on the same box). We keep the doorbell: guest CPU time and
  throughput matter more to a hosted service than 3 µs.
- **The exit left** is the receive interrupt's status read, which
  virtio-mmio has no way around.
- The NET and VSOCKETS options themselves cost +0.28 ms of guest boot
  (socket layer and protocol-family init) and nothing measurable in memory.

### virtio-net (`--net`)

Same box, as `nobody` with the sandbox on, `--map-kernel`, running
`/bin/probe` from the test image. These are p50s of 60 runs, interleaved.
A second set of 60 agreed within 0.2 ms. The kernels:

| | `.text` |
|---|---:|
| A: before (NET and VSOCK, no INET) | 4.26 MB |
| B: A + INET, VIRTIO_NET, IP_PNP (the default now) | 4.64 MB (+377 KB) |
| C: B + IPv6 | 4.87 MB (+233 KB) |

| | guest | setup | total | exits |
|---|---:|---:|---:|---:|
| A, no device | 4.79 ms | 0.62 ms | 5.46 ms | 47 |
| B, no device | 4.93 ms | 0.64 ms | 5.63 ms | 47 |
| C, no device | 5.18 ms | 0.65 ms | 5.87 ms | 47 |
| B `--net` | 5.43 ms | 0.84 ms | 6.26 ms | 118 |
| C `--net` | 5.67 ms | 0.84 ms | 6.50 ms | 118 |

Idle memory per VMM process (`smaps_rollup`), with 20 VMs held at once,
two rounds that agreed within 10 KB:

| | private dirty | PSS |
|---|---:|---:|
| A `--vsock` (waiting in `/bin/vsock-echo`) | 4.07 MB | 4.23 MB |
| B `--vsock` | 4.26 MB | 4.44 MB |
| B `--net` (holding a TCP connection to a host listener open, `net-probe sink`) | 4.54 MB | 4.71 MB |
| C `--net` | 4.68 MB | 4.86 MB |
| the network helper, per VM | 54 KB | 83 KB |

`tests/test_net.c --bench` against `net-probe` in the guest, five
interleaved runs:

| | |
|---|---:|
| 1-byte round trip, host → guest → host | 36–39 µs (vsock: 32.5–33) |
| bulk echo, 64 MiB both directions at once | 1.25–1.72 GiB/s each way (vsock: 1.36–1.68) |
| one way, 256 MiB, host → guest | 2.6–3.2 GiB/s |
| one way, 256 MiB, guest → host | 2.4–2.6 GiB/s |
| host socket connected, from spawn | 8–9 ms (the guest retries every 5 ms until the test listens) |

- **The NET config costs every VM**, device or not: +0.13–0.14 ms of
  guest boot and +0.19 MB, for IPv4, the socket layer and the device
  driver. It is in the default kernel because a hosted function that
  can't make an outbound call is of little use.
- **IPv6 isn't in it.** It would cost another +0.15–0.25 ms and +0.15 MB.
  The box has no global IPv6, and the device would need an IPv6 NAT. The
  helper's policy already handles IPv6 destinations, for when it gets one.
- **`--net` itself costs +0.5 ms of guest boot and +0.2 ms of
  setup.** In memory, it costs 0.28 MB more than a vsock device.
  - The guest's share is the device probe: 71 MMIO exits for transport
    registers, two queues and config space (vsock's three queues take
    76), plus filling the receive ring and bringing up `eth0`.
  - The setup is forking the helper and starting the I/O thread.
  - Patch 0038 removes the 10 ms that the kernel's IP autoconfiguration
    sleeps after opening the device ("to let things settle"). There is
    nothing to settle for a static address and a device that is always
    up.
- **The receive queue is 64 entries.** Linux sizes mergeable receive
  buffers so that one ring holds a 64 KiB frame. 64 entries make that
  ~1.5 KiB per buffer, about 100 KB of guest memory. The transmit queue
  (256 entries) costs nothing until used.
- **The MTU is 65520**, as in passt. The guest's TCP ends in the VMM, so
  large segments cost nothing on a wire: one 64 KiB segment replaces 45.
- **Four fixes ended the stalls in bulk transfers.** Before them, half
  the ctest's 8 MiB echoes stalled for 40 or 200 ms and came out at
  40–160 MiB/s. Now 12 of 12 run at 1.0–1.3 GiB/s.
  - *Host sockets get `TCP_NODELAY`.* With Nagle on in the VMM as well as
    in the guest, the last small piece of an exchange waited for the
    host's 40 ms delayed ACK.
  - *A zero window with our data unacknowledged means the guest dropped
    that data* (it was short of memory). We now resend from there as soon
    as the window opens, not after the 200 ms timeout. A zero window that
    has bytes past `snd_una` outstanding gets probed too.
  - *A frame's receive buffers are published together.* Before, a guest
    driver that polled in the middle could see half a frame.
  - *Delayed ACKs.* Data from the guest is acknowledged on our next
    segment, or after 200 µs, or at once past 32 KiB. A request/response
    exchange then takes one receive interrupt instead of two: the round
    trip went from 40 to 36 µs. Bulk transfers fill the 32 KiB with every
    segment, so they don't wait.
- Like vsock, transmit kicks ring the KVM ioeventfd doorbell, interrupt
  acknowledgements queue in KVM, and transmit completions wait up to
  200 µs for the next receive interrupt.

### Snapshots (`--snapshot`, `--restore`)

`/init snapshot run COMMAND` asks for a snapshot once the root filesystem
is entered, right before COMMAND starts. With `--snapshot FILE` the VMM
saves the VM and stops; `--restore FILE` starts from there.

Same box, as `nobody`, sandboxed, `/bin/probe` from the test image. p50 of
60 runs, interleaved:

| | guest | setup | total | touched | still shared |
|---|---:|---:|---:|---:|---:|
| cold boot | 4.66 ms | 0.63 ms | 5.32 ms | 5.9 MB | 2.1 MB |
| cold boot, `--ws` | 1.76 ms | 2.08 ms | 3.88 ms | 5.9 MB | 2.1 MB |
| `--restore` | 1.75 ms | 0.39 ms | 2.15 ms | 3.4 MB | 2.8 MB |
| `--restore --ws` (recorded after a restore) | 0.49 ms | 1.39 ms | 1.88 ms | 3.4 MB | 2.8 MB |

20 VMs held running (`/bin/vsock-echo` waiting for a connection), per VMM
process from `smaps_rollup`:

| | private dirty | PSS |
|---|---:|---:|
| cold boot | 3.88 MB | 4.05 MB |
| restored from one snapshot | 0.78 MB | 0.98 MB |

- **Restored RAM is the snapshot file**, mapped copy-on-write. Each VM
  pays only for the pages it writes after the restore. Everything the boot
  wrote (the kernel's data, page tables, slab, `/init`) is shared through
  the page cache. Private memory per idle VM drops 5×.
- **The file is sparse:** 64 MiB of RAM took 6.9 MB on disk. Taking the
  snapshot, which scans all of RAM and writes the nonzero runs, adds about
  12 ms to that one boot.
- **A diff** (`--snapshot-diff` in a restored VM) holds only the pages
  written since the restore, found through `/proc/self/pagemap`; it is
  restored over its base with `--base`. In microvm-sbxd's pauses (python
  image, 512 MiB) the save takes 10–11 ms for 22 MiB of changed pages in
  25 runs, and 35–39 ms for 76 MiB. A full save of the same VMs took
  115–134 ms: it reads all of RAM to find the nonzero pages. `--trace`
  reports `snapshot_us`, `snapshot_kib` and `snapshot_runs`.
- **What a restore still costs:**
  - VM and vCPU creation (0.26 ms, as for a boot);
  - loading the vCPU state;
  - the guest's first touches of its pages: ~1.3 ms of EPT faults, or
    ~1 ms of batched prefault with `--ws`. That's 860 pages.
  - After a restore the guest runs only `/init`'s resume (clock and RNG
    reseed: 2 port exits) and COMMAND.
- With `snapshot run` the snapshot point is in `/init`, so every restore
  runs the same COMMAND. With `agent run` the runtime takes the snapshot
  after it has loaded, and each restored VM gets its work over vsock
  (below).

### Free page reporting (`--balloon`)

A virtio-balloon device that only takes free page reporting: the guest
kernel reports memory it has free, and the VMM discards it
(`MADV_DONTNEED`). Kernel patch 0040 drains the per-CPU free lists on
each pass and adds `vm.page_reporting_flush`, which `/init` writes before
every snapshot. KVM box, python image, 512 MiB, as `nobody`.

The guest writes 200 MB (`b'x' * 200_000_000`), frees it and idles 10 s;
touched memory at exit (`--trace`):

| | touched |
|---|---:|
| no balloon | 225 MiB |
| `--balloon`, stock reporting (no per-CPU drain) | 91 MiB |
| `--balloon`, patch 0040 | **30 MiB** |

Without the drain, 55 MiB of the 200 freed sat on the per-CPU free lists
(`/proc/zoneinfo`: 14,057 pages against a `high` of 15,747). Pages there
are free but not in the lists that reporting walks.

microvm-sbxd pauses (`pausebench.py`, Python SDK, two rounds each),
diff on disk and pause time:

| | no balloon | order 9 | order 9 + drain | **order 0 + drain** |
|---|---:|---:|---:|---:|
| after a few commands | 21 MiB, 11–13 ms | 21 MiB | 21 MiB | **13 MiB, 10 ms** |
| after 200 MB written and freed | 210 MiB, 97–109 ms | 84 MiB, 43–48 ms | 30 MiB, 17–25 ms | **16 MiB, 11–22 ms** |
| after 64 MB kept in `/tmp` | 210 MiB, 104–111 ms | 85 MiB | 82 MiB | **78 MiB, 36–40 ms** |

- **The order** is the smallest free block reported: 2^order pages. The
  kernel's default is 9 (2 MiB). Orders 5, 4 and 3 gave 79, 79 and 78 MiB
  in the 200 MB phase before the drain; with the drain, order 4 gave
  15 and 19 MiB, order 0 13 and 16 MiB.
- **Order 0 costs nothing measurable.** A guest loop writing 8 MiB and
  allocating 64 small objects per iteration, freeing them, for 8 s: 209.5–
  210.7 iterations/s with no balloon and at orders 9, 4 and 0.
- An earlier version of this benchmark allocated `bytearray(200_000_000)`:
  all zeros, which a diff leaves out anyway, so it showed nothing.

### Several vCPUs (`--cpus N`)

Two kernels: `vmlinux` for one vCPU (no `CONFIG_SMP`) and `vmlinux-smp`
(`VARIANT=smp guest/kernel/build.sh`: `CONFIG_SMP`, `NR_CPUS=8`) for 2–8.
The SMP kernel is pre-patched with `tools/prepatch-alternatives.sh -c 2`.
On one CPU an SMP kernel patches its locking alternatives out, which the
pre-patched image for 2 or more doesn't match, so it patches at boot.
KVM box, alpine `/bin/true` with `--map-kernel`, 256 MiB, p50 of 30 runs
as `nobody`:

| kernel | vCPUs | guest | total | touched |
|---|---:|---:|---:|---:|
| `vmlinux` | 1 | 9.3 ms | 10.0 ms | 11.1 MiB |
| `vmlinux-smp` | 1 | 15.1 ms | 15.8 ms | 13.5 MiB |
| `vmlinux-smp` | 2 | 11.8 ms | 12.5 ms | 13.9 MiB |
| `vmlinux-smp` | 4 | 13.0 ms | 13.8 ms | 14.6 MiB |
| `vmlinux-smp` | 8 | 14.4 ms | 15.4 ms | 15.2 MiB |

- **Bringing the other CPUs up is cheap**: about 0.6 ms of guest time and
  about 220 KiB of touched memory per extra vCPU (per-CPU areas, the
  idle tasks' stacks).
- **The SMP kernel itself costs** about 2.5 ms and 2.8 MiB more than the
  one-CPU kernel. That is why one vCPU keeps `vmlinux`.
- **The work spreads**: 8 busy shell loops take 2,234 ms on 1 vCPU,
  1,146 ms on 2 and 362 ms on 8.
- **Sandbox agent** (`mvm_sbx_tests`, 256 MiB):

  | vCPUs | boot to agent | restore to connected | snapshot on disk |
  |---:|---:|---:|---:|
  | 1 | 13.6 ms | 2.2 ms | 12.0 MiB |
  | 2 | 15.7 ms | 2.7 ms | 13.2 MiB |
  | 8 | 19.0 ms | 3.3–3.6 ms | 14.8 MiB |

- **microvm-sbxd**, python image with `cpus=4`: four forked CPU-bound
  processes take 1.03× as long as one alone, and 1.10× after a pause and
  resume.

### Function invocations (guest agent)

`/init agent run /bin/fn-demo`: the demo runtime warms up, asks for the
snapshot, and the host invokes it over vsock (`src/agent/`). Same box, as
`nobody`, sandboxed, kernel pre-patched for KVM. Measured by
`mvm_agent_tests --bench 60`, three runs interleaved with other load
on the box:

| | p50 | p90 / p99 |
|---|---:|---:|
| restore → host connected to the agent | 1.74–1.87 ms | 1.88–2.00 ms (p90) |
| **restore → first response** (an echo invocation) | **2.09–2.16 ms** | 2.24–2.32 ms (p90) |
| cold boot → first response (no snapshot; shell-timed, includes `setpriv`) | ~10.2 ms | ~11.0 ms (p90) |
| invocation round trip, empty payload and result | 46.5–49.3 µs | 55–74 µs (p99) |
| invocation round trip, 1 KiB each way | 47.4–50.2 µs | 55–74 µs (p99) |
| invocation round trip, 64 KiB each way | 111–130 µs | 128–145 µs (p99) |
| invocation round trip, 1 MiB each way | 1.46 ms | 1.78–1.86 ms (p99) |

8 VMs restored from one snapshot, per VMM process from `smaps_rollup`:
- private dirty is 0.69 MB after one invocation and 0.82 MB after 101;
- PSS is 1.2 MB and 1.3 MB;
- the snapshot file holds 64 MiB of RAM in 7.2 MB on disk.

- **A restore answers its first invocation 0.3 ms after the host
  connects.** The connection itself needs no retries: the agent's vsock
  listener is in the snapshot, so the restored guest kernel accepts the
  host's `CONNECT` without waiting for user space. The host sends the
  INVOKE right behind it, without waiting for HELLO.
- **An invocation costs ~14 µs more than a raw vsock round trip** (about
  33 µs). The agent relays the INVOKE to the runtime over a pipe, and the
  runtime's RESULT and DONE back over another: two more context switches
  in the guest per invocation, plus the pipe reads and writes. The frames
  add 32–64 bytes.
- **Large payloads run at about 1.4 GiB/s** in each direction (1 MiB in
  and 1 MiB out in 1.46 ms), the same as raw vsock bulk throughput: the
  agent streams the payload and never buffers a whole one.
- The agent is part of `/init`, which grew from 9.2 to 17.6 KB. The demo
  runtime builds a 1 MiB table at warm-up. All of it is in the snapshot
  and shared through the page cache.

## Parallel starts (Windows dev box)

`build\mvm-parlaunch N EXE "ARGS"` (`tools/parlaunch.c`) starts N VMMs back
to back (`MVM_PAR_THREADS=T` launches from T threads) and waits for all of
them. For each VM it reports wall time (process created to exited, from
`GetProcessTimes`), the VMM's own `total`/`guest` times from `--trace`, and
where the rest went: `pre` (process created to `main()`, from the trace's
`start_unix_us`) and `post` (guest exit status to process gone). 6-core/12-
thread host, plain boots with `--ws`:

| N in flight | throughput | wall p50 | pre p50 | VMM total p50 | guest p50 |
|---:|---:|---:|---:|---:|---:|
| 1 | — | 20.5 ms | 16.3 ms | 3.2 ms | 1.0 ms |
| 4 | 150 VMs/s | 20 ms | | 3.8 ms | 1.4 ms |
| 16 | ~205 VMs/s | 43 ms | 35 ms | 5.3 ms | 1.8 ms |
| 64 | ~220–240 VMs/s | 85–130 ms | 108 ms | 6.5 ms | 2.0 ms |
| 128 | ~230–250 VMs/s | 130–175 ms | | 7.5 ms | 2.0 ms |

Container runs (`--rootfs`, all sharing one image) give the same picture:
~220 VMs/s, with VMM total 5–6 ms and guest 1.8 ms p50 even at 128 in flight.

- **The limit is Windows process creation, not the VMM.** An empty static C
  program through the same launcher takes 16.7 ms wall time and tops out at
  ~330 processes/s on this host, so the VMMs run at ~70% of the rate at
  which Windows creates processes that do nothing. For one VM, 16 of the
  20 ms come before `main()`. Under load that pre-`main()` time is what
  grows (to 100–200 ms), while the VMM's own time barely moves. Defender
  (`MsMpEng`) alone used ~5.6 CPU-ms per launch, and the CPUs were ~94%
  busy at peak.
- **Launching from more threads doesn't help.** Eight launcher threads cut
  `CreateProcess` from ~3 ms to ~0.8 ms per VM, and throughput stayed at
  220–260 VMs/s.
- For reference, Firecracker's paper reports up to 150 microVMs/s per host.
- The way past this limit is not paying for a process on the critical
  path: a pool of VMM processes started ahead of time, each waiting for one
  run request. The VM is still one process; only process creation moves
  off the latency path.

## Container runs (`--rootfs`)

`microvm --kernel vmlinux --rootfs IMAGE [-- CMD ARG...]` runs one command
in an EROFS image (built from tar layers or an OCI image by
`microvm-mkrootfs`) and exits with its status. The image is never parsed by the VMM. It is mapped
read-only into guest-physical memory at 4 GiB and listed in e820 as legacy
persistent memory. The guest's pmem driver makes it `/dev/pmem0`, `/init`
mounts it, chroots, forks and execs the command with stdout and stderr on a
pipe it forwards to the console port (one exit per read), and reports the
exit status on the control port. There is no device emulation, no queue
and no interrupt, and every VM reads the same host page-cache pages.

| phase (p50, from `/init`'s first mark) | time |
|---|---:|
| mount `/dev/pmem0` (EROFS, read-only) | 50 µs |
| chdir + chroot | 9 µs |
| pipe + fork | 18 µs |
| exec + run `/bin/probe` (freestanding, prints, exits; derived from the totals) | ~80 µs |
| exec + run a static glibc `hello` (800 KB), image pages *not* prefaulted | ~1.4 ms |
| the same, image pages in the working set | ~0.31 ms |

- **Image pages belong in the working set.** Every image page the guest
  reads is a first touch of the host's file mapping (a SLAT fault, several
  µs on WHP). `--ws-record` now also records the image pages the guest read,
  at their guest-physical page numbers (`100000+`), and `--ws` prefaults
  them read-only, after dropping any that fall outside the image mapped now.
  Guest time for the glibc `hello` went from 2.57 to 1.46 ms, and total p50
  from 4.9 to 3.9 ms. Prefaulting the *whole* image instead cost +130 µs for
  0.8 MB, so it would not scale to real images.
- **What the rootfs kernel options cost a boot that doesn't use them.** As
  first enabled: guest +146 µs and +167 touched pages (668 KB). Most of it
  was iomap's write-path reserves, two biosets of 32 bios with 4 KiB bvec
  arrays plus a 64 KiB zeroed page for DIO zeroing, all allocated by the fs
  initcalls. A read-only EROFS never uses them (0036 sizes the pools like
  `fs_bio_set` and allocates the zero page on first use). The kyber and
  mq-deadline schedulers came along too, though pmem is bio-based and never
  uses one, and so did the partition parsers. Without all of those: guest
  +59 µs, +90 pages. The +202 KB of kernel text is most of what's left, and
  it is shared across VMs with `--map-kernel`.
- **Three kernel fixes were needed for an e820 pmem root with no PCI:**
  - 0033: `e820__reserve_resources_late()`, which puts PRAM ranges into
    iomem, is only called from the PCI resource survey.
  - 0035: the pmem driver's namespace enable lives in `claim.c`, built only
    with BTT or PFN. Without it, every probe failed with ENXIO.
  - 0034: `/init` must not race the asynchronous nd device registration,
    which `kernel_init`'s `async_synchronize_full()` doesn't wait for.
- **Not done yet: DAX.** Without it the guest copies every image page it
  reads into its own page cache (the glibc `hello` run touches 0.6 MB more
  than `probe`). FS-DAX needs `ZONE_DEVICE` and a struct page per pmem page
  (1.5% of the image).

### What real images need (the userspace ABI and a container root)

The kernel used to be tinyconfig plus devices, with none of the interfaces
real programs use: no futex (glibc threads), epoll, eventfd or timerfd
(Node, Python asyncio), setuid, `/proc`, tmpfs, Unix sockets or `#!`
scripts. `config.fragment` now has them (SECURITY.md lists what stays
out), and `/init` gives the command a container's root: the image under a
tmpfs overlay, `/proc`, its own `/dev`, `/etc/hosts` and the others
(IMAGES.md). The cost, on the KVM box as `nobody`, p50 of 60 runs,
interleaved:

| | before | after | change |
|---|---:|---:|---:|
| boot to `/init` | 5.25 ms | 5.59 ms | +0.34 ms |
| run `/bin/probe` from an image | 5.67 ms | 6.33 ms | +0.67 ms |
| guest memory touched by that run | 6.53 MB | 7.14 MB | +0.60 MB |
| private dirty per idle VM (20 held running) | 4.30 MB | 4.59 MB | +0.29 MB |
| kernel text | 4.76 MB | 5.14 MB | +0.38 MB (shared) |

About half of the extra run time is the kernel's own initialisation, and
half is `/init` building the container root: the overlay, five mounts, the
device nodes and three files in `/etc`. A VM restored from a snapshot
skips both, because the snapshot is taken after them.

Which options cost what, one group left out at a time (40 runs each):

| left out | boot saved | touched saved |
|---|---:|---:|
| `SYSFS` | 0.44 ms | 0.39 MB |
| `PROC_FS`, `PROC_SYSCTL` | 0.26 ms | 0.21 MB |
| futex, epoll, the fds, file locks, inotify, rseq | within noise | 0.15 MB |
| `OVERLAY_FS` | within noise | 0.09 MB |
| shmem/tmpfs, SysV IPC, `MULTIUSER`, `UNIX` | within noise | ≤ 0.03 MB each |

sysfs cost as much as all the rest together. It makes a kernfs node for
every device and driver at boot, and a container rarely needs `/sys`:
glibc counts CPUs from `/proc/stat` without it. So it stays out. Turning
it back on is one line in `config.fragment`, and `/init` mounts it
read-only when it is there. The alternatives undo table that patch 0026
keeps in `__initdata` grew from 48 to 64 KiB for the extra code. It is
freed after boot.

### Container image conversion

`microvm-mkrootfs --oci` and `--docker-archive` ([IMAGES.md](IMAGES.md)).
The test image is realistic: 5 layers built from a Linux install's own
files with GNU tar and `gzip -6` (`tools/bench-oci.sh`, no docker, no
network):
- a base (`/etc`, `/usr/bin`, `/usr/sbin`);
- Python's stdlib;
- Perl and `/usr/share/doc`;
- headers, plus the test layer with `/bin/probe`;
- a clean-up layer that whites out `/usr/share/doc`, a file and the headers
  directory (opaque).

That is 599.8 MB of tar, 28,281 inodes in the result, and a 503.6 MB EROFS
image. The OCI layout is 190 MB (gzip); the docker-archive is 573 MB
(uncompressed layers). Both run as `nobody`, sandboxed, best of 3, on the
Debian 13 KVM box (Zen 4, 4.5 GHz):

| input | read + verify layers | write image | total |
|---|---:|---:|---:|
| OCI layout, gzip layers | 2.08 s | 1.01 s | **3.09 s** |
| docker-archive, plain tar layers | 0.29 s | 0.22 s | **0.51 s** |

Peak RSS is about 8 MB, the sandboxed child included (GNU time, dev box). File data is never
held in memory: the tree keeps (layer, offset) pairs, and the writer copies
from the layers. On the WSL dev box (Ryzen 7600X) the same image takes
3.8–3.9 s and 0.84–0.91 s.

| primitive (KVM box) | throughput |
|---|---:|
| inflate, base layer (110.5 → 289.8 MB) | 548 MB/s out (209 MB/s in) |
| inflate, Python layer (43.9 → 155.4 MB) | 704 MB/s out |
| SHA-256, SHA-NI | 2.7 GB/s |
| SHA-256, portable | 465 MB/s |

- **Where the OCI time goes.** A gzip layer is inflated three times:
  - the diff_id check, before any parsing;
  - the tar import;
  - the data copy, laid out in layer order so each pass is front to back.

  At about 650 MB/s that is roughly 0.9 s a pass for 600 MB. The rest is
  hashing (the compressed and uncompressed bytes) and the EROFS write.
  Hashing during the import pass would save one of the three passes, at
  the price of parsing a layer before its diff_id is checked. That is a
  follow-up in IMAGES.md.
- **The inflater.** On the dev box GNU `gzip -d` does the base layer at
  about 250 MB/s; ours does 557 MB/s, and up to 1076 MB/s on the
  more-compressible headers layer. Two changes got it there:
  - the Huffman loop keeps its state in registers and refills the 64-bit
    bit buffer only below 48 bits;
  - matches at distance ≥ 16 copy 16 bytes at a time.

  Together they cut conversion from 4.1 to 3.9 s.
- **Booting a big image costs the same as a small one.** For `-- /bin/probe`
  the p50 in-VM total is 6.86 ms from the 10-inode test image and 6.99 ms
  from the 503.6 MB one (30 runs each, `nobody`). EROFS reads only what the
  command touches.
- **zstd layers convert 1.7× faster than gzip.** `bench-oci.sh` also
  writes every layer with `zstd -3`, the level `docker buildx` and `podman
  push` use for zstd. A later run on the KVM box had more in `/usr`: 1210
  MB of layers, a 1048 MB image. Each conversion was run 3 times as
  `nobody`, with spreads under 0.5%:

  | layers | compressed | read layers | write image | total |
  |---|---:|---:|---:|---:|
  | gzip -6 (OCI layout) | 412 MB | 4.35 s | 2.14 s | **6.49 s** |
  | zstd -3 (OCI layout) | 389 MB | 2.52 s | 1.29 s | **3.82 s** |
  | plain tar (docker-archive) | 1.2 GB | 0.55 s | 0.46 s | **1.00 s** |

  The two layouts give the same image. Only the config file's
  `manifest-digest` differs, because the layer blobs do. Decoder
  throughput on the base layer (350.8 MB of zstd, or 363.4 MB of gzip, to
  1009.4 MB), streamed as the converter reads it, best of 4:

  | decoder | MB/s out |
  |---|---:|
  | ours, zstd (`src/image/zstd.c`) | 1190 |
  | ours, inflate | 625 |
  | `zstd -d` 1.5.7 (libzstd, to /dev/null) | ~1530 |
  | GNU `gzip -d` 1.13 (to /dev/null) | ~287 |

  The Python-headers layer (6.4 → 86.3 MB, mostly long matches) decodes at
  2.9 GB/s. Two things make most of the speed:
  - the literals' Huffman streams are decoded 4 at a time, interleaved,
    5 symbols per 64-bit refill;
  - matches copy in 16-byte chunks into 32 bytes of slack.

  4 symbols per refill measured the same, within 0.5%.

```bash
tools/bench-oci.sh build ~/oci-bench guest/kernel/out/test-layer.tar
build/mvm-mkoci --bench ~/oci-bench/l1.tar.gz
build/mvm-mkoci --bench ~/oci-bench/l1.tar.zst
```

### Public runtime images: Python, Bun, Node

These are the official images, pulled with `skopeo` by the digests below,
which were checked against Docker's `repo-info` records and Bun's release
tag. They were converted by `microvm-mkrootfs` as `nobody` and run
unchanged.

| image | digest (index) | runtime | layers → EROFS | convert |
|---|---|---|---:|---:|
| `alpine:latest` | `be265606…2c9a` | Alpine 3.24.3 | 8.7 → 10.5 MB | 0.09 s |
| `python:3-slim` | `8c13a3f3…e0d0` | Python 3.15.2 | 126.8 → 135.9 MB | 0.72 s |
| `oven/bun:slim` | `1846adf2…d9a4` | Bun 1.4.4 | 192.4 → 199.6 MB | 1.24 s |
| `node:lts-slim` | `e4db4c91…2c39` | Node 26.13.0 | 254.7 → 266.4 MB | 1.41 s |

One command per VM, start to exit status (MVMTRACE `total`, warm page
cache, p50 of 21, KVM box, `nobody`):

| command | total | guest RAM touched |
|---|---:|---:|
| alpine `/bin/true` | 7.5 ms | 7.6 MB |
| alpine `sh -c 'echo hi'` | 7.6 ms | 7.9 MB |
| `bun --version` | 15.5 ms | 15.2 MB |
| `bun -e "console.log('hi')"` | 27.5 ms | 24.5 MB |
| `python3 -c pass` | 28.1 ms | 19.1 MB |
| `python3 -c 'import json, ssl'` | 92.2 ms | 31.6 MB |
| `node -e 0` | 73.1 ms | 56.2 MB |
| `node -e "console.log('hi')"` | 78.4 ms | 59.1 MB |

The VM's part is the alpine row: about 7 ms. Everything above that is the
language starting up in the guest. Python pays for having no bytecode:
the image ships none (IMAGES.md), so `import json, ssl` takes 64 ms more
than `pass`, loading and compiling the modules from source on every
start.

**Python with a bytecode layer** (`tools/pyc-layer.sh`: the image's own
interpreter compiles every module on `sys.path` in a VM, and the `.pyc`
files go on top as one more layer, 694 files, 14 MB). MVMTRACE total, p50
of 21, on the function image (the python image without pip, with the
adapter):

| command | no bytecode | checked hashes (default) | unchecked hashes |
|---|---:|---:|---:|
| `python3 -c pass` | 27.8 ms | 24.0 ms | 24.7 ms |
| `python3 -c 'import json, ssl'` | 92.4 ms | **42.6 ms** | 43.5 ms |
| `python3 -c 'import asyncio, email, http.client'` | 263.2 ms | **79.6 ms** | 75.1 ms |

- Imports get 2 to 3.3 times faster, and touch less guest memory (26.7
  against 31.6 MB for `json, ssl`): compiling allocated more than loading.
- Checked hashes read each module's source and hash it, so a changed
  source is compiled again instead of running stale bytecode. They cost
  about 4 ms of 80 for the heaviest row, and nothing measurable for the
  others. Unchecked ones never look at the source again: with a module's
  source changed under the layer, a checked image ran the new source and
  an unchecked one the old bytecode.
- The layer is the same bytes every time it is built from the same image.

**As functions** (`tools/fn-images.sh`): the runtime adapter and a
function (`runtimes/examples/rng.*`, which imports its random sources at
warm-up) go on top as one `--add-layer`. Each runtime takes a snapshot
after its warm-up and is invoked through the agent. The times are wall
clock from launching the VMM to the first response printed by
`microvm-invoke`, as a client sees them: process start, the restore or
boot, the vsock connection, and the invocation (p50 of 20). Memory is per
VMM process, 8 VMs restored from one snapshot, held after one invocation
each:

| runtime | restore → first response | cold boot → first response | snapshot (taken once) | private dirty | PSS |
|---|---:|---:|---:|---:|---:|
| Python 3.15 | **7.3 ms** | 58.8 ms | 148 ms, 35.7 MB file | 1.9 MB | 4.2 MB |
| Bun 1.4.4 | **10.2 ms** | 55.5 ms | 156 ms, 41.9 MB file | 3.9 MB | 6.7 MB |
| Node 26.13 | **18.7 ms** | 95.4 ms | 197 ms, 69.3 MB file | 5.3 MB | 10.5 MB |

Python's function image has its bytecode layer (above); without it, cold
boot → first response was 133 ms and the snapshot took 216 ms (a 40.9 MB
file), and restores were the same. Each restored VM reseeds every random
number generator before its first invocation (SECURITY.md, "Language
runtimes and snapshots"), and these times include that. For Bun and Node it adds about 0.5 ms to the first
response: 9.7 and 18.2 ms when their generators still repeated.

- **Bytecode makes a Python cold boot 2.3× faster** (133 → 59 ms), so
  Python now cold-boots about as fast as Bun. A snapshot still answers 8×
  faster than that (7.3 ms). The snapshot file holds 256 MiB of RAM in
  36 MB, and every VM restored from it shares those pages through the page
  cache. Each one writes 1.9 MB of its own.
- **Node restores more slowly than Bun**, and each restored Node VM
  writes more of its own memory (5.3 against 3.9 MB).
- These restore times include `setpriv`, process start and the client's
  connection. The agent's own restore → first-response time, with the
  demo runtime, is 2.1 ms (above).

```bash
skopeo copy docker://docker.io/library/python@sha256:8c13a3f37a6a5b71498228e902c4b9f51c1f7900d49fabf71f9a650c6120e0d0 oci:python
sudo N=20 WRAP="setpriv --reuid=nobody --regid=nogroup --groups=kvm --no-new-privs" \
    tools/fn-images.sh build guest/kernel/out/vmlinux /tmp/fn python python
```

## Memory density

`tools/density.ps1 -N 20` starts 20 VMs back to back. Each boots to `/init hold` and
idles, like a long-running container. Per VM:

| kernel / VMM | ws_private | avail_drop | idle CPU |
|---|---:|---:|---:|
| before the memory diet | 12.6 MB | ~15 MB | 0% |
| 0003/0004, zero-page skipping, config | 8.8 MB | 13–17 MB | 0.04% |
| + 0006, 0007 | **7.6 MB** | ~11 MB | 0% |
| + `--map-kernel` (read-only kernel pages shared across VMs) | **5.3 MB** | — | 0% |
| `--mem 32` | 7.1 MB | ~11 MB | 0% |
| 0026–0031, working set from first touches; untouched read-only kernel chunks mapped from the file (N=10) | **5.5 MB** (was 7.3) | ~13 MB | 0% |

- `ws_private` is the private working set of the VMM process: guest pages
  touched plus the VMM itself (~0.5 MB). It is stable to 0.1 MB between runs.
- `avail_drop` is the drop in system-wide available memory, divided by N. It
  also catches what no process shows, such as Hyper-V SLAT tables and VP state.
  It is noisy: ±2 MB, and wildly off when another process frees memory
  mid-run.
- All 20 VMs reach `/init` within ~220 ms, mostly Windows process creation.
- The guest RAM ceiling is committed but never touched beyond what the guest
  uses.

Where the 5.1 MB came from (guest pages touched, 12.2 → 7.1 MB):

- **0003**: x86 poisons (0xcc-fills) every freed kernel-image page: initmem and
  the text/rodata and rodata/data 2 MB alignment gaps. The rodata/data gap
  (1.8 MB) is not even in the vmlinux file. It now poisons only with
  `init_on_free`.
- **Zero pages skipped on load**: ~40% of the vmlinux load segments are
  all-zero pages (alignment padding, zero-initialised page tables and buffers
  in `.data`). Guest RAM is already zero, so the loader copies through a
  256 KB bounce buffer and skips them. This adds ~0.3 ms to the loader thread,
  which is hidden behind partition creation on WHP. On KVM, where VM
  creation is fast, it will be on the critical path; a prelinked image without
  the zero pages would remove it.
- **0004**: `clear_bss()` zeroed ~1 MB of PMD-alignment padding in front of
  `.bss..decrypted` that no symbol lives in.
- `CONFIG_MITIGATION_CALL_DEPTH_TRACKING` off: it pads every function by 16
  bytes (−285 KB of text), and only Skylake-era Intel uses it. Those CPUs fall
  back to IBRS, so they stay mitigated.
- `CONFIG_LOG_BUF_SHIFT=14`: a 16 KB printk ring instead of 128 KB. 4 KB was
  too small: it dropped a message, and the "messages dropped" notice then cost
  ~70 console exits even under `quiet`.
- **0006**: the memory map (`struct page`, 64 B per 4 KB page) is initialised
  up to the end of the last 128 MB memory section, past the end of RAM.
  Every guest smaller than 128 MB therefore touched 2 MB of it. With 32 MB
  sections a 64 MB guest touches 1 MB of memory map, and a 32 MB guest
  0.5 MB.
- **0007** (`noroms`, on the default cmdline): skips probing 0xc0000–0xf0000
  for option-ROM signatures, which read 48 pages.

The guest's 7.1 MB now breaks down as:
- ~4.5 MB of kernel text, rodata and data actually used;
- 1.2 MB at the top of RAM (memory map, memblock allocations);
- ~1.4 MB between 1 and 16 MiB (runtime allocations: slabs, stacks, page
  tables);
- 0.05 MB in the low 1 MiB.

## What we learned

- **First-touch faults dominate on WHP.** Each guest page touched for the first time
  costs a second-level page-table (SLAT) fault in the hypervisor. One batched
  `WHvAdviseGpaRange(Populate)` over exactly the pages a boot touches (recorded once
  with `--ws-record`; boots are deterministic) cuts guest time 3x without using more
  memory. Prefaulting everything is slower *and* costs 5x the memory.
- **Every console byte is a VM exit** (~3–4 µs each on WHP). `--quiet` alone took
  33 ms off.
- **No PIT, PIC, IOAPIC or ACPI needed.** The guest reads TSC and LAPIC-timer frequencies
  from Hyper-V synthetic MSRs (WHP) or kvmclock (KVM), so nothing is calibrated.
- **Every console byte costs two exits** (data + line-status poll), so one
  80-byte warning cost ~0.6 ms. It came from an MP table without I/O
  interrupt entries. `/init` now prints its line on control port 0x702, which
  takes 1, 2 or 4 bytes per `out`: 8 exits instead of 64 for the 32-byte line.
  With patch 0011 the kernel log goes there too (`earlyprintk=microvm,keep`), so
  the guest has no 8250 driver at all, which also removes ~35 exits of UART
  probing. A full, non-quiet boot (6.2 KB of log) now takes ~1.7k exits and
  8 ms, against ~13k exits and 54 ms through the UART.
  The VMM still emulates the UART for stock kernels. Container output will go
  through virtio-console.
- **Legacy PTYs cost 12% of guest boot.** With `CONFIG_LEGACY_PTYS`, 256
  master/slave pairs are registered at boot: 512 tty devices. The stack-sampling
  profiler (`--inclusive`, `--callers`) found them through `pty_init`;
  self-time alone only showed generic device and sysfs code. Unix98 PTYs (devpts)
  allocate on demand, and containers need them anyway. Saves 0.4 ms and
  0.4 MB per VM.
- **Uevents nobody can receive cost 11% of guest boot.** Without netlink
  (`CONFIG_NET` off) and without a uevent helper there is no receiver, but
  every registered device still built a uevent environment: an allocation, a
  path walk, and a dozen `printf`-formatted variables. Patch 0009 skips the
  build in that case. It saves 0.4 ms, more than the sampled profile
  suggested, because the formatting showed up under `vsnprintf` rather than
  under the uevent code.
- **Boot-time code patching** rewrites ~12k sites (return thunks, retpolines,
  alternatives). Upstream serializes (IRET-to-self) after each one; patch 0002
  serializes once at the end, saving 0.9 ms with every mitigation still on.
  Patch 0008 then decodes the ~10k JMP/CALL/Jcc rel32 sites directly instead of
  running the generic x86 decoder on each one, which saves another 0.25 ms. A
  boot-time cross-check build compared every fast-path decode against
  `insn_decode_kernel()` and found no mismatches. What's left is mostly cache
  and TLB misses on the sites themselves: there is about one site every five
  cache lines. Prefetching 16 sites ahead (0010) hides some of that (−70 µs).
- **`optimize_nops()` was ~10% of guest boot.** It runs on all ~1,200
  alternative sites and decodes every instruction in each, one 0x90 padding
  byte at a time. 0014 skips the decoder for buffers that can't hold a NOP
  and for 0x90 at an instruction boundary. A debug build ran the original
  next to it on every site: 0 mismatches, 160 sites rewritten. 0013 skips
  `text_poke_early()` when the bytes don't change, saving a serializing
  `sync_core()` and a dirtied text page per site. Together: guest −275 µs.
- **Small things a VM pays for in exits.** An AMD initcall read the
  chipset's S5 reset reason over MMIO (an exit, plus an ioremap/iounmap and
  vmap purge); 0015 skips it under a hypervisor. CPU identification ran 72
  CPUIDs per pass over the scattered-feature table for 19 distinct values,
  twice per boot; 0016 reads each leaf once. Boot logs, including detected
  features and mitigations, are identical. Together: guest −68 µs.
- **Freeing the kernel image's alignment padding cost 14% of guest boot.**
  Text and rodata are 2 MB-aligned, which leaves 0.8 MB and 1.8 MB of padding
  that `mark_rodata_ro()` frees. Freeing makes those pages writable again,
  4 KB at a time, in both the kernel mapping and the direct map, after
  splitting large pages: ~1M cycles, measured by timing each
  `change_page_attr_set_clr()` call in a debug build. With 0017
  (`keep_image_gaps`, on the default cmdline) the padding stays reserved,
  read-only and non-executable. The guest has 2.5 MB less free memory, which
  costs the host nothing: the padding is zeros, never loaded or touched.
  Guest −295 µs. Also tried: starting NX at rodata, so the large page at the
  end of text needn't split (−40 µs, within noise). Dropped, because it
  leaves the padding executable.
- **0018: sealing ENDBRs is a no-op without IBT.** The kernel overwrote the
  ENDBR of every function never called indirectly, even on CPUs (like this
  Zen 4) where ENDBR and its poison are both NOPs. Skipping it there: guest
  −70 to −95 µs.
- **Return sites pre-patched at build time (0019, `guest/kernel/prepatch.py`).**
  All 10,014 `jmp __x86_return_thunk` sites are rewritten in the image to
  the thunk this host class needs (`srso_alias_return_thunk` on Zen 3/4),
  and the kernel skips the rewrite when it picks that same thunk. A debug
  build ran the full loop on the pre-patched image anyway: 0 bytes would
  change. An image pre-patched for the wrong thunk still gets every site
  re-patched at boot. Guest −75 µs, less than the profile suggested: the
  loop also warmed the caches for the code after it. With `--map-kernel`,
  each VM keeps 964 KB of kernel shared instead of 260 KB.
- **Exits a VM pays for absent hardware: 30 → 23.** The PMU probe made 7
  MSR exits, because unknown MSRs read as 0 and look like a working counter.
  The AMD counter MSRs now fault with #GP, as they would on a CPU without
  them, and Linux gives up after one access ("PMU not available due to
  virtualization"). `ISA_DMA_API` is off, so no i8237 DMA probe (port 0x87).
  Left as is: the DE_CFG LFENCE write (2 exits; the CPUID bit that would
  skip it isn't visible even to the Windows root partition). The PIT stop
  (4) and the PIC probe (3) went later with 0025.
- **0020: boot options looked up without a `strlen` per table entry.** Each
  option was measured once per `__setup`/`kernel_param` entry, and every
  `__setup` string once per unknown option: ~4.5k `strlen` calls for a dozen
  options. Guest −45 µs (p50 over 60 interleaved runs).
- **0021: static call sites sorted at build time.** `static_call_init`
  heapsorted the 212-entry table on every boot. Heapsort does no less work on
  sorted input, and every compare and swap is an indirect call through a
  retpoline. `prepatch.py` now sorts it, and the kernel only checks the order.
  Guest −56 µs.
- **0022: one E820 scan for the empty page-table slots past RAM.** Each
  `init_memory_mapping` call tested every slot above a 64 MB guest's RAM
  with two scans of the E820 table: over 4k tests per boot. Now one scan
  serves all the slots below the next RAM or ACPI address. A debug build ran
  both checks side by side (at 64 MB, 1.5 GB and 3 GB of guest RAM): no
  difference. Guest −15 and −37 µs in two interleaved runs.
- **0023: init memory freed with one CPA pass.** `free_init_pages` made the
  592 KB of init memory non-executable, then writable, as two passes that each
  walk every page and its direct-map alias and flush the TLB. One pass now
  sets both bits. Final page tables are identical. Guest −23 µs.
- **0024: no stale-ISR scan on a virtual LAPIC.** `setup_local_APIC` read all
  8 ISR and 8 IRR registers, to EOI interrupts that a crashed previous kernel
  left in service. Each read is an MMIO exit. A virtual LAPIC starts from reset,
  so the scan now runs only in a kdump kernel or on bare metal. The host was
  noisy for this A/B: guest p50 −77, +54 and −42 µs in three runs, and B's
  minimum was lower every time (−28 to −89 µs).
- **0025: `reduced_hw`, exits 23 → 16.** Booted without ACPI, the kernel can't
  learn that there is no PIT or PIC, so it stopped the PIT (4 port writes) and
  probed the PIC (3 port accesses), each an exit to the VMM. The VMM now
  passes `reduced_hw`, which applies the same overrides as hardware-reduced
  ACPI (no PIT init, no ISA IRQ setup, NULL PIC). Guest −33 µs. The only log
  change is `nr_irqs` 24 → 8: the 16 legacy ISA IRQs aren't reserved.
- **Guest RAM mapped in two steps.** `WHvMapGpaRange` costs ~11 µs per MB
  (0.75 ms for 64 MB), scales linearly, and doesn't get faster on several
  threads: the hypervisor serializes it. With `--ws`, only the recorded
  working set is mapped before the guest starts (0.25 ms). The rest is mapped by
  a thread that starts with the vCPU, after the prefault. Started any earlier,
  it contends with the prefault for the same lock (+156 µs). A guest access to
  RAM that isn't mapped yet exits as MMIO, waits for the thread, and reruns.
  Tested with a one-page working set: one wait, normal boot. Setup −421 µs,
  guest +35 µs, total −372 µs (p50, 100 interleaved runs).
- **0026: all boot-time text patching moved to build time.** Retpolines,
  alternatives, paravirt calls and ENDBR sealing were still rewritten on
  every boot (about a tenth of it, mostly cache misses). They depend on the
  exact CPU features, so instead of guessing them like 0019,
  `tools/prepatch-alternatives.ps1` boots the image twice: once stopping just
  before `alternative_instructions()` rewrites the text, once just after it.
  The text that differs between the two memory dumps is exactly what the
  rewrite wrote (3,049 bytes in 657 runs). `prepatch.py --alternatives`
  copies it into the image, with the inputs that decided it (CPU feature
  and bug bits, the return thunk, `pv_ops`) and an undo table. The kernel
  skips the rewrite only if this boot's inputs are byte-for-byte the same;
  otherwise it restores the compiled bytes and patches as usual. Checked by
  dumping both images at the patch point: 0 bytes differ, both when the
  inputs match and with `mitigations=off`, which takes the undo path. Guest
  1.59 → 1.34 ms (−256 µs p50, 40 interleaved runs), and the boot writes 55
  instead of 123 of 812 text pages, so `--map-kernel` shares more. The tool
  also writes the static call sites whose keys are still at their compiled
  targets (76 of 212) as `static_call_init()` would. The kernel skips a
  site that already holds what it computes, so 47 text pages are written.
  No time change. A first
  version found its bytes by diffing the image against one snapshot, and
  also undid static-call trampolines and the dcache's runtime constants,
  which other code had rewritten before the patch point. On the undo path
  that turned `x86_idle` into a bare `ret`.
- **0026 on another CPU: restore before anything runs.** An image
  pre-patched on the KVM box panicked under WHP ("Attempted to kill the
  idle task", at a `mov %rax,%cr4` setting PKE). The undo table was fine,
  but it was applied at the patch point, and the pre-patched text had been
  running since the first instruction. `identify_cpu()`'s PKU test was
  already patched to "yes", and the WHP vCPU has no PKU. The inputs now
  start with the raw CPUID leaves the features come from, read first thing
  in `x86_64_start_kernel()`. On a mismatch, the compiled text goes back
  right there. `microvm --cpuid-hide 7.0:ecx:0x8` (no PKU) reproduces
  the crash on KVM, and `ctest -R prepatch` boots an image pre-patched on
  the host with CPUID bits hidden. On another CPU, the text at the patch
  point equals a fresh kernel's (0 bytes differ). On the same CPU (box,
  `--map-kernel --ws`, p50 of 60 interleaved runs), the 14 CPUIDs don't
  show: guest 1770 → 1759 µs, same pages touched and shared. On KVM the
  same-CPU image differs from a fresh kernel in 10 static-call tail sites,
  `jmp __x86_return_thunk` for `ret`, which run the same (SECURITY.md,
  0026).
- **0027: page-attribute changes a page table at a time.** Once a large
  page is split, `change_page_attr` handled each 4k page as its own step,
  with a full page-table walk and alias pass per page. At boot that adds up
  to thousands of steps: `mark_rodata_ro`'s NX sweep crosses the text gap and
  the data/bss large page that the read-only IDT splits, and then the init
  memory is freed. Now one step handles the rest of the page table, as long
  as the pfns are contiguous and the alias handling would be the same. Each
  page still gets its own protection checks. Page tables after boot are
  identical (`ptwalk`). The page-table walk went from 30 profile samples to
  under 5; guest −50 µs (p50, 40 interleaved runs).
- **0028: messages the console hides aren't formatted either.** Under
  `quiet` the kernel still formatted each of ~100 boot messages twice (once
  to size its log record), for a log nothing reads. With
  `printk_drop_suppressed`, which `--quiet` now adds, a message is dropped
  before formatting if the console would suppress it. The level comes from
  the format's prefix; a message whose level could only come from its
  arguments is logged as usual. Without `quiet`, console output is
  identical with and without the option (93 lines). Guest −96 µs (p50, 40
  interleaved runs). The cost: `dmesg` in the guest keeps only warnings
  and worse. Leave out `--quiet` to keep the full log.
- **0029: no call per struct page.** `memmap_init_range` called
  `__init_single_page` for each of the 16,384 pages of a 64 MiB guest. The
  function is a dozen stores, and with the SRSO return thunk the call and
  return cost more than the stores. Inlined into the loop: guest −47 and
  −76 µs (p50, 40 and 60 interleaved runs).
- **0030: no command-line pass per initcall level.** Before each of the
  eight initcall levels, the whole command line was copied and parsed
  against every `kernel_param` to set that level's params. This kernel has
  none: all 23 are level −1 and are set earlier. The pass is skipped for a
  level with no params. `parse_args` fell from 20 to under 5 profile samples
  (40 boots), about 15 µs, below the A/B noise floor (−24 µs p50).
- **0031: boot options matched against `__setup` entries inline.** Each
  option was compared with each of 273 entries twice (early params, then
  `obsolete_checksetup`), through an out-of-line `parameqn()` call per
  entry, or per character. With the return thunk, those calls were most of
  the cost. The characters are now compared inline. `do_early_param` fell
  from 16 to 6 samples; guest −26 µs (p50, 60 interleaved runs). Console
  output is identical, unknown options included.
- **Working sets record what the guest touched (WHP).** `--ws-record` took
  every page resident after the run, which includes the whole kernel image
  the VMM copied in. That is 813 "text" pages, 510 of them the 2 MiB of
  `int3` padding that aligns the PTI entry text. Recording now maps guest
  RAM a page at a time as the guest first touches it. Untouched holes of
  64 KiB or more are left out of the record; smaller ones stay, since each
  extra run costs a map and a prefault call, and a page one boot skips,
  another may touch (~3 µs a fault). Recording only first touches made the
  guest 60 µs slower and setup 40 µs slower. 1,655 → 1,113 pages:
  prefault −193 µs, setup −161 µs, total −69 µs (p50, 60 interleaved runs).
- **Kernel pages the guest never touches aren't copied.** With a working
  set, every 64 KiB chunk of a read-only kernel segment that holds none of
  its pages is mapped from the vmlinux file, copy-on-write, instead of
  copied: 2.7 MiB, mostly the `int3` padding and cold code. Shared by every
  VM through the page cache and never faulted in. The guest can still read
  (or write) them; it costs a slower file-backed fault then. Idle VM
  private working set 7.3 → 5.5 MB (`density.ps1 -N 10`), touched guest
  memory 6.6 → 4.7 MB. Mapping the views adds ~0.1 ms before RAM is
  committed, but the copy shrinks by as much (load −0.7 ms), and the total
  didn't move (−39 µs p50, 60 runs). As with `--map-kernel`, Windows won't
  let the vmlinux be overwritten while VMs that map it run.
- **Zero pages split out of the kernel's segments.** `prepatch.py` splits
  each `PT_LOAD` where 64 KiB or more of zero pages start, so they become
  zero-filled tails the loader never reads: 2.2 of 6.3 MiB (the text/rodata
  gap and `.bss`). The loaded image is identical. Load −437 µs, but the load
  runs alongside partition creation and isn't on the critical path (setup
  −19 µs); it saves CPU per start.
- **0032: a 4k CPA run's protections computed once.** After 0027,
  `static_protections()` still ran per page: four range checks plus, for
  kernel-text addresses, a full `lookup_address()` walk. A run is now the
  PTEs that equal the first one except for a contiguous pfn, and that fall
  in the same static-protection ranges. That makes one check over the run
  exact. The text-RO check depends on the mapping level, but its range is
  aligned to large pages, so it can't differ within a page table. Each new
  PTE is then the first one plus i pages; PROT_NONE is the exception
  because it stores the pfn inverted. Page tables after boot are identical
  (`ptwalk`). CPA profile samples fell from 121 to about 60 per 50 boots.
  Guest −59 µs p50, then −15 µs for the increment (60 interleaved runs
  each).
- **NULL static calls written at build time.** `static_call_init()` turned
  the ~115 call sites of the APIC driver's calls into NOPs at every boot,
  one `text_poke_early()` + IRET each, because they are NULL until the
  driver is installed. `prepatch.py` skipped them: the key had changed by
  the BEFORE snapshot. It now writes what `static_call_init()` computes from
  the compiled key (NOP5 for NULL, else a direct call) at a changed key's
  plain call sites. A wrong guess only costs the write it would have made
  anyway. Build-time sites 76 → 191; guest −20 µs (p50, 60 interleaved
  runs).
- **Not kept: one `sync_core()` per `static_call_update`.** The profile put
  most of the static call cost on the IRET after each patched site. Deferring
  it to one per update (with interrupts still off for each write) bought
  −6 µs, within noise. That's not worth relaxing a serialisation upstream
  keeps. The profiler's exits seem to land on IRETs more often than their
  time would justify.
- **Where the rest of boot goes** (marks and counters in a throwaway
  kernel, p50 of 30 runs):

  | Phase | Time |
  |---|---|
  | `setup_arch` | 200 µs |
  | `mm_core_init` | 95 µs |
  | sched/RCU/IRQ init | 58 µs |
  | `time_init` | 34 µs |
  | `arch_cpu_finalize_init` | 58 µs |
  | `rest_init` → `do_basic_setup` | 140 µs |
  | initcalls | 190 µs |
  | `free_initmem` + `mark_readonly` | 43 µs |
  | exec of `/init` | 40 µs |

  13 kthreads cost 154 µs in all, about 12 µs each:

  | Step | Total |
  |---|---|
  | fork | 51 µs |
  | handoff to kthreadd | 23 µs |
  | handoff to the child | 12 µs |
  | child setup | 7 µs |
  | handoff back to the creator | 61 µs |

  The handoffs are ordinary CFS/PELT bookkeeping, nothing in particular.
  `kswapd_init` (51 µs) is one kthread creation. The threads are:
  - three workqueue rescuers;
  - six kworkers, including each pool's spare idle worker;
  - the pwq release worker;
  - ksoftirqd, oom_reaper, kswapd.

  All of them are needed for memory management or workqueue
  forward-progress guarantees, so none are cut.
- **`/init`'s line in one exit.** Eight `outl` became one `rep outsb`. The
  WHP emulator can't do user-mode string I/O, so the backend does `OUTS`
  itself: it translates RSI at the guest's CPL, reads at most the rest of
  the page, and injects #PF for a page the guest hasn't mapped. `/init`
  reads the string first, so that fault is an ordinary guest fault. Without
  that read, `outsb` on a fresh page cost more than the eight exits it
  replaced. `/init` takes 25 µs instead of 43 µs (p50), and exits fell from
  16 to 8.
- **x2APIC: no gain on WHP.** With `CONFIG_X86_X2APIC` and WHP's x2APIC
  emulation, APIC accesses become MSR exits instead of MMIO exits. The guest
  switched to physical x2APIC, but boot time didn't change (+17 µs, noise).
  Left off.
- **Copy-on-write kernel mapping (`--map-kernel`)** saves memory per VM, but
  is slower on WHP. SLAT faults on file-backed pages cost ~1.4 µs vs ~0.33 µs
  for anonymous memory. Since 0019 the guest writes only ~120 of ~800 text
  pages, so the read-only segment (text, rodata) stays mostly shared. The
  writable segment (data, bss) is written almost entirely, so `--map-kernel`
  now copies it instead of mapping it. Against mapping both: prefault
  −0.6 ms, guest −0.18 ms, +150 KB private. Against plain copying: private
  memory 6.65 → 4.50 MB, but setup is still ~0.8 ms slower (prefault).
  These numbers come from a heavily loaded host; the per-phase deltas were
  consistent, the totals were not.
- **Prefaulting the kernel's pages before copying it in doesn't help**: the
  ~1 ms copy is ReadFile itself, not page faults. Overlapping it with
  partition creation on a second thread does.
- **The CMOS RTC read at boot was 22 of the remaining 53 exits.** Patch 0012
  takes the boot wall clock from `wallclock=SEC.NSEC`, which the VMM appends
  to the command line. Guest time drops ~20 µs; these short port exits cost
  ~1 µs each, not the ~4 µs of a full round trip through the run loop. The
  clock also gets nanosecond resolution instead of whole seconds.
- **Prefaulting the working set on a thread while the guest runs is a wash.**
  Setup gets 390 µs shorter, but the guest gets 320 µs slower, because its
  own SLAT faults contend with the populate call. Total p50 is −39 µs, within
  noise, so the populate stays synchronous.
- Remaining guest time is now flat. To profile, run `--profile`, then
  `tools/profile.py`; add `--inclusive` or `--callers SYM` for approximate
  callers, which come from scanning the guest stack for code addresses:
  - ~25%: boot-time patching (return thunks, retpolines, alternatives),
    mostly cache misses now
  - ~8%: `set_memory_*` page-attribute changes (`mark_rodata_ro`, freeing
    init memory and alignment gaps)
  - ~3%: the SRSO safe-RET return thunk (an AMD mitigation, kept on)
  - ~2.5%: printk formatting (messages are formatted even under `quiet`)

## Reproduce

```bash
guest/kernel/build.sh                      # in WSL or on Linux; writes guest/kernel/out/
VARIANT=smp guest/kernel/build.sh          # the SMP kernel for --cpus 2..8: out/vmlinux-smp
```

```powershell
build\microvm.exe --kernel guest\kernel\out\vmlinux --quiet --ws-record ws.txt
.\tools\bench.ps1 -N 20 -- --kernel guest\kernel\out\vmlinux --quiet --ws ws.txt
```

To pre-patch the kernel's alternatives for this machine's CPU (0026; run on
the host, since the snapshot boots need WHP or KVM):

```powershell
.\tools\prepatch-alternatives.ps1          # in place on guest\kernel\out\vmlinux
```

A container run: the image from tar layers (bottom first), a working set
per image and command, then the run:

```powershell
build\microvm-mkrootfs.exe img.erofs guest\kernel\out\test-layer.tar
build\microvm.exe --kernel guest\kernel\out\vmlinux --quiet --rootfs img.erofs --ws-record ws-img.txt -- /bin/probe
.\tools\ab.ps1 -A "--kernel guest\kernel\out\vmlinux --quiet --ws ws.txt" `
               -B "--kernel guest\kernel\out\vmlinux --quiet --rootfs img.erofs --ws ws-img.txt -- /bin/probe"
```

On a Linux / KVM host (as an unprivileged user in the `kvm` group; `WRAP`
or `MVM_PAR_WRAP` can drop to another one with `setpriv`):

```bash
tools/prepatch-alternatives.sh -o vmlinux-kvm   # pre-patch for this host's CPU view
build/microvm --kernel vmlinux-kvm --quiet --map-kernel --ws-record ws.txt
N=40 tools/bench.sh -c "--kernel vmlinux-kvm --quiet --map-kernel --ws ws.txt" -c "--hello"
build/mvm-parlaunch 128 build/microvm "--kernel vmlinux-kvm --quiet --map-kernel --ws ws.txt"
```

Through the jail, as root (a base namespace and a cgroup per VM; `{i}`
is the VM's index):

```bash
mkdir -p /run/mvm && mount --bind /run/mvm /run/mvm && mount --make-private /run/mvm
build/microvm-jail --make-base /run/mvm/base
echo "+memory +pids +cpu" > /sys/fs/cgroup/mvm/cgroup.subtree_control   # after mkdir /sys/fs/cgroup/mvm
MVM_PAR_WRAP="build/microvm-jail --uid 3000{i} --gid 3000{i} --base /run/mvm/base \
  --cgroup /sys/fs/cgroup/mvm/vm-{i} --mem-max 134217728 --pids-max 16 \
  --bind $PWD/vmlinux-kvm:/vmlinux --bind $PWD/ws.txt:/ws.txt --" \
  build/mvm-parlaunch 64 build/microvm "--kernel /vmlinux --quiet --map-kernel --ws /ws.txt"
```

vsock: boot cost with and without the device (the wrapper removes the
socket each run), then latency and throughput against the guest's echo:

```bash
printf '#!/bin/sh\nrm -f /tmp/mvb/v.sock\nexec "$@"\n' > wrap.sh && chmod +x wrap.sh && mkdir -p /tmp/mvb
N=60 EXE=build/microvm WRAP=./wrap.sh tools/bench.sh \
  -c "--kernel vmlinux-kvm --quiet --map-kernel --rootfs img.erofs -- /bin/probe" \
  -c "--kernel vmlinux-kvm --quiet --map-kernel --rootfs img.erofs --vsock /tmp/mvb/v.sock -- /bin/probe"
build/mvm_vsock_tests build/microvm vmlinux-kvm img.erofs --bench
```

virtio-net: boot cost with and without the device, idle memory per VM,
then latency and throughput against `net-probe` (the test's servers listen
on 127.0.0.1, so the guest needs `--net-allow 127.0.0.1/32`, which
`mvm_net_tests` passes itself):

```bash
N=60 EXE=build/microvm tools/bench.sh \
  -c "--kernel vmlinux-kvm --quiet --map-kernel --rootfs img.erofs -- /bin/probe" \
  -c "--kernel vmlinux-kvm --quiet --map-kernel --rootfs img.erofs --net -- /bin/probe"
build/mvm_net_tests build/microvm vmlinux-kvm img.erofs --bench
```

Snapshots: take one at `/init`'s snapshot point, record a restore's
working set, then compare with cold boots:

```bash
mkdir -p /tmp/mvb
K="--kernel vmlinux-kvm --quiet --map-kernel --rootfs img.erofs"
build/microvm $K --ws-record /tmp/mvb/ws-cold.txt -- /bin/probe
build/microvm $K --append snapshot --snapshot /tmp/mvb/snap -- /bin/probe
build/microvm --restore /tmp/mvb/snap --rootfs img.erofs --ws-record /tmp/mvb/ws-rest.txt
N=60 EXE=build/microvm tools/bench.sh -c "$K -- /bin/probe" -c "$K --ws /tmp/mvb/ws-cold.txt -- /bin/probe" \
  -c "--restore /tmp/mvb/snap --rootfs img.erofs" -c "--restore /tmp/mvb/snap --rootfs img.erofs --ws /tmp/mvb/ws-rest.txt"
```

Record working sets with `--map-kernel` on KVM: KVM can't trace first
touches, so the record is the guest memory that is resident afterwards.
A file-backed kernel page is resident only if the guest touched it; a
copied one always is.

Re-record `ws.txt` after every kernel change. A stale working set still
works, since pages it misses just fault in, but it costs: one recorded
twelve patches earlier made the guest ~80 µs slower and prefaulted 44 KB
it no longer touched.
