# microvm

microvm is a minimal virtual machine monitor (VMM) written in C23, for Linux
(KVM) and Windows (Windows Hypervisor Platform, WHP) hosts. It boots a small
x86-64 Linux guest in a few milliseconds, treats everything inside the guest
as hostile, and comes with the host-side tools around it:

- **Fast cold starts.** On Linux/KVM, boot to the guest's `/init` takes 3.2 ms
  (p50 of 40 interleaved runs, VMM included), and a container run takes 3.5 ms.
  On a Windows 11 dev box with WHP, a boot takes 2.9 ms from `main()` to the
  guest's exit status. Numbers and method: [BENCH.md](BENCH.md).
- **Hostile-guest security model.** The guest, its kernel included, is
  untrusted. The VMM sandboxes itself before the first guest instruction runs,
  and `microvm-jail` gives each VM its own host isolation. See [SECURITY.md](SECURITY.md).
- **OCI images into EROFS.** `microvm-mkrootfs` turns a container image (an OCI
  layout, a `docker save` archive, or bare layers) into a read-only EROFS root
  filesystem. The guest's writes go to a tmpfs over it, so the image is never
  changed. See [IMAGES.md](IMAGES.md).
- **E2B-compatible agent sandboxes.** `microvm-sbxd` serves E2B's REST and
  Connect APIs over HTTP/1.1, so the unmodified `e2b` SDKs can create and drive
  sandboxes. A paused sandbox restores and answers in 2.3–2.5 ms on KVM.
  See [SANDBOX.md](SANDBOX.md).
- **Snapshots, vsock and net.** A VM can be saved and restored (`--snapshot`,
  `--restore`). A virtio-vsock device (`--vsock`) connects host and guest over
  Unix sockets. A virtio-net device (`--net`) gives the guest TCP and UDP through
  host sockets, under an egress policy.

## Binaries

| Binary | Built on | What it is |
|---|---|---|
| `microvm` | Linux, Windows | The VMM. Boots a kernel, with an image (`--rootfs`) and a command, or the built-in smoke-test guest (`--hello`). |
| `microvm-mkrootfs` | Linux, Windows | Container image or layers to an EROFS root filesystem. |
| `microvm-sbxd` | Linux | The host daemon for E2B-compatible agent sandboxes. |
| `microvm-jail` | Linux | Runs one VMM isolated from the host: namespaces, a new root, a cgroup and a per-VM uid. |
| `microvm-invoke` | Linux | Calls a function in a VM running the guest agent (`src/agent/proto.h`). |

The build also makes `mvm-mkoci` (builds test OCI layouts from layer tarballs)
and `mvm-parlaunch` (N cold starts in parallel, for benchmarks). Both build on
Linux and Windows.

The full option list of `microvm` is the `usage()` function in
[src/main.c](src/main.c).

## Requirements

- CMake 3.25 or later, and a C compiler that supports C23.
- **Linux:** `/dev/kvm` must be readable and writable by the user running the
  VMM. On Linux the VMM needs no other access to the host ([SECURITY.md](SECURITY.md)).
- **Windows:** the Windows Hypervisor Platform feature must be enabled. The
  Windows link options are GNU ld style (`-static`, `-Wl,--dynamicbase,...`),
  so build with a GCC-based toolchain such as MinGW-w64. The repository does not
  pin a toolchain, and the CMake file has no MSVC settings.
- To build the guest kernel: `gcc`, `python3`, and network access to
  `cdn.kernel.org` (the kernel source is downloaded and checked). No KVM is
  needed to build it, and it builds on Linux or in WSL.

## Building

```sh
cmake -S . -B build
cmake --build build
```

The binaries are in `build/` (`build\microvm.exe` on Windows). Warnings are
errors by default; pass `-DMICROVM_WERROR=OFF` to turn that off. Pass
`-DMICROVM_SANITIZE=ON` for an AddressSanitizer and UBSan build (for tests and
debugging only).

## Testing

```sh
ctest --test-dir build
```

Which tests run depends on what the host has:

- **Need neither a hypervisor nor a guest kernel:** `unit`, `sandbox`, `image`,
  `agent_proto`, `oci`, `zstd`, `net_policy`, the `oci_*` converter tests, the
  `env_*` option checks, and the `fuzz_*` smoke runs (30,000 mutations each).
- **Need a hypervisor** (`/dev/kvm` or WHP): `hello`. Without one, the VMM exits
  with status 77 (`MVM_EXIT_NO_HV`) and ctest reports the test as skipped.
- **Linux jail tests:** `jail` runs `microvm-jail` and needs the namespaces it
  creates. `agent_jail`, `net_jail` and `sbx_jail` (added with the guest kernel,
  below) also need a hypervisor. They skip (status 77) when the host lacks either.
- **Need a guest kernel:** the boot, rootfs, vsock, agent, sbx and net tests are
  only added when `guest/kernel/out/vmlinux` exists at configure time
  ([CMakeLists.txt](CMakeLists.txt), around line 263). Build the kernel first,
  then run `cmake -S . -B build` again. The container tests also need
  `guest/kernel/out/test-layer.tar`, which the kernel build makes too. The
  `sbx_smp` test needs `vmlinux-smp` (below). A kernel-based test that finds no
  hypervisor exits 77 and is skipped.

## Building the guest kernel

```sh
guest/kernel/build.sh             # -> guest/kernel/out/vmlinux (and config, System.map, test-layer.tar)
VARIANT=smp guest/kernel/build.sh # -> guest/kernel/out/vmlinux-smp, for --cpus 2 to 8
```

The script builds `/init` (`guest/init/`), downloads the pinned Linux source,
applies the patches in `guest/kernel/patches/`, and builds with
`guest/kernel/config.fragment`. `VARIANT=smp` adds
`guest/kernel/config-smp.fragment` in its own source tree. The environment
variables are `KVER` (default 6.18.60), `KSHA256` (to pin the source's checksum),
`WORK` (default `~/.cache/microvm-kernel`) and `JOBS`.

## Quick start

**Boot the kernel.** With no image and no command, `/init` runs and prints a
line on the console.

```sh
guest/kernel/build.sh
build/microvm --kernel guest/kernel/out/vmlinux --quiet
```

**Build a root filesystem from a Docker image, and run it.** The image's
Entrypoint and Cmd run unless you give a command after `--`.

```sh
docker save myapp:latest -o myapp.tar
build/microvm-mkrootfs --docker-archive myapp.tar myapp.erofs
build/microvm --kernel guest/kernel/out/vmlinux --quiet --rootfs myapp.erofs
build/microvm --kernel guest/kernel/out/vmlinux --quiet --rootfs myapp.erofs -e NAME=value -- ARG...
```

Without Docker, the kernel build's test layer is a root filesystem too
(`guest/kernel/out/test-layer.tar`, from the same build):

```sh
build/microvm-mkrootfs test-rootfs.erofs guest/kernel/out/test-layer.tar
build/microvm --kernel guest/kernel/out/vmlinux --quiet --rootfs test-rootfs.erofs -- p "a b" c
```

**Start an agent sandbox.** `microvm-sbxd` runs the sandboxes, and the E2B
SDKs talk to it.

```sh
build/microvm-sbxd --vmm build/microvm --kernel guest/kernel/out/vmlinux \
  --dir /var/lib/sbxd --template base=myapp.erofs,mem=512 \
  --api-key-file /etc/sbxd.key --domain sbx.example.com --listen 127.0.0.1:3000

E2B_API_URL=http://127.0.0.1:3000 E2B_SANDBOX_URL=http://127.0.0.1:3000 \
E2B_API_KEY=$(cat /etc/sbxd.key) E2B_DOMAIN=sbx.example.com python agent.py
```

`--dir` is the daemon's state directory (sandboxes and images). Each
`--template NAME=IMAGE[,mem=MIB]` is an image that new sandboxes can start
from. SANDBOX.md has the full command, with SMP templates, networking and
limits.

## Documentation

| Document | Covers |
|---|---|
| [SANDBOX.md](SANDBOX.md) | Agent sandboxes: `microvm-sbxd`, the E2B API, the guest protocol, pause and resume. |
| [IMAGES.md](IMAGES.md) | Container images: `microvm-mkrootfs`'s inputs and options, and how the image config is applied. |
| [SECURITY.md](SECURITY.md) | The threat model, the VMM's sandbox, `microvm-jail`, networking, and guest-controlled input. |
| [BENCH.md](BENCH.md) | Cold-start benchmarks on KVM and WHP, and how to reproduce them. |
| [guest/kernel/patches/README.md](guest/kernel/patches/README.md) | The guest kernel patches. |

## Repository layout

- `src/`: the VMM. `main.c` is the command line; `vm.c` is the VM; `hv_kvm.c`
  (Linux) and `hv_whp.c` (Windows) are the hypervisor backends; `sandbox_linux.c`
  and `sandbox_win.c` are the VMM sandboxes. `dev/` holds the devices (virtio
  vsock, net and balloon, plus the serial port and interrupt controller), `boot/`
  the kernel loading, and `snapshot.c` the snapshots. `image/` is the image
  converter (`mkrootfs.c` is its command line). `agent/` and `sbx/` are the host
  sides of the guest protocols. `sbxd/` is `microvm-sbxd`, and `jail.c` is
  `microvm-jail`.
- `guest/`: what runs inside the VM. `init/` is `/init`: PID 1, the function
  agent, the container setup and the sandbox agent. `kernel/` has the build
  script, the config fragments and the patches. `rootfs-test/` has the probe
  programs the tests run.
- `runtimes/`: language runtimes for the guest agent's function invocations.
  `python/` and `js/` hold the runtime modules, and `examples/` has sample
  functions.
- `tests/`: the ctest suites (`test_*.c`, plus helper `.cmake` and `.py` files).
  `tests/sdk/` has checks that use the real E2B SDKs; they are not part of
  ctest.
- `tests/fuzz/`: the fuzz harnesses (see SECURITY.md, "Fuzzing"). `driver.c`
  is the standalone mutation driver.
- `tools/`: `mkoci.c` (test OCI layouts), `invoke.c` (`microvm-invoke`),
  `parlaunch*.c` (parallel starts), the benchmark scripts (`bench.sh`,
  `bench.ps1`, `ab.ps1`), and the kernel prepatch tools.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, follow
[SECURITY.md](SECURITY.md).

## License

microvm is licensed under the MIT License; see [LICENSE](LICENSE). The guest
kernel patches in `guest/kernel/patches/` are GPL-2.0-only, as the kernel they
patch is; see [guest/kernel/patches/README.md](guest/kernel/patches/README.md).
