<!-- SPDX-License-Identifier: MIT -->
# Contributing

Thanks for looking at microvm. This file covers how to build, test and
submit a change. For the threat model and how to report a vulnerability, see
[SECURITY.md](SECURITY.md).

## Requirements

- **CMake 3.25 or newer.**
- **A C23 compiler.** The code uses C23 features (`constexpr`, `nullptr`,
  `<stdckdint.h>`), so GCC 12 is too old. Use a current GCC or Clang.
- **Linux with `/dev/kvm`, or Windows with the Windows Hypervisor Platform
  (WHP).** The VMM needs one of them to run a guest. Without one, the
  tests that boot a VM skip (exit status 77) and the rest still run.

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Two options in `CMakeLists.txt` change the build:

| Option | Default | Meaning |
|---|---|---|
| `MICROVM_WERROR` | `ON` | Build with `-Werror`. Turn it off only to see warnings from a newer compiler. |
| `MICROVM_SANITIZE` | `OFF` | AddressSanitizer and UBSan. For tests and debugging only: the release VMM is not built this way. |

An ASan and UBSan build, as used for fuzzing campaigns:

```bash
cmake -B build-asan -DMICROVM_SANITIZE=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build-asan
```

Build directories named `build*/` are ignored by git.

### Guest kernel (for the VM tests)

Most VM tests need a guest kernel. Build it with:

```bash
guest/kernel/build.sh                  # -> guest/kernel/out/vmlinux
VARIANT=smp guest/kernel/build.sh      # -> guest/kernel/out/vmlinux-smp (for --cpus N)
```

The script downloads the Linux source on first run and pins it by checksum
(`KSHA256`). It also writes `guest/kernel/out/test-layer.tar`, which the
image tests use. CMake adds each VM test only when its kernel exists, so the
tests run only after the build. Re-run CMake after building the kernel.

## Test

```bash
ctest --test-dir build --output-on-failure
```

The suites, as `CMakeLists.txt` defines them:

- **Always built:** `unit` (`mvm_tests`), `sandbox` (the sandbox probes),
  `image`, `agent_proto`, `oci`, `zstd`, the `oci_*` CLI checks, and the
  `fuzz_*` smoke passes described below.
- **Linux, no guest needed:** `jail` (`microvm-jail`), `net_policy`.
- **Windows, no guest needed:** `net_policy`.
- **Needs a hypervisor:** `hello` (a built-in smoke-test guest) and the
  `env_*` checks. Without KVM or WHP, `hello` exits 77 and is reported as skipped.
- **With `guest/kernel/out/vmlinux`:** `boot` and `prepatch`.
- **With `vmlinux` and `guest/kernel/out/test-layer.tar`:** the `rootfs_*` and
  `image_*` tests; on Linux `vsock`, `agent`, `sbx`, `net` and their `*_jail`
  variants; on Windows `vsock`, `net` and `net_resolv_conf`.
- **With `guest/kernel/out/vmlinux-smp` as well:** `sbx_smp` (4 vCPUs).

CMake decides which of these exist when it configures, so after you build the
kernel, run `cmake -B build` again before `ctest`.

Run one suite with `-R`, for example `ctest --test-dir build -R sandbox --output-on-failure`.

The sandbox suite is the one to run after any change near `src/sandbox*.c`:
each probe must show that a forbidden action is blocked, and that a control
run without the sandbox succeeds.

### Fuzz targets

Each parser or device that reads untrusted input has a harness in
`tests/fuzz/`, named `fuzz_<name>.c`. The targets built by CMake are:

| Target | Covers |
|---|---|
| `fuzz_elf`, `fuzz_devices`, `fuzz_virtq`, `fuzz_snapshot`, `fuzz_balloon` | ELF loader, device model, virtqueues, snapshot restore, balloon |
| `fuzz_vsock`, `fuzz_net` | virtio-vsock and virtio-net (Linux only) |
| `fuzz_tar`, `fuzz_erofs`, `fuzz_inflate`, `fuzz_zstd`, `fuzz_json`, `fuzz_oci` | image builder and readers |
| `fuzz_agent`, `fuzz_sbx` | guest-agent and sandbox frame readers |
| `fuzz_http` | `microvm-sbxd` HTTP code (non-Windows) |

Each target is linked by `CMakeLists.txt` with `tests/fuzz/driver.c`, a
standalone mutation driver. GCC has no libFuzzer, so the driver supplies the
mutations and the harnesses supply the checks. Each harness defines
`LLVMFuzzerTestOneInput()` and `fuzz_seeds()`.

`ctest` runs every target once as a smoke test (`-runs=30000 -seed=1`;
`fuzz_oci` uses `-runs=10000 -seed=1 -max_len=16384`). To run a target
yourself, build it and call it with one of these forms:

```bash
cmake --build build --target fuzz_elf

# Replay saved inputs, or reproduce a crash, one file per argument:
build/fuzz_elf path/to/input.bin

# Mutate the built-in seeds. Runs are deterministic for a given -seed:
build/fuzz_elf -runs=10000000 -seed=$RANDOM
```

`-max_len=L` caps the size of each input. When a run crashes or a sanitizer
aborts, the failing input is in `fuzz-crash.bin` in the current directory if
you set `MVM_FUZZ_SAVE=1`. For a real campaign, build with
`-DMICROVM_SANITIZE=ON`, so that bugs the harness does not check directly
still abort. The harnesses check invariants, not only crashes (see the
comment at the top of each file).

With Clang you can build a harness for libFuzzer instead: define
`MVM_LIBFUZZER` to leave out `driver.c`. The AFL++ build uses the driver's
file mode, which takes the input files as arguments. See the comment at the
top of `tests/fuzz/driver.c`.

When you add a parser for untrusted input, add a harness for it in
`tests/fuzz/`, register it in `CMakeLists.txt` with a smoke test, and check
invariants that the parser must keep, such as "the output reads back the same"
or "the verdict does not depend on how the input was split".

## Code style

The style follows the code already in the tree. Match the file you are
editing.

- **Language:** C23, without GNU extensions (`CMAKE_C_EXTENSIONS OFF`).
  The POSIX build defines `_GNU_SOURCE` for the system headers.
- **Warnings:** `-Wall -Wextra -Wshadow -Wstrict-prototypes -Wvla -Wformat=2
  -Wimplicit-fallthrough`, with `-Werror` by default. A change must compile
  with no warnings.
- **Hardening flags**, applied to the VMM and its libraries:
  `-fstack-protector-strong -fcf-protection=full -ftrivial-auto-var-init=zero
  -fno-strict-aliasing`, `-fPIE` with `-D_FORTIFY_SOURCE=3` outside Debug, and
  `-static-pie` with `-z relro -z now -z noexecstack` on Linux. On Windows:
  `-static` with `DYNAMICBASE`, `NXCOMPAT` and `HIGH_ENTROPY_VA`.
  Do not remove or weaken these to make a change compile.
- **Layout:** four-space indentation. A function's opening brace goes on its
  own line; the braces of `if`, `for` and `switch` go on the line of the
  statement. Comments are `//`, and they explain why. Each source file starts
  with a comment that says what the file does.
- **No third-party C libraries.** Inflate, zstd, SHA-256 and JSON are
  implemented in the tree, and the VMM uses only the platform's own APIs.
  Keep it that way.

### Untrusted input

Some code reads bytes from parties the VMM does not trust. The guest is
hostile, its kernel included. So are the peers of the network device, the
clients of `microvm-sbxd`, and the layers of a container image. The rules
below come from the "Guest-controlled input" section of
[SECURITY.md](SECURITY.md):

- Reach guest memory only through the checked accessors (`guest_slice()` in
  `src/mem.h`). Do not turn a guest address into a pointer any other way.
- Check every offset, length and count before you use it. Do the arithmetic
  with the checked forms (`ckd_add`, `ckd_mul`, `ckd_sub`), and reject a value
  that wraps. Check a length against the bytes that are really there, not
  against the size the sender claims.
- Cap every buffer and every loop. An input may not make the VMM allocate
  without bound.
- A parser rejects what it does not understand. It must not guess, skip
  ahead, or repair the input.
- Parsers for untrusted input get a fuzz harness (see above).

## Licensing

- Every new file starts with an SPDX header, `SPDX-License-Identifier: MIT`,
  in the file's comment syntax. For C:

  ```c
  // SPDX-License-Identifier: MIT
  // What this file does, in a sentence or two.
  ```

  Shell, Python and CMake files use `#`. Markdown uses an HTML comment on the
  first line, as this file does. A YAML front matter block (the issue
  templates) takes a `#` comment inside the block, so GitHub still reads it.
- The guest kernel patches in `guest/kernel/patches/` modify Linux and are
  **GPL-2.0-only**. Their licence is the kernel's, not MIT, so they do not
  carry the MIT header.
- The rest of the project is MIT.
- Contributions are under the project's licence: by submitting a change you
  agree that it may be distributed under the same licence (inbound equals
  outbound). There is no CLA to sign.

## Commits

Each commit message starts with the subsystem it changes, a colon, and a short
description in lower case. Recent examples from `git log --oneline`:

```
net: --net-only (the --net-allow ranges and nothing else, the resolver included)
vsock: Windows hosts (AF_UNIX over Winsock, a loopback pair to wake the I/O thread)
sbxd: team pools (--cgroup: a team's vCPUs and memory, enforced by the kernel), GET /pools
```

Reuse the subsystem names the log already uses (`net`, `vsock`, `sbxd`, `WHP`,
`sandbox`, `jail`, `tests`). Put the reason for the change in the body, and keep
one logical change per commit.

## Pull requests

Open a pull request against the repository's default branch. The template asks
you to confirm that:

- the tests pass (`ctest`, in the configuration your change affects), and
- every new file has its SPDX header.

Say what changed and why in the description. If the change touches the
sandbox, the untrusted-input parsers, or the threat model, say so, and update
[SECURITY.md](SECURITY.md) in the same pull request.

## Reporting security issues

Do not report a vulnerability in a public issue or pull request. Use GitHub's
private vulnerability reporting instead: see
[Reporting a vulnerability](SECURITY.md#reporting-a-vulnerability).
