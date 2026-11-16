// SPDX-License-Identifier: MIT
// Process sandbox, entered once setup is done and before the guest runs.
//
// Threat model: everything inside the guest is hostile, and the device
// emulation in this process is the attack surface. If a guest manages to
// take over the VMM, the sandbox decides what it can reach: ideally nothing
// but the already-open hypervisor handles, stdout/stderr and its own memory.
//
// Linux: no_new_privs, non-dumpable, rlimits (no new fds, no core dumps,
//        no locked memory, capped address space), a Landlock ruleset that
//        denies all filesystem and network access, and a seccomp-BPF
//        allowlist that kills the process on any other syscall (fork and
//        clone included). ioctl() is only allowed on given fds with given
//        requests (KVM_RUN on the vCPU, ...). mmap/mprotect may never
//        create executable memory.
// Windows: a job object (no child processes, memory cap, kill on close, no
//        UI), process mitigation policies (no dynamic code, Microsoft-signed
//        DLLs only, no win32k, strict handle checks, no extension points), all
//        privileges removed and the token lowered to Low integrity.
//
// Everything is unprivileged: no root, no admin, no setuid helper.
#pragma once

#include "common.h"

typedef struct {
    int fd;
    unsigned long request;
} sandbox_ioctl;

typedef struct {
    const sandbox_ioctl *ioctls; // Linux: the only ioctls still allowed
    size_t nioctls;
    uint64_t mem_headroom;       // bytes of memory the process may still allocate; 0 = no cap
    // Linux: a device I/O thread runs too. It may poll, readv/writev and
    // shutdown its sockets, and accept4() on accept_fd only (if >= 0);
    // up to `nofile` fds may be open (instead of no new ones).
    bool device_io;
    int accept_fd;
    int recvmsg_fd; // > 0: recvmsg() on this fd only (the network helper's channel)
    unsigned nofile;
    // Called once Landlock and the rlimits are on but before seccomp, which
    // refuses new threads: start them here so they inherit every layer.
    void (*start_threads)(void *ctx);
    void *ctx;
    // Test hooks: apply only some layers.
    bool no_seccomp, no_landlock, no_rlimits;
} sandbox_cfg;

// Enter the sandbox. Irreversible. Layers the host can't provide at all
// (e.g. a kernel built without Landlock) are skipped and reported; failing
// to apply a layer that exists is an error, so callers must not run the
// guest when this fails. `report` (may be null) receives a one-line summary.
[[nodiscard]] int sandbox_enter(const sandbox_cfg *cfg, char *report, size_t report_len);

// Linux: the network helper process's sandbox (net_helper.h). Everything
// sandbox_enter() applies, but its own seccomp allowlist: requests in on
// `chan` (recvfrom), sockets out (sendmsg), route lookups on the netlink
// socket `nl` (sendto, recvfrom), and socket(AF_INET or AF_INET6, stream or
// datagram), connect() and close(). Landlock denies all files and TCP
// bind(). Only fds up to max(chan, nl) + 1 may be open.
[[nodiscard]] int sandbox_enter_net_helper(int chan, int nl, char *report, size_t report_len);
