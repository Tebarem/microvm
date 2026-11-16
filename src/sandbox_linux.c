// SPDX-License-Identifier: MIT
#include "sandbox.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifdef __SANITIZE_ADDRESS__
#  include <sanitizer/lsan_interface.h>
#endif

// ---- Landlock ---------------------------------------------------------------
// A ruleset that handles every access right the running kernel knows about
// and has no rules denies all of them.
#ifndef LANDLOCK_CREATE_RULESET_VERSION
#  define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

// connect_tcp: leave TCP connect() unrestricted (the network helper).
static int landlock_deny_all(int *abi_out, bool connect_tcp)
{
    const long abi = syscall(SYS_landlock_create_ruleset, nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
    *abi_out = (int)abi;
    if (abi < 0)
        return errno == ENOSYS || errno == EOPNOTSUPP ? 1 : -1; // 1: not available
    // Filesystem rights by ABI version (see landlock.h); later bits are only
    // accepted by kernels that know them.
    uint64_t fs = (1ull << 13) - 1; // ABI 1: EXECUTE .. MAKE_SYM
    if (abi >= 2)
        fs |= 1ull << 13; // REFER
    if (abi >= 3)
        fs |= 1ull << 14; // TRUNCATE
    if (abi >= 5)
        fs |= 1ull << 15; // IOCTL_DEV
    struct {
        uint64_t handled_access_fs, handled_access_net, scoped;
    } attr = {.handled_access_fs = fs};
    size_t attr_size = sizeof attr.handled_access_fs;
    if (abi >= 4) {
        attr.handled_access_net = connect_tcp ? 1 : 3; // BIND_TCP | CONNECT_TCP
        attr_size = 2 * sizeof(uint64_t);
    }
    if (abi >= 6) {
        attr.scoped = 3; // ABSTRACT_UNIX_SOCKET | SIGNAL
        attr_size = sizeof attr;
    }
    const int fd = (int)syscall(SYS_landlock_create_ruleset, &attr, attr_size, 0);
    if (fd < 0)
        return -1;
    const long rc = syscall(SYS_landlock_restrict_self, fd, 0);
    close(fd);
    return rc == 0 ? 0 : -1;
}

// ---- seccomp-BPF ------------------------------------------------------------
constexpr size_t MAX_INSNS = 512;
constexpr size_t MAX_IOCTLS = 256;

typedef struct {
    struct sock_filter f[MAX_INSNS];
    size_t n;
    bool overflow;
} bpf_prog;

static void emit(bpf_prog *p, uint16_t code, uint32_t k, uint8_t jt, uint8_t jf)
{
    if (p->n == MAX_INSNS) {
        p->overflow = true;
        return;
    }
    p->f[p->n++] = (struct sock_filter){code, jt, jf, k};
}

#define LD_NR() emit(p, BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr), 0, 0)
#define LD_ARG_LO(i) emit(p, BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args) + 8 * (i), 0, 0)
#define LD_ARG_HI(i) emit(p, BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args) + 8 * (i) + 4, 0, 0)
#define RET(v) emit(p, BPF_RET | BPF_K, (v), 0, 0)
#define JEQ(k, t, f) emit(p, BPF_JMP | BPF_JEQ | BPF_K, (k), (t), (f))

constexpr uint32_t ALLOW = SECCOMP_RET_ALLOW;
constexpr uint32_t KILL = SECCOMP_RET_KILL_PROCESS;

// Syscalls the run loop and exit path need, with no argument worth checking:
// they only act on already-open fds or on our own memory/threads.
static const int PLAIN[] = {
    SYS_read, SYS_write, SYS_pread64, SYS_pwrite64, SYS_lseek, SYS_fstat, SYS_close,
    SYS_futex, SYS_sched_yield, SYS_nanosleep, SYS_clock_nanosleep, SYS_clock_gettime,
    SYS_gettid, SYS_getpid, SYS_rt_sigreturn, SYS_rt_sigprocmask, SYS_restart_syscall,
    SYS_brk, SYS_munmap, SYS_mremap, SYS_madvise, SYS_getrandom,
    SYS_sigaltstack, SYS_exit, SYS_exit_group,
};

static int build_filter(const sandbox_cfg *cfg, bpf_prog *p)
{
    // Only native x86-64 syscalls: wrong arch or the x32 ABI is fatal.
    emit(p, BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch), 0, 0);
    JEQ(AUDIT_ARCH_X86_64, 1, 0);
    RET(KILL);
    LD_NR();
    emit(p, BPF_JMP | BPF_JGE | BPF_K, 0x40000000u /* __X32_SYSCALL_BIT */, 0, 1);
    RET(KILL);

    for (size_t i = 0; i < sizeof PLAIN / sizeof PLAIN[0]; i++) {
        JEQ((uint32_t)PLAIN[i], 0, 1);
        RET(ALLOW);
    }

    // ioctl(fd, request): only listed pairs. The kernel takes both as
    // unsigned int, so the low 32 bits are all that matter. Grouped by
    // request, each with the fds it is allowed on: every vCPU's fd allows
    // the same requests. A group is
    //   JEQ request (else to the next group), load fd, JEQ each fd (to
    //   ALLOW), KILL, ALLOW
    // and a request no group has is killed after the last one.
    if (cfg->nioctls > MAX_IOCTLS)
        return -1;
    static uint32_t req[MAX_IOCTLS], fds[MAX_IOCTLS][MAX_IOCTLS];
    static size_t nfd[MAX_IOCTLS];
    size_t nreq = 0;
    for (size_t i = 0; i < cfg->nioctls; i++) {
        const uint32_t r = (uint32_t)cfg->ioctls[i].request, fd = (uint32_t)cfg->ioctls[i].fd;
        size_t k = 0;
        while (k < nreq && req[k] != r)
            k++;
        if (k == nreq)
            req[nreq] = r, nfd[nreq++] = 0;
        size_t j = 0;
        while (j < nfd[k] && fds[k][j] != fd)
            j++;
        if (j == nfd[k])
            fds[k][nfd[k]++] = fd;
    }
    size_t block = 2; // load request ... final KILL
    for (size_t k = 0; k < nreq; k++)
        block += nfd[k] + 4;
    if (block > 255) // a jump offset is 8 bits
        return -1;
    JEQ(SYS_ioctl, 0, (uint8_t)block);
    LD_ARG_LO(1);
    for (size_t k = 0; k < nreq; k++) {
        const size_t m = nfd[k];
        JEQ(req[k], 0, (uint8_t)(m + 3));
        LD_ARG_LO(0);
        for (size_t j = 0; j < m; j++)
            JEQ(fds[k][j], (uint8_t)(m - j), 0);
        RET(KILL);
        RET(ALLOW);
    }
    RET(KILL);

    // mmap/mprotect: never executable. (READ_IMPLIES_EXEC is cleared before
    // the filter goes in, so PROT_READ can't smuggle PROT_EXEC in.)
    static const int PROT_CALLS[] = {SYS_mmap, SYS_mprotect};
    for (size_t i = 0; i < 2; i++) {
        JEQ((uint32_t)PROT_CALLS[i], 0, 4);
        LD_ARG_LO(2);
        emit(p, BPF_JMP | BPF_JSET | BPF_K, PROT_EXEC, 1, 0);
        RET(ALLOW);
        RET(KILL);
    }

    // The device I/O thread: waiting on and moving bytes through sockets it
    // already has, and accepting connections on one listening socket.
    if (cfg->device_io) {
        static const int IO[] = {SYS_poll, SYS_ppoll, SYS_readv, SYS_writev, SYS_shutdown};
        for (size_t i = 0; i < sizeof IO / sizeof IO[0]; i++) {
            JEQ((uint32_t)IO[i], 0, 1);
            RET(ALLOW);
        }
        if (cfg->accept_fd >= 0) {
            JEQ(SYS_accept4, 0, 4);
            LD_ARG_LO(0);
            JEQ((uint32_t)cfg->accept_fd, 0, 1);
            RET(ALLOW);
            RET(KILL);
        }
        // recvmsg() on the network helper's channel: its answers carry
        // the sockets it opened (SCM_RIGHTS).
        if (cfg->recvmsg_fd > 0) {
            JEQ(SYS_recvmsg, 0, 4);
            LD_ARG_LO(0);
            JEQ((uint32_t)cfg->recvmsg_fd, 0, 1);
            RET(ALLOW);
            RET(KILL);
        }
        LD_NR();
    }

    // tgkill(tgid, tid, SIGUSR1): a vCPU kick (a stop, a snapshot parking
    // the other vCPUs, the profiler), nothing else. Landlock's signal
    // scoping keeps it inside this process.
    JEQ(SYS_tgkill, 0, 4);
    LD_ARG_LO(2);
    JEQ(SIGUSR1, 0, 1);
    RET(ALLOW);
    RET(KILL);

    RET(KILL);
    return p->overflow ? -1 : 0;
}

static int install_filter(const sandbox_cfg *cfg)
{
    static bpf_prog p;
    p.n = 0;
    p.overflow = false;
    if (build_filter(cfg, &p))
        return -1;
    const struct sock_fprog prog = {.len = (unsigned short)p.n, .filter = p.f};
    // TSYNC: every thread (e.g. the profiler's sampler) gets the filter.
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog);
}

// ---- entry ------------------------------------------------------------------
static int set_limit(int res, rlim_t v)
{
    const struct rlimit r = {v, v};
    return setrlimit(res, &r);
}

// The process's personality. A seccomp filter that locks it (systemd's
// LockPersonality=) refuses even the query, so then /proc says; read it
// while the process is still dumpable, or /proc/self is root's.
static int current_personality(void)
{
    const int p = personality(0xffffffff);
    if (p >= 0 || errno != EPERM)
        return p;
    unsigned v = 0;
    FILE *f = fopen("/proc/self/personality", "re");
    const bool ok = f && fscanf(f, "%x", &v) == 1;
    if (f)
        fclose(f);
    return ok ? (int)v : -1;
}

// ASan builds only. LeakSanitizer's end-of-process check can't run in the
// sandbox: it stops the world with prctl(PR_SET_DUMPABLE), a ptrace()ing
// clone and /proc/self/task, which seccomp, Landlock and RLIMIT_NOFILE all
// refuse, so a sandboxed process was killed in exit(). Check now instead,
// while it still can; this also turns the exit check off. Leaks made after
// this point go unreported (run with --no-sandbox to see those).
static void leak_check_before_sandbox(void)
{
#ifdef __SANITIZE_ADDRESS__
    __lsan_do_leak_check();
#endif
}

int sandbox_enter(const sandbox_cfg *cfg, char *report, size_t report_len)
{
    leak_check_before_sandbox();
    char landlock[32] = "off";
    const int pers = current_personality();
    if (pers < 0 || ((pers & READ_IMPLIES_EXEC) && personality((unsigned long)pers & ~READ_IMPLIES_EXEC) < 0))
        return -1;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0))
        return -1;

    if (cfg->mem_headroom) {
        // Address space in use now (all of guest RAM is already reserved)
        // plus headroom. Read before RLIMIT_NOFILE goes to 0.
        unsigned long long pages = 0;
        FILE *f = fopen("/proc/self/statm", "re");
        if (!f || fscanf(f, "%llu", &pages) != 1) {
            if (f)
                fclose(f);
            return -1;
        }
        fclose(f);
        if (set_limit(RLIMIT_AS, (rlim_t)(pages * 4096 + cfg->mem_headroom)))
            return -1;
    }

    // Landlock needs a ruleset fd, so it goes in before RLIMIT_NOFILE = 0.
    if (!cfg->no_landlock) {
        int abi = 0;
        const int rc = landlock_deny_all(&abi, false);
        if (rc < 0)
            return -1;
        snprintf(landlock, sizeof landlock, rc ? "unavailable" : "abi%d", abi);
    }

    // No new fds, no core dumps, no locked memory. Not RLIMIT_NPROC: KVM
    // (6.13+, and 6.12 stable) starts its per-VM NX huge page recovery
    // worker on the first KVM_RUN as a task of this process, charged to our
    // uid, and with NPROC = 0 every KVM_RUN fails with EAGAIN. New processes
    // and threads are refused by the seccomp filter instead.
    if (!cfg->no_rlimits &&
        (set_limit(RLIMIT_NOFILE, cfg->device_io ? cfg->nofile : 0) || set_limit(RLIMIT_CORE, 0) ||
         set_limit(RLIMIT_MEMLOCK, 0)))
        return -1;
    if (cfg->start_threads)
        cfg->start_threads(cfg->ctx);

    if (!cfg->no_seccomp && install_filter(cfg))
        return -1;
    if (report)
        snprintf(report, report_len, "sandbox: seccomp=%s landlock=%s rlimits=%s nnp=on",
                 cfg->no_seccomp ? "off" : "kill", landlock, cfg->no_rlimits ? "off" : "on");
    return 0;
}

// ---- the network helper -------------------------------------------------------
// A process that only opens sockets for the VMM (net_helper.c): requests
// come in on `chan`, route lookups go out on the netlink socket `nl`.
static int build_helper_filter(int chan, int nl, bpf_prog *p)
{
    emit(p, BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch), 0, 0);
    JEQ(AUDIT_ARCH_X86_64, 1, 0);
    RET(KILL);
    LD_NR();
    emit(p, BPF_JMP | BPF_JGE | BPF_K, 0x40000000u /* __X32_SYSCALL_BIT */, 0, 1);
    RET(KILL);
    // clock_gettime: the limits' clock, where the vDSO falls back to the
    // syscall (a clocksource it can't read).
    static const int HPLAIN[] = {SYS_write, SYS_close, SYS_exit, SYS_exit_group, SYS_rt_sigreturn,
                                 SYS_restart_syscall, SYS_connect, SYS_clock_gettime};
    for (size_t i = 0; i < MVM_ARRAY_LEN(HPLAIN); i++) {
        JEQ((uint32_t)HPLAIN[i], 0, 1);
        RET(ALLOW);
    }
#ifdef __SANITIZE_ADDRESS__
    // ASan builds only: the compiler puts __asan_handle_no_return() before
    // every noreturn call (the helper's _exit()s), and it asks where the
    // signal stack is with sigaltstack(NULL, &old). Only that query
    // (ss == NULL, all 64 bits) is allowed; setting a stack is still killed.
    JEQ(SYS_sigaltstack, 0, 6);
    LD_ARG_LO(0);
    JEQ(0, 0, 3);
    LD_ARG_HI(0);
    JEQ(0, 0, 1);
    RET(ALLOW);
    RET(KILL);
    LD_NR();
#endif
    // recvfrom on either fd; sendmsg (the replies) on chan; sendto on nl.
    JEQ(SYS_recvfrom, 0, 5);
    LD_ARG_LO(0);
    JEQ((uint32_t)chan, 1, 0);
    JEQ((uint32_t)nl, 0, 1);
    RET(ALLOW);
    RET(KILL);
    LD_NR();
    JEQ(SYS_sendmsg, 0, 4);
    LD_ARG_LO(0);
    JEQ((uint32_t)chan, 0, 1);
    RET(ALLOW);
    RET(KILL);
    LD_NR();
    JEQ(SYS_sendto, 0, 4);
    LD_ARG_LO(0);
    JEQ((uint32_t)nl, 0, 1);
    RET(ALLOW);
    RET(KILL);
    // setsockopt: TCP_NODELAY and SO_MAX_PACING_RATE only.
    LD_NR();
    JEQ(SYS_setsockopt, 0, 9);
    LD_ARG_LO(1);
    JEQ(IPPROTO_TCP, 0, 2);
    LD_ARG_LO(2);
    JEQ(TCP_NODELAY, 3, 4);
    JEQ(SOL_SOCKET, 0, 3);
    LD_ARG_LO(2);
    JEQ(SO_MAX_PACING_RATE, 0, 1);
    RET(ALLOW);
    RET(KILL);
    // socket(AF_INET or AF_INET6, stream or datagram, non-blocking, 0).
    LD_NR();
    JEQ(SYS_socket, 0, 10);
    LD_ARG_LO(0);
    JEQ(AF_INET, 1, 0);
    JEQ(AF_INET6, 0, 5);
    LD_ARG_LO(1);
    JEQ(SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 1, 0);
    JEQ(SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, 2);
    LD_ARG_LO(2);
    JEQ(0, 1, 0);
    RET(KILL);
    RET(ALLOW);
    RET(KILL); // everything else
    return p->overflow ? -1 : 0;
}

int sandbox_enter_net_helper(int chan, int nl, char *report, size_t report_len)
{
    // No leak check here: the helper only ever leaves by _exit(), which
    // skips LSan's, and in a child forked from the VMM, memory reachable
    // only from the VMM's other threads would look leaked.
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0))
        return -1;
    int abi = 0;
    const int rc = landlock_deny_all(&abi, true);
    if (rc < 0)
        return -1;
    // fds 0-4 are all it has; a new socket is 5, until it is passed on.
    const int top = chan > nl ? chan : nl;
    if (set_limit(RLIMIT_NOFILE, (rlim_t)top + 2) || set_limit(RLIMIT_CORE, 0) || set_limit(RLIMIT_MEMLOCK, 0))
        return -1;
    static bpf_prog p;
    p.n = 0;
    p.overflow = false;
    if (build_helper_filter(chan, nl, &p))
        return -1;
    const struct sock_fprog prog = {.len = (unsigned short)p.n, .filter = p.f};
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog))
        return -1;
    if (report)
        snprintf(report, report_len, "net helper sandbox: seccomp=kill landlock=%s", rc ? "unavailable" : "on");
    return 0;
}
