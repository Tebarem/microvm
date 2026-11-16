// SPDX-License-Identifier: MIT
// Guest /init: freestanding (no libc), a few KB, so exec costs ~nothing.
//
// 1. marks "init reached" on the microvm control port,
// 2. prints one line on the microvm console port (one VM exit),
// 3. reports exit status 0 on the control port; the VMM stops right there,
//    so the guest never has to run its reboot path.
//
// `init hold` (kernel command line "... -- hold") skips step 3 and idles
// forever instead: a stand-in for a long-running container, used by the
// memory-density benchmark (tools/density.ps1).
//
// `init run [COMMAND [ARG...]]` (the VMM's --rootfs IMAGE [-- COMMAND...])
// enters the root filesystem image (/dev/pmem0, read-only EROFS, made
// writable with a tmpfs overlay: image.c) and runs the command there the
// way the image's config says (Entrypoint, Cmd, Env, WorkingDir, User), or
// COMMAND as root for an image without one. Its stdout and stderr go to the
// console port, and its exit status is reported instead of 0. /init stays
// pid 1: it reaps orphans, and the VM ends when the command itself exits,
// even if something it started still holds its output open.
//
// `init snapshot run COMMAND...` asks the VMM for a snapshot (port 0x706)
// once the root filesystem is entered, right before COMMAND starts. With
// --snapshot FILE the VMM saves the VM there and stops; every VM restored
// from FILE continues here. Either way /init then takes the resume record
// (port 0x707): the host's wall clock, which it sets, and fresh randomness,
// which reseeds the kernel's RNG and empties every MADV_WIPEONFORK page
// (RNDVMFORK, kernel patch 0039), so VMs restored from one snapshot don't
// share the snapshot's random state, the kernel's or BoringSSL-style
// userspace generators'.
//
// `init env run ...` first reads the VMM's --env strings from port 0x707
// (never the kernel command line: every process can read /proc/cmdline).
//
// `init agent run COMMAND...` runs COMMAND as a function runtime and serves
// invocations to it from the host over vsock (agent.c): the runtime warms
// up, then asks for the snapshot itself.
//
// Build: see guest/kernel/build.sh.

typedef unsigned long u64;

#include "init.h"

enum {
    SYS_read = 0,
    SYS_write = 1,
    SYS_open = 2,
    SYS_close = 3,
    SYS_poll = 7,
    SYS_rt_sigaction = 13,
    SYS_rt_sigreturn = 15,
    SYS_pipe = 22,
    SYS_pause = 34,
    SYS_dup2 = 33,
    SYS_fork = 57,
    SYS_execve = 59,
    SYS_exit = 60,
    SYS_wait4 = 61,
    SYS_fcntl = 72,
    SYS_reboot = 169,
    SYS_ioperm = 173,
    SYS_clock_settime = 227,
    SYS_ioctl = 16,
    SYS_pipe2 = 293,
};

enum {
    PORT_MARK = 0x700, PORT_EXIT = 0x701, PORT_CONSOLE = 0x702, PORT_SNAPSHOT = 0x706,
    PORT_RESUME = 0x707, NPORTS = 8, MARK_INIT = 2, RESUME_LEN = 48,
};
// <linux/random.h>
// RNDVMFORK (kernel patch 0039): reseed, and empty every MADV_WIPEONFORK
// mapping of every process.
enum { RNDADDENTROPY = 0x40085203, RNDVMFORK = 0x5240 };
enum { ENOENT = 2, EINTR = 4, EAGAIN = 11 };
enum { O_NONBLOCK = 04000, O_CLOEXEC = 02000000, F_SETFL = 4, POLLIN = 1, WNOHANG = 1, SIGCHLD = 17 };

static long syscall5(long n, long a, long b, long c, long d, long e)
{
    long r;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return r;
}

static long syscall3(long n, long a, long b, long c) { return syscall5(n, a, b, c, 0, 0); }

static void outb(unsigned short port, unsigned char v)
{
    __asm__ volatile("outb %0, %1" : : "a"(v), "Nd"(port));
}

// The whole buffer in one VM exit (the VMM reads it from guest memory).
// The pages must be mapped already, or the VMM has to bounce the access
// back as a page fault first (one more exit).
static void outsb(unsigned short port, const void *p, u64 n)
{
    __asm__ volatile("rep outsb" : "+S"(p), "+c"(n) : "d"(port) : "memory");
}

static void insb(unsigned short port, void *p, u64 n)
{
    __asm__ volatile("rep insb" : "+D"(p), "+c"(n) : "d"(port) : "memory");
}

static u64 len(const char *s)
{
    u64 n = 0;
    while (s[n])
        n++;
    return n;
}

static bool streq(const char *a, const char *b)
{
    while (*a && *a == *b)
        a++, b++;
    return *a == *b;
}

bool ports;
bool to_stderr; // in the command's process: no ports, fd 2 is the pipe

// A message on the console port (or nowhere, without ports).
void say(const char *a, const char *b, long err)
{
    char buf[256];
    u64 n = 0;
    for (const char *s = "microvm-init: "; *s && n < 200; s++)
        buf[n++] = *s;
    for (const char *s = a; *s && n < 200; s++)
        buf[n++] = *s;
    for (const char *s = b; s && *s && n < 240; s++)
        buf[n++] = *s;
    if (err) {
        // ": error N" with N = -err
        for (const char *s = ": error "; *s; s++)
            buf[n++] = *s;
        char d[20];
        int k = 0;
        for (unsigned long v = (unsigned long)-err; k == 0 || v; v /= 10)
            d[k++] = (char)('0' + v % 10);
        while (k)
            buf[n++] = d[--k];
    }
    buf[n++] = '\n';
    if (to_stderr)
        syscall3(SYS_write, 2, (long)buf, (long)n);
    else if (ports)
        outsb(PORT_CONSOLE, buf, n);
}

[[noreturn]] void stop(int status)
{
    if (ports)
        outb(PORT_EXIT, (unsigned char)status);
    // Fallback if the control port isn't there: reboot (i8042 reset).
    syscall3(SYS_reboot, (long)0xfee1dead, 672274793, 0x01234567);
    for (;;)
        syscall3(SYS_exit, status, 0, 0);
}

// execve(argv[0]) with envp, searching envp's PATH (or the usual one) if
// it has no '/'. Returns the exit status to report: 127 if not found, 126
// if found but not runnable.
int exec_env(char **argv, char *const *envp)
{
    const char *name = argv[0];
    bool slash = false;
    for (const char *c = name; *c; c++)
        slash |= *c == '/';
    if (slash) {
        long r = syscall3(SYS_execve, (long)name, (long)argv, (long)envp);
        say("cannot run ", name, r);
        return r == -ENOENT ? 127 : 126;
    }
    const char *search = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    for (char *const *e = envp; *e; e++)
        if ((*e)[0] == 'P' && (*e)[1] == 'A' && (*e)[2] == 'T' && (*e)[3] == 'H' && (*e)[4] == '=')
            search = *e + 5;
    char path[4096];
    long last = -ENOENT;
    for (const char *p = search; *p;) {
        u64 n = 0;
        while (*p && *p != ':' && n < sizeof path - 2)
            path[n++] = *p++;
        if (*p == ':')
            p++;
        if (n)
            path[n++] = '/';
        u64 m = len(name);
        if (n + m >= sizeof path)
            continue;
        for (u64 i = 0; i <= m; i++)
            path[n + i] = name[i];
        long r = syscall3(SYS_execve, (long)path, (long)argv, (long)envp);
        if (r != -ENOENT)
            last = r;
    }
    say("cannot run ", name, last);
    return last == -ENOENT ? 127 : 126;
}


void report_free_pages(void)
{
    const long fd = syscall3(SYS_open, (long)"/proc/sys/vm/page_reporting_flush", 1 /* O_WRONLY */ | O_CLOEXEC, 0);
    if (fd < 0)
        return;
    syscall3(SYS_write, fd, (long)"1", 1);
    syscall3(SYS_close, fd, 0, 0);
}

void ctl_latch(unsigned char which) { outb(PORT_RESUME, which); }
void ctl_read(void *p, u64 n) { insb(PORT_RESUME, p, n); }

// After the snapshot point: the host's clock and fresh randomness.
// `rnd` is /dev/urandom, opened before the root filesystem was entered.
void resume(long rnd)
{
    static unsigned char rec[RESUME_LEN];
    for (u64 i = 0; i < sizeof rec; i++) // map the page: no fault inside rep insb
        ((volatile unsigned char *)rec)[i] = 0;
    outb(PORT_RESUME, 0);
    insb(PORT_RESUME, rec, sizeof rec);
    long ts[2] = {0, 0};
    for (int i = 0; i < 8; i++)
        ts[0] |= (long)rec[i] << (8 * i);
    for (int i = 0; i < 4; i++)
        ts[1] |= (long)rec[8 + i] << (8 * i);
    long r;
    if (ts[0] > 0 && (r = syscall3(SYS_clock_settime, 0 /* CLOCK_REALTIME */, (long)ts, 0)) < 0)
        say("cannot set the clock", nullptr, r);
    struct {
        int entropy_bits, size;
        unsigned char buf[32];
    } e = {256, 32, {0}};
    for (int i = 0; i < 32; i++)
        e.buf[i] = rec[16 + i];
    // A restored VM that can't reseed must not run: it would share the
    // snapshot's random state with every other VM restored from it.
    if (rnd < 0 || (r = syscall3(SYS_ioctl, rnd, RNDADDENTROPY, (long)&e)) < 0 ||
        (r = syscall3(SYS_ioctl, rnd, RNDVMFORK, 0)) < 0) {
        say("cannot reseed the RNG", nullptr, rnd < 0 ? rnd : r);
        stop(125);
    }
    if (rnd >= 0)
        syscall3(SYS_close, rnd, 0, 0);
}

// SIGCHLD wakes the forwarding loop through a pipe: a child's exit can't
// be missed between checking for it and waiting.
static long sigchld_w = -1;

static void on_sigchld(int sig)
{
    (void)sig;
    syscall3(SYS_write, sigchld_w, (long)"c", 1);
}

void sig_restore(void);
__asm__(".globl sig_restore\n"
        "sig_restore:\n"
        "    mov $15, %eax\n" // rt_sigreturn
        "    syscall\n");

static long catch_sigchld(void)
{
    long sp[2];
    long r = syscall3(SYS_pipe2, (long)sp, O_CLOEXEC | O_NONBLOCK, 0);
    if (r < 0)
        return r;
    sigchld_w = sp[1];
    // struct kernel_sigaction: handler, flags, restorer, mask. No
    // SA_RESTART: a blocked poll() returns at once.
    const long act[4] = {(long)on_sigchld, 0x04000000 /* SA_RESTORER */ | 1 /* SA_NOCLDSTOP */,
                         (long)sig_restore, 0};
    if ((r = syscall5(SYS_rt_sigaction, SIGCHLD, (long)act, 0, 8, 0)) < 0)
        return r;
    return sp[0];
}

// Mount the image, enter it, run argv there; returns its exit status.
static int run(char **argv, bool snapshot)
{
    const long rnd = snapshot ? syscall3(SYS_open, (long)"/dev/urandom", 1 /* O_WRONLY */, 0) : -1;
    long r = enter_root();
    if (r)
        return (int)r;
    if (!image_load())
        return 125;
    if (snapshot && ports) {
        report_free_pages();
        outb(PORT_SNAPSHOT, 1); // a restored VM continues from here
        resume(rnd);
    }
    const long sig_r = catch_sigchld();
    if (sig_r < 0) {
        say("SIGCHLD", nullptr, sig_r);
        return 125;
    }
    int fds[2];
    if ((r = syscall3(SYS_pipe, (long)fds, 0, 0)) < 0) {
        say("pipe", nullptr, r);
        return 125;
    }
    long pid = syscall3(SYS_fork, 0, 0, 0);
    if (pid < 0) {
        say("fork", nullptr, pid);
        return 125;
    }
    if (pid == 0) {
        // The command needn't reach the VMM's ports, only its own output.
        syscall3(SYS_ioperm, PORT_MARK, NPORTS, 0);
        syscall3(SYS_dup2, fds[1], 1, 0);
        syscall3(SYS_dup2, fds[1], 2, 0);
        syscall3(SYS_close, fds[0], 0, 0);
        syscall3(SYS_close, fds[1], 0, 0);
        to_stderr = true;
        int st = image_exec(argv);
        for (;;)
            syscall3(SYS_exit, st, 0, 0);
    }
    syscall3(SYS_close, fds[1], 0, 0);
    // Forward the command's output (one exit per read) until it exits, and
    // reap every other process that ends meanwhile: we are pid 1, so
    // orphans are ours. Once the command is gone, take what it left in the
    // pipe and stop, whoever else still holds the pipe open.
    static char buf[4096];
    int status = 0;
    bool done = false, eof = false;
    while (!done) {
        struct {
            int fd;
            short events, revents;
        } p[2] = {{(int)sig_r, POLLIN, 0}, {eof ? -1 : fds[0], POLLIN, 0}};
        r = syscall3(SYS_poll, (long)p, 2, -1);
        if (r < 0 && r != -EINTR) {
            say("poll", nullptr, r);
            return 125;
        }
        if (p[1].revents) {
            long n = syscall3(SYS_read, fds[0], (long)buf, sizeof buf);
            if (n > 0 && ports)
                outsb(PORT_CONSOLE, buf, (u64)n);
            eof = n == 0 || (n < 0 && n != -EINTR);
        }
        char junk[64];
        while (syscall3(SYS_read, sig_r, (long)junk, sizeof junk) > 0)
            ;
        int st;
        while ((r = syscall5(SYS_wait4, -1, (long)&st, WNOHANG, 0, 0)) > 0)
            if (r == pid)
                status = st, done = true;
    }
    syscall3(SYS_fcntl, fds[0], F_SETFL, O_NONBLOCK);
    for (long n; !eof && (n = syscall3(SYS_read, fds[0], (long)buf, sizeof buf)) != 0 && n != -EAGAIN;)
        if (n > 0 && ports)
            outsb(PORT_CONSOLE, buf, (u64)n);
    if ((status & 0x7f) == 0)
        return (status >> 8) & 0xff; // exited
    return 128 + (status & 0x7f);    // killed by a signal
}

// The kernel starts us with the stack holding argc, argv[], envp[].
__asm__(".globl _start\n"
        "_start:\n"
        "    mov %rsp, %rdi\n"
        "    and $-16, %rsp\n"
        "    call init_main\n"
        "    hlt\n");

[[noreturn]] void init_main(long *sp);

[[noreturn]] void init_main(long *sp)
{
    const long argc = sp[0];
    char **argv = (char **)(sp + 1);
    // Any argv word: the kernel also passes unknown cmdline words to init.
    bool hold = false, snapshot = false, agent = false, env = false, sandbox = false;
    long run_at = 0;
    for (long i = 1; i < argc && !run_at; i++) {
        hold |= streq(argv[i], "hold");
        snapshot |= streq(argv[i], "snapshot");
        agent |= streq(argv[i], "agent");
        sandbox |= streq(argv[i], "sandbox");
        env |= streq(argv[i], "env");
        // "layers2" .. "layers8": the image is in layers (enter_root)
        const char *a = argv[i];
        if (a[0] == 'l' && a[1] == 'a' && a[2] == 'y' && a[3] == 'e' && a[4] == 'r' && a[5] == 's' &&
            a[6] >= '2' && a[6] <= '8' && !a[7])
            image_layers = (unsigned)(a[6] - '0');
        if (streq(argv[i], "run")) // argv[argc] is nullptr: no command
            run_at = i + 1;
    }

    // 0x700..0x707: a 4-byte access to PORT_CONSOLE covers 0x702..0x705.
    ports = syscall3(SYS_ioperm, PORT_MARK, NPORTS, 1) == 0;
    if (ports)
        outb(PORT_MARK, MARK_INIT);

    if (env && (!ports || !env_read()))
        stop(125);
    if (run_at)
        stop(sandbox ? sbx_run() : agent ? agent_run(argv + run_at) : run(argv + run_at, snapshot));

    // The marker line goes to the VMM's console port in one exit (rep
    // outsb). Through the kernel console (8250) it costs two exits per byte.
    static const char line[] = "microvm-init: hello from /init\n";
    if (ports) {
        // Fault the string's page in with a plain read first.
        (void)*(volatile const char *)line;
        (void)*(volatile const char *)(line + sizeof line - 1);
        outsb(PORT_CONSOLE, line, sizeof line - 1);
    }
    // Also in the kernel log; printed on the console only without the
    // control port, or without `quiet`.
    static const char crit[] = "<2>microvm-init: hello from /init\n";
    static const char info[] = "<6>microvm-init: started\n";
    long fd = syscall3(SYS_open, (long)"/dev/kmsg", 1 /* O_WRONLY */, 0);
    if (fd >= 0) {
        const char *m = ports ? info : crit;
        syscall3(SYS_write, fd, (long)m, (long)len(m));
    }

    if (hold)
        for (;;)
            syscall3(SYS_pause, 0, 0, 0);

    stop(0);
}
