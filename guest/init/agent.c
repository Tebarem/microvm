// SPDX-License-Identifier: MIT
// The guest agent, part of /init (freestanding like init.c):
//
//   init agent run COMMAND [ARG...]     (--append agent, --rootfs IMAGE -- COMMAND...)
//
// mounts the root filesystem, listens on vsock port MVA_PORT, and starts
// COMMAND as the function runtime with four pipes (src/agent/proto.h):
// fd 0 brings it INVOKE frames, fd 3 takes its READY, RESULT and DONE
// frames, and fds 1 and 2 are its stdout and stderr. /init stays pid 1 and
// keeps the control ports; the runtime gets none of them.
//
// 1. Warm-up: the runtime loads its code, then sends READY. Its output so
//    far goes to the console. With MVA_READY_SNAPSHOT, the agent stops
//    every other process (SIGSTOP to all), asks the VMM for the snapshot
//    (port 0x706), and then, in this VM and in every VM restored from the
//    snapshot, takes the resume record (the host's clock, fresh randomness
//    for the kernel's RNG) before it lets them continue (SIGCONT). No user
//    code runs between the snapshot point and the reseed.
// 2. Serving: the agent accepts one host connection at a time, says HELLO,
//    and relays invocations: it forwards INVOKE to the runtime (checking
//    the fixed part, and refusing malformed ones), and frames the runtime's
//    stdout, stderr and RESULT back to the host, truncated to the caps the
//    host gave, then DONE. At the deadline it kills the runtime.
// 3. If the runtime dies, overruns its deadline or breaks the protocol, the
//    agent reports that in DONE (with MVA_DONE_VM_ENDS), waits briefly for
//    the host to read it, and stops the VM: a runtime in an unknown state is
//    never reused.
#include "../../src/agent/proto.h"
#include "init.h"

typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
    long r;
    register long r10 __asm__("r10") = d, r8 __asm__("r8") = e, r9 __asm__("r9") = f;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return r;
}

static long sys3(long n, long a, long b, long c) { return sys6(n, a, b, c, 0, 0, 0); }

enum {
    SYS_read = 0, SYS_write = 1, SYS_open = 2, SYS_close = 3, SYS_poll = 7, SYS_dup2 = 33,
    SYS_nanosleep = 35, SYS_socket = 41, SYS_sendto = 44, SYS_shutdown = 48, SYS_bind = 49,
    SYS_listen = 50, SYS_fork = 57, SYS_exit = 60, SYS_wait4 = 61, SYS_kill = 62, SYS_fcntl = 72,
    SYS_ioperm = 173, SYS_clock_gettime = 228, SYS_accept4 = 288, SYS_pipe2 = 293,
};
enum {
    O_WRONLY = 1, O_NONBLOCK = 04000, O_CLOEXEC = 02000000, F_SETFL = 4,
    AF_VSOCK = 40, SOCK_STREAM = 1, SHUT_WR = 1, MSG_DONTWAIT = 0x40, MSG_NOSIGNAL = 0x4000,
    POLLIN = 1, POLLOUT = 4, POLLERR = 8, POLLHUP = 0x10,
    EINTR = 4, EAGAIN = 11, WNOHANG = 1, SIGKILL = 9, SIGCONT = 18, SIGSTOP = 19,
    CLOCK_MONOTONIC = 1,
    PORT_MARK = 0x700, PORT_CONSOLE = 0x702, PORT_SNAPSHOT = 0x706, NPORTS = 8,
};

// gcc may emit calls to these for struct copies; no libc here.
void *memcpy(void *d, const void *s, unsigned long n);
void *memset(void *d, int c, unsigned long n);
void *memmove(void *d, const void *s, unsigned long n);
void *memcpy(void *d, const void *s, unsigned long n)
{
    void *r = d;
    __asm__ volatile("rep movsb" : "+D"(d), "+S"(s), "+c"(n) : : "memory");
    return r;
}
void *memset(void *d, int c, unsigned long n)
{
    void *r = d;
    __asm__ volatile("rep stosb" : "+D"(d), "+c"(n) : "a"(c) : "memory");
    return r;
}
void *memmove(void *d, const void *s, unsigned long n)
{
    if ((u8 *)d <= (const u8 *)s || (u8 *)d >= (const u8 *)s + n)
        return memcpy(d, s, n);
    u8 *dp = (u8 *)d + n;
    const u8 *sp = (const u8 *)s + n;
    while (n--)
        *--dp = *--sp;
    return d;
}

static void outb(u16 port, u8 v) { __asm__ volatile("outb %0, %1" : : "a"(v), "Nd"(port)); }
static void outsb(u16 port, const void *p, u64 n)
{
    __asm__ volatile("rep outsb" : "+S"(p), "+c"(n) : "d"(port) : "memory");
}

static u32 le32(const u8 *p) { return (u32)p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24; }
static u16 le16(const u8 *p) { return (u16)(p[0] | p[1] << 8); }
static void put32(u8 *p, u32 v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (u8)(v >> (8 * i));
}

static u64 now_ns(void)
{
    long ts[2] = {0, 0};
    sys3(SYS_clock_gettime, CLOCK_MONOTONIC, (long)ts, 0);
    return (u64)ts[0] * 1000000000ul + (u64)ts[1];
}

static void nap_ms(long ms)
{
    const long ts[2] = {ms / 1000, (ms % 1000) * 1000000};
    sys3(SYS_nanosleep, (long)ts, 0, 0);
}

struct pollfd {
    int fd;
    short events, revents;
};

struct sockaddr_vm {
    u16 family, reserved;
    u32 port, cid;
    u8 flags, zero[3];
};

// RESERVE: room always kept in `out` for a DONE.
enum { OUT_CAP = 256u << 10, RT_CAP = MVA_HDR + MVA_MAX_CHUNK, FIXED = MVA_HDR + MVA_INVOKE_FIXED, RESERVE = 64 };

// Host -> guest: where we are in the current INVOKE frame.
enum hstate { H_HDR, H_FIXED, H_BODY, H_DISCARD, H_WAIT };

static struct {
    long ls, conn;                   // vsock listener, host connection (-1: none)
    long inv_w, rsp_r, out_r, err_r; // the runtime's pipes, our ends (-1: closed)
    long pid;
    bool serving;
    u32 served, ready_flags;
    // host -> guest
    enum hstate hs;
    u8 hdr[FIXED];
    u32 hdr_have;
    u32 frame_len, body_left; // body bytes of the frame still to read from the host
    u32 in_off, in_len;       // forwarding window in `in`
    // the invocation in flight
    bool inflight, done_pending;
    u32 id, max_result, max_output, trunc;
    u64 res_n, out_n, err_n, t0, deadline;
    long rt_status;
    // runtime -> agent frames
    u32 r_len;
    // agent -> host
    u32 o_start, o_end;
} a;

static u8 in[64u << 10];
static u8 rt[RT_CAP];
static u8 out[OUT_CAP];
static u8 tmp[MVA_MAX_CHUNK];

static void xclose(long *fd)
{
    if (*fd >= 0)
        sys3(SYS_close, *fd, 0, 0);
    *fd = -1;
}

static u32 room(void)
{
    if (a.o_start == a.o_end)
        a.o_start = a.o_end = 0;
    else if (a.o_start > OUT_CAP / 2) {
        memmove(out, out + a.o_start, a.o_end - a.o_start);
        a.o_end -= a.o_start;
        a.o_start = 0;
    }
    return OUT_CAP - a.o_end;
}

// Append a frame (the caller checked room()).
static void emit(u8 type, u32 id, const void *body, u32 len)
{
    u8 *p = out + a.o_end;
    put32(p, MVA_MAGIC);
    p[4] = MVA_VERSION;
    p[5] = type;
    p[6] = p[7] = 0;
    put32(p + 8, id);
    put32(p + 12, len);
    if (len)
        memcpy(p + MVA_HDR, body, len);
    a.o_end += MVA_HDR + len;
}

// Write what we can to the host. false if the host is gone.
static bool flush(void)
{
    while (a.conn >= 0 && a.o_start < a.o_end) {
        const long w = sys6(SYS_sendto, a.conn, (long)(out + a.o_start), a.o_end - a.o_start,
                            MSG_DONTWAIT | MSG_NOSIGNAL, 0, 0);
        if (w == -EAGAIN)
            return true;
        if (w == -EINTR)
            continue;
        if (w <= 0)
            return false;
        a.o_start += (u32)w;
    }
    return true;
}

static void kill_all(void)
{
    sys3(SYS_kill, -1, SIGKILL, 0); // everything but pid 1, the runtime's children too
    long st;
    while (sys6(SYS_wait4, -1, (long)&st, 0, 0, 0, 0) > 0) // reap them all
        ;
    a.pid = -1;
}

// The VM ends: let the host read what we said, then stop.
[[noreturn]] static void end_vm(int status)
{
    const u64 end = now_ns() + 1000000000ul;
    while (a.conn >= 0 && a.o_start < a.o_end && now_ns() < end) {
        struct pollfd p = {(int)a.conn, POLLOUT, 0};
        sys3(SYS_poll, (long)&p, 1, 50);
        if (!flush())
            break;
    }
    // The VMM may stop before its I/O thread has passed our last bytes on:
    // wait (briefly) for the host to close once it has read the DONE.
    if (a.conn >= 0) {
        sys3(SYS_shutdown, a.conn, SHUT_WR, 0);
        while (now_ns() < end) {
            struct pollfd p = {(int)a.conn, POLLIN, 0};
            if (sys3(SYS_poll, (long)&p, 1, 50) > 0 && sys3(SYS_read, a.conn, (long)tmp, sizeof tmp) <= 0)
                break;
        }
    }
    stop(status);
}

// The VM's exit status for a VM-ending DONE.
static int vm_code(u32 kind, int status)
{
    return kind == MVA_TIMEOUT ? 124 : kind == MVA_FAULT ? 125 : kind == MVA_SIGNALED ? 128 + status : status;
}

static void drain_logs(void);

// The invocation is over. VM_ENDS kinds don't come back.
static void finish(u32 kind, int status, u32 flags)
{
    u8 b[16];
    put32(b, kind);
    put32(b + 4, (u32)status);
    put32(b + 8, a.trunc | flags);
    put32(b + 12, (u32)((now_ns() - a.t0) / 1000));
    room();
    emit(MVA_DONE, a.id, b, 16);
    a.inflight = a.done_pending = false;
    a.hs = H_HDR, a.hdr_have = 0;
    a.served++;
    if (flags & MVA_DONE_VM_ENDS)
        end_vm(vm_code(kind, status));
    if (!flush()) {
        xclose(&a.conn);
        a.o_start = a.o_end = 0;
    }
}

// The runtime must not live on in an unknown state: kill it and end the VM.
[[noreturn]] static void fatal(u32 kind, int status)
{
    if (a.pid > 0)
        kill_all();
    drain_logs();
    if (a.inflight && a.conn >= 0)
        finish(kind, status, MVA_DONE_VM_ENDS);
    end_vm(vm_code(kind, status));
}

// The runtime exited (status st, from wait4).
[[noreturn]] static void runtime_gone(long st)
{
    a.pid = -1;
    if (!a.serving)
        say("the runtime exited before it was ready", nullptr, 0);
    const bool sig = (st & 0x7f) != 0;
    fatal(sig ? MVA_SIGNALED : MVA_EXITED, sig ? (int)(st & 0x7f) : (int)((st >> 8) & 0xff));
}

static void reap(void)
{
    long st = 0, r;
    while ((r = sys6(SYS_wait4, -1, (long)&st, WNOHANG, 0, 0, 0)) > 0)
        if (r == a.pid)
            runtime_gone(st);
}

// Read the runtime's stdout or stderr: into the invocation, or the console.
// 0: nothing more for now (or closed), 1: read some, 2: no room to read.
static int read_log(long *fd, u8 type)
{
    if (*fd < 0)
        return 0;
    const u32 rm = room();
    if (rm < MVA_HDR + RESERVE + 4096)
        return 2;
    u32 cap = rm - MVA_HDR - RESERVE;
    if (cap > sizeof tmp)
        cap = sizeof tmp;
    const long n = sys3(SYS_read, *fd, (long)tmp, cap);
    if (n == -EAGAIN || n == -EINTR)
        return 0;
    if (n <= 0) {
        xclose(fd);
        return 0;
    }
    if (!a.inflight) {
        if (ports)
            outsb(PORT_CONSOLE, tmp, (u64)n);
        return 1;
    }
    u64 *got = type == MVA_STDOUT ? &a.out_n : &a.err_n;
    const u64 take = a.max_output - *got < (u64)n ? a.max_output - *got : (u64)n;
    if (take < (u64)n)
        a.trunc |= type == MVA_STDOUT ? MVA_DONE_TRUNC_STDOUT : MVA_DONE_TRUNC_STDERR;
    if (take)
        emit(type, a.id, tmp, (u32)take);
    *got += take;
    return 1;
}

// Everything the runtime wrote before it said DONE is in the pipes already.
// false while that can't all be read for lack of room.
static bool logs_drained(void)
{
    for (int r; (r = read_log(&a.out_r, MVA_STDOUT));)
        if (r == 2)
            return false;
    for (int r; (r = read_log(&a.err_r, MVA_STDERR));)
        if (r == 2)
            return false;
    return true;
}

static void drain_logs(void)
{
    for (int i = 0; i < 64 && !logs_drained(); i++)
        if (!flush())
            break;
}

static bool ok_header(const u8 *h)
{
    return le32(h) == MVA_MAGIC && h[4] == MVA_VERSION && h[6] == 0 && h[7] == 0;
}

// Frames from the runtime (fd 3).
static void read_runtime(void)
{
    if (a.rsp_r < 0 || room() < RT_CAP + RESERVE) // what we emit is at most what we read
        return;
    const long n = sys3(SYS_read, a.rsp_r, (long)(rt + a.r_len), RT_CAP - a.r_len);
    if (n == -EAGAIN || n == -EINTR)
        return;
    if (n <= 0) { // it closed fd 3: it is exiting, or broken
        xclose(&a.rsp_r);
        for (int i = 0; i < 100; i++) {
            long st = 0;
            const long r = sys6(SYS_wait4, a.pid, (long)&st, WNOHANG, 0, 0, 0);
            if (r == a.pid)
                runtime_gone(st);
            nap_ms(1);
        }
        fatal(MVA_FAULT, 0);
    }
    a.r_len += (u32)n;
    while (a.r_len >= MVA_HDR) {
        const u8 type = rt[5];
        const u32 id = le32(rt + 8), len = le32(rt + 12);
        const bool data = type == MVA_RESULT;
        if (!ok_header(rt) || (data && (len == 0 || len > MVA_MAX_CHUNK)) ||
            (type == MVA_DONE && len != 16) || (type == MVA_READY && len != 4) ||
            (type != MVA_RESULT && type != MVA_DONE && type != MVA_READY) ||
            (type == MVA_READY) == a.serving || (type != MVA_READY && (!a.inflight || id != a.id || a.done_pending)) ||
            // DONE before it has read the whole INVOKE
            (type == MVA_DONE && (a.hs != H_WAIT || a.in_off != a.in_len))) {
            say("the runtime broke the protocol", nullptr, 0);
            fatal(MVA_FAULT, 0);
        }
        if (a.r_len < MVA_HDR + len)
            return;
        const u8 *b = rt + MVA_HDR;
        if (type == MVA_READY) {
            a.serving = true;
            a.ready_flags = le32(b);
        } else if (type == MVA_RESULT) {
            const u64 take = a.max_result - a.res_n < len ? a.max_result - a.res_n : len;
            if (take < len)
                a.trunc |= MVA_DONE_TRUNC_RESULT;
            if (take)
                emit(MVA_RESULT, a.id, b, (u32)take);
            a.res_n += take;
        } else {
            if (le32(b) != MVA_RETURNED || le32(b + 8) || le32(b + 12)) {
                say("the runtime broke the protocol", nullptr, 0);
                fatal(MVA_FAULT, 0);
            }
            a.done_pending = true;
            a.rt_status = (int)le32(b + 4);
        }
        memmove(rt, rt + MVA_HDR + len, a.r_len - MVA_HDR - len);
        a.r_len -= MVA_HDR + len;
    }
}

static void host_lost(void)
{
    if (a.inflight) // nobody to answer, and the runtime is mid-call
        fatal(MVA_FAULT, 0);
    xclose(&a.conn);
    a.o_start = a.o_end = 0;
    a.hs = H_HDR;
    a.hdr_have = 0;
}

// Read the host's next bytes, never past the current frame. false if the
// host is gone (or broke the protocol).
static bool read_host(void)
{
    if (a.in_off < a.in_len || (a.hs == H_BODY && a.body_left == 0))
        return true; // (a hangup shows when we read next)
    u8 *dst;
    u32 want;
    switch (a.hs) {
    case H_HDR:
        dst = a.hdr + a.hdr_have, want = MVA_HDR - a.hdr_have;
        break;
    case H_FIXED:
        dst = a.hdr + a.hdr_have, want = FIXED - a.hdr_have;
        break;
    case H_BODY:
    case H_DISCARD:
        dst = in, want = a.body_left < sizeof in ? a.body_left : sizeof in;
        break;
    default: { // the whole INVOKE is in: the host must wait for DONE
        const long n = sys3(SYS_read, a.conn, (long)tmp, 1);
        return n == -EAGAIN || n == -EINTR;
    }
    }
    const long n = sys3(SYS_read, a.conn, (long)dst, want);
    if (n == -EAGAIN || n == -EINTR)
        return true;
    if (n <= 0)
        return false;
    if (a.hs == H_HDR || a.hs == H_FIXED) {
        a.hdr_have += (u32)n;
        if (a.hs == H_HDR && a.hdr_have == MVA_HDR) {
            const u8 *h = a.hdr;
            a.frame_len = le32(h + 12);
            if (!ok_header(h) || h[5] != MVA_INVOKE || a.frame_len > MVA_MAX_INVOKE)
                return false; // no way to find the next frame: drop the connection
            a.id = le32(h + 8);
            if (a.frame_len < MVA_INVOKE_FIXED) {
                a.hs = H_DISCARD, a.body_left = a.frame_len, a.inflight = true, a.t0 = now_ns();
                a.trunc = 0;
            } else {
                a.hs = H_FIXED;
            }
        } else if (a.hs == H_FIXED && a.hdr_have == FIXED) {
            const u8 *f = a.hdr + MVA_HDR;
            const u32 dl = le32(f), mr = le32(f + 4), mo = le32(f + 8), pl = le32(f + 16);
            const u32 ns = (u32)le16(f + 12) + le16(f + 14);
            const u64 need = (u64)MVA_INVOKE_FIXED + 4ul * ns + pl;
            a.inflight = true;
            a.t0 = now_ns();
            a.trunc = 0;
            a.res_n = a.out_n = a.err_n = 0;
            a.body_left = a.frame_len - MVA_INVOKE_FIXED;
            if (dl < 1 || dl > MVA_MAX_DEADLINE_MS || mr > MVA_MAX_RESULT || mo > MVA_MAX_OUTPUT ||
                le16(f + 12) > MVA_MAX_STRINGS || le16(f + 14) > MVA_MAX_STRINGS || pl > MVA_MAX_PAYLOAD ||
                a.frame_len < need || a.frame_len - need > MVA_MAX_STRING_BYTES) {
                a.hs = H_DISCARD;
            } else {
                a.deadline = a.t0 + (u64)dl * 1000000ul;
                a.max_result = mr, a.max_output = mo;
                memcpy(in, a.hdr, FIXED); // forward the frame as it came
                a.in_off = 0, a.in_len = FIXED;
                a.hs = H_BODY;
            }
        }
        if (a.hs == H_DISCARD && a.body_left == 0) {
            a.hs = H_HDR, a.hdr_have = 0;
            finish(MVA_REFUSED, 0, 0);
        }
        return true;
    }
    a.body_left -= (u32)n;
    if (a.hs == H_DISCARD) {
        if (a.body_left == 0) {
            a.hs = H_HDR, a.hdr_have = 0;
            finish(MVA_REFUSED, 0, 0);
        }
        return true;
    }
    a.in_off = 0, a.in_len = (u32)n;
    return true;
}

// Forward the INVOKE to the runtime (fd 0).
static void forward(void)
{
    while (a.in_off < a.in_len) {
        const long w = sys3(SYS_write, a.inv_w, (long)(in + a.in_off), a.in_len - a.in_off);
        if (w == -EAGAIN || w == -EINTR)
            return;
        if (w <= 0) // it closed fd 0
            fatal(MVA_FAULT, 0);
        a.in_off += (u32)w;
    }
    if (a.hs == H_BODY && a.body_left == 0) {
        a.hs = H_WAIT;
        a.hdr_have = 0;
    }
}

static long xpipe(long fds[2], bool ours_read)
{
    int p[2];
    const long r = sys3(SYS_pipe2, (long)p, O_CLOEXEC, 0);
    if (r < 0)
        return r;
    fds[0] = p[0], fds[1] = p[1];
    return sys3(SYS_fcntl, fds[ours_read ? 0 : 1], F_SETFL, O_NONBLOCK);
}

static void say_n(const char *what, u64 v)
{
    char d[24], *p = d + sizeof d - 1;
    *p = 0;
    do
        *--p = (char)('0' + v % 10);
    while (v /= 10);
    say(what, p, 0);
}

int agent_run(char **argv)
{
    // Opened before the root filesystem is entered, as for `snapshot run`.
    const long rnd = sys3(SYS_open, (long)"/dev/urandom", O_WRONLY | O_CLOEXEC, 0);
    if (enter_root() || !image_load())
        return 125;
    a.ls = sys3(SYS_socket, AF_VSOCK, SOCK_STREAM | O_NONBLOCK | O_CLOEXEC, 0);
    const struct sockaddr_vm addr = {.family = AF_VSOCK, .port = MVA_PORT, .cid = 0xffffffffu};
    long r = a.ls;
    if (r < 0 || (r = sys3(SYS_bind, a.ls, (long)&addr, sizeof addr)) < 0 ||
        (r = sys3(SYS_listen, a.ls, 4, 0)) < 0) {
        say("cannot listen on vsock (is there a --vsock device?)", nullptr, r);
        return 125;
    }
    long inv[2], rsp[2], o[2], e[2];
    if ((r = xpipe(inv, false)) < 0 || (r = xpipe(rsp, true)) < 0 || (r = xpipe(o, true)) < 0 ||
        (r = xpipe(e, true)) < 0) {
        say("pipe", nullptr, r);
        return 125;
    }
    a.pid = sys3(SYS_fork, 0, 0, 0);
    if (a.pid < 0) {
        say("fork", nullptr, a.pid);
        return 125;
    }
    if (a.pid == 0) {
        sys3(SYS_ioperm, PORT_MARK, NPORTS, 0);
        sys3(SYS_dup2, inv[0], 0, 0);
        sys3(SYS_dup2, o[1], 1, 0);
        sys3(SYS_dup2, e[1], 2, 0);
        sys3(SYS_dup2, rsp[1], 3, 0); // the rest are close-on-exec
        to_stderr = true;
        const int st = image_exec(argv);
        for (;;)
            sys3(SYS_exit, st, 0, 0);
    }
    sys3(SYS_close, inv[0], 0, 0);
    sys3(SYS_close, rsp[1], 0, 0);
    sys3(SYS_close, o[1], 0, 0);
    sys3(SYS_close, e[1], 0, 0);
    a.inv_w = inv[1], a.rsp_r = rsp[0], a.out_r = o[0], a.err_r = e[0];
    a.conn = -1;

    // 1. Warm-up, until READY.
    while (!a.serving) {
        struct pollfd p[3] = {{(int)a.rsp_r, POLLIN, 0}, {(int)a.out_r, POLLIN, 0}, {(int)a.err_r, POLLIN, 0}};
        sys3(SYS_poll, (long)p, 3, 1000);
        read_log(&a.out_r, MVA_STDOUT);
        read_log(&a.err_r, MVA_STDERR);
        read_runtime();
        reap();
    }
    if (a.ready_flags & MVA_READY_SNAPSHOT) {
        // Nothing but us may run between the snapshot point and the
        // reseed: stop every process (pid 1 is never signalled), and let
        // them go only after resume(). A stop signal is acted on before
        // the process next returns to user mode.
        sys3(SYS_kill, -1, SIGSTOP, 0);
        report_free_pages();
        if (ports)
            outb(PORT_SNAPSHOT, 1); // VMs restored from the snapshot continue here
        resume(rnd);
        sys3(SYS_kill, -1, SIGCONT, 0);
    } else if (rnd >= 0) {
        sys3(SYS_close, rnd, 0, 0);
    }

    // 2. Serve.
    for (;;) {
        struct pollfd p[5];
        int np = 0, ic = -1, ir = -1, io = -1, ie = -1;
        const u32 rm = room();
        if (a.conn < 0) {
            ic = np, p[np++] = (struct pollfd){(int)a.ls, POLLIN, 0};
        } else {
            short ev = a.o_start < a.o_end ? POLLOUT : 0;
            // Host bytes only when the last ones are forwarded.
            if (a.in_off == a.in_len)
                ev |= POLLIN;
            ic = np, p[np++] = (struct pollfd){(int)a.conn, ev, 0};
        }
        if (a.in_off < a.in_len)
            p[np++] = (struct pollfd){(int)a.inv_w, POLLOUT, 0};
        if (a.rsp_r >= 0 && rm >= RT_CAP + RESERVE)
            ir = np, p[np++] = (struct pollfd){(int)a.rsp_r, POLLIN, 0};
        if (a.out_r >= 0 && rm >= MVA_HDR + RESERVE + 4096)
            io = np, p[np++] = (struct pollfd){(int)a.out_r, POLLIN, 0};
        if (a.err_r >= 0 && rm >= MVA_HDR + RESERVE + 4096)
            ie = np, p[np++] = (struct pollfd){(int)a.err_r, POLLIN, 0};
        long wait = 1000;
        if (a.inflight && a.hs != H_DISCARD) {
            const u64 t = now_ns();
            wait = t >= a.deadline ? 0 : (long)((a.deadline - t) / 1000000ul) + 1;
            if (wait > 1000)
                wait = 1000;
        }
        long n = sys3(SYS_poll, (long)p, np, wait);
        if (n < 0 && n != -EINTR) {
            say("poll", nullptr, n);
            fatal(MVA_FAULT, 0);
        }
        if (ic >= 0 && a.conn < 0 && (p[ic].revents & POLLIN)) {
            const long c = sys6(SYS_accept4, a.ls, 0, 0, O_NONBLOCK | O_CLOEXEC, 0, 0);
            if (c >= 0) {
                a.conn = c;
                a.hs = H_HDR, a.hdr_have = 0;
                u8 b[16] = {0};
                put32(b, MVA_VERSION);
                put32(b + 4, a.served);
                emit(MVA_HELLO, 0, b, 16);
            }
        } else if (ic >= 0 && a.conn >= 0) {
            if ((p[ic].revents & (POLLIN | POLLHUP | POLLERR)) && !read_host())
                host_lost();
        }
        if (a.in_off < a.in_len)
            forward();
        if (io >= 0 && p[io].revents)
            read_log(&a.out_r, MVA_STDOUT);
        if (ie >= 0 && p[ie].revents)
            read_log(&a.err_r, MVA_STDERR);
        if (ir >= 0 && p[ir].revents)
            read_runtime();
        if (a.done_pending && logs_drained())
            finish(MVA_RETURNED, (int)a.rt_status, 0);
        if (a.inflight && a.hs != H_DISCARD && a.hs >= H_BODY && now_ns() >= a.deadline) {
            say_n("deadline passed: killing the runtime, invocation ", a.id);
            fatal(MVA_TIMEOUT, 0);
        }
        if (a.conn >= 0 && !flush())
            host_lost();
        if (n == 0 || (ir >= 0 && (p[ir].revents & POLLHUP)) || (io >= 0 && (p[io].revents & POLLHUP)))
            reap();
    }
}
