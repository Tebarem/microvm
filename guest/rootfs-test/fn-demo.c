// SPDX-License-Identifier: MIT
// /bin/fn-demo in the test root filesystem: a function runtime for the
// guest agent (`init agent run /bin/fn-demo`; protocol in
// src/agent/proto.h). Freestanding like /bin/probe.
//
//   fn-demo [nosnap]
// warms up (reads /etc/message and builds a 1 MiB table: its "code"),
// sends READY (asking for the snapshot unless `nosnap`), then serves
// invocations forever. The invocation's first argument picks what to do:
//
//   echo            result = payload; one line on stdout and one on stderr
//   upper           result = payload in upper case
//   info            result = "n=<invocations so far> token=<warm-up checksum>
//                   random=<16 bytes from getrandom, hex> time=<s.ms>
//                   wof=<the MADV_WIPEONFORK byte warm-up set to 1: 0
//                   once a restore emptied it> message=<what warm-up
//                   read> args=<rest of args>"
//   env             result = the environment strings, one per line
//   status N        returns status N (result "status")
//   sleep MS        sleeps, then returns
//   spam N          N bytes on stdout and N on stderr
//   big N           an N-byte result
//   exit N          the runtime exits with N mid-invocation
//   crash           the runtime dies of SIGSEGV
//   badframe        writes a malformed frame on fd 3

#include "../../src/agent/proto.h"

typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned char u8;

static long sys3(long n, long a, long b, long c)
{
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
    long r;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return r;
}

enum {
    SYS_read = 0, SYS_write = 1, SYS_open = 2, SYS_close = 3, SYS_nanosleep = 35, SYS_getpid = 39,
    SYS_exit = 60, SYS_kill = 62, SYS_clock_gettime = 228, SYS_getrandom = 318, EINTR = 4,
};

void *memcpy(void *d, const void *s, unsigned long n);
void *memset(void *d, int c, unsigned long n);
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

[[noreturn]] static void quit(int st)
{
    for (;;)
        sys3(SYS_exit, st, 0, 0);
}

static bool read_full(long fd, u8 *p, u64 n)
{
    for (u64 off = 0; off < n;) {
        const long r = sys3(SYS_read, fd, (long)(p + off), (long)(n - off));
        if (r == -EINTR)
            continue;
        if (r <= 0)
            return false;
        off += (u64)r;
    }
    return true;
}

static void write_full(long fd, const void *p, u64 n)
{
    for (u64 off = 0; off < n;) {
        const long w = sys3(SYS_write, fd, (long)((const u8 *)p + off), (long)(n - off));
        if (w == -EINTR)
            continue;
        if (w <= 0)
            quit(1);
        off += (u64)w;
    }
}

static u32 le32(const u8 *p) { return (u32)p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24; }
static void put32(u8 *p, u32 v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (u8)(v >> (8 * i));
}

static void frame(u8 type, u32 id, const void *body, u32 len)
{
    u8 h[MVA_HDR];
    put32(h, MVA_MAGIC);
    h[4] = MVA_VERSION;
    h[5] = type;
    h[6] = h[7] = 0;
    put32(h + 8, id);
    put32(h + 12, len);
    write_full(3, h, sizeof h);
    if (len)
        write_full(3, body, len);
}

static u64 slen(const char *s)
{
    u64 k = 0;
    while (s[k])
        k++;
    return k;
}

static u64 num(const u8 *s, u32 n)
{
    u64 v = 0;
    for (u32 i = 0; i < n && s[i] >= '0' && s[i] <= '9'; i++)
        v = v * 10 + (u64)(s[i] - '0');
    return v;
}

// ---- warm-up state: in the snapshot, shared by every restore ---------------
static u8 table[1u << 20];
static u32 token;
static char message[128];
static u64 message_len;
static u64 invocations;

// A byte in a MADV_WIPEONFORK page, set at warm-up: how BoringSSL-style
// generators notice a fork, and (kernel patch 0039) a restore.
static volatile u8 *wof;

static void warm_up(void)
{
    const long p = sys6(9 /* mmap */, 0, 4096, 3 /* PROT_READ|WRITE */, 0x22 /* MAP_PRIVATE|ANONYMOUS */, -1, 0);
    if (p > 0 && sys3(28 /* madvise */, p, 4096, 18 /* MADV_WIPEONFORK */) == 0) {
        wof = (volatile u8 *)p;
        *wof = 1;
    }
    const long fd = sys3(SYS_open, (long)"/etc/message", 0, 0);
    if (fd >= 0) {
        const long n = sys3(SYS_read, fd, (long)message, sizeof message - 1);
        message_len = n > 0 ? (u64)n : 0;
        while (message_len && message[message_len - 1] == '\n')
            message_len--;
        sys3(SYS_close, fd, 0, 0);
    }
    u32 h = 2166136261u;
    for (u32 i = 0; i < sizeof table; i++) {
        table[i] = (u8)(i * 2654435761u >> 24);
        h = (h ^ table[i]) * 16777619u;
    }
    token = h;
}

// ---- one invocation ------------------------------------------------------------
static u8 body[MVA_MAX_INVOKE];
static u8 res[1u << 16];
static u64 res_n;
static u32 cur;

static void res_flush(void)
{
    if (res_n)
        frame(MVA_RESULT, cur, res, (u32)res_n);
    res_n = 0;
}

static void res_put(const void *p, u64 n)
{
    const u8 *b = p;
    while (n) {
        u64 k = sizeof res - res_n < n ? sizeof res - res_n : n;
        memcpy(res + res_n, b, k);
        res_n += k, b += k, n -= k;
        if (res_n == sizeof res)
            res_flush();
    }
}

static void res_str(const char *s) { res_put(s, slen(s)); }

static void res_dec(u64 v, int min)
{
    char d[24];
    int k = 0;
    while (k < min || v || k == 0) {
        d[k++] = (char)('0' + v % 10);
        v /= 10;
    }
    while (k)
        res_put(&d[--k], 1);
}

static void out_line(long fd, const char *a, u64 v)
{
    char b[96];
    u64 n = 0;
    for (; *a && n < 60; a++)
        b[n++] = *a;
    char d[24];
    int k = 0;
    do
        d[k++] = (char)('0' + v % 10);
    while (v /= 10);
    while (k)
        b[n++] = d[--k];
    b[n++] = '\n';
    write_full(fd, b, n);
}

static void done(int status)
{
    res_flush();
    u8 b[16] = {0};
    put32(b, MVA_RETURNED);
    put32(b + 4, (u32)status);
    frame(MVA_DONE, cur, b, 16);
}

static bool is(const u8 *s, u32 n, const char *w)
{
    const u64 k = slen(w);
    if (k != n)
        return false;
    for (u32 i = 0; i < n; i++)
        if (s[i] != (u8)w[i])
            return false;
    return true;
}

static void invoke(u32 len)
{
    // The fixed part, then the strings, all bounds-checked: the agent only
    // checked the fixed part.
    if (len < MVA_INVOKE_FIXED)
        quit(2);
    const u32 nargs = (u32)body[12] | (u32)body[13] << 8, nenv = (u32)body[14] | (u32)body[15] << 8;
    const u32 plen = le32(body + 16);
    static const u8 *str[2 * MVA_MAX_STRINGS];
    static u32 slen_[2 * MVA_MAX_STRINGS];
    u64 at = MVA_INVOKE_FIXED;
    if (nargs > MVA_MAX_STRINGS || nenv > MVA_MAX_STRINGS)
        quit(2);
    for (u32 i = 0; i < nargs + nenv; i++) {
        if (at + 4 > len)
            quit(2);
        const u32 n = le32(body + at);
        if (n > MVA_MAX_STRING || at + 4 + n > len)
            quit(2);
        str[i] = body + at + 4;
        slen_[i] = n;
        at += 4 + n;
    }
    if (at + plen != len)
        quit(2);
    const u8 *payload = body + at;
    invocations++;
    const u8 *cmd = nargs ? str[0] : (const u8 *)"echo";
    const u32 cn = nargs ? slen_[0] : 4;
    const u64 arg1 = nargs > 1 ? num(str[1], slen_[1]) : 0;
    if (is(cmd, cn, "echo")) {
        out_line(1, "echo: payload bytes ", plen);
        out_line(2, "echo: on stderr, invocation ", invocations);
        res_put(payload, plen);
        done(0);
    } else if (is(cmd, cn, "upper")) {
        for (u32 i = 0; i < plen; i++) {
            const u8 c = payload[i];
            const u8 u = c >= 'a' && c <= 'z' ? (u8)(c - 32) : c;
            res_put(&u, 1);
        }
        done(0);
    } else if (is(cmd, cn, "info")) {
        u8 rnd[16] = {0};
        sys3(SYS_getrandom, (long)rnd, sizeof rnd, 0);
        long ts[2] = {0, 0};
        sys3(SYS_clock_gettime, 0, (long)ts, 0);
        res_str("n=");
        res_dec(invocations, 1);
        res_str(" token=");
        res_dec(token, 1);
        res_str(" random=");
        for (int i = 0; i < 16; i++) {
            const char hx[2] = {"0123456789abcdef"[rnd[i] >> 4], "0123456789abcdef"[rnd[i] & 15]};
            res_put(hx, 2);
        }
        res_str(" time=");
        res_dec((u64)ts[0], 1);
        res_str(".");
        res_dec((u64)ts[1] / 1000000, 3);
        res_str(" wof=");
        res_dec(wof ? *wof : 9, 1);
        res_str(" message=");
        res_put(message, message_len);
        res_str(" args=");
        for (u32 i = 1; i < nargs; i++) {
            if (i > 1)
                res_str(",");
            res_put(str[i], slen_[i]);
        }
        done(0);
    } else if (is(cmd, cn, "env")) {
        for (u32 i = 0; i < nenv; i++) {
            res_put(str[nargs + i], slen_[nargs + i]);
            res_str("\n");
        }
        done(0);
    } else if (is(cmd, cn, "status")) {
        res_str("status");
        done((int)arg1);
    } else if (is(cmd, cn, "sleep")) {
        const long ts[2] = {(long)(arg1 / 1000), (long)(arg1 % 1000) * 1000000};
        sys3(SYS_nanosleep, (long)ts, 0, 0);
        res_str("slept");
        done(0);
    } else if (is(cmd, cn, "spam")) {
        static u8 junk[4096];
        memset(junk, 's', sizeof junk);
        for (int fd = 1; fd <= 2; fd++)
            for (u64 left = arg1; left;) {
                const u64 k = left < sizeof junk ? left : sizeof junk;
                write_full(fd, junk, k);
                left -= k;
            }
        done(0);
    } else if (is(cmd, cn, "big")) {
        for (u64 i = 0; i < arg1; i++) {
            const u8 c = (u8)('a' + i % 26);
            res_put(&c, 1);
        }
        done(0);
    } else if (is(cmd, cn, "exit")) {
        write_full(1, "exiting\n", 8);
        quit((int)arg1);
    } else if (is(cmd, cn, "crash")) {
        sys3(SYS_kill, sys3(SYS_getpid, 0, 0, 0), 11 /* SIGSEGV */, 0);
    } else if (is(cmd, cn, "badframe")) {
        frame(0x7e, cur, "x", 1);
        for (;;)
            sys3(SYS_nanosleep, (long)(const long[2]){1, 0}, 0, 0);
    } else {
        write_full(2, "fn-demo: unknown command\n", 25);
        done(64);
    }
}

[[noreturn]] void demo_main(long *sp);

[[noreturn]] void demo_main(long *sp)
{
    const long argc = sp[0];
    char **argv = (char **)(sp + 1);
    const bool snap = !(argc > 1 && argv[1][0] == 'n');
    warm_up();
    write_full(1, "fn-demo: warmed up\n", 19);
    u8 ready[4];
    put32(ready, snap ? MVA_READY_SNAPSHOT : 0);
    frame(MVA_READY, 0, ready, 4);
    for (;;) {
        u8 h[MVA_HDR];
        if (!read_full(0, h, sizeof h))
            quit(0); // the agent is gone
        const u32 len = le32(h + 12);
        if (le32(h) != MVA_MAGIC || h[4] != MVA_VERSION || h[5] != MVA_INVOKE || len > sizeof body ||
            !read_full(0, body, len))
            quit(2);
        cur = le32(h + 8);
        invoke(len);
    }
}

__asm__(".globl _start\n"
        "_start:\n"
        "    mov %rsp, %rdi\n"
        "    and $-16, %rsp\n"
        "    call demo_main\n"
        "    hlt\n");
