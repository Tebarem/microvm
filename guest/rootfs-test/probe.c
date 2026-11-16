// SPDX-License-Identifier: MIT
// /bin/probe in the test root filesystem (guest/kernel/build.sh packs it
// into out/test-layer.tar; ctest builds an image from it and boots it).
//
//   probe [STATUS] [WORD...]
// prints "probe: [WORD]... message: <contents of /etc/message>" on stdout,
// "probe: stderr" on stderr, and exits with STATUS (decimal, default 0).
// A WORD "random" also prints the kernel's AT_RANDOM bytes for this exec
// as " random: <hex>", and "time" the wall clock as " time: <s>.<ms>"
// (the snapshot test checks that restored VMs differ and are on time).
// For the image-config tests: "id" prints " id: uid=U gid=G groups=A,B",
// "cwd" the working directory, "env:NAME" " NAME=value" (or " NAME unset"),
// "write:PATH" creates PATH with "written\n" in it, and "read:PATH" prints
// its first line, each as " PATH: ..." with "error N" if it fails.
// "cpus" prints " cpus: N ran on: M": the CPUs this process may run on,
// and on how many of them it ran, moving to each in turn (the SMP tests).
// Freestanding like /init: no libc, so the test needs nothing but gcc.

typedef unsigned long u64;

static long sys3(long n, long a, long b, long c)
{
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

enum {
    SYS_read = 0, SYS_write = 1, SYS_open = 2, SYS_close = 3, SYS_exit = 60, SYS_getcwd = 79,
    SYS_getgroups = 115, SYS_getresuid = 118, SYS_getresgid = 120, SYS_sched_setaffinity = 203,
    SYS_sched_getaffinity = 204, SYS_clock_gettime = 228, SYS_getcpu = 309,
};
enum { AT_RANDOM = 25 };

static char out[4096];
static u64 n;

static void put(const char *s, u64 len)
{
    for (u64 i = 0; i < len && n < sizeof out; i++)
        out[n++] = s[i];
}

static u64 slen(const char *s)
{
    u64 k = 0;
    while (s[k])
        k++;
    return k;
}

static bool streq(const char *a, const char *b)
{
    while (*a && *a == *b)
        a++, b++;
    return *a == *b;
}

static void put_dec(u64 v, int min_digits)
{
    char d[20];
    int k = 0;
    while (k < min_digits || v || k == 0) {
        d[k++] = (char)('0' + v % 10);
        v /= 10;
    }
    while (k)
        put(&d[--k], 1);
}

static bool prefix(const char *s, const char *p, const char **rest)
{
    while (*p && *s == *p)
        s++, p++;
    *rest = s;
    return !*p;
}

static void put_err(long r)
{
    put("error ", 6);
    put_dec((u64)-r, 1);
}

[[noreturn]] void probe_main(long *sp);

[[noreturn]] void probe_main(long *sp)
{
    const long argc = sp[0];
    char **argv = (char **)(sp + 1);
    long status = 0;
    long first = 1;
    if (argc > 1 && argv[1][0] >= '0' && argv[1][0] <= '9') {
        for (const char *c = argv[1]; *c >= '0' && *c <= '9'; c++)
            status = status * 10 + (*c - '0');
        first = 2;
    }
    put("probe:", 6);
    for (long i = first; i < argc; i++) {
        put(" [", 2);
        put(argv[i], slen(argv[i]));
        put("]", 1);
    }
    const char *arg;
    for (long i = first; i < argc; i++) {
        if (streq(argv[i], "random")) {
            long *p = sp + 1 + argc + 1;
            while (*p) // envp
                p++;
            for (p++; p[0]; p += 2) // auxv
                if (p[0] == AT_RANDOM) {
                    const unsigned char *r = (const unsigned char *)p[1];
                    put(" random: ", 9);
                    for (int k = 0; k < 16; k++)
                        put(&"0123456789abcdef"[r[k] >> 4], 1), put(&"0123456789abcdef"[r[k] & 15], 1);
                }
        } else if (streq(argv[i], "time")) {
            long ts[2] = {0, 0};
            sys3(SYS_clock_gettime, 0, (long)ts, 0);
            put(" time: ", 7);
            put_dec((u64)ts[0], 1);
            put(".", 1);
            put_dec((u64)ts[1] / 1000000, 3);
        } else if (streq(argv[i], "id")) {
            unsigned r[3], g[3], gs[64];
            sys3(SYS_getresuid, (long)&r[0], (long)&r[1], (long)&r[2]);
            sys3(SYS_getresgid, (long)&g[0], (long)&g[1], (long)&g[2]);
            const long ng = sys3(SYS_getgroups, 64, (long)gs, 0);
            put(" id: uid=", 9);
            put_dec(r[0], 1);
            put(" gid=", 5);
            put_dec(g[0], 1);
            put(" groups=", 8);
            for (long k = 0; k < ng; k++) {
                if (k)
                    put(",", 1);
                put_dec(gs[k], 1);
            }
        } else if (streq(argv[i], "cpus")) {
            u64 mask[2] = {0, 0}, n = 0, ran = 0;
            const long r = sys3(SYS_sched_getaffinity, 0, sizeof mask, (long)mask);
            for (unsigned c = 0; r > 0 && c < 128; c++) {
                if (!(mask[c / 64] >> (c % 64) & 1))
                    continue;
                n++;
                u64 one[2] = {0, 0};
                one[c / 64] = 1ul << (c % 64);
                unsigned cpu = ~0u;
                if (!sys3(SYS_sched_setaffinity, 0, sizeof one, (long)one) &&
                    !sys3(SYS_getcpu, (long)&cpu, 0, 0) && cpu == c)
                    ran++;
            }
            put(" cpus: ", 7);
            put_dec(n, 1);
            put(" ran on: ", 9);
            put_dec(ran, 1);
        } else if (streq(argv[i], "cwd")) {
            char d[256];
            const long r = sys3(SYS_getcwd, (long)d, sizeof d, 0);
            put(" cwd: ", 6);
            if (r > 0)
                put(d, (u64)r - 1);
            else
                put_err(r);
        } else if (prefix(argv[i], "env:", &arg)) {
            const char *v = nullptr;
            for (char **e = argv + argc + 1; *e && !v; e++) {
                const char *rest;
                if (prefix(*e, arg, &rest) && *rest == '=')
                    v = *e;
            }
            put(" ", 1);
            if (v) {
                put(v, slen(v));
            } else {
                put(arg, slen(arg));
                put(" unset", 6);
            }
        } else if (prefix(argv[i], "write:", &arg) || prefix(argv[i], "read:", &arg)) {
            const bool wr = argv[i][0] == 'w';
            put(" ", 1);
            put(arg, slen(arg));
            put(": ", 2);
            const long fd = sys3(SYS_open, (long)arg, wr ? 01101 /* O_WRONLY|O_CREAT|O_TRUNC */ : 0, 0644);
            long r = fd;
            if (fd >= 0) {
                char b[128];
                r = wr ? sys3(SYS_write, fd, (long)"written\n", 8) : sys3(SYS_read, fd, (long)b, sizeof b);
                if (!wr && r >= 0) {
                    long k = 0;
                    while (k < r && b[k] != '\n')
                        k++;
                    put(b, (u64)k);
                } else if (r >= 0) {
                    put("ok", 2);
                }
                sys3(SYS_close, fd, 0, 0);
            }
            if (r < 0)
                put_err(r);
        }
    }
    put(" message: ", 10);
    long fd = sys3(SYS_open, (long)"/etc/message", 0, 0);
    if (fd >= 0) {
        long r = sys3(SYS_read, fd, (long)(out + n), (long)(sizeof out - n));
        if (r > 0)
            n += (u64)r;
    } else {
        put("(none)\n", 7);
    }
    sys3(SYS_write, 1, (long)out, (long)n);
    sys3(SYS_write, 2, (long)"probe: stderr\n", 14);
    for (;;)
        sys3(SYS_exit, status & 0xff, 0, 0);
}

__asm__(".globl _start\n"
        "_start:\n"
        "    mov %rsp, %rdi\n"
        "    and $-16, %rsp\n"
        "    call probe_main\n"
        "    hlt\n");
