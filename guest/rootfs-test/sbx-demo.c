// SPDX-License-Identifier: MIT
// /bin/sbx-demo in the test root filesystem, for the sandbox agent's tests
// (tests/test_sbx.c). Freestanding like /init.
//
//   sbx-demo cat          copy stdin to stdout until its end, then exit 3
//   sbx-demo tty          print "tty COLSxROWS" (or "notty"), then echo
//                         input lines as "got: LINE" until "q"
//   sbx-demo spam N       write N bytes ('x') to stdout, then "end\n" to stderr
//   sbx-demo sleep MS     sleep, then print "slept"
//   sbx-demo serve PORT   a TCP server on 127.0.0.1:PORT: each connection
//                         gets "hello PORT\n", then its bytes echoed back
//   sbx-demo rand         16 random bytes (getrandom) as hex
//   sbx-demo spawn        start a child that sleeps an hour, print its pid
typedef unsigned long u64;

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
    SYS_read = 0, SYS_write = 1, SYS_close = 3, SYS_ioctl = 16, SYS_nanosleep = 35, SYS_socket = 41,
    SYS_accept = 43, SYS_bind = 49, SYS_listen = 50, SYS_setsockopt = 54, SYS_fork = 57, SYS_exit = 60,
    SYS_getrandom = 318,
};

static void out(int fd, const char *s, u64 n) { sys3(SYS_write, fd, (long)s, (long)n); }
static u64 len(const char *s)
{
    u64 n = 0;
    while (s[n])
        n++;
    return n;
}
static void say(const char *s) { out(1, s, len(s)); }
static bool is(const char *a, const char *b)
{
    while (*a && *a == *b)
        a++, b++;
    return *a == *b;
}
static u64 num(const char *s)
{
    u64 v = 0;
    while (*s >= '0' && *s <= '9')
        v = v * 10 + (u64)(*s++ - '0');
    return v;
}
static u64 fmt(char *b, u64 v)
{
    char t[24];
    int n = 0;
    do
        t[n++] = (char)('0' + v % 10);
    while (v /= 10);
    for (int i = 0; i < n; i++)
        b[i] = t[n - 1 - i];
    return (u64)n;
}
static void nap(long ms)
{
    const long ts[2] = {ms / 1000, (ms % 1000) * 1000000};
    sys3(SYS_nanosleep, (long)ts, 0, 0);
}

static int run(int argc, char **argv)
{
    static char buf[65536];
    if (argc < 2)
        return 2;
    const char *m = argv[1];
    if (is(m, "cat")) {
        for (long n; (n = sys3(SYS_read, 0, (long)buf, sizeof buf)) > 0;)
            out(1, buf, (u64)n);
        return 3;
    }
    if (is(m, "tty")) {
        unsigned short ws[4] = {0, 0, 0, 0};
        if (sys3(SYS_ioctl, 0, 0x5413 /* TIOCGWINSZ */, (long)ws) < 0) {
            say("notty\n");
        } else {
            u64 k = 0;
            k += fmt(buf + k, ws[1]);
            buf[k++] = 'x';
            k += fmt(buf + k, ws[0]);
            out(1, "tty ", 4);
            buf[k++] = '\n';
            out(1, buf, k);
        }
        u64 have = 0;
        for (long n; (n = sys3(SYS_read, 0, (long)(buf + have), (long)(sizeof buf - have))) > 0;) {
            have += (u64)n;
            for (u64 i = 0; i < have; i++) {
                if (buf[i] != '\n' && buf[i] != '\r')
                    continue;
                if (i == 1 && buf[0] == 'q')
                    return 0;
                out(1, "got: ", 5);
                out(1, buf, i);
                out(1, "\n", 1);
                for (u64 j = i + 1; j < have; j++)
                    buf[j - i - 1] = buf[j];
                have -= i + 1;
                i = (u64)-1;
            }
        }
        return 0;
    }
    if (is(m, "spam") && argc > 2) {
        for (u64 i = 0; i < sizeof buf; i++)
            buf[i] = 'x';
        for (u64 left = num(argv[2]); left;) {
            const u64 n = left < sizeof buf ? left : sizeof buf;
            long w = sys3(SYS_write, 1, (long)buf, (long)n);
            if (w <= 0)
                return 1;
            left -= (u64)w;
        }
        out(2, "end\n", 4);
        return 0;
    }
    if (is(m, "sleep") && argc > 2) {
        nap((long)num(argv[2]));
        say("slept\n");
        return 0;
    }
    if (is(m, "rand")) {
        unsigned char r[16];
        if (sys3(SYS_getrandom, (long)r, 16, 0) != 16)
            return 1;
        for (int i = 0; i < 16; i++) {
            buf[2 * i] = "0123456789abcdef"[r[i] >> 4];
            buf[2 * i + 1] = "0123456789abcdef"[r[i] & 15];
        }
        buf[32] = '\n';
        out(1, buf, 33);
        return 0;
    }
    if (is(m, "spawn")) {
        long pid = sys3(SYS_fork, 0, 0, 0);
        if (pid == 0) {
            nap(3600 * 1000);
            return 0;
        }
        u64 k = fmt(buf, (u64)pid);
        buf[k++] = '\n';
        out(1, buf, k);
        return 0;
    }
    if (is(m, "serve") && argc > 2) {
        const u64 port = num(argv[2]);
        const long s = sys3(SYS_socket, 2, 1, 0);
        const int one = 1;
        sys6(SYS_setsockopt, s, 1, 2 /* SO_REUSEADDR */, (long)&one, 4, 0);
        struct {
            unsigned short family, port;
            unsigned char addr[4], zero[8];
        } a = {2, (unsigned short)(port >> 8 | (port & 0xff) << 8), {127, 0, 0, 1}, {0}};
        if (s < 0 || sys3(SYS_bind, s, (long)&a, sizeof a) < 0 || sys3(SYS_listen, s, 8, 0) < 0)
            return 1;
        say("listening\n");
        for (;;) {
            const long c = sys3(SYS_accept, s, 0, 0);
            if (c < 0)
                continue;
            if (sys3(SYS_fork, 0, 0, 0) == 0) {
                u64 k = 0;
                for (const char *h = "hello "; *h; h++)
                    buf[k++] = *h;
                k += fmt(buf + k, port);
                buf[k++] = '\n';
                out((int)c, buf, k);
                for (long n; (n = sys3(SYS_read, c, (long)buf, sizeof buf)) > 0;)
                    out((int)c, buf, (u64)n);
                return 0;
            }
            sys3(SYS_close, c, 0, 0);
        }
    }
    return 2;
}

__asm__(".globl _start\n"
        "_start:\n"
        "    mov %rsp, %rdi\n"
        "    and $-16, %rsp\n"
        "    call demo_main\n"
        "    hlt\n");

[[noreturn]] void demo_main(long *sp);
[[noreturn]] void demo_main(long *sp)
{
    const int st = run((int)sp[0], (char **)(sp + 1));
    for (;;)
        sys3(SYS_exit, st, 0, 0);
}
