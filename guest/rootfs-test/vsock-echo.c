// SPDX-License-Identifier: MIT
// /bin/vsock-echo in the test root filesystem.
//
//   vsock-echo PORT [COUNT]
// listens on vsock port PORT, then COUNT times (default 1): accepts one
// connection and sends back every byte it reads until the host closes its
// side (or resets the connection). Prints "vsock-echo: COUNT connections,
// N bytes" (N: bytes read) and exits 0; a failure to listen or accept
// prints the step and exits 1.
//
//   vsock-echo -c PORT NOPORT MSG
// the other way round: checks that connecting to the host's port NOPORT is
// refused, connects to the host's port PORT (retrying for ~2 s while the
// host gets ready), sends MSG, shuts its side, reads the reply to EOF and
// prints "vsock-echo: refused NOPORT; reply: REPLY". Freestanding like
// /bin/probe.

typedef unsigned long u64;

static long sys3(long n, long a, long b, long c)
{
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

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

enum {
    SYS_sendto = 44, MSG_NOSIGNAL = 0x4000,
    SYS_read = 0, SYS_write = 1, SYS_close = 3, SYS_socket = 41, SYS_accept = 43,
    SYS_shutdown = 48, SYS_bind = 49, SYS_listen = 50, SYS_exit = 60, SYS_nanosleep = 35,
    SYS_connect = 42,
};
enum { AF_VSOCK = 40, SOCK_STREAM = 1, SHUT_WR = 1 };

struct sockaddr_vm {
    unsigned short family, reserved;
    unsigned int port, cid;
    unsigned char flags, zero[3];
};

static u64 slen(const char *s)
{
    u64 k = 0;
    while (s[k])
        k++;
    return k;
}

static u64 num(const char *s)
{
    u64 v = 0;
    for (; *s >= '0' && *s <= '9'; s++)
        v = v * 10 + (u64)(*s - '0');
    return v;
}

static char *fmt(char *p, u64 v)
{
    char t[24];
    int k = 0;
    do
        t[k++] = (char)('0' + v % 10);
    while (v /= 10);
    while (k)
        *p++ = t[--k];
    return p;
}

[[noreturn]] static void fail(const char *what)
{
    sys3(SYS_write, 2, (long)"vsock-echo: failed: ", 20);
    sys3(SYS_write, 2, (long)what, (long)slen(what));
    sys3(SYS_write, 2, (long)"\n", 1);
    for (;;)
        sys3(SYS_exit, 1, 0, 0);
}

static char buf[65536];

static long connect_host(unsigned port)
{
    const long s = sys3(SYS_socket, AF_VSOCK, SOCK_STREAM, 0);
    if (s < 0)
        fail("socket");
    const struct sockaddr_vm a = {.family = AF_VSOCK, .port = port, .cid = 2};
    const long r = sys3(SYS_connect, s, (long)&a, sizeof a);
    if (r < 0) {
        sys3(SYS_close, s, 0, 0);
        return r;
    }
    return s;
}

static void put(char **p, const char *t)
{
    while (*t)
        *(*p)++ = *t++;
}

[[noreturn]] static void client(long argc, char **argv)
{
    if (argc < 5)
        fail("usage: vsock-echo -c PORT NOPORT MSG");
    if (connect_host((unsigned)num(argv[3])) >= 0)
        fail("a connection to a port nobody listens on was accepted");
    long s = -1;
    for (int i = 0; i < 400 && s < 0; i++) { // the host may not be listening yet
        s = connect_host((unsigned)num(argv[2]));
        if (s < 0) {
            const long ts[2] = {0, 5000000};
            sys3(SYS_nanosleep, (long)ts, 0, 0);
        }
    }
    if (s < 0)
        fail("connect");
    const char *msg = argv[4];
    if (sys3(SYS_write, s, (long)msg, (long)slen(msg)) != (long)slen(msg))
        fail("write");
    sys3(SYS_shutdown, s, SHUT_WR, 0);
    long n = 0;
    for (long r; n < (long)sizeof buf - 1 && (r = sys3(SYS_read, s, (long)(buf + n), (long)sizeof buf - 1 - n)) > 0;)
        n += r;
    buf[n] = 0;
    char out[256], *p = out;
    put(&p, "vsock-echo: refused ");
    put(&p, argv[3]);
    put(&p, "; reply: ");
    for (long i = 0; i < n && p < out + sizeof out - 2; i++)
        *p++ = buf[i];
    *p++ = '\n';
    sys3(SYS_write, 1, (long)out, p - out);
    for (;;)
        sys3(SYS_exit, 0, 0, 0);
}

[[noreturn]] void echo_main(long *sp);

[[noreturn]] void echo_main(long *sp)
{
    const long argc = sp[0];
    char **argv = (char **)(sp + 1);
    if (argc < 2)
        fail("usage: vsock-echo PORT [COUNT]");
    if (argv[1][0] == '-' && argv[1][1] == 'c')
        client(argc, argv);
    const u64 count = argc > 2 ? num(argv[2]) : 1;
    const long s = sys3(SYS_socket, AF_VSOCK, SOCK_STREAM, 0);
    if (s < 0)
        fail("socket");
    struct sockaddr_vm a = {.family = AF_VSOCK, .port = (unsigned)num(argv[1]), .cid = 0xffffffffu};
    if (sys3(SYS_bind, s, (long)&a, sizeof a) < 0)
        fail("bind");
    if (sys3(SYS_listen, s, 4, 0) < 0)
        fail("listen");
    u64 total = 0;
    for (u64 i = 0; i < count; i++) {
        const long c = sys3(SYS_accept, s, 0, 0);
        if (c < 0)
            fail("accept");
        for (;;) {
            // A reset (the host hung up without reading) ends the
            // connection like EOF does; the host checks the bytes.
            const long r = sys3(SYS_read, c, (long)buf, sizeof buf);
            if (r <= 0)
                break;
            total += (u64)r;
            long off = 0;
            while (off < r) {
                // A host that hung up must end the connection, not us.
                const long w = sys6(SYS_sendto, c, (long)(buf + off), r - off, MSG_NOSIGNAL, 0, 0);
                if (w <= 0)
                    break;
                off += w;
            }
            if (off < r)
                break;
        }
        sys3(SYS_shutdown, c, SHUT_WR, 0);
        sys3(SYS_close, c, 0, 0);
    }
    char msg[96] = "vsock-echo: ", *p = msg + 12;
    p = fmt(p, count);
    for (const char *t = " connections, "; *t; t++)
        *p++ = *t;
    p = fmt(p, total);
    for (const char *t = " bytes\n"; *t; t++)
        *p++ = *t;
    sys3(SYS_write, 1, (long)msg, p - msg);
    for (;;)
        sys3(SYS_exit, 0, 0, 0);
}

__asm__(".globl _start\n"
        "_start:\n"
        "    mov %rsp, %rdi\n"
        "    and $-16, %rsp\n"
        "    call echo_main\n"
        "    hlt\n");
