// SPDX-License-Identifier: MIT
// /bin/net-probe in the test root filesystem: the guest side of the
// virtio-net tests (tests/test_net.c). Freestanding like /bin/probe.
//
//   net-probe tcp ADDR PORT MSG     connect, send MSG, shut the sending side,
//                                   read the reply to EOF, print it
//   net-probe udp ADDR PORT MSG     send MSG as one datagram, print the reply
//                                   (2 s timeout)
//   net-probe dns NAME              an A query for NAME to 10.0.2.3:53, print
//                                   the answer's rcode and address count
//   net-probe refused ADDR PORT     expect the TCP connect to fail; print errno
//   net-probe echo ADDR PORT        connect and send back every byte until EOF
//   net-probe sink ADDR PORT        connect, read to EOF, then send the count
//   net-probe source ADDR PORT N    connect, send N bytes, shut the sending side,
//                                   wait for EOF
//   net-probe sleep MS              wait MS milliseconds
// Several commands may follow each other, separated by "+". Each prints one
// line "net-probe: ..."; the exit status is the number that failed.

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
    SYS_read = 0, SYS_write = 1, SYS_close = 3, SYS_poll = 7, SYS_socket = 41, SYS_connect = 42,
    SYS_sendto = 44, SYS_recvfrom = 45, SYS_shutdown = 48, SYS_exit = 60, SYS_nanosleep = 35,
};
enum { AF_INET = 2, SOCK_STREAM = 1, SOCK_DGRAM = 2, SHUT_WR = 1, POLLIN = 1, MSG_NOSIGNAL = 0x4000 };

struct sockaddr_in {
    unsigned short family, port;
    unsigned int addr;
    unsigned char zero[8];
};

struct pollfd {
    int fd;
    short events, revents;
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

static bool eq(const char *a, const char *b)
{
    while (*a && *a == *b)
        a++, b++;
    return *a == *b;
}

// "a.b.c.d" in network order.
static unsigned addr(const char *s)
{
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        unsigned o = 0;
        while (*s >= '0' && *s <= '9')
            o = o * 10 + (unsigned)(*s++ - '0');
        v |= (o & 255) << (8 * i);
        if (*s == '.')
            s++;
    }
    return v;
}

static struct sockaddr_in mkaddr(const char *a, const char *port)
{
    const unsigned p = (unsigned)num(port);
    return (struct sockaddr_in){.family = AF_INET, .port = (unsigned short)((p >> 8) | (p << 8)), .addr = addr(a)};
}

static char out[512];
static u64 olen;

static void put(const char *s)
{
    while (*s && olen < sizeof out - 2)
        out[olen++] = *s++;
}

static void putn(const char *s, long n)
{
    for (long i = 0; i < n && olen < sizeof out - 2; i++)
        out[olen++] = s[i] >= 32 && s[i] < 127 ? s[i] : '.';
}

static void putd(long v)
{
    char t[24];
    int k = 0;
    if (v < 0) {
        put("-");
        v = -v;
    }
    do
        t[k++] = (char)('0' + v % 10);
    while (v /= 10);
    while (k)
        out[olen < sizeof out - 2 ? olen++ : olen] = t[--k];
}

static void line(void)
{
    out[olen++] = '\n';
    sys3(SYS_write, 1, (long)out, (long)olen);
    olen = 0;
}

static char buf[65536];

static bool wait_in(long fd, int ms)
{
    struct pollfd p = {.fd = (int)fd, .events = POLLIN};
    return sys3(SYS_poll, (long)&p, 1, ms) == 1;
}

static long tcp_connect(const char *a, const char *port)
{
    const long s = sys3(SYS_socket, AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return s;
    const struct sockaddr_in sa = mkaddr(a, port);
    const long r = sys3(SYS_connect, s, (long)&sa, sizeof sa);
    if (r < 0) {
        sys3(SYS_close, s, 0, 0);
        return r;
    }
    return s;
}

static int cmd_tcp(char **a)
{
    put("net-probe: tcp ");
    const long s = tcp_connect(a[0], a[1]);
    if (s < 0) {
        put("connect failed: ");
        putd(s);
        line();
        return 1;
    }
    const long n = (long)slen(a[2]);
    if (sys6(SYS_sendto, s, (long)a[2], n, MSG_NOSIGNAL, 0, 0) != n) {
        put("send failed");
        line();
        return 1;
    }
    sys3(SYS_shutdown, s, SHUT_WR, 0);
    long got = 0;
    for (long r; got < (long)sizeof buf && (r = sys3(SYS_read, s, (long)(buf + got), (long)sizeof buf - got)) > 0;)
        got += r;
    sys3(SYS_close, s, 0, 0);
    put("reply: ");
    putn(buf, got);
    line();
    return 0;
}

static int cmd_udp(char **a)
{
    put("net-probe: udp ");
    const long s = sys3(SYS_socket, AF_INET, SOCK_DGRAM, 0);
    const struct sockaddr_in sa = mkaddr(a[0], a[1]);
    const long n = (long)slen(a[2]);
    if (s < 0 || sys6(SYS_sendto, s, (long)a[2], n, 0, (long)&sa, sizeof sa) != n) {
        put("send failed");
        line();
        return 1;
    }
    if (!wait_in(s, 2000)) {
        put("no reply");
        line();
        return 1;
    }
    const long r = sys6(SYS_recvfrom, s, (long)buf, sizeof buf, 0, 0, 0);
    sys3(SYS_close, s, 0, 0);
    put("reply: ");
    putn(buf, r > 0 ? r : 0);
    line();
    return r > 0 ? 0 : 1;
}

static int cmd_dns(char **a)
{
    put("net-probe: dns ");
    // Header: id 0x4d56, RD, one question.
    static unsigned char q[300] = {0x4d, 0x56, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    u64 n = 12;
    for (const char *s = a[0]; *s && n < 280;) {
        u64 k = 0;
        while (s[k] && s[k] != '.')
            k++;
        q[n++] = (unsigned char)k;
        for (u64 i = 0; i < k; i++)
            q[n++] = (unsigned char)s[i];
        s += k;
        if (*s == '.')
            s++;
    }
    q[n++] = 0;
    q[n++] = 0, q[n++] = 1; // A
    q[n++] = 0, q[n++] = 1; // IN
    const long s = sys3(SYS_socket, AF_INET, SOCK_DGRAM, 0);
    const struct sockaddr_in sa = mkaddr("10.0.2.3", "53");
    if (s < 0 || sys6(SYS_sendto, s, (long)q, (long)n, 0, (long)&sa, sizeof sa) != (long)n || !wait_in(s, 3000)) {
        put("no answer");
        line();
        return 1;
    }
    const long r = sys6(SYS_recvfrom, s, (long)buf, sizeof buf, 0, 0, 0);
    sys3(SYS_close, s, 0, 0);
    if (r < 12 || (unsigned char)buf[0] != 0x4d || (unsigned char)buf[1] != 0x56) {
        put("bad answer");
        line();
        return 1;
    }
    put("rcode ");
    putd(buf[3] & 15);
    put(" answers ");
    putd((unsigned char)buf[6] << 8 | (unsigned char)buf[7]);
    line();
    return 0;
}

static int cmd_refused(char **a)
{
    put("net-probe: refused ");
    const long s = tcp_connect(a[0], a[1]);
    if (s >= 0) {
        sys3(SYS_close, s, 0, 0);
        put("NO: connected");
        line();
        return 1;
    }
    put("yes, errno ");
    putd(-s);
    line();
    return 0;
}

static long connect_retry(char **a);

static int cmd_echo(char **a)
{
    const long s = connect_retry(a);
    put("net-probe: echo ");
    if (s < 0) {
        put("connect failed");
        line();
        return 1;
    }
    long total = 0;
    for (;;) {
        const long r = sys3(SYS_read, s, (long)buf, sizeof buf);
        if (r <= 0)
            break;
        total += r;
        bool hung = false; // the host hung up: stop
        for (long off = 0; off < r && !hung;) {
            const long w = sys6(SYS_sendto, s, (long)(buf + off), r - off, MSG_NOSIGNAL, 0, 0);
            hung = w <= 0;
            off += w;
        }
        if (hung)
            break;
    }
    sys3(SYS_shutdown, s, SHUT_WR, 0);
    sys3(SYS_close, s, 0, 0);
    putd(total);
    put(" bytes");
    line();
    return 0;
}

static long connect_retry(char **a)
{
    long s = -1;
    for (int i = 0; i < 400 && s < 0; i++) { // the host may not be listening yet
        s = tcp_connect(a[0], a[1]);
        if (s < 0) {
            const long ts[2] = {0, 5000000};
            sys3(35 /* nanosleep */, (long)ts, 0, 0);
        }
    }
    return s;
}

static int cmd_sink(char **a)
{
    const long s = connect_retry(a);
    put("net-probe: sink ");
    if (s < 0) {
        put("connect failed");
        line();
        return 1;
    }
    long total = 0;
    for (long r; (r = sys3(SYS_read, s, (long)buf, sizeof buf)) > 0;)
        total += r;
    char t[24];
    int k = 0, j = 0;
    char d[24];
    long v = total;
    do
        d[k++] = (char)('0' + v % 10);
    while (v /= 10);
    while (k)
        t[j++] = d[--k];
    t[j++] = '\n';
    sys6(SYS_sendto, s, (long)t, j, MSG_NOSIGNAL, 0, 0);
    sys3(SYS_close, s, 0, 0);
    putd(total);
    put(" bytes");
    line();
    return 0;
}

static int cmd_source(char **a)
{
    const long s = connect_retry(a);
    put("net-probe: source ");
    if (s < 0) {
        put("connect failed");
        line();
        return 1;
    }
    for (u64 i = 0; i < sizeof buf; i++)
        buf[i] = (char)(i * 131 + (i >> 9));
    long left = (long)num(a[2]), sent = 0;
    while (left > 0) {
        const long w = sys6(SYS_sendto, s, (long)buf, left < (long)sizeof buf ? left : (long)sizeof buf,
                            MSG_NOSIGNAL, 0, 0);
        if (w <= 0)
            break;
        left -= w;
        sent += w;
    }
    sys3(SYS_shutdown, s, SHUT_WR, 0);
    while (sys3(SYS_read, s, (long)buf, sizeof buf) > 0)
        ;
    sys3(SYS_close, s, 0, 0);
    putd(sent);
    put(" bytes");
    line();
    return left > 0;
}

[[noreturn]] void probe_main(long *sp);

[[noreturn]] void probe_main(long *sp)
{
    const long argc = sp[0];
    char **argv = (char **)(sp + 1);
    int fails = 0;
    for (long i = 1; i < argc;) {
        long end = i;
        while (end < argc && !eq(argv[end], "+"))
            end++;
        char **a = argv + i + 1;
        const long na = end - i - 1;
        const char *c = argv[i];
        if (eq(c, "tcp") && na == 3)
            fails += cmd_tcp(a);
        else if (eq(c, "udp") && na == 3)
            fails += cmd_udp(a);
        else if (eq(c, "dns") && na == 1)
            fails += cmd_dns(a);
        else if (eq(c, "refused") && na == 2)
            fails += cmd_refused(a);
        else if (eq(c, "echo") && na == 2)
            fails += cmd_echo(a);
        else if (eq(c, "sink") && na == 2)
            fails += cmd_sink(a);
        else if (eq(c, "source") && na == 3)
            fails += cmd_source(a);
        else if (eq(c, "sleep") && na == 1) {
            const u64 ms = num(a[0]);
            const long ts[2] = {(long)(ms / 1000), (long)(ms % 1000) * 1000000};
            sys3(SYS_nanosleep, (long)ts, 0, 0);
            put("net-probe: slept");
            line();
        }
        else {
            put("net-probe: bad command ");
            put(c);
            line();
            fails++;
        }
        i = end + 1;
    }
    for (;;)
        sys3(SYS_exit, fails, 0, 0);
}

__asm__(".globl _start\n"
        "_start:\n"
        "    mov %rsp, %rdi\n"
        "    and $-16, %rsp\n"
        "    call probe_main\n"
        "    hlt\n");
