// SPDX-License-Identifier: MIT
// virtio-net end to end, Windows hosts (test_net.c is the Linux one; this
// covers the same ground minus snapshots and the jail, which WHP doesn't
// have), and the egress policy.
//
//   mvm_net_tests --policy                      the policy alone (no VM)
//   mvm_net_tests MICROVM VMLINUX IMAGE [--bench]
//
// The test's own servers listen on 127.0.0.1, which the guest reaches as
// 10.0.2.2 with --net-allow 127.0.0.1/32 (and only then): a TCP server that
// answers what it read, a UDP echo, and a resolver for --net-dns. Booted:
// - /bin/net-probe: a TCP exchange, a UDP echo, a DNS query through
//   10.0.2.3, and refusals (cloud metadata, a closed port, a private
//   range);
// - the same without --net-allow: the host's loopback is refused;
// - the host's own address: refused by the policy (the --stats file tells);
// - net-probe echo: round trips and bulk data both ways at once;
// - limits: a denied port, --net-max-dests, --net-tx-rate, and the --stats
//   file that counts them.
// Nothing here listens anywhere but on loopback.
// Exits 77 (skipped) where the VMM can't run a guest.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
// after winsock2.h
#include <windows.h>
#include <ws2tcpip.h>

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net_helper.h"

static int fails;

static void check(bool ok, const char *what)
{
    printf("  %-62s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok)
        fails++;
}

static double now_ms(void)
{
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart * 1e3 / (double)f.QuadPart;
}

#include "net_policy_tests.h"

// ---- the host's servers -----------------------------------------------------------------
static SOCKET lst_reply, lst_echo, udp_echo, udp_dns;
static uint16_t p_reply, p_echo, p_udp, p_dns, p_closed;
static atomic_int n_reply, n_dns;

// A socket on 127.0.0.1 (listening, if it is a stream one) that the VMs
// this test starts don't inherit.
static SOCKET bound(int type, uint16_t *port)
{
    const SOCKET fd = WSASocketW(AF_INET, type, 0, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int len = sizeof a;
    if (fd == INVALID_SOCKET || bind(fd, (struct sockaddr *)&a, sizeof a) ||
        getsockname(fd, (struct sockaddr *)&a, &len))
        return INVALID_SOCKET;
    *port = ntohs(a.sin_port);
    if (type == SOCK_STREAM && listen(fd, 16))
        return INVALID_SOCKET;
    return fd;
}

static bool readable(SOCKET fd, int ms)
{
    WSAPOLLFD p = {.fd = fd, .events = POLLRDNORM};
    return WSAPoll(&p, 1, ms) > 0;
}

static void serve_reply(SOCKET c)
{
    char buf[4096];
    size_t n = 0;
    while (n < sizeof buf - 16 && readable(c, 3000)) {
        const int r = recv(c, buf + n, (int)(sizeof buf - 16 - n), 0);
        if (r <= 0)
            break;
        n += (size_t)r;
    }
    char out[4200];
    const int k = snprintf(out, sizeof out, "host got: %.*s", (int)n, buf);
    (void)send(c, out, k, 0);
    closesocket(c);
}

static void serve_dns(void)
{
    uint8_t q[512];
    struct sockaddr_in from;
    int fl = sizeof from;
    const int n = recvfrom(udp_dns, (char *)q, sizeof q - 16, 0, (struct sockaddr *)&from, &fl);
    if (n < 17)
        return;
    n_dns++;
    uint8_t a[600];
    memcpy(a, q, (size_t)n);
    a[2] = 0x81, a[3] = 0x80; // a response, recursion available, no error
    a[6] = 0, a[7] = 1;       // one answer: example.com A 192.0.2.1
    a[8] = a[9] = a[10] = a[11] = 0;
    static const uint8_t ans[] = {0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1};
    memcpy(a + n, ans, sizeof ans);
    (void)sendto(udp_dns, (const char *)a, n + (int)sizeof ans, 0, (struct sockaddr *)&from, fl);
}

static DWORD WINAPI servers(void *arg)
{
    (void)arg;
    for (;;) {
        WSAPOLLFD p[3] = {{lst_reply, POLLRDNORM, 0}, {udp_echo, POLLRDNORM, 0}, {udp_dns, POLLRDNORM, 0}};
        if (WSAPoll(p, 3, -1) <= 0)
            continue;
        if (p[0].revents & POLLRDNORM) {
            const SOCKET c = accept(lst_reply, nullptr, nullptr);
            if (c != INVALID_SOCKET) {
                n_reply++;
                serve_reply(c);
            }
        }
        if (p[1].revents & POLLRDNORM) {
            static uint8_t b[65536];
            struct sockaddr_in from;
            int fl = sizeof from;
            const int n = recvfrom(udp_echo, (char *)b + 11, sizeof b - 11, 0, (struct sockaddr *)&from, &fl);
            if (n >= 0) {
                memcpy(b, "udp echo: ", 10);
                memmove(b + 10, b + 11, (size_t)n);
                (void)sendto(udp_echo, (const char *)b, n + 10, 0, (struct sockaddr *)&from, fl);
            }
        }
        if (p[2].revents & POLLRDNORM)
            serve_dns();
    }
    return 0;
}

// An IPv4 address of this host that isn't loopback, preferring a public one.
static bool host_addr(char *out, size_t len)
{
    char name[256];
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *res;
    if (gethostname(name, sizeof name) || getaddrinfo(name, nullptr, &hints, &res))
        return false;
    bool found = false, public_ = false;
    for (const struct addrinfo *i = res; i; i = i->ai_next) {
        const uint8_t *a = (const uint8_t *)&((const struct sockaddr_in *)i->ai_addr)->sin_addr;
        if (a[0] == 127)
            continue;
        const bool pub = a[0] != 10 && !(a[0] == 172 && (a[1] & 0xf0) == 16) && !(a[0] == 192 && a[1] == 168) &&
                         !(a[0] == 100 && (a[1] & 0xc0) == 64) && !(a[0] == 169 && a[1] == 254);
        if (!found || (pub && !public_)) {
            inet_ntop(AF_INET, a, out, len);
            found = true;
            public_ = pub;
        }
    }
    freeaddrinfo(res);
    return found;
}

// ---- VMs ---------------------------------------------------------------------------------------
static char dir[MAX_PATH];
static char **vm; // MICROVM VMLINUX IMAGE, at 1 to 3
static HANDLE job; // the VMs die with the test

static void path_in_dir(char *out, size_t cap, const char *name)
{
    if (snprintf(out, cap, "%s\\%s", dir, name) >= (int)cap)
        exit(1);
}

// Start the VMM (--net and `tail`) with its output in out_path. Returns the
// process, or nullptr.
static HANDLE spawn(const char *const *tail, const char *out_path)
{
    char line[4096];
    int n = snprintf(line, sizeof line, "\"%s\" --kernel \"%s\" --quiet --rootfs \"%s\" --net", vm[1], vm[2], vm[3]);
    for (; *tail && n < (int)sizeof line; tail++)
        n += snprintf(line + n, sizeof line - (size_t)n, " \"%s\"", *tail);
    if (n >= (int)sizeof line)
        return nullptr;
    SECURITY_ATTRIBUTES sa = {.nLength = sizeof sa, .bInheritHandle = TRUE};
    const HANDLE out = CreateFileA(out_path, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
    if (out == INVALID_HANDLE_VALUE)
        return nullptr;
    STARTUPINFOA si = {.cb = sizeof si, .dwFlags = STARTF_USESTDHANDLES, .hStdOutput = out,
                       .hStdError = GetStdHandle(STD_ERROR_HANDLE), .hStdInput = INVALID_HANDLE_VALUE};
    PROCESS_INFORMATION pi;
    const BOOL ok = CreateProcessA(nullptr, line, nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi);
    CloseHandle(out);
    if (!ok)
        return nullptr;
    AssignProcessToJobObject(job, pi.hProcess);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

// Wait for the VMM, read what it printed. Returns its exit status (-1: it
// had to be killed).
static int wait_vm(HANDLE proc, const char *out_path, char *out, size_t cap, DWORD timeout_ms)
{
    DWORD st = (DWORD)-1;
    memset(out, 0, cap);
    if (!proc)
        return -1;
    if (WaitForSingleObject(proc, timeout_ms) != WAIT_OBJECT_0) {
        printf("  (the VM was still running after %lu s: killed)\n", (unsigned long)timeout_ms / 1000);
        TerminateProcess(proc, 1);
        WaitForSingleObject(proc, INFINITE);
    } else {
        GetExitCodeProcess(proc, &st);
    }
    CloseHandle(proc);
    FILE *f = fopen(out_path, "rb");
    if (f) {
        (void)!fread(out, 1, cap - 1, f);
        fclose(f);
    }
    DeleteFileA(out_path);
    return (int)st;
}

static SOCKET accept_timeout(SOCKET l, int ms)
{
    if (!readable(l, ms))
        return INVALID_SOCKET;
    const SOCKET c = accept(l, nullptr, nullptr);
    const DWORD give_up = 5000; // reads and writes
    if (c != INVALID_SOCKET) {
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&give_up, sizeof give_up);
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, (const char *)&give_up, sizeof give_up);
    }
    return c;
}

// Send `n` patterned bytes while reading them back.
static bool bulk(SOCKET fd, size_t n, double *ms)
{
    uint8_t *o = malloc(n), *in = malloc(n);
    for (size_t i = 0; i < n; i++)
        o[i] = (uint8_t)(i * 131 + (i >> 9));
    size_t sent = 0, got = 0;
    u_long on = 1, off = 0;
    ioctlsocket(fd, (long)FIONBIO, &on);
    const double t0 = now_ms();
    bool ok = true;
    while (ok && got < n) {
        WSAPOLLFD p = {.fd = fd, .events = (SHORT)(POLLRDNORM | (sent < n ? POLLWRNORM : 0))};
        if (WSAPoll(&p, 1, 5000) <= 0) {
            ok = false;
            break;
        }
        if ((p.revents & POLLWRNORM) && sent < n) {
            const int w = send(fd, (const char *)o + sent, (int)(n - sent > 262144 ? 262144 : n - sent), 0);
            if (w > 0)
                sent += (size_t)w;
        }
        if (p.revents & (POLLRDNORM | POLLHUP | POLLERR)) {
            const int r = recv(fd, (char *)in + got, (int)(n - got > (1 << 20) ? 1 << 20 : n - got), 0);
            if (r > 0)
                got += (size_t)r;
            else if (r == 0 || WSAGetLastError() != WSAEWOULDBLOCK)
                ok = false;
        }
    }
    *ms = now_ms() - t0;
    ioctlsocket(fd, (long)FIONBIO, &off);
    ok = ok && !memcmp(o, in, n);
    free(o);
    free(in);
    return ok;
}

// --stats FILE: the last line the VMM wrote, as name/number pairs.
static unsigned long long stat_of(const char *path, const char *name)
{
    char b[256] = {0}, key[32];
    FILE *f = fopen(path, "rb");
    if (!f)
        return ~0ull;
    (void)!fread(b, 1, sizeof b - 1, f);
    fclose(f);
    unsigned long long v;
    int used;
    for (const char *s = b; sscanf(s, "%31s %llu%n", key, &v, &used) == 2; s += used)
        if (!strcmp(key, name))
            return v;
    return ~0ull;
}

static int count(const char *out, const char *what)
{
    int n = 0;
    for (const char *s = out; (s = strstr(s, what)); s++)
        n++;
    return n;
}

static void probe_vm(void)
{
    char out_path[MAX_PATH], out[2048];
    path_in_dir(out_path, sizeof out_path, "out1");
    char dns[32], pr[8], pu[8], pc[8];
    snprintf(dns, sizeof dns, "127.0.0.1:%u", p_dns);
    snprintf(pr, sizeof pr, "%u", p_reply);
    snprintf(pu, sizeof pu, "%u", p_udp);
    snprintf(pc, sizeof pc, "%u", p_closed);
    const char *tail[] = {"--net-allow", "127.0.0.1/32", "--net-dns", dns, "--",
                          "/bin/net-probe", "tcp", "10.0.2.2", pr, "hello-from-the-guest",
                          "+", "udp", "10.0.2.2", pu, "ping",
                          "+", "dns", "example.com",
                          "+", "refused", "169.254.169.254", "80",
                          "+", "refused", "10.0.2.2", pc,
                          "+", "refused", "192.168.1.1", "80",
                          nullptr};
    const int st = wait_vm(spawn(tail, out_path), out_path, out, sizeof out, 10000);
    if (st == 77) {
        printf("skipped: %s", out);
        RemoveDirectoryA(dir);
        exit(77);
    }
    printf("allowed loopback, the test's resolver:\n");
    check(strstr(out, "net-probe: tcp reply: host got: hello-from-the-guest\n") && n_reply == 1,
          "TCP: the host server got the message, the guest its reply");
    check(strstr(out, "net-probe: udp reply: udp echo: ping\n"), "UDP: echoed");
    check(strstr(out, "net-probe: dns rcode 0 answers 1\n") && n_dns == 1, "DNS through 10.0.2.3 to --net-dns");
    const int refused = count(out, "net-probe: refused yes");
    check(refused == 3, "refused: metadata, a closed port, a private range");
    check(st == 0, "the guest exits 0");
    if (st != 0 || refused != 3)
        printf("  guest said:\n%s\n", out);
}

// The host's own address (and so what listens on 0.0.0.0) is refused by the
// policy, not by the host: nothing here listens on it, so the counters tell
// the two apart. They are written every 2 s: the guest stays that long.
static void host_addr_vm(void)
{
    char host[64] = "", out_path[MAX_PATH], stats[MAX_PATH], out[1024], pc[8];
    path_in_dir(out_path, sizeof out_path, "out5");
    path_in_dir(stats, sizeof stats, "stats5");
    snprintf(pc, sizeof pc, "%u", p_closed);
    printf("the host's own address:\n");
    if (!host_addr(host, sizeof host)) {
        printf("  (this host has none but loopback: not checked)\n");
        return;
    }
    const char *tail[] = {"--net-allow", "127.0.0.1/32", "--stats", stats, "--",
                          "/bin/net-probe", "refused", host, "80",
                          "+", "refused", "10.0.2.2", pc,
                          "+", "sleep", "2300", nullptr};
    const int st = wait_vm(spawn(tail, out_path), out_path, out, sizeof out, 10000);
    printf("  (%s)\n", host);
    check(st == 0 && count(out, "net-probe: refused yes") == 2, "refused, like a closed port on loopback");
    check(stat_of(stats, "refused") == 1 && stat_of(stats, "flows") == 1,
          "--stats: the policy refused one; the closed port got as far as the host");
    if (st != 0)
        printf("  guest said:\n%s\n", out);
    DeleteFileA(stats);
}

static void no_allow_vm(void)
{
    char out_path[MAX_PATH], out[1024], pr[8];
    path_in_dir(out_path, sizeof out_path, "out2");
    snprintf(pr, sizeof pr, "%u", p_reply);
    const char *tail[] = {"--", "/bin/net-probe", "refused", "10.0.2.2", pr, nullptr};
    const int before = n_reply;
    const int st = wait_vm(spawn(tail, out_path), out_path, out, sizeof out, 10000);
    printf("default policy:\n");
    check(st == 0 && strstr(out, "net-probe: refused yes, errno 111"), "the host's loopback is refused");
    check(n_reply == before, "... and the host server saw nothing");
}

static void echo_vm(bool bench)
{
    char out_path[MAX_PATH], out[1024], pe[8];
    path_in_dir(out_path, sizeof out_path, "out3");
    snprintf(pe, sizeof pe, "%u", p_echo);
    const char *tail[] = {"--net-allow", "127.0.0.1/32", "--", "/bin/net-probe", "echo", "10.0.2.2", pe, nullptr};
    const double t0 = now_ms();
    const HANDLE proc = spawn(tail, out_path);
    const SOCKET c = accept_timeout(lst_echo, 5000);
    const double t_conn = now_ms() - t0;
    printf("echo:\n");
    check(c != INVALID_SOCKET, "the guest connected to the host");
    double rtt_us = 0, bulk_ms = 0;
    const size_t big = bench ? 64u << 20 : 8u << 20;
    const int rounds = bench ? 5000 : 500;
    if (c != INVALID_SOCKET) {
        const int nodelay = 1;
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof nodelay);
        char b = 'x';
        bool ok = true;
        const double r0 = now_ms();
        for (int i = 0; ok && i < rounds; i++)
            ok = send(c, &b, 1, 0) == 1 && recv(c, &b, 1, 0) == 1;
        rtt_us = (now_ms() - r0) * 1000 / rounds;
        check(ok, "1-byte round trips");
        check(bulk(c, big, &bulk_ms), "bulk both ways at once, intact");
        shutdown(c, SD_SEND);
        char e;
        check(recv(c, &e, 1, 0) == 0, "half-close: the guest sees EOF and closes too");
        closesocket(c);
    }
    const int st = wait_vm(proc, out_path, out, sizeof out, 10000);
    unsigned long long total = 0;
    const char *at = strstr(out, "net-probe: echo ");
    check(st == 0 && at && sscanf(at, "net-probe: echo %llu", &total) == 1 &&
              total == (unsigned long long)rounds + big,
          "the guest echoed every byte and exited 0");
    printf("connected %.1f ms after spawn; round trip %.1f us; bulk %.0f MiB/s each way\n", t_conn, rtt_us,
           bulk_ms > 0 ? (double)big / (1 << 20) / (bulk_ms / 1000) : 0.0);
}

static void limits_vm(void)
{
    char out_path[MAX_PATH], out[2048], stats[MAX_PATH], pr[8], pc[8];
    path_in_dir(out_path, sizeof out_path, "out6");
    path_in_dir(stats, sizeof stats, "stats");
    snprintf(pr, sizeof pr, "%u", p_reply);
    snprintf(pc, sizeof pc, "%u", p_closed);
    // A denied port (the reply server's), the closed port (allowed: 127.0.0.1
    // is the one address of the minute), then a second address.
    const char *tail[] = {"--net-allow", "127.0.0.1/32", "--net-deny-port", pr, "--net-max-dests", "1",
                          "--stats", stats, "--",
                          "/bin/net-probe", "refused", "10.0.2.2", pr,
                          "+", "refused", "10.0.2.2", pc,
                          "+", "refused", "1.1.1.1", "80",
                          "+", "sleep", "500", nullptr};
    const int before = n_reply;
    const int st = wait_vm(spawn(tail, out_path), out_path, out, sizeof out, 10000);
    printf("limits:\n");
    const int refused = count(out, "net-probe: refused yes");
    check(st == 0 && refused == 3, "a denied port, a closed one, an address past --net-max-dests: refused");
    check(n_reply == before, "the denied port's server saw nothing");
    check(stat_of(stats, "denied") == 1 && stat_of(stats, "limited") == 1 && stat_of(stats, "refused") == 0,
          "--stats: one denied, one limited (the closed port connected, then was refused by the host)");
    if (st != 0 || refused != 3)
        printf("  guest said:\n%s\n", out);
    DeleteFileA(stats);

    // --net-tx-rate: 6 MB out at 2 MB/s takes 2 s at least (a second's
    // worth, 2 MB, goes at once), however fast the link.
    char pe[8];
    snprintf(pe, sizeof pe, "%u", p_echo);
    const char *tail2[] = {"--net-allow", "127.0.0.1/32", "--net-tx-rate", "2000000", "--stats", stats, "--",
                           "/bin/net-probe", "source", "10.0.2.2", pe, "6000000", "+", "sleep", "2500", nullptr};
    const HANDLE proc = spawn(tail2, out_path);
    const SOCKET c = accept_timeout(lst_echo, 5000);
    size_t got = 0;
    double ms = 0;
    if (c != INVALID_SOCKET) {
        static char buf[1 << 16];
        const double t0 = now_ms();
        for (int r; (r = recv(c, buf, sizeof buf, 0)) > 0;)
            got += (size_t)r;
        ms = now_ms() - t0;
        closesocket(c);
    }
    const int st2 = wait_vm(proc, out_path, out, sizeof out, 20000);
    check(st2 == 0 && got == 6000000, "--net-tx-rate 2000000: 6 MB arrive whole");
    check(ms > 1700 && ms < 6000, "... in 2 s or so, not at once");
    printf("  6 MB in %.0f ms\n", ms);
    check(stat_of(stats, "tx") >= 6000000 && stat_of(stats, "flows") == 1 && stat_of(stats, "cpu_ns") > 0,
          "--stats: the bytes out, the flow and the CPU time");
    DeleteFileA(stats);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa))
        return 1;
    policy_tests();
    if (argc == 2 && !strcmp(argv[1], "--policy"))
        return fails ? 1 : 0;
    if (argc < 4) {
        fprintf(stderr, "usage: %s --policy | MICROVM VMLINUX IMAGE [--bench]\n", argv[0]);
        return 2;
    }
    const bool bench = argc > 4 && !strcmp(argv[4], "--bench");
    vm = argv;
    job = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION lim = {0};
    lim.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &lim, sizeof lim))
        return 1;
    char tmp[MAX_PATH];
    if (!GetTempPathA(sizeof tmp, tmp) ||
        snprintf(dir, sizeof dir, "%smvm-net-%lu", tmp, (unsigned long)GetCurrentProcessId()) >= (int)sizeof dir ||
        !CreateDirectoryA(dir, nullptr))
        return 1;
    // Servers. A closed port: bound, then closed again.
    lst_reply = bound(SOCK_STREAM, &p_reply);
    lst_echo = bound(SOCK_STREAM, &p_echo);
    udp_echo = bound(SOCK_DGRAM, &p_udp);
    udp_dns = bound(SOCK_DGRAM, &p_dns);
    const SOCKET closed = bound(SOCK_STREAM, &p_closed);
    if (lst_reply == INVALID_SOCKET || lst_echo == INVALID_SOCKET || udp_echo == INVALID_SOCKET ||
        udp_dns == INVALID_SOCKET || closed == INVALID_SOCKET)
        return 1;
    closesocket(closed);
    if (!CreateThread(nullptr, 0, servers, nullptr, 0, nullptr))
        return 1;

    probe_vm();
    no_allow_vm();
    echo_vm(bench);
    if (!bench) {
        host_addr_vm();
        limits_vm();
    }
    RemoveDirectoryA(dir);
    printf(fails ? "%d checks FAILED\n" : "all checks passed\n", fails);
    return fails ? 1 : 0;
}
