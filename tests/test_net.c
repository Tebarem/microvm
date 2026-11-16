// SPDX-License-Identifier: MIT
// virtio-net end to end (Linux / KVM), and the egress policy.
//
//   mvm_net_tests --policy                      the policy alone (no VM)
//   mvm_net_tests MICROVM VMLINUX IMAGE [--bench] [--jail MICROVM-JAIL]
//
// The test's own servers listen on 127.0.0.1, which the guest reaches as
// 10.0.2.2 with --net-allow 127.0.0.1/32 (and only then): a TCP server that
// answers what it read, a UDP echo, and a resolver for --net-dns. Booted:
// - /bin/net-probe: a TCP exchange, a UDP echo, a DNS query through
//   10.0.2.3, and refusals (cloud metadata, a closed port, a private
//   range, the host's own address with a listener on 0.0.0.0);
// - the same without --net-allow: the host's loopback is refused;
// - net-probe echo: round trips and bulk data both ways at once;
// - snapshots: taken with --net, restored VMs reach the host;
// - limits: a denied port, --net-max-dests, --net-tx-rate, and the --stats
//   file that counts them.
// --bench adds one-way throughput (sink, source) and more round trips.
// --jail starts every VM through microvm-jail (tests/jail_wrap.h): the
// jail's network helper, outside the VM's network namespace, opens the
// sockets, and the same checks must pass.
// Exits 77 (skipped) where the VMM can't run a guest.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "jail_wrap.h"
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
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

#include "net_policy_tests.h"

// ---- the host's servers -----------------------------------------------------------------
static int lst_reply, lst_any, lst_echo, udp_echo, udp_dns;
static uint16_t p_reply, p_any, p_echo, p_udp, p_dns, p_closed;
static atomic_int n_reply, n_any, n_dns;

static int bound(int type, uint32_t addr, uint16_t *port)
{
    const int fd = socket(AF_INET, type | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(addr)};
    socklen_t len = sizeof a;
    if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof a) || getsockname(fd, (struct sockaddr *)&a, &len))
        return -1;
    *port = ntohs(a.sin_port);
    if (type == SOCK_STREAM && listen(fd, 16))
        return -1;
    return fd;
}

static void serve_reply(int c)
{
    char buf[4096];
    size_t n = 0;
    struct pollfd p = {.fd = c, .events = POLLIN};
    while (n < sizeof buf - 16 && poll(&p, 1, 3000) == 1) {
        const ssize_t r = read(c, buf + n, sizeof buf - 16 - n);
        if (r <= 0)
            break;
        n += (size_t)r;
    }
    char out[4200];
    const int k = snprintf(out, sizeof out, "host got: %.*s", (int)n, buf);
    (void)!write(c, out, (size_t)k);
    close(c);
}

static void serve_dns(void)
{
    uint8_t q[512];
    struct sockaddr_in from;
    socklen_t fl = sizeof from;
    const ssize_t n = recvfrom(udp_dns, q, sizeof q - 16, 0, (struct sockaddr *)&from, &fl);
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
    (void)!sendto(udp_dns, a, (size_t)n + sizeof ans, 0, (struct sockaddr *)&from, fl);
}

static void *servers(void *arg)
{
    (void)arg;
    for (;;) {
        struct pollfd p[4] = {{lst_reply, POLLIN, 0}, {lst_any, POLLIN, 0}, {udp_echo, POLLIN, 0}, {udp_dns, POLLIN, 0}};
        if (poll(p, 4, -1) < 0)
            continue;
        if (p[0].revents & POLLIN) {
            const int c = accept4(lst_reply, nullptr, nullptr, SOCK_CLOEXEC);
            if (c >= 0) {
                n_reply++;
                serve_reply(c);
            }
        }
        if (p[1].revents & POLLIN) {
            const int c = accept4(lst_any, nullptr, nullptr, SOCK_CLOEXEC);
            if (c >= 0) {
                n_any++;
                close(c);
            }
        }
        if (p[2].revents & POLLIN) {
            uint8_t b[65536];
            struct sockaddr_in from;
            socklen_t fl = sizeof from;
            const ssize_t n = recvfrom(udp_echo, b + 11, sizeof b - 11, 0, (struct sockaddr *)&from, &fl);
            if (n >= 0) {
                memcpy(b, "udp echo: ", 10);
                memmove(b + 10, b + 11, (size_t)n);
                (void)!sendto(udp_echo, b, (size_t)n + 10, 0, (struct sockaddr *)&from, fl);
            }
        }
        if (p[3].revents & POLLIN)
            serve_dns();
    }
    return nullptr;
}

// An IPv4 address of this host that isn't loopback, preferring a public one.
static bool host_addr(char *out, size_t len)
{
    struct ifaddrs *ifs;
    if (getifaddrs(&ifs))
        return false;
    bool found = false, public_ = false;
    for (struct ifaddrs *i = ifs; i; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET)
            continue;
        const uint8_t *a = (const uint8_t *)&((struct sockaddr_in *)i->ifa_addr)->sin_addr;
        if (a[0] == 127)
            continue;
        const bool pub = a[0] != 10 && !(a[0] == 172 && (a[1] & 0xf0) == 16) && !(a[0] == 192 && a[1] == 168) &&
                         !(a[0] == 100 && (a[1] & 0xc0) == 64) && !(a[0] == 169 && a[1] == 254);
        if (!found || (pub && !public_)) {
            inet_ntop(AF_INET, a, out, (socklen_t)len);
            found = true;
            public_ = pub;
        }
    }
    freeifaddrs(ifs);
    return found;
}

// ---- VMs ---------------------------------------------------------------------------------------
static char dir[] = "/tmp/mvm-net-XXXXXX";
static jw_cfg jw; // the VMM, directly or through microvm-jail

static pid_t spawn(const char *const *extra, const char *out_path)
{
    const char *args[128];
    if (jw_wrap(&jw, extra, args, 128)) {
        printf("  (command line too long)\n");
        return -1;
    }
    const pid_t pid = fork_child();
    if (pid == 0) {
        const int o = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        dup2(o, 1);
        execv(args[0], (char **)args);
        _exit(127);
    }
    return pid;
}

static int wait_vm(pid_t pid, const char *out_path, char *out, size_t cap, double timeout_ms)
{
    int st = 0;
    if (pid < 0) {
        memset(out, 0, cap);
        return -1;
    }
    const double t0 = now_ms();
    while (waitpid(pid, &st, WNOHANG) == 0 && now_ms() - t0 < timeout_ms)
        usleep(1000);
    if (waitpid(pid, &st, WNOHANG) == 0) {
        printf("  (the VM was still running after %.0f s: killed)\n", timeout_ms / 1000);
        kill(pid, SIGKILL);
        waitpid(pid, &st, 0);
    }
    memset(out, 0, cap);
    const int o = open(out_path, O_RDONLY);
    if (o >= 0) {
        (void)!read(o, out, cap - 1);
        close(o);
    }
    unlink(out_path);
    return st;
}

static bool exited(int st, int code) { return WIFEXITED(st) && WEXITSTATUS(st) == code; }

static int accept_timeout(int l, int ms)
{
    struct pollfd p = {.fd = l, .events = POLLIN};
    if (poll(&p, 1, ms) != 1)
        return -1;
    return accept4(l, nullptr, nullptr, SOCK_CLOEXEC);
}

// Send `n` patterned bytes while reading them back.
static bool bulk(int fd, size_t n, double *ms)
{
    uint8_t *o = malloc(n), *in = malloc(n);
    for (size_t i = 0; i < n; i++)
        o[i] = (uint8_t)(i * 131 + (i >> 9));
    size_t sent = 0, got = 0;
    const double t0 = now_ms();
    bool ok = true;
    while (ok && got < n) {
        struct pollfd p = {.fd = fd, .events = POLLIN | (sent < n ? POLLOUT : 0)};
        if (poll(&p, 1, 5000) <= 0) {
            ok = false;
            break;
        }
        if ((p.revents & POLLOUT) && sent < n) {
            const ssize_t w = send(fd, o + sent, n - sent > 262144 ? 262144 : n - sent, MSG_DONTWAIT);
            if (w > 0)
                sent += (size_t)w;
        }
        if (p.revents & POLLIN) {
            const ssize_t r = recv(fd, in + got, n - got, MSG_DONTWAIT);
            if (r > 0)
                got += (size_t)r;
            else if (r == 0 || errno != EAGAIN)
                ok = false;
        }
    }
    *ms = now_ms() - t0;
    ok = ok && !memcmp(o, in, n);
    free(o);
    free(in);
    return ok;
}

static const char *K[8]; // --kernel VMLINUX --quiet --rootfs IMAGE --net

static void base_args(const char **a, int *n)
{
    for (int i = 0; K[i]; i++)
        a[(*n)++] = K[i];
}

static void probe_vm(void)
{
    char host[64] = "", out_path[96], out[2048], cmd[512];
    snprintf(out_path, sizeof out_path, "%s/out1", dir);
    const bool have_host = host_addr(host, sizeof host);
    char dns[32], pr[8], pu[8], pc[8], pa[8];
    snprintf(dns, sizeof dns, "127.0.0.1:%u", p_dns);
    snprintf(pr, sizeof pr, "%u", p_reply);
    snprintf(pu, sizeof pu, "%u", p_udp);
    snprintf(pc, sizeof pc, "%u", p_closed);
    snprintf(pa, sizeof pa, "%u", p_any);
    const char *a[64];
    int n = 0;
    base_args(a, &n);
    const char *tail[] = {"--net-allow", "127.0.0.1/32", "--net-dns", dns, "--",
                          "/bin/net-probe", "tcp", "10.0.2.2", pr, "hello-from-the-guest",
                          "+", "udp", "10.0.2.2", pu, "ping",
                          "+", "dns", "example.com",
                          "+", "refused", "169.254.169.254", "80",
                          "+", "refused", "10.0.2.2", pc,
                          "+", "refused", "192.168.1.1", "80",
                          "+", "refused", have_host ? host : "10.0.2.2", have_host ? pa : pc,
                          nullptr};
    for (int i = 0; tail[i]; i++)
        a[n++] = tail[i];
    a[n] = nullptr;
    const int st = wait_vm(spawn(a, out_path), out_path, out, sizeof out, 10000);
    if (exited(st, 77)) {
        printf("skipped: %s", out);
        exit(77);
    }
    printf("allowed loopback, the test's resolver:\n");
    check(strstr(out, "net-probe: tcp reply: host got: hello-from-the-guest\n") && n_reply == 1,
          "TCP: the host server got the message, the guest its reply");
    check(strstr(out, "net-probe: udp reply: udp echo: ping\n"), "UDP: echoed");
    check(strstr(out, "net-probe: dns rcode 0 answers 1\n") && n_dns == 1, "DNS through 10.0.2.3 to --net-dns");
    int refused = 0;
    for (const char *s = out; (s = strstr(s, "net-probe: refused yes")); s++)
        refused++;
    check(refused == 4, "refused: metadata, a closed port, a private range, the host itself");
    snprintf(cmd, sizeof cmd, "  (the host's own address: %s, a listener on 0.0.0.0:%u)", host, p_any);
    if (have_host)
        printf("%s\n", cmd);
    check(n_any == 0, "nothing reached the host's 0.0.0.0 listener");
    check(exited(st, 0), "the guest exits 0");
    if (!exited(st, 0) || refused != 4)
        printf("  guest said:\n%s\n", out);
}

static void no_allow_vm(void)
{
    char out_path[96], out[1024], pr[8];
    snprintf(out_path, sizeof out_path, "%s/out2", dir);
    snprintf(pr, sizeof pr, "%u", p_reply);
    const char *a[32];
    int n = 0;
    base_args(a, &n);
    const char *tail[] = {"--", "/bin/net-probe", "refused", "10.0.2.2", pr, nullptr};
    for (int i = 0; tail[i]; i++)
        a[n++] = tail[i];
    a[n] = nullptr;
    const int before = n_reply;
    const int st = wait_vm(spawn(a, out_path), out_path, out, sizeof out, 10000);
    printf("default policy:\n");
    check(exited(st, 0) && strstr(out, "net-probe: refused yes, errno 111"), "the host's loopback is refused");
    check(n_reply == before, "... and the host server saw nothing");
}

static void echo_vm(bool bench)
{
    char out_path[96], out[1024], pe[8];
    snprintf(out_path, sizeof out_path, "%s/out3", dir);
    snprintf(pe, sizeof pe, "%u", p_echo);
    const char *a[32];
    int n = 0;
    base_args(a, &n);
    const char *tail[] = {"--net-allow", "127.0.0.1/32", "--", "/bin/net-probe", "echo", "10.0.2.2", pe, nullptr};
    for (int i = 0; tail[i]; i++)
        a[n++] = tail[i];
    a[n] = nullptr;
    const double t0 = now_ms();
    const pid_t pid = spawn(a, out_path);
    const int c = accept_timeout(lst_echo, 5000);
    const double t_conn = now_ms() - t0;
    printf("echo:\n");
    check(c >= 0, "the guest connected to the host");
    double rtt_us = 0, bulk_ms = 0;
    const size_t big = bench ? 64u << 20 : 8u << 20;
    const int rounds = bench ? 5000 : 500;
    if (c >= 0) {
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int));
        char b = 'x';
        bool ok = true;
        const double r0 = now_ms();
        for (int i = 0; ok && i < rounds; i++)
            ok = write(c, &b, 1) == 1 && read(c, &b, 1) == 1;
        rtt_us = (now_ms() - r0) * 1000 / rounds;
        check(ok, "1-byte round trips");
        check(bulk(c, big, &bulk_ms), "bulk both ways at once, intact");
        shutdown(c, SHUT_WR);
        char e;
        check(read(c, &e, 1) == 0, "half-close: the guest sees EOF and closes too");
        close(c);
    }
    const int st = wait_vm(pid, out_path, out, sizeof out, 10000);
    unsigned long long total = 0;
    const char *at = strstr(out, "net-probe: echo ");
    check(exited(st, 0) && at && sscanf(at, "net-probe: echo %llu", &total) == 1 &&
              total == (unsigned long long)rounds + big,
          "the guest echoed every byte and exited 0");
    printf("connected %.1f ms after spawn; round trip %.1f us; bulk %.0f MiB/s each way\n", t_conn, rtt_us,
           bulk_ms > 0 ? (double)big / (1 << 20) / (bulk_ms / 1000) : 0.0);
}

// One way: the host sends (sink) or receives (source) `big` bytes.
static void oneway_vm(bool to_guest, size_t big)
{
    char out_path[96], out[1024], pe[8], nb[24];
    snprintf(out_path, sizeof out_path, "%s/out4", dir);
    snprintf(pe, sizeof pe, "%u", p_echo);
    snprintf(nb, sizeof nb, "%zu", big);
    const char *a[32];
    int n = 0;
    base_args(a, &n);
    const char *tail[] = {"--net-allow", "127.0.0.1/32", "--", "/bin/net-probe", to_guest ? "sink" : "source",
                          "10.0.2.2", pe, nb, nullptr};
    for (int i = 0; tail[i]; i++)
        a[n++] = tail[i];
    if (to_guest)
        a[n - 1] = nullptr;
    a[n] = nullptr;
    const pid_t pid = spawn(a, out_path);
    const int c = accept_timeout(lst_echo, 5000);
    double ms = 0;
    bool ok = c >= 0;
    static uint8_t buf[1 << 20];
    if (ok && to_guest) {
        const double t0 = now_ms();
        for (size_t sent = 0; ok && sent < big;) {
            const ssize_t w = write(c, buf, big - sent < sizeof buf ? big - sent : sizeof buf);
            ok = w > 0;
            sent += ok ? (size_t)w : 0;
        }
        shutdown(c, SHUT_WR);
        char line[32] = {0};
        ok = ok && read(c, line, sizeof line - 1) > 0 && strtoull(line, nullptr, 10) == big;
        ms = now_ms() - t0;
    } else if (ok) {
        const double t0 = now_ms();
        size_t got = 0;
        for (ssize_t r; (r = read(c, buf, sizeof buf)) > 0;)
            got += (size_t)r;
        ms = now_ms() - t0;
        ok = got == big;
    }
    if (c >= 0)
        close(c);
    const int st = wait_vm(pid, out_path, out, sizeof out, 20000);
    check(ok && exited(st, 0), to_guest ? "host -> guest, intact" : "guest -> host, intact");
    printf("  %s: %.0f MiB/s\n", to_guest ? "host -> guest" : "guest -> host",
           ms > 0 ? (double)big / (1 << 20) / (ms / 1000) : 0.0);
}

// --stats FILE: the last line the VMM wrote, as name/number pairs.
static unsigned long long stat_of(const char *path, const char *name)
{
    char b[256] = {0}, key[32];
    const int fd = open(path, O_RDONLY);
    if (fd < 0)
        return ~0ull;
    (void)!read(fd, b, sizeof b - 1);
    close(fd);
    unsigned long long v;
    int used;
    for (const char *s = b; sscanf(s, "%31s %llu%n", key, &v, &used) == 2; s += used)
        if (!strcmp(key, name))
            return v;
    return ~0ull;
}

static void limits_vm(void)
{
    char out_path[96], out[2048], stats[96], pr[8], pc[8];
    snprintf(out_path, sizeof out_path, "%s/out6", dir);
    snprintf(stats, sizeof stats, "%s/stats", dir);
    snprintf(pr, sizeof pr, "%u", p_reply);
    snprintf(pc, sizeof pc, "%u", p_closed);
    const char *a[48];
    int n = 0;
    base_args(a, &n);
    // A denied port (the reply server's), the closed port (allowed: 127.0.0.1
    // is the one address of the minute), then a second address.
    const char *tail[] = {"--net-allow", "127.0.0.1/32", "--net-deny-port", pr, "--net-max-dests", "1",
                          "--stats", stats, "--",
                          "/bin/net-probe", "refused", "10.0.2.2", pr,
                          "+", "refused", "10.0.2.2", pc,
                          "+", "refused", "1.1.1.1", "80",
                          "+", "sleep", "500", nullptr};
    for (int i = 0; tail[i]; i++)
        a[n++] = tail[i];
    a[n] = nullptr;
    const int before = n_reply;
    const int st = wait_vm(spawn(a, out_path), out_path, out, sizeof out, 10000);
    printf("limits:\n");
    int refused = 0;
    for (const char *s = out; (s = strstr(s, "net-probe: refused yes")); s++)
        refused++;
    check(exited(st, 0) && refused == 3, "a denied port, a closed one, an address past --net-max-dests: refused");
    check(n_reply == before, "the denied port's server saw nothing");
    check(stat_of(stats, "denied") == 1 && stat_of(stats, "limited") == 1 && stat_of(stats, "refused") == 0,
          "--stats: one denied, one limited (the closed port connected, then was refused by the host)");
    if (!exited(st, 0) || refused != 3)
        printf("  guest said:\n%s\n", out);
    unlink(stats);

    // --net-tx-rate: 6 MB out at 2 MB/s takes 2 s at least (a second's
    // worth, 2 MB, goes at once), however fast the link.
    char pe[8], nb[24];
    snprintf(pe, sizeof pe, "%u", p_echo);
    snprintf(nb, sizeof nb, "%u", 6000000u);
    n = 0;
    base_args(a, &n);
    const char *tail2[] = {"--net-allow", "127.0.0.1/32", "--net-tx-rate", "2000000", "--stats", stats, "--",
                           "/bin/net-probe", "source", "10.0.2.2", pe, nb, "+", "sleep", "2500", nullptr};
    for (int i = 0; tail2[i]; i++)
        a[n++] = tail2[i];
    a[n] = nullptr;
    const pid_t pid = spawn(a, out_path);
    const int c = accept_timeout(lst_echo, 5000);
    size_t got = 0;
    double ms = 0;
    if (c >= 0) {
        static uint8_t buf[1 << 16];
        const double t0 = now_ms();
        for (ssize_t r; (r = read(c, buf, sizeof buf)) > 0;)
            got += (size_t)r;
        ms = now_ms() - t0;
        close(c);
    }
    const int st2 = wait_vm(pid, out_path, out, sizeof out, 20000);
    check(exited(st2, 0) && got == 6000000, "--net-tx-rate 2000000: 6 MB arrive whole");
    check(ms > 1700 && ms < 6000, "... in 2 s or so, not at once");
    printf("  6 MB in %.0f ms\n", ms);
    check(stat_of(stats, "tx") >= 6000000 && stat_of(stats, "flows") == 1 && stat_of(stats, "cpu_ns") > 0,
          "--stats: the bytes out, the flow and the CPU time");
    unlink(stats);
}

static void snapshots(void)
{
    char snap[96], out_path[96], out[1024], pr[8];
    snprintf(snap, sizeof snap, "%s/snap", dir);
    snprintf(out_path, sizeof out_path, "%s/out5", dir);
    snprintf(pr, sizeof pr, "%u", p_reply);
    const char *a[40];
    int n = 0;
    base_args(a, &n);
    const char *tail[] = {"--append", "snapshot", "--snapshot", snap, "--", "/bin/net-probe", "tcp", "10.0.2.2",
                          pr, "after-restore", nullptr};
    for (int i = 0; tail[i]; i++)
        a[n++] = tail[i];
    a[n] = nullptr;
    printf("snapshots:\n");
    int st = wait_vm(spawn(a, out_path), out_path, out, sizeof out, 10000);
    struct stat sb;
    check(exited(st, 0) && !stat(snap, &sb) && sb.st_size > 0, "a snapshot with a network device");
    const char *back[] = {"--restore", snap, "--rootfs", K[4], "--net", "--net-allow", "127.0.0.1/32", nullptr};
    for (int i = 0; i < 2; i++) {
        const int before = n_reply;
        st = wait_vm(spawn(back, out_path), out_path, out, sizeof out, 10000);
        check(exited(st, 0) && strstr(out, "net-probe: tcp reply: host got: after-restore\n") &&
                  n_reply == before + 1,
              "restored: the guest reaches the host");
    }
    const char *nonet[] = {"--restore", snap, "--rootfs", K[4], nullptr};
    st = wait_vm(spawn(nonet, out_path), out_path, out, sizeof out, 10000);
    check(!exited(st, 0), "restoring without --net is refused");
    unlink(snap);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    jw.jail = jw_take_arg(&argc, argv);
    policy_tests();
    if (argc == 2 && !strcmp(argv[1], "--policy"))
        return fails ? 1 : 0;
    if (argc < 4) {
        fprintf(stderr, "usage: %s --policy | MICROVM VMLINUX IMAGE [--bench]\n", argv[0]);
        return 2;
    }
    const bool bench = argc > 4 && !strcmp(argv[4], "--bench");
    if (access("/dev/kvm", R_OK | W_OK)) {
        printf("skipped: no usable /dev/kvm\n");
        return 77;
    }
    if (jw.jail && !jw_usable()) {
        printf("skipped: microvm-jail needs root or unprivileged user namespaces\n");
        return 77;
    }
    if (!mkdtemp(dir))
        return 1;
    jw.vmm = argv[1], jw.kernel = argv[2], jw.rootfs = argv[3], jw.dir = dir;
    if (jw.jail)
        printf("every VM through %s%s\n", jw.jail, geteuid() ? " (unprivileged)" : " (as root: VM uid 65534)");
    chmod(dir, 0777); // a wrapper may run the VMM as another user
    const char *k[] = {"--kernel", argv[2], "--quiet", "--rootfs", argv[3], "--net", nullptr};
    memcpy(K, k, sizeof k);
    // Servers. A closed port: bound, then closed again.
    lst_reply = bound(SOCK_STREAM, INADDR_LOOPBACK, &p_reply);
    lst_any = bound(SOCK_STREAM, INADDR_ANY, &p_any);
    lst_echo = bound(SOCK_STREAM, INADDR_LOOPBACK, &p_echo);
    udp_echo = bound(SOCK_DGRAM, INADDR_LOOPBACK, &p_udp);
    udp_dns = bound(SOCK_DGRAM, INADDR_LOOPBACK, &p_dns);
    const int closed = bound(SOCK_STREAM, INADDR_LOOPBACK, &p_closed);
    if (lst_reply < 0 || lst_any < 0 || lst_echo < 0 || udp_echo < 0 || udp_dns < 0 || closed < 0)
        return 1;
    close(closed);
    pthread_t th;
    pthread_create(&th, nullptr, servers, nullptr);

    probe_vm();
    no_allow_vm();
    echo_vm(bench);
    if (bench) {
        printf("one way, 256 MiB:\n");
        for (int i = 0; i < 2; i++) {
            oneway_vm(true, 256u << 20);
            oneway_vm(false, 256u << 20);
        }
    } else {
        snapshots();
        limits_vm();
    }
    rmdir(dir);
    printf(fails ? "%d checks FAILED\n" : "all checks passed\n", fails);
    return fails ? 1 : 0;
}
