// SPDX-License-Identifier: MIT
// The network helper process (see net_helper.h).
#include "net_helper.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#  include "dev/hostsock.h"
// after winsock2.h
#  include <iphlpapi.h>

#  include "clock.h"
#else
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <linux/netlink.h>
#  include <linux/rtnetlink.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <poll.h>
#  include <signal.h>
#  include <sys/prctl.h>
#  include <sys/socket.h>
#  include <sys/syscall.h>
#  include <unistd.h>
#  include <time.h>

#  include "sandbox.h"
#endif

// ---- the channel ----------------------------------------------------------------
// Request (24 bytes): id, proto, v6, port (host order), address. Reply
// (8 bytes): id, 0 or an errno, with the socket attached on success.
typedef struct {
    uint32_t id;
    uint8_t proto, v6;
    uint16_t port;
    uint8_t addr[16];
} helper_req;

typedef struct {
    uint32_t id;
    int32_t err;
} helper_rep;

static_assert(sizeof(helper_req) == 24 && sizeof(helper_rep) == 8);

// ---- policy -------------------------------------------------------------------------
static bool in_cidr(const net_cidr *c, const net_dst *d)
{
    if (c->v6 != d->v6)
        return false;
    const unsigned whole = c->bits / 8, rest = c->bits % 8;
    if (memcmp(c->addr, d->addr, whole))
        return false;
    return !rest || ((c->addr[whole] ^ d->addr[whole]) & (uint8_t)(0xff << (8 - rest))) == 0;
}

static int parse_addr(const char *s, net_dst *d)
{
    *d = (net_dst){0};
    if (inet_pton(AF_INET, s, d->addr) == 1)
        return 0;
    if (inet_pton(AF_INET6, s, d->addr) == 1) {
        d->v6 = true;
        return 0;
    }
    return -1;
}

int net_policy_allow(net_policy *p, const char *cidr)
{
    char a[64], whole[80];
    unsigned long port = 0;
    const char *comma = strchr(cidr, ',');
    if (comma) { // ,PORT
        char *end;
        port = strtoul(comma + 1, &end, 10);
        const size_t len = (size_t)(comma - cidr);
        if (comma[1] < '0' || comma[1] > '9' || *end || !port || port > 65535 || len >= sizeof whole)
            return -1;
        memcpy(whole, cidr, len);
        whole[len] = 0;
        cidr = whole;
    }
    const char *slash = strchr(cidr, '/');
    const size_t n = slash ? (size_t)(slash - cidr) : strlen(cidr);
    if (p->nallow == NET_MAX_ALLOW || n >= sizeof a)
        return -1;
    memcpy(a, cidr, n);
    a[n] = 0;
    net_dst d;
    if (parse_addr(a, &d))
        return -1;
    const unsigned max = d.v6 ? 128 : 32;
    unsigned bits = max;
    if (slash) {
        char *end;
        const unsigned long b = strtoul(slash + 1, &end, 10);
        if (!slash[1] || *end || b > max)
            return -1;
        bits = (unsigned)b;
    }
    net_cidr *c = &p->allow[p->nallow++];
    *c = (net_cidr){.v6 = d.v6, .bits = (uint8_t)bits, .port = (uint16_t)port};
    memcpy(c->addr, d.addr, 16);
    return 0;
}

int net_policy_dns(net_policy *p, const char *addr)
{
    // ADDR, IPV4:PORT or [IPV6]:PORT
    char a[64];
    unsigned long port = 53;
    const char *colon = strrchr(addr, ':');
    size_t n = strlen(addr);
    if (addr[0] == '[') {
        const char *close = strchr(addr, ']');
        if (!close || (close[1] && close[1] != ':'))
            return -1;
        n = (size_t)(close - addr - 1);
        addr++;
        colon = close[1] ? close + 1 : nullptr;
    } else if (colon && strchr(addr, ':') == colon) {
        n = (size_t)(colon - addr);
    } else {
        colon = nullptr; // a bare IPv6 address
    }
    if (colon) {
        char *end;
        port = strtoul(colon + 1, &end, 10);
        if (!colon[1] || *end || !port || port > 65535)
            return -1;
    }
    if (p->ndns == NET_MAX_DNS || n >= sizeof a)
        return -1;
    memcpy(a, addr, n);
    a[n] = 0;
    if (parse_addr(a, &p->dns[p->ndns]))
        return -1;
    p->dns[p->ndns].port = (uint16_t)port;
    p->ndns++;
    return 0;
}

int net_policy_number(const char *s, uint64_t max, uint64_t *out)
{
    if (*s < '0' || *s > '9')
        return -1;
    char *end;
    errno = 0;
    const unsigned long long v = strtoull(s, &end, 10);
    if (*end || errno || !v || v > max)
        return -1;
    *out = v;
    return 0;
}

int net_policy_deny_port(net_policy *p, const char *port)
{
    uint64_t v;
    if (p->ndeny_port == NET_MAX_DENY_PORTS || net_policy_number(port, 65535, &v))
        return -1;
    p->deny_port[p->ndeny_port++] = (uint16_t)v;
    return 0;
}

constexpr uint64_t NS = 1000000000;

int net_limit_flow(net_limits *l, const net_policy *p, uint64_t now_ns)
{
    if (!p->flow_rate)
        return 0;
    // GCRA: each flow takes 1/rate of a second; up to 5 s worth at once.
    const uint64_t step = NS / p->flow_rate, tat = l->flow_tat > now_ns ? l->flow_tat : now_ns;
    if (tat - now_ns > 5 * NS - step)
        return -EAGAIN;
    l->flow_tat = tat + step;
    return 0;
}

int net_limit_dest(net_limits *l, const net_policy *p, const net_dst *to, uint64_t now_ns)
{
    if (!p->max_dests)
        return 0;
    if (!l->minute || now_ns - l->minute >= 60 * NS) {
        l->minute = now_ns ? now_ns : 1;
        l->ndests = 0;
    }
    uint8_t key[17] = {to->v6};
    memcpy(key + 1, to->addr, 16);
    for (uint32_t i = 0; i < l->ndests; i++)
        if (!memcmp(l->dests[i], key, sizeof key))
            return 0;
    if (l->ndests >= p->max_dests || l->ndests == NET_MAX_DESTS)
        return -EAGAIN;
    memcpy(l->dests[l->ndests++], key, sizeof key);
    return 0;
}

#if defined(_WIN32)
// The adapters' addresses and resolvers (free() it), or nullptr.
static IP_ADAPTER_ADDRESSES *adapters(void)
{
    ULONG len = 16 * 1024;
    for (int tries = 0; tries < 3; tries++) {
        IP_ADAPTER_ADDRESSES *a = malloc(len);
        if (!a)
            return nullptr;
        const ULONG rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                                             GAA_FLAG_INCLUDE_GATEWAYS, nullptr, a, &len);
        if (rc == ERROR_SUCCESS)
            return a;
        free(a);
        if (rc != ERROR_BUFFER_OVERFLOW)
            return nullptr;
    }
    return nullptr;
}

static bool sockaddr_dst(const struct sockaddr *sa, net_dst *d)
{
    *d = (net_dst){0};
    if (sa->sa_family == AF_INET) {
        memcpy(d->addr, &((const struct sockaddr_in *)sa)->sin_addr, 4);
        return true;
    }
    if (sa->sa_family == AF_INET6) {
        d->v6 = true;
        memcpy(d->addr, &((const struct sockaddr_in6 *)sa)->sin6_addr, 16);
        return true;
    }
    return false;
}

// The resolvers of the adapter the host's own traffic leaves by: the one
// that is up, has a gateway and the lowest metric.
void net_policy_host_dns(net_policy *p)
{
    if (p->ndns)
        return;
    IP_ADAPTER_ADDRESSES *all = adapters();
    const IP_ADAPTER_ADDRESSES *best = nullptr;
    for (const IP_ADAPTER_ADDRESSES *a = all; a; a = a->Next)
        if (a->OperStatus == IfOperStatusUp && a->FirstGatewayAddress && a->FirstDnsServerAddress &&
            (!best || a->Ipv4Metric < best->Ipv4Metric))
            best = a;
    for (const IP_ADAPTER_DNS_SERVER_ADDRESS *s = best ? best->FirstDnsServerAddress : nullptr;
         s && p->ndns < NET_MAX_DNS; s = s->Next) {
        net_dst d;
        if (!sockaddr_dst(s->Address.lpSockaddr, &d))
            continue;
        // Scoped addresses (link-local, and the site-local placeholders
        // Windows lists where there is no IPv6 resolver) aren't ours to use.
        if (d.v6 && d.addr[0] == 0xfe && (d.addr[1] & 0x80))
            continue;
        d.port = 53;
        p->dns[p->ndns++] = d;
    }
    free(all);
}
#else
void net_policy_host_dns(net_policy *p)
{
    if (p->ndns)
        return;
    FILE *f = fopen("/etc/resolv.conf", "re");
    if (!f)
        return;
    char line[256];
    while (p->ndns < NET_MAX_DNS && fgets(line, sizeof line, f)) {
        char addr[64];
        if (sscanf(line, " nameserver %63s", addr) == 1) {
            char *pct = strchr(addr, '%'); // a scoped link-local address: not ours to use
            if (!pct)
                (void)net_policy_dns(p, addr);
        }
    }
    fclose(f);
}
#endif

typedef struct {
    uint8_t a[16];
    uint8_t bits;
} range;

// Special-purpose ranges a guest may not reach unless allowed (IANA's
// special-purpose registries, plus the private ranges a provider's own
// network lives in).
static const range V4_BLOCK[] = {
    {{0}, 8},             // "this network"
    {{10}, 8},            // RFC 1918
    {{100, 64}, 10},      // carrier-grade NAT (Tailscale's 100.x)
    {{127}, 8},           // loopback
    {{169, 254}, 16},     // link-local: cloud metadata services
    {{172, 16}, 12},      // RFC 1918 (docker's default bridges)
    {{192, 0, 0}, 24},    // IETF protocol assignments
    {{192, 168}, 16},     // RFC 1918
    {{198, 18}, 15},      // benchmarking
    {{224}, 4},           // multicast
    {{240}, 4},           // reserved, and the broadcast address
};
static const range V6_BLOCK[] = {
    {{0}, 96},                                   // ::/96: unspecified, loopback, IPv4-compatible
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}, 96}, // IPv4-mapped
    {{0, 0x64, 0xff, 0x9b}, 32},                 // NAT64 (64:ff9b::/96 and 64:ff9b:1::/48)
    {{0x01, 0x00}, 64},                          // discard-only
    {{0x20, 0x01, 0x0d, 0xb8}, 32},              // documentation
    {{0x20, 0x02}, 16},                          // 6to4: an IPv4 address inside
    {{0xfc}, 7},                                 // unique local (ULA): docker, EC2 metadata fd00:ec2::254
    {{0xfe, 0x80}, 10},                          // link-local
    {{0xfe, 0xc0}, 10},                          // site-local (deprecated)
    {{0xff}, 8},                                 // multicast
};

static bool blocked(const net_dst *d)
{
    const range *r = d->v6 ? V6_BLOCK : V4_BLOCK;
    const size_t n = d->v6 ? MVM_ARRAY_LEN(V6_BLOCK) : MVM_ARRAY_LEN(V4_BLOCK);
    for (size_t i = 0; i < n; i++) {
        net_cidr c = {.v6 = d->v6, .bits = r[i].bits};
        memcpy(c.addr, r[i].a, 16);
        if (in_cidr(&c, d))
            return true;
    }
    return false;
}

int net_policy_route(const net_policy *p, const net_dst *d, net_dst *out, net_route_fn route_type, void *ctx)
{
    if (p->deny_all || (d->proto != NET_TCP && d->proto != NET_UDP))
        return -EACCES;
    *out = *d;
    if (!d->v6 && !memcmp(d->addr, NET_DNS_IP, 4)) {
        // The resolver: chosen by the host, not by the guest.
        if (d->port != 53 || !p->ndns || p->allow_only)
            return -EACCES;
        *out = p->dns[0];
        out->proto = d->proto;
        return 0;
    }
    if (!d->v6 && !memcmp(d->addr, NET_GATEWAY_IP, 4)) {
        memset(out->addr, 0, 16);
        out->addr[0] = 127, out->addr[3] = 1;
    }
    if (!out->port)
        return -EACCES;
    for (int i = 0; i < p->ndeny_port; i++)
        if (out->port == p->deny_port[i])
            return -EPERM;
    for (int i = 0; i < p->nallow; i++)
        if (in_cidr(&p->allow[i], out) && (!p->allow[i].port || p->allow[i].port == out->port))
            return 0;
    if (p->allow_only || blocked(out))
        return -EACCES;
    // The host's own addresses (and so everything listening on 0.0.0.0),
    // broadcast and anything the host can't route.
    if (route_type && route_type(ctx, out) != RTN_UNICAST)
        return -EACCES;
    return 0;
}

#if defined(_WIN32)
// ---- Windows: no helper process yet ---------------------------------------------------
// The policy and the limits are applied here, in the VMM, to every flow the
// guest opens. That holds against a hostile guest. It does not hold against
// a VMM the guest took over: the Windows sandbox (sandbox_win.c) doesn't
// take socket creation away, so a helper process would add nothing until it
// does.
static net_policy the_policy;
static net_limits the_limits;

// The host's own addresses count as local, as on Linux (and so everything
// listening on 0.0.0.0). Asked again at most every 2 s.
static int route_type(void *ctx, const net_dst *d)
{
    (void)ctx;
    static net_dst mine[64];
    static int nmine;
    static uint64_t asked;
    const uint64_t now = mvm_now_ns();
    if (!asked || now - asked > 2000000000ull) {
        IP_ADAPTER_ADDRESSES *all = adapters();
        if (!all)
            return -1;
        nmine = 0;
        for (const IP_ADAPTER_ADDRESSES *a = all; a; a = a->Next)
            for (const IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u && nmine < 64; u = u->Next)
                if (sockaddr_dst(u->Address.lpSockaddr, &mine[nmine]))
                    nmine++;
        free(all);
        asked = now ? now : 1;
    }
    for (int i = 0; i < nmine; i++)
        if (mine[i].v6 == d->v6 && !memcmp(mine[i].addr, d->addr, d->v6 ? 16 : 4))
            return RTN_LOCAL;
    return RTN_UNICAST;
}

static int open_socket(const net_dst *d)
{
    const sock fd = socket(d->v6 ? AF_INET6 : AF_INET, d->proto == NET_TCP ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (fd == NOSOCK)
        return -EIO;
    struct sockaddr_storage sa = {0};
    int len;
    if (d->v6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&sa;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(d->port);
        memcpy(&s6->sin6_addr, d->addr, 16);
        len = sizeof *s6;
    } else {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&sa;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(d->port);
        memcpy(&s4->sin_addr, d->addr, 4);
        len = sizeof *s4;
    }
    const int nodelay = 1; // see the Linux helper
    // The device keeps flows as ints: a socket handle past that range (there
    // are none in practice) can't be one.
    if (fd > (sock)INT32_MAX || !sock_nonblock(fd) ||
        (d->proto == NET_TCP &&
         setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof nodelay)) ||
        (connect(fd, (const struct sockaddr *)&sa, len) && WSAGetLastError() != WSAEWOULDBLOCK)) {
        sock_close(fd);
        return -EIO;
    }
    return (int)fd;
}

int net_helper_start(const net_policy *p)
{
    if (!sock_init()) {
        mvm_log("--net: no Winsock");
        return -1;
    }
    the_policy = *p;
    net_policy_host_dns(&the_policy);
    return 0; // no channel: net_helper_open() ignores it
}

int net_helper_check_fd(int fd) { (void)fd; return -1; } // --net-fd: Linux only

int net_helper_open(void *ctx, const net_dst *d)
{
    (void)ctx;
    net_dst to;
    const uint64_t now = mvm_now_ns();
    int rc = net_limit_flow(&the_limits, &the_policy, now);
    if (!rc)
        rc = net_policy_route(&the_policy, d, &to, route_type, nullptr);
    if (!rc)
        rc = net_limit_dest(&the_limits, &the_policy, &to, now);
    return rc ? rc : open_socket(&to);
}

#else
// ---- the helper process ---------------------------------------------------------------
// RTM_GETROUTE for one address: its route's type (RTN_*), or -1.
static int route_type(void *ctx, const net_dst *d)
{
    const int nl = (int)(intptr_t)ctx;
    static uint32_t seq;
    struct {
        struct nlmsghdr h;
        struct rtmsg r;
        struct rtattr a;
        uint8_t addr[16];
    } req = {
        .h = {.nlmsg_len = (uint32_t)(NLMSG_LENGTH(sizeof(struct rtmsg)) + RTA_LENGTH(d->v6 ? 16 : 4)),
              .nlmsg_type = RTM_GETROUTE, .nlmsg_flags = NLM_F_REQUEST, .nlmsg_seq = ++seq},
        .r = {.rtm_family = d->v6 ? AF_INET6 : AF_INET, .rtm_dst_len = d->v6 ? 128 : 32},
        .a = {.rta_len = (unsigned short)RTA_LENGTH(d->v6 ? 16 : 4), .rta_type = RTA_DST},
    };
    memcpy(req.addr, d->addr, d->v6 ? 16 : 4);
    if (send(nl, &req, req.h.nlmsg_len, 0) != (ssize_t)req.h.nlmsg_len)
        return -1;
    static uint8_t buf[4096];
    for (;;) {
        const ssize_t n = recv(nl, buf, sizeof buf, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < (ssize_t)sizeof(struct nlmsghdr))
            return -1;
        const struct nlmsghdr *h = (const struct nlmsghdr *)buf;
        if (h->nlmsg_seq != seq) // a late answer to an earlier question
            continue;
        if (h->nlmsg_type != RTM_NEWROUTE || h->nlmsg_len < NLMSG_LENGTH(sizeof(struct rtmsg)) ||
            (ssize_t)h->nlmsg_len > n)
            return -1; // NLMSG_ERROR: no route
        return ((const struct rtmsg *)NLMSG_DATA(h))->rtm_type;
    }
}

static int open_socket(const net_dst *d, uint64_t tx_rate)
{
    const int fd = socket(d->v6 ? AF_INET6 : AF_INET,
                          (d->proto == NET_TCP ? SOCK_STREAM : SOCK_DGRAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;
    // The guest's TCP already decides when to send: a second Nagle here
    // would hold its last small segment for the host's delayed ACK (40 ms).
    // The VMM paces the guest's flows together (net_set_tx_rate); the kernel
    // paces each socket, where a compromised VMM can't undo it.
    if (d->proto == NET_TCP && (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) ||
                                (tx_rate && setsockopt(fd, SOL_SOCKET, SO_MAX_PACING_RATE,
                                                       &(unsigned){(unsigned)tx_rate}, sizeof(unsigned))))) {
        const int e = errno;
        close(fd);
        return -e;
    }
    struct sockaddr_storage sa = {0};
    socklen_t len;
    if (d->v6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&sa;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(d->port);
        memcpy(&s6->sin6_addr, d->addr, 16);
        len = sizeof *s6;
    } else {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&sa;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(d->port);
        memcpy(&s4->sin_addr, d->addr, 4);
        len = sizeof *s4;
    }
    if (connect(fd, (struct sockaddr *)&sa, len) && errno != EINPROGRESS) {
        const int e = errno;
        close(fd);
        return -e;
    }
    return fd;
}

static void reply(int chan, uint32_t id, int err, int fd)
{
    helper_rep rep = {.id = id, .err = err};
    struct iovec iov = {&rep, sizeof rep};
    union {
        struct cmsghdr h;
        uint8_t b[CMSG_SPACE(sizeof(int))];
    } cm = {0};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1};
    if (fd >= 0) {
        m.msg_control = cm.b;
        m.msg_controllen = sizeof cm.b;
        struct cmsghdr *c = CMSG_FIRSTHDR(&m);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &fd, sizeof fd);
    }
    while (sendmsg(chan, &m, MSG_NOSIGNAL) < 0 && errno == EINTR)
        ;
}

void net_helper_main(int chan, const net_policy *pol)
{
    static net_policy p; // a copy: the caller's memory may be anything
    p = *pol;
    net_policy_host_dns(&p);
    const int nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    // Only the channel and the netlink socket stay open, as fds 3 and 4
    // (by way of numbers above both, so neither overwrites the other).
    const int c2 = nl < 0 ? -1 : fcntl(chan, F_DUPFD, 10), n2 = nl < 0 ? -1 : fcntl(nl, F_DUPFD, 10);
    if (c2 < 0 || n2 < 0 || dup2(c2, 3) < 0 || dup2(n2, 4) < 0 || syscall(SYS_close_range, 5u, ~0u, 0u)) {
        mvm_log("net helper: setup failed: %s", strerror(errno));
        _exit(1);
    }
    char report[160];
    if (sandbox_enter_net_helper(3, 4, report, sizeof report)) {
        mvm_log("net helper: cannot sandbox itself");
        _exit(1);
    }
    for (;;) {
        helper_req q;
        const ssize_t n = recv(3, &q, sizeof q, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n == 0)
            _exit(0); // the VMM is gone
        if (n != (ssize_t)sizeof q)
            _exit(1);
        net_dst d = {.proto = q.proto, .v6 = q.v6 != 0, .port = q.port}, to;
        memcpy(d.addr, q.addr, 16);
        if (!d.v6)
            memset(d.addr + 4, 0, 12);
        static net_limits lim;
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        const uint64_t now = (uint64_t)ts.tv_sec * NS + (uint64_t)ts.tv_nsec;
        int rc = net_limit_flow(&lim, &p, now);
        if (!rc)
            rc = net_policy_route(&p, &d, &to, route_type, (void *)(intptr_t)4);
        if (!rc)
            rc = net_limit_dest(&lim, &p, &to, now);
        const int fd = rc ? -1 : open_socket(&to, p.tx_rate);
        if (!rc && fd < 0)
            rc = fd;
        reply(3, q.id, rc, fd);
        if (fd >= 0)
            close(fd);
    }
}

int net_helper_start(const net_policy *p)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv))
        return -1;
    const pid_t parent = getpid();
    const pid_t pid = fork();
    if (pid < 0) {
        close(sv[0]);
        close(sv[1]);
        return -1;
    }
    if (pid == 0) {
        // Dies with the VMM (and if it died already, now).
        if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) || getppid() != parent)
            _exit(1);
        close(sv[0]);
        net_helper_main(sv[1], p);
    }
    close(sv[1]);
    return sv[0];
}

int net_helper_check_fd(int fd)
{
    int type = 0, dom = 0;
    socklen_t l1 = sizeof type, l2 = sizeof dom;
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &l1) || getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &dom, &l2))
        return -1;
    return type == SOCK_SEQPACKET && dom == AF_UNIX ? 0 : -1;
}

int net_helper_open(void *ctx, const net_dst *d)
{
    const int chan = (int)(intptr_t)ctx;
    static uint32_t id;
    helper_req q = {.id = ++id, .proto = d->proto, .v6 = d->v6, .port = d->port};
    memcpy(q.addr, d->addr, 16);
    if (write(chan, &q, sizeof q) != (ssize_t)sizeof q)
        return -EIO;
    for (;;) {
        struct pollfd pf = {.fd = chan, .events = POLLIN};
        const int r = poll(&pf, 1, 2000);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            return -ETIMEDOUT;
        helper_rep rep;
        struct iovec iov = {&rep, sizeof rep};
        union {
            struct cmsghdr h;
            uint8_t b[CMSG_SPACE(sizeof(int) * 4)];
        } cm;
        struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = cm.b, .msg_controllen = sizeof cm.b};
        const ssize_t n = recvmsg(chan, &m, MSG_CMSG_CLOEXEC);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -EIO;
        int fd = -1;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
            if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
                continue;
            const size_t k = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (size_t i = 0; i < k; i++) {
                int x;
                memcpy(&x, CMSG_DATA(c) + i * sizeof(int), sizeof x);
                if (fd < 0)
                    fd = x;
                else
                    close(x); // only ever one
            }
        }
        if (n != (ssize_t)sizeof rep || rep.id != q.id || rep.err || fd < 0) {
            if (fd >= 0)
                close(fd);
            if (n == (ssize_t)sizeof rep && rep.id == q.id)
                return rep.err < 0 ? rep.err : -EIO;
            continue; // a late reply to a request that timed out
        }
        return fd;
    }
}

#endif
