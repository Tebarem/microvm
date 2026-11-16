// SPDX-License-Identifier: MIT
// The egress policy's checks (no VM), shared by test_net.c and
// test_net_win.c. The including file has check(), the sockets headers
// (inet_pton) and net_helper.h.
#pragma once

// ---- the policy ---------------------------------------------------------------------
static int fake_route(void *ctx, const net_dst *d)
{
    (void)ctx;
    static const uint8_t local4[4] = {203, 0, 113, 7};
    return !d->v6 && !memcmp(d->addr, local4, 4) ? RTN_LOCAL : RTN_UNICAST;
}

static int route(const net_policy *p, const char *addr, uint16_t port, uint8_t proto, net_dst *out)
{
    net_dst d = {.proto = proto, .port = port};
    if (inet_pton(AF_INET, addr, d.addr) != 1) {
        d.v6 = true;
        if (inet_pton(AF_INET6, addr, d.addr) != 1)
            return -999;
    }
    return net_policy_route(p, &d, out, fake_route, nullptr);
}

static void policy_tests(void)
{
    printf("egress policy:\n");
    net_policy p = {0};
    net_dst o;
    struct {
        const char *addr;
        uint16_t port;
        bool ok;
    } base[] = {
        {"8.8.8.8", 443, true},          {"1.1.1.1", 53, true},
        {"2001:4860:4860::8888", 443, true},
        {"10.0.2.2", 80, false},         // the host's loopback
        {"127.0.0.1", 80, false},        {"169.254.169.254", 80, false},
        {"10.1.2.3", 80, false},         {"172.17.0.1", 2375, false}, // docker
        {"192.168.1.1", 80, false},      {"100.100.100.100", 53, false}, // tailscale
        {"100.64.0.1", 80, false},       {"0.0.0.0", 80, false},
        {"224.0.0.1", 80, false},        {"255.255.255.255", 80, false},
        {"198.18.0.1", 80, false},       {"203.0.113.7", 22, false}, // the host's own (fake route)
        {"8.8.8.8", 0, false},           {"10.0.2.3", 53, false},    // no resolver configured
        {"::1", 80, false},              {"fe80::1", 80, false},
        {"fd00:ec2::254", 80, false},    {"::ffff:127.0.0.1", 80, false},
        {"64:ff9b::808:808", 80, false}, {"2002:7f00:1::1", 80, false},
        {"ff02::1", 80, false},          {"::", 80, false},
    };
    bool all = true;
    for (size_t i = 0; i < sizeof base / sizeof base[0]; i++) {
        const int rc = route(&p, base[i].addr, base[i].port, NET_TCP, &o);
        if ((rc == 0) != base[i].ok) {
            printf("    %s port %u: %s, expected %s\n", base[i].addr, base[i].port, rc ? "refused" : "allowed",
                   base[i].ok ? "allowed" : "refused");
            all = false;
        }
    }
    check(all, "the default policy: public allowed, the rest refused");

    {
        net_policy only = {.allow_only = true};
        check(net_policy_allow(&only, "127.0.0.1/32") == 0 && route(&only, "10.0.2.2", 80, NET_TCP, &o) == 0 &&
                  route(&only, "8.8.8.8", 443, NET_TCP, &o) != 0 && route(&only, "10.0.2.3", 53, NET_UDP, &o) != 0 &&
                  route(&only, "10.1.2.3", 80, NET_TCP, &o) != 0,
              "--net-only: the allow ranges and nothing else, not even the resolver");
        net_policy ports = {.allow_only = true};
        check(net_policy_allow(&ports, "127.0.0.1/32,7718") == 0 && net_policy_allow(&ports, "::1,7719") == 0 &&
                  route(&ports, "10.0.2.2", 7718, NET_TCP, &o) == 0 && route(&ports, "10.0.2.2", 7718, NET_UDP, &o) == 0 &&
                  route(&ports, "10.0.2.2", 7719, NET_TCP, &o) != 0 && route(&ports, "10.0.2.2", 80, NET_TCP, &o) != 0 &&
                  route(&ports, "::1", 7719, NET_TCP, &o) == 0 && route(&ports, "::1", 7718, NET_TCP, &o) != 0,
              "--net-allow ADDR,PORT: that port alone");
        net_policy bad = {0};
        check(net_policy_allow(&bad, "127.0.0.1,") && net_policy_allow(&bad, "127.0.0.1,0") &&
                  net_policy_allow(&bad, "127.0.0.1,65536") && net_policy_allow(&bad, "127.0.0.1,80x") &&
                  net_policy_allow(&bad, "127.0.0.1,-1") && net_policy_allow(&bad, ",80") && !bad.nallow,
              "... and a bad port is refused");
    }

    check(!net_policy_dns(&p, "127.0.0.1:5353") && route(&p, "10.0.2.3", 53, NET_UDP, &o) == 0 && !o.v6 &&
              o.port == 5353 && o.addr[0] == 127 && o.proto == NET_UDP,
          "10.0.2.3:53 goes to the resolver, even on loopback");
    check(route(&p, "10.0.2.3", 80, NET_TCP, &o) != 0, "10.0.2.3 is a resolver only");
    check(!net_policy_allow(&p, "127.0.0.1/32") && route(&p, "10.0.2.2", 8080, NET_TCP, &o) == 0 &&
              o.addr[0] == 127 && o.addr[3] == 1 && o.port == 8080,
          "--net-allow 127.0.0.1/32: 10.0.2.2 is the host's loopback");
    check(route(&p, "127.0.0.2", 80, NET_TCP, &o) != 0, "... and only that address");
    check(!net_policy_allow(&p, "203.0.113.0/24") && route(&p, "203.0.113.7", 22, NET_TCP, &o) == 0,
          "an allowed range overrides the route check");
    net_policy q = {0};
    check(net_policy_allow(&q, "10.0.0.0/33") && net_policy_allow(&q, "::1/129") &&
              net_policy_allow(&q, "garbage") && net_policy_allow(&q, "1.2.3.4/") && !q.nallow,
          "bad ranges are refused");
    check(!net_policy_allow(&q, "fd00::/8") && route(&q, "fd12::1", 80, NET_TCP, &o) == 0 &&
              route(&q, "fe80::1", 80, NET_TCP, &o) != 0,
          "an IPv6 range");
    check(!net_policy_dns(&q, "[::1]:5300") && q.dns[0].v6 && q.dns[0].port == 5300 &&
              !net_policy_dns(&q, "::1") && q.dns[1].port == 53 && net_policy_dns(&q, "1.2.3.4:0") &&
              net_policy_dns(&q, "1.2.3.4:70000") && net_policy_dns(&q, "[::1"),
          "resolver addresses and ports");

    printf("denied ports and limits:\n");
    net_policy m = {0};
    check(!net_policy_deny_port(&m, "25") && !net_policy_deny_port(&m, "587") && net_policy_deny_port(&m, "0") &&
              net_policy_deny_port(&m, "65536") && net_policy_deny_port(&m, "x") && net_policy_deny_port(&m, "-1") &&
              m.ndeny_port == 2,
          "--net-deny-port: ports from 1 to 65535");
    check(route(&m, "8.8.8.8", 25, NET_TCP, &o) == -EPERM && route(&m, "8.8.8.8", 587, NET_UDP, &o) == -EPERM &&
              route(&m, "8.8.8.8", 443, NET_TCP, &o) == 0 && route(&m, "10.1.2.3", 25, NET_TCP, &o) == -EPERM,
          "a denied port: EPERM, TCP and UDP, any address");
    check(!net_policy_dns(&m, "127.0.0.1") && route(&m, "10.0.2.3", 53, NET_UDP, &o) == 0,
          "... the resolver still works");
    uint64_t v = 0;
    check(!net_policy_number("1000", 1000, &v) && v == 1000 && net_policy_number("1001", 1000, &v) &&
              net_policy_number("0", 9, &v) && net_policy_number("", 9, &v) && net_policy_number("+1", 9, &v) &&
              net_policy_number("1x", 9, &v) && net_policy_number("99999999999999999999999", ~0ull, &v),
          "numbers: 1 to the maximum, digits only");
    const uint64_t S = 1000000000, t0 = 1000 * S;
    net_limits l = {0};
    m.flow_rate = 10;
    int burst = 0;
    while (burst < 1000 && !net_limit_flow(&l, &m, t0))
        burst++;
    check(burst == 50, "--net-flow-rate 10: a burst of 5 s worth (50), then refused");
    check(net_limit_flow(&l, &m, t0 + S / 20) == -EAGAIN && !net_limit_flow(&l, &m, t0 + S / 10) &&
              net_limit_flow(&l, &m, t0 + S / 10) == -EAGAIN,
          "... then one each 1/10 s");
    int later = 0;
    while (later < 1000 && !net_limit_flow(&l, &m, t0 + 3 * S))
        later++;
    check(later == 29, "... and after 3 s idle, 3 s worth again");
    net_limits d = {0};
    m.max_dests = 3;
    net_dst a1 = {.addr = {1, 1, 1, 1}}, a2 = {.addr = {2, 2, 2, 2}}, a3 = {.addr = {3, 3, 3, 3}},
            a4 = {.addr = {4, 4, 4, 4}}, a4v6 = {.v6 = true, .addr = {4, 4, 4, 4}};
    check(!net_limit_dest(&d, &m, &a1, t0) && !net_limit_dest(&d, &m, &a2, t0) && !net_limit_dest(&d, &m, &a1, t0) &&
              !net_limit_dest(&d, &m, &a3, t0 + S) && net_limit_dest(&d, &m, &a4, t0 + S) == -EAGAIN &&
              net_limit_dest(&d, &m, &a4v6, t0 + S) == -EAGAIN,
          "--net-max-dests 3: a 4th address refused, the 3 reached still allowed");
    check(!net_limit_dest(&d, &m, &a2, t0 + 59 * S) && net_limit_dest(&d, &m, &a4, t0 + 59 * S) == -EAGAIN &&
              !net_limit_dest(&d, &m, &a4, t0 + 60 * S),
          "... a new minute, new addresses");
    net_policy none = {0};
    check(!net_limit_flow(&l, &none, t0) && !net_limit_dest(&d, &none, &a4, t0), "no limits given: none");
}
