// SPDX-License-Identifier: MIT
// The network helper: the only process of a VM that can create sockets.
//
// The VMM's sandbox has no socket() or connect(), and seccomp can't look
// at a connect() address anyway (it is behind a pointer). So the VMM never
// connects anywhere: for each new guest flow its virtio-net device asks
// the helper, over a socketpair, for a socket to one destination. The
// helper maps the guest's gateway and DNS addresses, applies the egress
// policy, creates and connects the socket, and passes it back
// (SCM_RIGHTS). The VMM can then only read and write it.
//
// A compromised VMM gets nothing it couldn't ask for as a guest: the
// policy is in the helper, which parses one fixed 24-byte request at a
// time and runs in a sandbox of its own (seccomp, Landlock, no files).
//
// Egress policy (net_policy_route):
// - 10.0.2.3 port 53 (UDP or TCP) goes to the host's resolver (the first
//   nameserver in /etc/resolv.conf, or --net-dns), even where the policy
//   would refuse that address: the guest can't choose it.
// - 10.0.2.2 is the host's loopback (127.0.0.1), refused unless allowed.
// - Refused unless an --net-allow range holds the address: loopback,
//   "this network", link-local (169.254.169.254, the cloud metadata
//   service, is in it), RFC 1918 private ranges, carrier-grade NAT
//   100.64/10 (Tailscale), benchmarking 198.18/15, multicast, reserved
//   and broadcast; for IPv6 the matching ranges plus ULA fc00::/7,
//   IPv4-mapped/NAT64/6to4 forms; and any address the host's routing
//   table says is local, broadcast, multicast or unroutable (the host's
//   own public addresses, and so every service listening on 0.0.0.0).
// - With deny_all (--net-deny-all), everything is refused, the resolver
//   too: the guest has a network device and nowhere to go (E2B's
//   allow_internet_access=false, for a VM restored from a snapshot that
//   was taken with a network).
// - With allow_only (--net-only), nothing but the allow ranges is reachable:
//   no public internet and no resolver. For a guest that should talk to
//   services on its host and to nothing else.
// - --net-deny-port PORT refuses that port everywhere, TCP and UDP (mail:
//   25, 465, 587), with EPERM rather than EACCES, so the device can count
//   it apart.
//
// Limits (net_limit_flow, net_limit_dest), against a guest used to scan,
// flood or spam from the host's addresses. Refusals are EAGAIN.
// - --net-flow-rate N: new flows a second, in bursts of up to 5 s worth.
//   Every request counts, refused ones too.
// - --net-max-dests N: different addresses a minute. Ones already reached
//   this minute stay reachable; a new one past N is refused.
// - --net-tx-rate BYTES: each TCP socket is paced to it (SO_MAX_PACING_RATE)
//   by the kernel, which the VMM can't change. The device's own cap on all
//   its flows together (net_set_tx_rate) is the one a guest meets; this is
//   what's left if the VMM falls.
//
// Windows hosts have no helper process yet: the same policy and limits
// (but --net-tx-rate's per-socket pacing, and --net-fd) are applied inside
// the VMM, whose sandbox there doesn't take sockets away. That stops a
// hostile guest, not a VMM the guest took over.
#pragma once

#include "dev/net.h"

#if defined(_WIN32)
enum { RTN_UNICAST = 1, RTN_LOCAL = 2 }; // Linux's names for what a route is (net_route_fn)
#endif

constexpr int NET_MAX_ALLOW = 16;
constexpr int NET_MAX_DNS = 3;
constexpr int NET_MAX_DENY_PORTS = 16;
constexpr uint32_t NET_MAX_DESTS = 4096;         // --net-max-dests at most
constexpr uint64_t NET_MAX_TX_RATE = 1000000000; // --net-tx-rate at most: 8 Gbit/s

typedef struct {
    bool v6;
    uint8_t bits;
    uint8_t addr[16];
    uint16_t port; // 0: every port
} net_cidr;

typedef struct {
    net_cidr allow[NET_MAX_ALLOW];
    int nallow;
    net_dst dns[NET_MAX_DNS]; // where the guest's DNS address goes (port 53)
    int ndns;
    bool deny_all;
    bool allow_only;
    uint16_t deny_port[NET_MAX_DENY_PORTS];
    int ndeny_port;
    uint32_t flow_rate; // new flows a second (0: no limit)
    uint32_t max_dests; // different addresses a minute (0: no limit)
    uint64_t tx_rate;   // bytes a second out, each TCP socket (0: no limit)
} net_policy;

// The limits' state (the helper's; one VM's).
typedef struct {
    uint64_t flow_tat; // when the flows so far would have been spread out at flow_rate
    uint64_t minute;   // when the destinations below started being counted
    uint32_t ndests;
    uint8_t dests[NET_MAX_DESTS][17]; // v6, then the address
} net_limits;

// "ADDR/BITS" (or a bare address) into the allow list, with ",PORT" after it
// for that port alone (TCP and UDP). 0 or -1.
[[nodiscard]] int net_policy_allow(net_policy *p, const char *cidr);
// A resolver for the guest's DNS address: ADDR, IPV4:PORT or [IPV6]:PORT
// (port 53 by default). 0 or -1.
[[nodiscard]] int net_policy_dns(net_policy *p, const char *addr);
// The nameservers in the host's /etc/resolv.conf, if none were given.
void net_policy_host_dns(net_policy *p);
// --net-deny-port PORT (1-65535). 0 or -1.
[[nodiscard]] int net_policy_deny_port(net_policy *p, const char *port);
// A decimal number from 1 to max into *out. 0 or -1.
[[nodiscard]] int net_policy_number(const char *s, uint64_t max, uint64_t *out);

// A new flow at now_ns: 0, or -EAGAIN past --net-flow-rate.
[[nodiscard]] int net_limit_flow(net_limits *l, const net_policy *p, uint64_t now_ns);
// An allowed flow to `to`: 0, or -EAGAIN for a new address past
// --net-max-dests this minute.
[[nodiscard]] int net_limit_dest(net_limits *l, const net_policy *p, const net_dst *to, uint64_t now_ns);

// Where a guest destination goes: *out gets the host's address for it.
// Returns 0, -EACCES if the policy refuses it, or -EPERM for a denied port. `route_type` asks the
// host's routing table (RTN_* for the address; nullptr: assume unicast).
typedef int (*net_route_fn)(void *ctx, const net_dst *d);
[[nodiscard]] int net_policy_route(const net_policy *p, const net_dst *d, net_dst *out,
                                   net_route_fn route_type, void *ctx);

// Fork the helper (call while single-threaded, before guest RAM exists).
// Returns the VMM's end of the channel, or -1.
[[nodiscard]] int net_helper_start(const net_policy *p);
// The helper's loop on an existing channel (microvm-jail starts it outside
// the VM's network namespace). Never returns.
[[noreturn]] void net_helper_main(int chan, const net_policy *p);
// 0 if FD is a helper channel (an AF_UNIX SOCK_SEQPACKET socket), else -1.
[[nodiscard]] int net_helper_check_fd(int fd);
// The device's net_open_fn: ctx is the channel fd, as (void *)(intptr_t).
int net_helper_open(void *ctx, const net_dst *d);
