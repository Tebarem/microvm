// SPDX-License-Identifier: MIT
// virtio-net (device 1) with a userspace NAT: the guest gets an Ethernet
// link with a static IPv4 address, and the VMM turns its TCP and UDP flows
// into ordinary host sockets. No tap device, no bridge, no privileges.
//
//   guest 10.0.2.15/24 --- gateway 10.0.2.2 (the VMM) --- host sockets
//
// - The VMM answers ARP for every address on the link but the guest's own,
//   and echo requests (ping) to the gateway and DNS addresses itself.
// - A guest TCP connection ends in the VMM: it answers the guest's
//   handshake once the host socket has connected (an RST if that fails),
//   then moves the byte streams. The VMM is the guest's TCP peer, so the
//   link has no loss and the guest's own checksums are never needed.
// - A guest UDP flow (its port, the destination address and port) gets a
//   connected host UDP socket; replies come back from that destination.
// - 10.0.2.3 port 53 is the host's DNS resolver; 10.0.2.2 is the host's
//   loopback, which the egress policy refuses unless told otherwise.
//
// The device never creates a socket itself: it asks an `open` callback for
// each new flow (in the VMM: the network helper process, net_helper.h,
// which decides what may be reached).
//
// Runs on its own I/O thread, like vsock; the guest's queue kicks only wake
// it (a KVM ioeventfd doorbell where there is one).
#pragma once

#include "virtio.h"

typedef struct net net;

enum : uint8_t { NET_TCP = 6, NET_UDP = 17 };

// A destination as the guest addressed it. The open callback maps the
// gateway and DNS addresses to the host's.
typedef struct {
    uint8_t proto; // NET_TCP or NET_UDP
    bool v6;
    uint16_t port;
    uint8_t addr[16]; // IPv4: the first 4 bytes, network order
} net_dst;

// Open a host socket for a new guest flow: TCP non-blocking with its
// connect() started (EINPROGRESS is fine), UDP connected. Returns the fd
// (the device owns it now) or a negative errno.
typedef int (*net_open_fn)(void *ctx, const net_dst *d);

// The guest's static configuration (also on its kernel command line).
constexpr uint8_t NET_GUEST_IP[4] = {10, 0, 2, 15};
constexpr uint8_t NET_GATEWAY_IP[4] = {10, 0, 2, 2};
constexpr uint8_t NET_DNS_IP[4] = {10, 0, 2, 3};

net *net_create(net_open_fn open, void *open_ctx, const guest_mem *mem, ioapic *irq, unsigned pin);
virtio_dev *net_dev(net *n);
// Start the I/O thread, which runs net_poll(n, -1) forever.
[[nodiscard]] int net_start(net *n);
// One pass of the I/O loop: wait up to timeout_ms (-1: no limit) for host
// sockets, the guest or a timer, then move what can move. (Tests and
// fuzzing call it directly, with no I/O thread.)
void net_poll(net *n, int timeout_ms);
// An eventfd the guest's queue kicks may signal directly (KVM_IOEVENTFD).
int net_doorbell_fd(const net *n);
// Cap what all the guest's flows send out together, in bytes a second
// (0: none; call before net_start). TCP waits: the window the guest sees
// closes. UDP over the cap is dropped.
void net_set_tx_rate(net *n, uint64_t bytes_per_s);
// Every 2 s, write the counters to fd (an os_file's handle, at offset 0) as one line of
// names and numbers, since the device started:
//   cpu_ns N tx N rx N flows N refused N denied N limited N
// cpu_ns: the whole VMM's CPU time (the guest's included); tx, rx: payload
// bytes out and in; flows: opened; refused: by the egress policy; denied:
// to a denied port (--net-deny-port); limited: by --net-flow-rate or
// --net-max-dests. The host reads it to tell abuse (net_set_tx_rate's
// caller decides what to do). Call before net_start.
void net_set_stats_fd(net *n, intptr_t fd);
// Most fds the device will hold at once (for RLIMIT_NOFILE).
unsigned net_max_fds(void);
// The guest kernel's static IP configuration ("ip=..."). Returns the length.
int net_cmdline(char *buf, size_t len);
