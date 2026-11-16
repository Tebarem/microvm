// SPDX-License-Identifier: MIT
// Fuzz the virtio-net device and its NAT (Linux): a hostile guest sends
// arbitrary frames (TCP with any flags, sequence numbers, options and
// lengths, UDP, DNS, ARP, ICMP, IPv6, fragments, lying length fields,
// headers split across descriptors), offers receive buffers of any size or
// none, resets the device and pokes memory, while the host ends of its flows
// (socketpairs standing in for the helper's sockets) write, read, half-close
// and hang up. net_poll() runs on this thread in place of the I/O thread.
// Includes net.c to check the device's own state as it goes.
//
// What must hold, unless the guest rewrote memory behind the driver's back:
// - the receive ring: buffers come back in the order offered, never longer
//   than offered, a frame's buffers all published at once;
// - every frame is well formed: our MACs, IPv4 to the guest, correct
//   lengths, valid checksums (or DATA_VALID when the guest allows that);
// - TCP to the guest stays inside the window the guest advertised, and its
//   bytes are the host's bytes at the right sequence numbers;
// - what reaches a host socket is the guest's bytes, in order, no gaps;
// - the device's flows stay consistent; a reset frees them all and leaks no
//   file descriptor.
//
// Input: one byte of negotiated features, then 10-byte records {op, a[9]}.
#include "dev/net.c"

#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include "fuzz.h"

enum : uint64_t {
    RX_DESC = 0x0000, RX_AVAIL = 0x0400, RX_USED = 0x0800,
    TX_DESC = 0x1000, TX_AVAIL = 0x1800, TX_USED = 0x1c00,
    TX_BUF = 0x4000,  // TX_SLOTS slots of 0x1000
    RX_BUF = 0x20000, // RXN slots of 0x1000
    MEM_SIZE = 0x40000,
};
enum : uint16_t { RXN = 32, TXN = 64, TX_SLOTS = 16 };
enum { NG = 8, NP = 24 };

static guest_mem mem;
static ioapic irq;
static net *dev;
static bool tainted; // the guest wrote memory or registers behind the driver
// A frame lied about where its TCP payload starts: the device rightly took
// header bytes as data, so what reaches a host socket is no longer only the
// guest's numbered bytes.
static bool lied_offset;
static uint16_t rx_avail, rx_seen, tx_avail;
static uint32_t rx_len[RXN];
static uint8_t split_mode;
static int refuse_next; // the next open fails with this (0: it doesn't)
static int base_fds = -1;
static uint8_t frame[70000];

static const uint8_t RADDR[4][4] = {{10, 0, 2, 2}, {1, 2, 3, 4}, {93, 184, 216, 34}, {10, 0, 2, 3}};

// ---- the host ends --------------------------------------------------------------------
typedef struct {
    int fd, devfd;
    bool tcp;
    uint8_t salt;  // host -> guest bytes: (uint8_t)(salt + offset)
    uint32_t wr;   // bytes written
    bool got_any;  // guest -> host: consecutive bytes from the first one on
    uint8_t next;
} peer;
static peer peers[NP];

static bool devfd_in_use(int fd)
{
    for (int i = 0; i < MAX_TCP; i++)
        if (dev->t[i].state != T_FREE && dev->t[i].fd == fd)
            return true;
    for (int i = 0; i < MAX_UDP; i++)
        if (dev->u[i].used && dev->u[i].fd == fd)
            return true;
    return false;
}

static void peer_close(peer *p)
{
    if (p->fd >= 0)
        close(p->fd);
    *p = (peer){.fd = -1, .devfd = -1};
}

// The device closed its end: this host end is done (and the number may
// come back for a new socket).
static void reap(void)
{
    for (int i = 0; i < NP; i++)
        if (peers[i].fd >= 0 && !devfd_in_use(peers[i].devfd))
            peer_close(&peers[i]);
}

static int open_cb(void *ctx, const net_dst *d)
{
    (void)ctx;
    FUZZ_ASSERT(d->proto == NET_TCP || d->proto == NET_UDP);
    FUZZ_ASSERT(!d->v6 && d->port);
    if (refuse_next) {
        const int e = refuse_next;
        refuse_next = 0;
        return e;
    }
    reap();
    peer *p = nullptr;
    for (int i = 0; i < NP && !p; i++)
        if (peers[i].fd < 0)
            p = &peers[i];
    if (!p)
        return -EMFILE;
    int sv[2];
    if (socketpair(AF_UNIX, (d->proto == NET_TCP ? SOCK_STREAM : SOCK_DGRAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv))
        return -errno;
    *p = (peer){.fd = sv[1], .devfd = sv[0], .tcp = d->proto == NET_TCP, .salt = (uint8_t)(sv[1] * 37)};
    return sv[0];
}

static void peer_op(const uint8_t *a)
{
    peer *p = &peers[a[0] % NP];
    if (p->fd < 0)
        return;
    static uint8_t buf[1 << 17];
    switch (a[1] % 6) {
    case 0:
    case 1: { // write
        const size_t len = (size_t)(a[2] | a[3] << 8 | (a[4] & 1) << 16) % sizeof buf + 1;
        for (size_t i = 0; i < len; i++)
            buf[i] = (uint8_t)(p->salt + p->wr + i);
        const ssize_t w = write(p->fd, buf, p->tcp ? len : len % 2000 + 1);
        if (w > 0 && p->tcp)
            p->wr += (uint32_t)w;
        break;
    }
    case 2: { // read: the guest's bytes, consecutive
        for (ssize_t r; (r = read(p->fd, buf, sizeof buf)) > 0;) {
            if (!p->tcp || tainted || lied_offset)
                continue;
            for (ssize_t i = 0; i < r; i++) {
                FUZZ_ASSERT(!p->got_any || buf[i] == p->next);
                p->got_any = true;
                p->next = (uint8_t)(buf[i] + 1);
            }
        }
        break;
    }
    case 3:
        shutdown(p->fd, SHUT_WR);
        break;
    case 4:
        peer_close(p);
        break;
    default: // a small receive buffer: the device's writes back up
        (void)setsockopt(p->fd, SOL_SOCKET, SO_RCVBUF, &(int){1}, sizeof(int));
        (void)setsockopt(p->devfd, SOL_SOCKET, SO_SNDBUF, &(int){1}, sizeof(int));
        break;
    }
}

// ---- the guest's side of its TCP connections ------------------------------------------
typedef struct {
    enum : uint8_t { G_NONE, G_SYN, G_EST } st;
    uint32_t iss, snd_nxt;       // ours
    uint32_t dev_iss, rcv_nxt;   // the device's
    bool ws;                     // we offered window scale
    uint8_t ws_shift;
    uint16_t mss;
    bool honest;                 // every ACK we sent was rcv_nxt: the edge below is real
    uint32_t edge;               // the right edge of the window we advertised
    bool have_k;
    uint8_t k;                   // host bytes: (uint8_t)(offset + k)
} gconn;
static gconn gc[NG];

// Every SYN each connection sent in this input. The device keeps a pending
// flow when a SYN with its ISN comes again, so the MSS it holds may be that of
// any earlier SYN with the same ISN, not just the last one the model knows.
#define NSYN 16
static struct {
    unsigned n;
    struct {
        uint32_t iss;
        uint16_t mss;
    } s[NSYN];
} syns[NG];

// The largest MSS the device may hold for connection c's SYN with this ISN,
// and remember this one.
static uint16_t syn_seen(int c, uint32_t iss, uint16_t mss, bool *again)
{
    uint16_t m = mss;
    *again = syns[c].n > NSYN;
    if (*again)
        return MTU - 40; // lost track
    for (unsigned i = 0; i < syns[c].n; i++)
        if (syns[c].s[i].iss == iss) {
            *again = true;
            if (syns[c].s[i].mss > m)
                m = syns[c].s[i].mss;
        }
    if (syns[c].n < NSYN)
        syns[c].s[syns[c].n] = (typeof(syns[c].s[0])){iss, mss};
    syns[c].n++;
    return m;
}

static uint16_t gport(int c) { return (uint16_t)(40000 + c); }
static uint16_t rport(int c) { return (uint16_t)(80 + c); }

// ---- the transport ----------------------------------------------------------------------
static void no_msi(void *ctx, uint64_t a, uint32_t d) { (void)ctx, (void)a, (void)d; }

static void vw(uint64_t off, uint32_t v)
{
    uint64_t x = v;
    virtio_mmio_access(&dev->dev, off, 4, true, &x);
}

static void queue(uint16_t q, uint16_t num, uint64_t desc, uint64_t avail, uint64_t used)
{
    vw(0x030, q);
    vw(0x038, num);
    vw(0x080, (uint32_t)desc);
    vw(0x090, (uint32_t)avail);
    vw(0x0a0, (uint32_t)used);
    vw(0x044, 1);
}

static void bring_up(uint8_t feat)
{
    vw(0x070, 0);
    memset(mem.base, 0, MEM_SIZE);
    vw(0x070, 3);
    vw(0x024, 1);
    vw(0x020, 1); // VERSION_1
    vw(0x024, 0);
    vw(0x020, (feat & 1 ? F_CSUM : 0) | (feat & 2 ? F_GUEST_CSUM : 0) | (feat & 4 ? F_MTU | F_MAC : 0) |
                  (feat & 8 ? 0 : F_MRG_RXBUF)); // mostly mergeable, as Linux negotiates
    vw(0x070, 11);
    queue(0, RXN, RX_DESC, RX_AVAIL, RX_USED);
    queue(1, TXN, TX_DESC, TX_AVAIL, TX_USED);
    vw(0x070, 15);
    rx_avail = rx_seen = tx_avail = 0;
}

static void desc(uint64_t base, uint16_t i, uint64_t addr, uint32_t len, uint16_t flags, uint16_t next)
{
    uint8_t *e = mem.base + base + 16u * i;
    put_le64(e, addr);
    put_le32(e + 8, len);
    put_le16(e + 12, flags);
    put_le16(e + 14, next);
}

static void offer_rx(unsigned count, uint8_t sizes)
{
    for (unsigned k = 0; k < count && (uint16_t)(rx_avail - rx_seen) < RXN; k++) {
        const uint16_t slot = rx_avail % RXN;
        // Mostly 1.5 KiB as Linux posts them; now and then one too small for
        // a frame, a tiny one, or a whole slot.
        static const uint32_t L[8] = {1536, 1536, 1536, 4096, 90, 128, 300, 1536};
        const uint32_t len = L[(sizes >> (k % 3 * 3)) & 7];
        rx_len[slot] = len;
        desc(RX_DESC, slot, RX_BUF + 0x1000u * slot, len, 2, 0);
        put_le16(mem.base + RX_AVAIL + 4 + 2u * slot, slot);
        rx_avail++;
        __atomic_store_n((uint16_t *)(mem.base + RX_AVAIL + 2), rx_avail, __ATOMIC_RELEASE);
    }
    vw(0x050, 0);
}

static void poll_dev(void)
{
    net_poll(dev, 0);
    reap();
}

// A frame from the guest: frame[0..len) after a 12-byte virtio header.
static void tx(uint32_t len)
{
    // No more in flight than the slots hold: the device takes them when it polls.
    while ((uint16_t)(tx_avail - get_le16(mem.base + TX_USED + 2)) >= TX_SLOTS) {
        const uint16_t before = get_le16(mem.base + TX_USED + 2);
        poll_dev();
        if (get_le16(mem.base + TX_USED + 2) == before) {
            tainted = true; // the queue is broken: it no longer takes frames
            return;
        }
    }
    const uint16_t slot = tx_avail % TX_SLOTS;
    uint8_t *b = mem.base + TX_BUF + 0x1000u * slot;
    if (len > 0x1000 - VHDR)
        len = 0x1000 - VHDR;
    memset(b, 0, VHDR);
    if (split_mode & 0x80) // a header the guest made up
        memcpy(b, frame + len - (len > 12 ? 12 : len), len > 12 ? 12 : len);
    memcpy(b + VHDR, frame, len);
    const uint64_t at = TX_BUF + 0x1000u * slot;
    const uint32_t total = VHDR + len;
    // Split the chain: none, mid-header, at the virtio header, mid-payload.
    static const uint32_t S[8] = {0, 1, 12, 13, 26, 40, 60, 300};
    uint32_t c1 = S[split_mode & 7], c2 = S[(split_mode >> 3) & 7] + c1;
    const uint16_t d0 = (uint16_t)(4 * slot);
    if (!c1 || c1 >= total) {
        desc(TX_DESC, d0, at, total, 0, 0);
    } else if (c2 <= c1 || c2 >= total) {
        desc(TX_DESC, d0, at, c1, 1, (uint16_t)(d0 + 1));
        desc(TX_DESC, d0 + 1, at + c1, total - c1, 0, 0);
    } else {
        desc(TX_DESC, d0, at, c1, 1, (uint16_t)(d0 + 1));
        desc(TX_DESC, d0 + 1, at + c1, c2 - c1, 1, (uint16_t)(d0 + 2));
        desc(TX_DESC, d0 + 2, at + c2, total - c2, 0, 0);
    }
    put_le16(mem.base + TX_AVAIL + 4 + 2u * (tx_avail % TXN), d0);
    tx_avail++;
    __atomic_store_n((uint16_t *)(mem.base + TX_AVAIL + 2), tx_avail, __ATOMIC_RELEASE);
    vw(0x050, 1);
}

// ---- building frames ------------------------------------------------------------------
static uint32_t eth_ip(uint8_t proto, const uint8_t dst[4], uint32_t l4len, uint8_t mangle)
{
    memcpy(frame, GW_MAC, 6);
    memcpy(frame + 6, GUEST_MAC, 6);
    put_be16(frame + 12, 0x0800);
    uint8_t *ip = frame + ETH;
    ip[0] = 0x45;
    ip[1] = 0;
    put_be16(ip + 2, (uint16_t)(20 + l4len));
    put_be16(ip + 4, 0);
    put_be16(ip + 6, 0x4000); // DF
    ip[8] = 64;
    ip[9] = proto;
    put_be16(ip + 10, 0);
    memcpy(ip + 12, NET_GUEST_IP, 4);
    memcpy(ip + 16, dst, 4);
    switch (mangle % 16) { // now and then, a header that lies
    case 1: put_be16(ip + 2, (uint16_t)(20 + l4len + 1 + mangle)); break;     // longer than the frame
    case 2: put_be16(ip + 2, (uint16_t)(l4len > mangle ? 20 + l4len - mangle : 0)); break;
    case 3: ip[0] = (uint8_t)(0x40 | (mangle >> 4)); break;                   // any IHL
    case 4: put_be16(ip + 6, (uint16_t)(0x2000 | mangle)); break;            // a fragment
    case 5: ip[12] = 10, ip[15] = 99; break;                                 // not from the guest
    case 6: ip[0] = 0x65; break;                                             // IPv6 in IPv4's clothes
    default: break;
    }
    return ETH + 20;
}

static void tcp_frame(int c, const uint8_t dst[4], uint32_t seq, uint32_t ack, uint8_t flags, uint16_t win,
                      const uint8_t *opt, uint32_t optlen, uint32_t plen, uint8_t mangle)
{
    const uint32_t thl = 20 + optlen;
    if (plen > 0x1000 - VHDR - ETH - 20 - thl)
        plen = 0x1000 - VHDR - ETH - 20 - thl;
    const uint32_t l4 = eth_ip(NET_TCP, dst, thl + plen, mangle);
    if (mangle % 16 == 3 || mangle % 16 == 7)
        lied_offset = true;
    uint8_t *th = frame + l4;
    put_be16(th, gport(c));
    put_be16(th + 2, rport(c));
    put_be32(th + 4, seq);
    put_be32(th + 8, ack);
    th[12] = (uint8_t)((thl / 4) << 4);
    if (mangle % 16 == 7)
        th[12] = (uint8_t)(mangle & 0xf0); // any data offset
    th[13] = flags;
    put_be16(th + 14, win);
    put_be16(th + 16, 0);
    put_be16(th + 18, 0);
    if (optlen)
        memcpy(th + 20, opt, optlen);
    for (uint32_t i = 0; i < plen; i++)
        th[thl + i] = (uint8_t)(seq + i); // the guest's bytes: their sequence number's low byte
    tx(l4 + thl + plen);
}

static void guest_tcp(const uint8_t *a)
{
    const int c = a[0] % NG;
    gconn *g = &gc[c];
    const uint8_t *dst = RADDR[c % 4];
    const uint8_t mangle = a[8] & 0x80 ? a[7] : 0;
    const uint16_t win = a[6] & 1 ? (uint16_t)(a[5] << 8) : 0xffff;
    const bool lie = a[6] & 2; // an ACK that isn't rcv_nxt
    const uint32_t ack = lie ? get_le32(a + 2) : g->rcv_nxt;
    if (g->st == G_EST && !lie) {
        const uint32_t edge = ack + ((uint32_t)win << (g->ws ? g->ws_shift : 0));
        if (seq_lt(g->edge, edge))
            g->edge = edge;
    } else if (lie) {
        g->honest = false;
    }
    switch (a[1] % 8) {
    case 0: { // SYN, with options or without
        *g = (gconn){.st = G_SYN, .iss = get_le32(a + 2), .honest = true, .mss = 536};
        g->snd_nxt = g->iss + 1;
        uint8_t opt[12] = {2, 4, 0, 0, 1, 3, 3, 0, 1, 1, 1, 1};
        uint32_t optlen = 0;
        if (a[6] & 4) {
            g->mss = (uint16_t)(a[3] << 8 | a[4]);
            put_be16(opt + 2, g->mss);
            if (g->mss < 64)
                g->mss = 64;
            if (g->mss > MTU - 40)
                g->mss = MTU - 40;
            optlen = 4;
        }
        if (a[6] & 8) {
            g->ws = true;
            g->ws_shift = a[5] % 16 > 14 ? 14 : a[5] % 16;
            opt[7] = a[5] % 16;
            optlen = 8;
        }
        if (a[6] & 16) { // options that don't parse
            memcpy(opt, a + 2, 6);
            optlen = 12;
            g->honest = false;
            g->mss = MTU - 40; // whatever the device made of them
        }
        if (mangle) { // the device may not have seen the options as sent
            g->mss = MTU - 40;
            g->honest = false;
        }
        // The same SYN again: the device keeps the connection it has, and
        // what it took from the first one.
        bool again;
        g->mss = syn_seen(c, g->iss, g->mss, &again);
        if (again)
            g->honest = false;
        tcp_frame(c, dst, g->iss, 0, TH_SYN, 0xffff, opt, optlen, 0, mangle);
        break;
    }
    case 1: // an ACK (a window update)
        tcp_frame(c, dst, g->snd_nxt, ack, TH_ACK, win, nullptr, 0, 0, mangle);
        break;
    case 2:
    case 3: { // data: in order, resent, overlapping, or ahead
        const uint32_t plen = (uint32_t)(a[3] | a[4] << 8) % 3900;
        uint32_t seq = g->snd_nxt;
        if (a[6] & 32)
            seq -= a[7];
        else if (a[6] & 64)
            seq += a[7];
        tcp_frame(c, dst, seq, ack, TH_ACK | (a[6] & 128 ? TH_PSH : 0), win, nullptr, 0, plen, mangle);
        if (seq_lt(g->snd_nxt, seq + plen) && !seq_lt(g->snd_nxt, seq))
            g->snd_nxt = seq + plen;
        break;
    }
    case 4: // FIN, maybe with data
        tcp_frame(c, dst, g->snd_nxt, ack, TH_FIN | TH_ACK, win, nullptr, 0, a[3] % 64, mangle);
        g->snd_nxt += a[3] % 64 + 1;
        break;
    case 5:
        tcp_frame(c, dst, g->snd_nxt, ack, TH_RST | (a[6] & 4 ? TH_ACK : 0), 0, nullptr, 0, 0, mangle);
        g->st = G_NONE;
        break;
    case 6: // any flags, any sequence number
        tcp_frame(c, dst, get_le32(a + 2), ack, a[7], win, nullptr, 0, a[3] % 32, mangle);
        if (a[7] & (TH_SYN | TH_RST))
            g->st = G_NONE;
        if ((a[7] & (TH_SYN | TH_RST | TH_ACK)) == TH_SYN) { // a SYN to the device, without options
            bool again;
            syn_seen(c, get_le32(a + 2), mangle ? MTU - 40 : 536, &again);
        }
        break;
    default: { // somewhere it mustn't go, or nowhere
        static const uint8_t ODD[6][4] = {{10, 0, 2, 15}, {255, 255, 255, 255}, {224, 0, 0, 1},
                                          {127, 0, 0, 1}, {0, 0, 0, 0}, {10, 0, 2, 255}};
        tcp_frame(c, ODD[a[2] % 6], get_le32(a + 3), 0, TH_SYN, 0xffff, nullptr, 0, 0, mangle);
        break;
    }
    }
}

static void guest_udp(const uint8_t *a)
{
    // A real query (sometimes cut short) to the resolver: what a refused
    // resolver answers with NXDOMAIN.
    static const uint8_t q[] = {0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'p', 'y', 'p', 4, 'p', 'y', 'p', 'i',
                                3, 'o', 'r', 'g', 0, 0, 1, 0, 1};
    const uint8_t *dst = RADDR[a[0] % 4];
    const bool dns = a[1] & 1, query = dns && a[1] & 2;
    const uint32_t plen = query ? (uint32_t)sizeof q - (a[3] & 1 ? a[3] % (uint32_t)sizeof q : 0)
                                : (uint32_t)(a[2] | a[3] << 8) % 2000;
    const uint32_t l4 = eth_ip(NET_UDP, dns ? NET_DNS_IP : dst, 8 + plen, a[8] & 0x80 ? a[7] : 0);
    uint8_t *uh = frame + l4;
    put_be16(uh, (uint16_t)(50000 + a[4] % 4));
    put_be16(uh + 2, dns ? 53 : (uint16_t)(a[5] % 3 ? 7 : get_be16(a + 5)));
    put_be16(uh + 4, (uint16_t)(a[6] & 1 ? get_be16(a + 6) : 8 + plen)); // a length that lies, now and then
    put_be16(uh + 6, 0);
    for (uint32_t i = 0; i < plen; i++)
        uh[8 + i] = query ? (i < 2 ? a[4 + i] : q[i]) : (uint8_t)(i + a[1]);
    tx(l4 + 8 + plen);
}

static void guest_other(const uint8_t *a)
{
    switch (a[0] % 6) {
    case 0: { // ARP: for the gateway, the resolver, someone else; or garbage
        memset(frame, 0xff, 6);
        memcpy(frame + 6, GUEST_MAC, 6);
        put_be16(frame + 12, 0x0806);
        uint8_t *p = frame + ETH;
        put_be16(p, 1), put_be16(p + 2, 0x0800), p[4] = 6, p[5] = 4;
        put_be16(p + 6, a[1] & 1 ? 2 : 1);
        memcpy(p + 8, GUEST_MAC, 6);
        memcpy(p + 14, NET_GUEST_IP, 4);
        memset(p + 18, 0, 6);
        memcpy(p + 24, RADDR[a[2] % 4], 4);
        if (a[1] & 2)
            p[24] = a[3];
        if (a[1] & 4)
            memcpy(p, a + 3, 6);
        tx(ETH + 28 - (a[1] & 8 ? a[4] % 28 : 0));
        break;
    }
    case 1: { // ICMP echo
        const uint32_t plen = (uint32_t)(a[2] | a[3] << 8) % 1600;
        const uint32_t l4 = eth_ip(1, a[1] & 1 ? NET_GATEWAY_IP : RADDR[a[1] % 4], 8 + plen, a[8] & 0x80 ? a[7] : 0);
        uint8_t *ic = frame + l4;
        ic[0] = a[1] & 2 ? a[4] : 8, ic[1] = 0;
        put_be16(ic + 2, 0), put_be16(ic + 4, 0x1234), put_be16(ic + 6, a[5]);
        for (uint32_t i = 0; i < plen; i++)
            ic[8 + i] = (uint8_t)i;
        tx(l4 + 8 + plen);
        break;
    }
    case 2: { // IPv6
        memcpy(frame, GW_MAC, 6);
        memcpy(frame + 6, GUEST_MAC, 6);
        put_be16(frame + 12, 0x86dd);
        memset(frame + ETH, 0, 40);
        frame[ETH] = 0x60;
        put_be16(frame + ETH + 4, a[1]);
        frame[ETH + 6] = a[2];
        tx(ETH + 40 + a[1] % 64);
        break;
    }
    case 3: // short, or another ethertype
        memcpy(frame, a + 1, 8);
        put_be16(frame + 12, get_be16(a + 2));
        tx(a[4] % 60);
        break;
    case 4: { // any protocol number, any length
        const uint32_t l4 = eth_ip(a[1], RADDR[a[2] % 4], a[3], a[7]);
        memset(frame + l4, a[4], a[3]);
        tx(l4 + a[3]);
        break;
    }
    default: { // TCP with headers cut short or options that run off the end
        const uint32_t l4 = eth_ip(NET_TCP, RADDR[a[1] % 4], a[2] % 64, 0);
        for (uint32_t i = 0; i < a[2] % 64; i++)
            frame[l4 + i] = a[3 + i % 6];
        frame[l4 + 12] = 0xf0; // 60-byte header
        tx(l4 + a[2] % 64);
        break;
    }
    }
}

// ---- checking what the device sent ----------------------------------------------------
static uint16_t csum16(uint32_t sum, const uint8_t *p, uint32_t len)
{
    for (uint32_t i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)p[i] << 8 | p[i + 1];
    if (len & 1)
        sum += (uint32_t)p[len - 1] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)sum;
}

// The device's live flow for connection c, if any. Inputs reuse sequence
// numbers, so a frame still in the ring may come from an earlier flow on
// the same ports: only the live one's frames can be checked against it.
static const tflow *live_flow(int c)
{
    for (int i = 0; i < MAX_TCP; i++) {
        const tflow *f = &dev->t[i];
        if (f->state != T_FREE && f->k.gport == gport(c) && f->k.rport == rport(c) &&
            !memcmp(f->k.raddr, RADDR[c % 4], 4))
            return f;
    }
    return nullptr;
}

static void check_tcp(const uint8_t *ip, const uint8_t *th, uint32_t l4len)
{
    FUZZ_ASSERT(l4len >= 20);
    const uint32_t thl = (th[12] >> 4) * 4u;
    FUZZ_ASSERT(thl >= 20 && thl <= l4len);
    const uint16_t gp = get_be16(th + 2), rp = get_be16(th);
    const uint32_t seq = get_be32(th + 4), ack = get_be32(th + 8);
    const uint8_t fl = th[13];
    const uint32_t plen = l4len - thl;
    const int c = gp - 40000;
    if (c < 0 || c >= NG || rp != rport(c) || memcmp(ip + 12, RADDR[c % 4], 4))
        return; // an RST to something the guest made up
    gconn *g = &gc[c];
    if (fl & TH_RST) {
        g->st = G_NONE;
        return;
    }
    if (fl & TH_SYN) {
        FUZZ_ASSERT(fl & TH_ACK && plen == 0);
        const tflow *lf = live_flow(c);
        if (g->st == G_SYN && ack == g->iss + 1 && lf && lf->iss == seq) {
            g->st = G_EST;
            g->dev_iss = seq;
            g->rcv_nxt = g->edge = seq + 1;
            g->have_k = false;
            // window scale only if we offered it
            bool ws = false;
            for (uint32_t i = 20; i + 2 < thl; i += th[i] <= 1 ? 1 : th[i + 1])
                if (th[i] == 3)
                    ws = true;
            g->ws = g->ws && ws;
        }
        return;
    }
    if (g->st != G_EST || !seq_lt(g->dev_iss, seq + 1 + plen))
        return;
    const tflow *lf = live_flow(c);
    if (!lf || lf->iss != g->dev_iss)
        return; // from a flow that is gone

    FUZZ_ASSERT(fl & TH_ACK);
    FUZZ_ASSERT(plen <= g->mss);
    if (g->honest)
        FUZZ_ASSERT(!seq_lt(g->edge, seq + plen)); // inside the window we gave
    for (uint32_t i = 0; i < plen; i++) {
        const uint32_t off = seq + i - g->dev_iss - 1;
        if (!g->have_k) {
            g->k = (uint8_t)(th[thl + i] - off);
            g->have_k = true;
        }
        FUZZ_ASSERT(th[thl + i] == (uint8_t)(off + g->k));
    }
    if (seq == g->rcv_nxt || (seq_lt(seq, g->rcv_nxt) && seq_lt(g->rcv_nxt, seq + plen)))
        g->rcv_nxt = seq + plen;
    if ((fl & TH_FIN) && g->rcv_nxt == seq + plen)
        g->rcv_nxt++;
}

static void check_frame(const uint8_t *f, uint32_t len)
{
    const uint8_t *vh = f;
    if (dev->dev.driver_features & F_GUEST_CSUM)
        FUZZ_ASSERT(vh[0] == VH_DATA_VALID);
    FUZZ_ASSERT(len >= VHDR + ETH);
    const uint8_t *e = f + VHDR;
    FUZZ_ASSERT(!memcmp(e, GUEST_MAC, 6) && !memcmp(e + 6, GW_MAC, 6));
    const uint16_t type = get_be16(e + 12);
    FUZZ_ASSERT(type == 0x0800 || type == 0x0806);
    if (type == 0x0806) {
        FUZZ_ASSERT(len >= VHDR + ETH + 28 && get_be16(e + ETH + 6) == 2);
        return;
    }
    const uint8_t *ip = e + ETH;
    const uint32_t iplen = len - VHDR - ETH;
    FUZZ_ASSERT(iplen >= 20 && ip[0] == 0x45 && get_be16(ip + 2) == iplen);
    FUZZ_ASSERT(!memcmp(ip + 16, NET_GUEST_IP, 4));
    FUZZ_ASSERT(csum16(0, ip, 20) == 0xffff);
    const bool do_csum = !(dev->dev.driver_features & F_GUEST_CSUM);
    const uint32_t l4len = iplen - 20;
    uint32_t pseudo = (uint32_t)get_be16(ip + 12) + get_be16(ip + 14) + get_be16(ip + 16) + get_be16(ip + 18) +
                      ip[9] + l4len;
    switch (ip[9]) {
    case NET_TCP:
        if (do_csum)
            FUZZ_ASSERT(csum16(pseudo, ip + 20, l4len) == 0xffff);
        check_tcp(ip, ip + 20, l4len);
        break;
    case NET_UDP:
        FUZZ_ASSERT(l4len >= 8 && get_be16(ip + 24) == l4len);
        if (do_csum && get_be16(ip + 26))
            FUZZ_ASSERT(csum16(pseudo, ip + 20, l4len) == 0xffff);
        if (do_csum && !get_be16(ip + 26) && !memcmp(ip + 12, NET_DNS_IP, 4)) {
            // Only the answers to refused queries made here go without a
            // checksum (the resolver's datagrams get one): NXDOMAIN, one
            // question, nothing else, and the question ends exactly with the
            // datagram.
            FUZZ_ASSERT(l4len >= 8 + 12 + 1 + 4 && (ip[30] & 0x80) && (ip[31] & 15) == 3);
            const uint8_t *d = ip + 28;
            const uint32_t dl = l4len - 8;
            FUZZ_ASSERT(get_be16(d + 4) == 1 && !get_be16(d + 6) && !get_be16(d + 8) && !get_be16(d + 10));
            uint32_t i = 12;
            while (i < dl && d[i])
                i += 1u + d[i];
            FUZZ_ASSERT(i + 1 + 4 == dl && i - 12 + 1 <= 255);
        }
        break;
    case 1: // an echo reply from the gateway or the resolver, or a refused datagram's
        FUZZ_ASSERT(l4len >= 8 && csum16(0, ip + 20, l4len) == 0xffff);
        if (ip[20] == 3) {
            // Administratively prohibited, from the gateway, quoting a UDP
            // datagram from the guest: a valid IP header and the UDP header.
            const uint8_t *q = ip + 28;
            FUZZ_ASSERT(ip[21] == 13 && l4len == 36 && !memcmp(ip + 12, NET_GATEWAY_IP, 4));
            FUZZ_ASSERT(q[0] == 0x45 && q[9] == NET_UDP && !memcmp(q + 12, NET_GUEST_IP, 4));
            FUZZ_ASSERT(csum16(0, q, 20) == 0xffff && get_be16(q + 2) == 20 + get_be16(q + 24));
            break;
        }
        FUZZ_ASSERT(ip[20] == 0);
        FUZZ_ASSERT(!memcmp(ip + 12, NET_GATEWAY_IP, 4) || !memcmp(ip + 12, NET_DNS_IP, 4));
        break;
    default:
        FUZZ_ASSERT(!"a protocol we never send");
    }
}

// Take what the device returned on the receive queue, as the guest would.
static void consume_rx(void)
{
    const uint16_t used = __atomic_load_n((uint16_t *)(mem.base + RX_USED + 2), __ATOMIC_ACQUIRE);
    FUZZ_ASSERT(tainted || (uint16_t)(used - rx_seen) <= (uint16_t)(rx_avail - rx_seen));
    if (tainted || (uint16_t)(used - rx_seen) > RXN) {
        rx_seen = used;
        return;
    }
    while (rx_seen != used) {
        const uint8_t *ent = mem.base + RX_USED + 4 + 8u * (rx_seen % RXN);
        const uint32_t id = get_le32(ent), len = get_le32(ent + 4);
        // In the order offered, never more than offered.
        FUZZ_ASSERT(id == rx_seen % RXN && len <= rx_len[id]);
        rx_seen++;
        if (!len) { // handed back unused: too small for anything
            FUZZ_ASSERT(rx_len[id] < RX_MIN_BUF);
            continue;
        }
        FUZZ_ASSERT(len >= VHDR);
        const uint8_t *b = mem.base + RX_BUF + 0x1000u * id;
        const uint16_t nb = get_le16(b + 10);
        FUZZ_ASSERT(nb >= 1 && (nb == 1 || (dev->dev.driver_features & F_MRG_RXBUF)));
        // All of a frame's buffers are there at once.
        FUZZ_ASSERT((uint16_t)(used - rx_seen) >= nb - 1u);
        uint32_t flen = len;
        memcpy(frame, b, len);
        for (unsigned i = 1; i < nb; i++) {
            const uint8_t *en = mem.base + RX_USED + 4 + 8u * (rx_seen % RXN);
            const uint32_t id2 = get_le32(en), l2 = get_le32(en + 4);
            FUZZ_ASSERT(id2 == rx_seen % RXN && l2 > 0 && l2 <= rx_len[id2] && flen + l2 <= sizeof frame);
            memcpy(frame + flen, mem.base + RX_BUF + 0x1000u * id2, l2);
            flen += l2;
            rx_seen++;
        }
        check_frame(frame, flen);
    }
}

// ---- the device's own state -------------------------------------------------------------
static void check_state(void)
{
    FUZZ_ASSERT(dev->nrst >= 0 && dev->nrst <= MAX_RST);
    FUZZ_ASSERT(dev->nctrl >= 0 && dev->nctrl <= MAX_CTRL);
    FUZZ_ASSERT(dev->udp_pending >= -1 && dev->udp_pending < MAX_UDP);
    FUZZ_ASSERT(dev->udp_pending < 0 || dev->u[dev->udp_pending].used);
    for (int i = 0; i < MAX_TCP; i++) {
        const tflow *f = &dev->t[i];
        FUZZ_ASSERT(f->state <= T_EST);
        FUZZ_ASSERT((f->state == T_FREE) == (f->fd < 0));
        FUZZ_ASSERT(f->in == dev->t[0].in + (size_t)i * (TCP_IN + TCP_OUT));
        FUZZ_ASSERT(f->in_len <= TCP_IN && f->in_head < TCP_IN);
        FUZZ_ASSERT(f->out_len <= TCP_OUT && f->out_head < TCP_OUT);
        if (f->state != T_EST)
            continue;
        FUZZ_ASSERT(!seq_lt(f->snd_nxt, f->snd_una) && !seq_lt(f->snd_max, f->snd_nxt));
        FUZZ_ASSERT(f->snd_max - f->snd_una <= f->out_len + 1); // our FIN takes one
        FUZZ_ASSERT(f->mss >= 64 && f->mss <= MTU - 40);
        FUZZ_ASSERT(f->snd_wscale <= 14);
    }
    for (int i = 0; i < MAX_UDP; i++)
        FUZZ_ASSERT(dev->u[i].used == (dev->u[i].fd >= 0));
}

static int count_fds(void)
{
    int k = 0;
    DIR *d = opendir("/proc/self/fd");
    if (!d)
        return -1;
    while (readdir(d))
        k++;
    closedir(d);
    return k;
}

static void dev_op(const uint8_t *a)
{
    switch (a[0] % 8) {
    case 0:
    case 1:
        poll_dev();
        break;
    case 2: { // time passes: every timer is due
        for (int i = 0; i < MAX_TCP; i++) {
            tflow *f = &dev->t[i];
            if (f->rto_at)
                f->rto_at = 1;
            if (f->ack_at)
                f->ack_at = 1;
        }
        for (int i = 0; i < MAX_UDP; i++)
            if (dev->u[i].used && a[1] & 1)
                dev->u[i].expire = 0;
        dev->tx_irq_at = 0;
        poll_dev();
        break;
    }
    case 3:
        split_mode = a[1];
        refuse_next = !(a[2] & 1) ? 0 : a[2] & 2 ? -EACCES : -ECONNREFUSED; // the policy, or a failure
        break;
    case 4: { // a snapshot of the device, maybe damaged, loaded back
        uint8_t buf[2048];
        snap_w w = {.p = buf, .cap = sizeof buf};
        OPS.save(&dev->dev, &w);
        FUZZ_ASSERT(!w.bad);
        if (a[1] & 1 && w.len)
            buf[a[2] % w.len] ^= a[3];
        snap_r r = {.p = buf, .len = a[1] & 2 ? a[4] % (w.len + 1) : w.len};
        const int nrst = dev->nrst;
        rst_entry keep[MAX_RST];
        memcpy(keep, dev->rst, sizeof keep);
        if (!OPS.load(&dev->dev, &r)) { // as a failed restore: never used
            dev->nrst = nrst;
            memcpy(dev->rst, keep, sizeof keep);
        }
        break;
    }
    case 5: // a raw register write
        if (a[1] & 1) {
            static const uint16_t regs[] = {0x030, 0x038, 0x044, 0x050, 0x064, 0x070, 0x080, 0x0a0};
            vw(regs[a[2] % 8], get_le32(a + 3));
            tainted = true;
        }
        break;
    case 6: // the guest rewrites its own memory, rings included
        mem.base[get_le32(a + 1) % MEM_SIZE] = a[5];
        tainted = true;
        break;
    default: { // config space reads
        uint64_t v = 0;
        virtio_mmio_access(&dev->dev, 0x100 + a[1] % 16, 1 + a[2] % 4, false, &v);
        break;
    }
    }
}

static void run_record(const uint8_t *r)
{
    const uint8_t *a = r + 1;
    switch (r[0] % 10) {
    case 0:
    case 1:
    case 2:
        guest_tcp(a);
        break;
    case 3:
        guest_udp(a);
        break;
    case 4:
        guest_other(a);
        break;
    case 5:
        offer_rx(a[0] % (RXN + 1), a[1]);
        if (a[2] & 1)
            consume_rx();
        break;
    case 6:
        consume_rx();
        break;
    case 7:
        peer_op(a);
        break;
    case 8:
        dev_op(a);
        break;
    default:
        poll_dev();
        consume_rx();
        break;
    }
    check_state();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!dev) {
        signal(SIGPIPE, SIG_IGN);
        mem = (guest_mem){.base = os_mem_reserve(MEM_SIZE), .size = MEM_SIZE};
        ioapic_init(&irq, 1, no_msi, nullptr);
        dev = net_create(open_cb, nullptr, &mem, &irq, 5);
        FUZZ_ASSERT(mem.base && dev);
        for (int i = 0; i < NP; i++)
            peers[i] = (peer){.fd = -1, .devfd = -1};
        base_fds = count_fds();
    }
    vw(0x070, 0); // a reset frees every flow
    for (int i = 0; i < NP; i++)
        peer_close(&peers[i]);
    uint64_t v;
    (void)!read(dev->wake_fd, &v, sizeof v);
    FUZZ_ASSERT(count_fds() == base_fds); // nothing leaked by the last input
    memset(gc, 0, sizeof gc);
    memset(syns, 0, sizeof syns);
    tainted = lied_offset = false;
    split_mode = 0;
    refuse_next = 0;
    bring_up(size ? data[0] : 0);
    check_state();
    offer_rx(RXN, 0);
    for (size_t i = 1; i + 10 <= size; i += 10)
        run_record(data + i);
    vw(0x070, 0);
    for (int i = 0; i < MAX_TCP; i++)
        FUZZ_ASSERT(dev->t[i].state == T_FREE && dev->t[i].fd < 0);
    for (int i = 0; i < MAX_UDP; i++)
        FUZZ_ASSERT(!dev->u[i].used);
    FUZZ_ASSERT(dev->nrst == 0 && dev->nctrl == 0 && dev->udp_pending < 0);
    return 0;
}

// ---- seeds --------------------------------------------------------------------------------
static uint8_t seed[64 * 10 + 1], seed2[64 * 10 + 1], seed3[64 * 10 + 1];
static uint8_t *out;
static size_t at;

static void r(uint8_t op, uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3, uint8_t a4, uint8_t a5, uint8_t a6,
              uint8_t a7, uint8_t a8)
{
    const uint8_t rec[10] = {op, a0, a1, a2, a3, a4, a5, a6, a7, a8};
    memcpy(out + at, rec, 10);
    at += 10;
}

const fuzz_seed *fuzz_seeds(size_t *n)
{
    static fuzz_seed s[3];
    // Seed 1: a connection: SYN with MSS and window scale, the SYN-ACK, data
    // both ways, the host reads, FINs.
    out = seed, at = 0;
    seed[at++] = 0;                          // mergeable, checksums computed
    r(0, 0, 0, 1, 0x05, 0xb4, 7, 4 | 8, 0, 0); // SYN, MSS 1460, wscale 7
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);         // poll, read the SYN-ACK
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(0, 0, 1, 0, 0, 0, 0, 0, 0, 0);         // ACK
    r(0, 0, 2, 0, 200, 1, 0, 128, 0, 0);     // 456 bytes
    r(0, 0, 2, 0, 100, 0, 0, 32, 50, 0);     // resent, overlapping
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(7, 0, 2, 0, 0, 0, 0, 0, 0, 0);         // the host reads
    r(7, 0, 0, 0xff, 0x2f, 0, 0, 0, 0, 0);   // and writes 12 KiB
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(5, 32, 0, 1, 0, 0, 0, 0, 0, 0);        // more receive buffers
    r(0, 0, 1, 0, 0, 0, 0, 0, 0, 0);
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(0, 0, 1, 0, 0, 0, 0, 0, 0, 0);
    r(8, 2, 0, 0, 0, 0, 0, 0, 0, 0);         // timers
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(7, 0, 3, 0, 0, 0, 0, 0, 0, 0);         // the host shuts its side
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(0, 0, 4, 0, 3, 0, 0, 0, 0, 0);         // the guest's FIN
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(0, 0, 1, 0, 0, 0, 0, 0, 0, 0);
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(8, 3, 0, 3, 0, 0, 0, 0, 0, 0);         // the policy refuses a DNS query: NXDOMAIN back
    r(3, 0, 1 | 2, 0, 0, 7, 9, 0, 0, 0);
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(8, 3, 0, 3, 0, 0, 0, 0, 0, 0);         // and a datagram: ICMP back
    r(3, 1, 0, 20, 0, 0, 0, 0, 0, 0);
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    s[0] = (fuzz_seed){seed, at};
    // Seed 2: UDP, DNS, ARP, ping, IPv6, a refused connection, junk.
    out = seed2, at = 0;
    seed2[at++] = 2 | 8;                     // GUEST_CSUM, no mergeable buffers
    r(3, 0, 0, 20, 0, 0, 0, 0, 0, 0);        // UDP to the gateway, port 7
    r(3, 0, 1, 30, 0, 1, 0, 0, 0, 0);        // DNS
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(7, 0, 0, 40, 0, 0, 0, 0, 0, 0);        // a datagram back
    r(7, 1, 0, 40, 0, 0, 0, 0, 0, 0);
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(4, 0, 0, 0, 0, 0, 0, 0, 0, 0);         // ARP for the gateway
    r(4, 1, 1, 100, 0, 0, 0, 0, 0, 0);       // ping the gateway
    r(4, 2, 8, 0, 0, 0, 0, 0, 0, 0);         // IPv6
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(8, 3, 0, 1, 0, 0, 0, 0, 0, 0);         // refuse the next connection
    r(0, 1, 0, 9, 0, 0, 0, 0, 0, 0);
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(0, 2, 7, 1, 2, 3, 4, 5, 6, 0);         // SYN to a broadcast address
    r(4, 5, 0, 40, 1, 2, 3, 4, 5, 6);        // a TCP header cut short
    r(0, 3, 2, 0, 50, 0, 0, 0, 0, 0x80 | 1); // data on no flow, a lying IP length
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(8, 4, 1, 3, 0x55, 0, 0, 0, 0, 0);      // a damaged snapshot
    s[1] = (fuzz_seed){seed2, at};
    // Seed 3: a host that doesn't read while the guest sends, a small
    // receive window, a zero window, split descriptors, timers.
    out = seed3, at = 0;
    seed3[at++] = 1;
    r(8, 3, 9 | 2 << 3, 0, 0, 0, 0, 0, 0, 0); // split chains
    r(0, 4, 0, 5, 0, 0, 0, 0, 0, 0);
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(0, 4, 1, 0, 0, 0, 0, 0, 0, 0);
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(7, 0, 5, 0, 0, 0, 0, 0, 0, 0);         // small socket buffers
    for (int i = 0; i < 12; i++)
        r(0, 4, 3, 0, 0x30, 0x0f, 0, 0, 0, 0); // 3888 bytes each
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(7, 0, 0, 0xff, 0xff, 1, 0, 0, 0, 0);   // the host writes 128 KiB
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(0, 4, 1, 0, 0, 0, 0, 1, 0, 0);         // a zero window
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(8, 2, 0, 0, 0, 0, 0, 0, 0, 0);         // the probe
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(0, 4, 1, 0, 0, 0, 0x10, 1, 0, 0);      // it opens
    r(5, 32, 0, 1, 0, 0, 0, 0, 0, 0);
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(7, 0, 2, 0, 0, 0, 0, 0, 0, 0);         // the host reads at last
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    r(0, 4, 5, 0, 0, 0, 0, 0, 0, 0);         // RST
    r(9, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    s[2] = (fuzz_seed){seed3, at};
    *n = 3;
    return s;
}
