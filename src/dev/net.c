// SPDX-License-Identifier: MIT
// virtio-net with a userspace NAT (see net.h).
//
// Everything the guest sends is hostile. Each frame's headers are copied
// out of guest memory once (at most 146 bytes: virtio header, Ethernet, the
// longest IPv4 and TCP headers) and parsed from that copy; payload bytes go
// from guest memory straight to the host socket. Anything this doesn't
// understand is dropped: IP fragments, IP options are skipped, other
// ethertypes and protocols are ignored, IPv6 isn't offered yet.
//
// TCP, guest side. The VMM is the guest's peer:
// - SYN: the device asks for a host socket (the open callback), and answers
//   SYN-ACK once its connect() completed, RST if it failed or was refused.
// - Guest -> host: in-order data only, straight to the host socket; what it
//   doesn't take now waits in a TCP_IN buffer, and the window we advertise
//   is that buffer's free space. Data past the window or out of order is
//   dropped (the guest resends it).
// - Host -> guest: read into a TCP_OUT ring that holds everything the guest
//   hasn't acknowledged, sent as segments no bigger than the guest's MSS,
//   its window and the receive buffers it posted. A retransmission timer
//   resends from the oldest unacknowledged byte, and probes a zero window.
// - FIN each way when that side is done; RST when either side fails.
// UDP: each (guest port, destination) gets a connected host socket; replies
// go back as datagrams from that destination. Idle flows expire.
// A datagram the policy refuses is answered at once (udp_refused): DNS with
// NXDOMAIN, anything else with ICMP "administratively prohibited".
#include "net.h"

#include <stdio.h>
#include <stdlib.h>

#include "hostsock.h"

#if !defined(_WIN32)
#  include <sys/mman.h>
#  include <time.h>
#endif

#include "../clock.h"
#include "../os.h"

// ---- limits -------------------------------------------------------------------
constexpr int MAX_TCP = 64;
constexpr int MAX_UDP = 32;
constexpr int MAX_RST = 64;    // RSTs waiting for a receive buffer
constexpr int MAX_CTRL = 4;    // ARP and echo replies waiting
constexpr uint32_t CTRL_MAX = 1514;
constexpr uint32_t TCP_OUT = 256 * 1024; // per flow, host -> guest, until acknowledged
constexpr uint32_t TCP_IN = 128 * 1024;  // per flow, guest -> host, until the socket takes it
constexpr uint8_t OUR_WSCALE = 2;        // TCP_IN >> 2 fits the 16-bit window
// The link MTU. With the guest's TCP ending here, segments as big as the
// link allows cost nothing on the wire: one 64 KiB segment instead of 45.
constexpr uint32_t MTU = 65520;
constexpr uint32_t VHDR = 12; // virtio_net_hdr_v1
constexpr uint32_t ETH = 14;
constexpr uint32_t HB_MAX = VHDR + ETH + 60 + 60; // longest headers we parse
constexpr uint32_t RX_MIN_BUF = 128; // smaller receive buffers are handed back unused
constexpr uint64_t RTO_NS = 200 * 1000 * 1000;
constexpr uint64_t RTO_MAX_NS = 5ull * 1000 * 1000 * 1000;
constexpr int MAX_RETRIES = 8;
constexpr uint64_t UDP_IDLE_NS = 60ull * 1000 * 1000 * 1000;
constexpr uint64_t DNS_IDLE_NS = 5ull * 1000 * 1000 * 1000;
// Transmit completions only let the guest free buffers. They wait for the
// next receive interrupt, this long at most, or less once enough bytes or
// descriptors are waiting: the guest's TCP stack limits how much it keeps
// in flight until completions free it (TCP small queues).
constexpr uint64_t TX_IRQ_DELAY_NS = 200 * 1000;
constexpr uint32_t TX_IRQ_BYTES = 32 * 1024;
// Data from the guest is acknowledged on our next segment to it, or after
// this long, or at once past ACK_BYTES. A request/response exchange then
// takes one receive interrupt per round trip instead of two. Bulk senders
// fill ACK_BYTES with every large segment, so they see no delay.
constexpr uint64_t ACK_DELAY_NS = 200 * 1000;
constexpr uint64_t NS_S = 1000000000;
constexpr uint64_t STATS_NS = 2 * NS_S;  // net_set_stats_fd's period
constexpr uint64_t TX_RESUME = 16384;    // a capped flow waits for this much room

enum : uint16_t { Q_RX = 0, Q_TX = 1 };
// Feature bits (virtio 1.2, 5.1.3).
enum : uint64_t {
    F_CSUM = 1ull << 0,       // the guest may leave its checksums to us (we never check them)
    F_GUEST_CSUM = 1ull << 1, // we may say ours are fine without computing them
    F_MTU = 1ull << 3,
    F_MAC = 1ull << 5,
    F_MRG_RXBUF = 1ull << 15, // one frame across several receive buffers
};
enum : uint8_t { VH_DATA_VALID = 2 };
enum : uint8_t { TH_FIN = 1, TH_SYN = 2, TH_RST = 4, TH_PSH = 8, TH_ACK = 16 };

static const uint8_t GW_MAC[6] = {0x02, 0x6d, 0x76, 0x00, 0x00, 0x02};
static const uint8_t GUEST_MAC[6] = {0x02, 0x6d, 0x76, 0x00, 0x00, 0x0f};

static uint16_t get_be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t get_be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static void put_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8), p[1] = (uint8_t)v; }
static void put_be32(uint8_t *p, uint32_t v) { put_be16(p, (uint16_t)(v >> 16)), put_be16(p + 2, (uint16_t)v); }
static uint32_t min32(uint32_t a, uint32_t b) { return a < b ? a : b; }
static bool seq_lt(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }

// ---- flows ---------------------------------------------------------------------
typedef enum : uint8_t {
    T_FREE,
    T_CONNECTING, // the guest's SYN taken, the host socket connecting
    T_SYNACK,     // connected: SYN-ACK owed (or sent), waiting for the guest's ACK
    T_EST,
} tcp_state;

typedef struct {
    uint8_t raddr[4];
    uint16_t gport, rport;
} flow_key;

typedef struct {
    tcp_state state;
    int fd;
    flow_key k;
    // guest -> host
    uint32_t rcv_nxt;       // the next sequence number we expect from the guest
    uint8_t *in;            // TCP_IN bytes: what the host socket hasn't taken yet
    uint32_t in_head, in_len;
    uint32_t adv_wnd;       // the window we last advertised (bytes)
    bool guest_fin, shut_wr_done;
    // host -> guest
    uint32_t iss, snd_una, snd_nxt, snd_max;
    uint8_t *out;           // TCP_OUT bytes: [snd_una, snd_una + out_len)
    uint32_t out_head, out_len;
    uint32_t snd_wnd;       // the guest's window, scaled
    uint8_t snd_wscale;     // the guest's window scale (0 without the option)
    bool wscale_ok;         // both sides scale
    uint16_t mss;
    bool synack_sent, readable, host_eof, fin_acked;
    bool need_ack;          // a pure ACK (or window update) is owed
    uint32_t unacked;       // guest bytes taken since our last segment
    uint64_t ack_at;        // a delayed ACK is owed then (0: none)
    bool probe;             // the retransmission timer asks for a window probe
    uint64_t rto_at, rto;
    uint8_t retries;
} tflow;

typedef struct {
    bool used;
    bool readable;
    bool dns;
    int fd;
    flow_key k;
    uint64_t expire;
} uflow;

typedef struct {
    flow_key k;
    uint32_t seq, ack;
    uint8_t flags;
} rst_entry;

// One receive buffer taken for the frame being written.
typedef struct {
    uint16_t head;
    uint8_t nw;
    uint32_t wlen;
    virtq_seg w[VIRTQ_DEFAULT_SEGS]; // the device's chains are no longer (ops.max_segs is 0)
} rxbuf;

struct net {
    virtio_dev dev;
    net_open_fn open;
    void *open_ctx;
    sock wake_fd; // readable once wake() was called (Linux: an eventfd)
#if defined(_WIN32)
    sock wake_wr; // the other end of wake_fd
    // A socket the vCPU thread drops (a device reset) while the I/O thread
    // waits on it is closed by the I/O thread once it is back: WSAPoll must
    // not be handed a closed socket.
    bool waiting;
    sock dead[MAX_TCP + MAX_UDP];
    int ndead;
#endif
    tflow t[MAX_TCP];
    uflow u[MAX_UDP];
    rst_entry rst[MAX_RST];
    int nrst;
    struct {
        uint16_t len;
        uint8_t b[CTRL_MAX];
    } ctrl[MAX_CTRL];
    int nctrl;
    // a datagram from a host UDP socket that didn't fit the guest's buffers yet
    uint8_t *udp_buf; // 64 KiB
    int udp_pending;  // its flow, or -1
    uint32_t udp_len;
    rxbuf rxb[VIRTQ_MAX_SIZE];
    unsigned rr;
    uint64_t prng;
    // deferred transmit interrupts (see TX_IRQ_DELAY_NS)
    bool tx_irq;
    uint64_t tx_irq_at;
    uint32_t tx_irq_bytes, tx_irq_descs;
    // statistics (for tests and --trace)
    uint64_t n_drop, n_refused;
    // the egress cap (net_set_tx_rate)
    uint64_t tx_rate, tx_tat;
    bool tx_blocked; // a flow stopped for want of room: flush again at tx_wake_at()
    // the counters (net_set_stats_fd)
    intptr_t stats_fd;
    uint64_t stats_at, stats_last;
    struct {
        uint64_t tx, rx, flows, refused, denied, limited;
    } st;
};

static uint32_t rnd32(net *n)
{
    // splitmix64: the guest-facing initial sequence numbers needn't be secret
    // (the guest is the only one on this link), only distinct.
    uint64_t z = (n->prng += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return (uint32_t)(z ^ (z >> 31));
}

// A flow's host socket (the open callback's fd).
static sock S(int fd) { return (sock)fd; }

#if defined(_WIN32)
static void wake(net *n) { (void)sock_write(n->wake_wr, "", 1); }

static void wake_clear(net *n)
{
    char buf[64];
    while (sock_read(n->wake_fd, buf, sizeof buf) == (intptr_t)sizeof buf) {
    }
}

static void host_close(net *n, int fd)
{
    if (n->waiting) { // at most one per flow until the I/O thread is back
        n->dead[n->ndead++] = S(fd);
        wake(n);
    } else {
        sock_close(S(fd));
    }
}
#else
static void wake(net *n)
{
    const uint64_t one = 1;
    (void)!write(n->wake_fd, &one, sizeof one);
}

static void wake_clear(net *n)
{
    uint64_t v;
    (void)!read(n->wake_fd, &v, sizeof v);
}

static void host_close(net *n, int fd)
{
    (void)n;
    sock_close(fd);
}
#endif

static bool key_eq(const flow_key *a, const flow_key *b)
{
    return a->gport == b->gport && a->rport == b->rport && !memcmp(a->raddr, b->raddr, 4);
}

static void tcp_free(net *n, tflow *f)
{
    if (f->fd >= 0)
        host_close(n, f->fd);
    uint8_t *in = f->in, *out = f->out;
    // Give the pages back: a flow that carried data touched them, even if
    // its buffers are empty now.
    if (f->state == T_EST) {
        os_mem_discard(in, TCP_IN);
        os_mem_discard(out, TCP_OUT);
    }
    *f = (tflow){.fd = -1, .in = in, .out = out};
}

static void queue_rst(net *n, const flow_key *k, uint32_t seq, uint32_t ack, uint8_t flags)
{
    if (n->nrst < MAX_RST)
        n->rst[n->nrst++] = (rst_entry){*k, seq, ack, (uint8_t)(TH_RST | flags)};
}

// End the flow and tell the guest, if it knew of it.
static void tcp_reset(net *n, tflow *f)
{
    if (f->state == T_EST || (f->state == T_SYNACK && f->synack_sent))
        queue_rst(n, &f->k, f->snd_max, f->rcv_nxt, TH_ACK);
    else if (f->state == T_CONNECTING || f->state == T_SYNACK)
        queue_rst(n, &f->k, 0, f->rcv_nxt, TH_ACK); // refused
    tcp_free(n, f);
}

static void udp_free(net *n, uflow *u)
{
    if (u->used)
        host_close(n, u->fd);
    *u = (uflow){.fd = -1};
}

static tflow *tcp_find(net *n, const flow_key *k)
{
    for (int i = 0; i < MAX_TCP; i++)
        if (n->t[i].state != T_FREE && key_eq(&n->t[i].k, k))
            return &n->t[i];
    return nullptr;
}

// The window we advertise: TCP_IN's free space, scaled.
static uint16_t tcp_window(tflow *f)
{
    const uint32_t free_ = TCP_IN - f->in_len;
    f->adv_wnd = f->wscale_ok ? free_ & ~((1u << OUR_WSCALE) - 1) : min32(free_, 65535);
    return (uint16_t)(f->wscale_ok ? free_ >> OUR_WSCALE : f->adv_wnd);
}

// ---- checksums -----------------------------------------------------------------
typedef struct {
    uint64_t sum;
    bool odd; // an odd number of bytes so far
} csum;

static void csum_add(csum *c, const uint8_t *p, size_t n)
{
    if (!n)
        return;
    if (c->odd) {
        c->sum += *p++;
        n--;
        c->odd = false;
    }
    for (; n >= 2; p += 2, n -= 2)
        c->sum += (uint32_t)(p[0] << 8 | p[1]);
    if (n) {
        c->sum += (uint32_t)p[0] << 8;
        c->odd = true;
    }
}

static uint16_t csum_fold(const csum *c)
{
    uint64_t s = c->sum;
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

// ---- receive buffers -------------------------------------------------------------
typedef struct {
    int n;          // buffers taken
    uint32_t space; // their bytes
} rxset;

static bool mergeable(const net *n) { return n->dev.driver_features & F_MRG_RXBUF; }

// Take receive buffers until `need` bytes fit, or as many as there are if
// at least `min` fit. Returns false (nothing taken) if `min` doesn't fit;
// *drop then says the frame never will (the guest posted every buffer it
// can and they are too small together).
static bool rx_take(net *n, uint32_t need, uint32_t min, rxset *s, bool *drop)
{
    virtio_dev *d = &n->dev;
    *s = (rxset){0};
    *drop = false;
    const uint16_t qn = d->q[Q_RX].num;
    while (s->space < need && s->n < qn) {
        if (s->n && !mergeable(n))
            break;
        virtq_chain ch;
        if (virtq_pop(d, Q_RX, &ch) != 1)
            break;
        if (ch.wlen < RX_MIN_BUF) { // no frame fits: hand it back unused
            if (s->n) {
                // Not now: buffers before it may yet go back to the ring
                // (virtq_unpop only rewinds), so it waits its turn.
                virtq_unpop(d, Q_RX);
                break;
            }
            virtq_push(d, Q_RX, ch.head, 0);
            continue;
        }
        rxbuf *b = &n->rxb[s->n++];
        b->head = ch.head;
        b->nw = ch.nw;
        b->wlen = ch.wlen;
        memcpy(b->w, ch.w, sizeof ch.w[0] * ch.nw);
        if (ckd_add(&s->space, s->space, ch.wlen))
            s->space = UINT32_MAX;
    }
    if (s->space >= min)
        return true;
    *drop = s->n == qn || (!mergeable(n) && s->n == 1);
    for (int i = 0; i < s->n; i++)
        virtq_unpop(d, Q_RX);
    *s = (rxset){0};
    return false;
}

static void rx_write(net *n, const rxset *s, uint32_t off, const void *src, uint32_t len)
{
    const uint8_t *p = src;
    for (int i = 0; i < s->n && len; i++) {
        const rxbuf *b = &n->rxb[i];
        if (off >= b->wlen) {
            off -= b->wlen;
            continue;
        }
        for (unsigned j = 0; j < b->nw && len; j++) {
            if (off >= b->w[j].len) {
                off -= b->w[j].len;
                continue;
            }
            const uint32_t k = min32(b->w[j].len - off, len);
            memcpy(b->w[j].p + off, p, k);
            p += k;
            len -= k;
            off = 0;
        }
    }
}

// Hand `total` bytes of the taken buffers to the guest as one frame.
static void rx_push(net *n, const rxset *s, uint32_t total)
{
    uint8_t vh[VHDR] = {0};
    if (n->dev.driver_features & F_GUEST_CSUM)
        vh[0] = VH_DATA_VALID;
    int used = 0;
    for (uint32_t left = total; used < s->n && left; used++)
        left -= min32(left, n->rxb[used].wlen);
    put_le16(vh + 10, (uint16_t)used);
    rx_write(n, s, 0, vh, VHDR);
    // All at once: a driver polling meanwhile must never see part of a
    // frame (Linux drops a frame whose buffers aren't all there yet).
    uint16_t head[VIRTQ_MAX_SIZE];
    uint32_t len[VIRTQ_MAX_SIZE];
    for (int i = 0; i < used; i++) {
        head[i] = n->rxb[i].head;
        len[i] = min32(total, n->rxb[i].wlen);
        total -= len[i];
    }
    virtq_push_n(&n->dev, Q_RX, head, len, (unsigned)used);
    // Taken but not needed after all (the frame shrank): back to the guest.
    for (int i = s->n - 1; i >= used; i--)
        virtq_unpop(&n->dev, Q_RX);
}

// Ethernet + IPv4 headers for a frame to the guest, at b (after the virtio
// header). Returns the IPv4 header's offset.
static void ip4_header(uint8_t *b, const uint8_t src[4], uint8_t proto, uint32_t l4len)
{
    memcpy(b, GUEST_MAC, 6);
    memcpy(b + 6, GW_MAC, 6);
    put_be16(b + 12, 0x0800);
    uint8_t *ip = b + ETH;
    ip[0] = 0x45;
    ip[1] = 0;
    put_be16(ip + 2, (uint16_t)(20 + l4len));
    put_be16(ip + 4, 0);
    put_be16(ip + 6, 0x4000); // DF
    ip[8] = 64;
    ip[9] = proto;
    put_be16(ip + 10, 0);
    memcpy(ip + 12, src, 4);
    memcpy(ip + 16, NET_GUEST_IP, 4);
    csum c = {0};
    csum_add(&c, ip, 20);
    put_be16(ip + 10, csum_fold(&c));
}

static void pseudo4(csum *c, const uint8_t src[4], uint8_t proto, uint32_t l4len)
{
    csum_add(c, src, 4);
    csum_add(c, NET_GUEST_IP, 4);
    const uint8_t t[4] = {0, proto, (uint8_t)(l4len >> 8), (uint8_t)l4len};
    csum_add(c, t, 4);
}

static bool need_csum(const net *n) { return !(n->dev.driver_features & F_GUEST_CSUM); }

// ---- frames to the guest ---------------------------------------------------------------
// A TCP segment: `len` payload bytes from the flow's ring at sequence `seq`.
// Returns false if there was no room (nothing sent). *sent: the payload
// bytes that fit.
static bool tcp_emit(net *n, tflow *f, uint32_t seq, uint8_t flags, uint32_t len, uint32_t *sent)
{
    const bool syn = flags & TH_SYN;
    const uint32_t thl = syn ? 28 : 20;
    const uint32_t hl = VHDR + ETH + 20 + thl;
    rxset s;
    bool drop;
    if (!rx_take(n, hl + len, hl + (len ? 1 : 0), &s, &drop))
        return false;
    if (len > s.space - hl)
        len = s.space - hl;
    uint8_t h[VHDR + ETH + 20 + 28];
    const uint32_t l4 = thl + len;
    ip4_header(h + VHDR, f->k.raddr, NET_TCP, l4);
    uint8_t *th = h + VHDR + ETH + 20;
    put_be16(th, f->k.rport);
    put_be16(th + 2, f->k.gport);
    put_be32(th + 4, seq);
    put_be32(th + 8, f->rcv_nxt);
    f->unacked = 0; // every segment acknowledges everything
    f->ack_at = 0;
    th[12] = (uint8_t)((thl / 4) << 4);
    th[13] = flags | TH_ACK;
    put_be16(th + 14, tcp_window(f));
    put_be16(th + 16, 0);
    put_be16(th + 18, 0);
    if (syn) {
        th[20] = 2, th[21] = 4; // MSS
        put_be16(th + 22, (uint16_t)(MTU - 40));
        th[24] = 1;             // NOP, then window scale
        th[25] = 3, th[26] = 3, th[27] = f->wscale_ok ? OUR_WSCALE : 0;
        if (!f->wscale_ok)
            th[24] = th[25] = th[26] = th[27] = 1; // NOPs: no window scale
    }
    // Payload from the ring: up to two pieces.
    const uint32_t at = (f->out_head + (seq - f->snd_una)) % TCP_OUT;
    const uint32_t p1 = min32(len, TCP_OUT - at);
    if (need_csum(n)) {
        csum c = {0};
        pseudo4(&c, f->k.raddr, NET_TCP, l4);
        csum_add(&c, th, thl);
        csum_add(&c, f->out + at, p1);
        csum_add(&c, f->out, len - p1);
        put_be16(th + 16, csum_fold(&c));
    }
    rx_write(n, &s, 0, h, hl);
    rx_write(n, &s, hl, f->out + at, p1);
    rx_write(n, &s, hl + p1, f->out, len - p1);
    rx_push(n, &s, hl + len);
    *sent = len;
    return true;
}

static bool emit_rst(net *n, const rst_entry *r)
{
    const uint32_t hl = VHDR + ETH + 20 + 20;
    rxset s;
    bool drop;
    if (!rx_take(n, hl, hl, &s, &drop))
        return false;
    uint8_t h[VHDR + ETH + 20 + 20];
    ip4_header(h + VHDR, r->k.raddr, NET_TCP, 20);
    uint8_t *th = h + VHDR + ETH + 20;
    memset(th, 0, 20);
    put_be16(th, r->k.rport);
    put_be16(th + 2, r->k.gport);
    put_be32(th + 4, r->seq);
    put_be32(th + 8, r->ack);
    th[12] = 5 << 4;
    th[13] = r->flags;
    csum c = {0};
    pseudo4(&c, r->k.raddr, NET_TCP, 20);
    csum_add(&c, th, 20);
    put_be16(th + 16, csum_fold(&c));
    rx_write(n, &s, 0, h, hl);
    rx_push(n, &s, hl);
    return true;
}

// A datagram from flow u's destination. False if it has to wait.
static bool emit_udp(net *n, const uflow *u, const uint8_t *data, uint32_t len)
{
    const uint32_t hl = VHDR + ETH + 20 + 8;
    rxset s;
    bool drop;
    if (!rx_take(n, hl + len, hl + len, &s, &drop)) {
        if (drop)
            n->n_drop++;
        return drop; // dropped counts as done
    }
    uint8_t h[VHDR + ETH + 20 + 8];
    ip4_header(h + VHDR, u->k.raddr, NET_UDP, 8 + len);
    uint8_t *uh = h + VHDR + ETH + 20;
    put_be16(uh, u->k.rport);
    put_be16(uh + 2, u->k.gport);
    put_be16(uh + 4, (uint16_t)(8 + len));
    put_be16(uh + 6, 0);
    if (need_csum(n)) {
        csum c = {0};
        pseudo4(&c, u->k.raddr, NET_UDP, 8 + len);
        csum_add(&c, uh, 8);
        csum_add(&c, data, len);
        const uint16_t v = csum_fold(&c);
        put_be16(uh + 6, v ? v : 0xffff);
    }
    rx_write(n, &s, 0, h, hl);
    rx_write(n, &s, hl, data, len);
    rx_push(n, &s, hl + len);
    return true;
}

static bool emit_ctrl(net *n, const uint8_t *frame, uint32_t len)
{
    rxset s;
    bool drop;
    if (!rx_take(n, VHDR + len, VHDR + len, &s, &drop))
        return drop;
    rx_write(n, &s, VHDR, frame, len);
    rx_push(n, &s, VHDR + len);
    return true;
}

// Everything flow f can send now. False if the guest's buffers ran out.
static bool tcp_output(net *n, tflow *f, uint64_t now)
{
    if (f->state == T_SYNACK && !f->synack_sent) {
        uint32_t k;
        if (!tcp_emit(n, f, f->iss, TH_SYN, 0, &k))
            return false;
        f->synack_sent = true;
        f->snd_nxt = f->snd_max = f->iss + 1;
        f->rto_at = now + f->rto;
        return true;
    }
    if (f->state != T_EST)
        return true;
    bool sent_any = false;
    for (;;) {
        const uint32_t flight = f->snd_nxt - f->snd_una; // may include our FIN
        const uint32_t unsent = flight >= f->out_len ? 0 : f->out_len - flight;
        const uint32_t usable = f->snd_wnd > flight ? f->snd_wnd - flight : 0;
        const uint32_t len = min32(min32(unsent, usable), f->mss);
        if (len) {
            uint32_t k;
            if (!tcp_emit(n, f, f->snd_nxt, len == unsent ? TH_PSH : 0, len, &k))
                return false;
            f->snd_nxt += k;
        } else if (f->host_eof && flight == f->out_len && !f->fin_acked) {
            uint32_t k;
            if (!tcp_emit(n, f, f->snd_nxt, TH_FIN, 0, &k))
                return false;
            f->snd_nxt++;
        } else if (f->probe || (f->need_ack && !sent_any)) {
            // A window probe is a segment the guest has seen already: it
            // answers with an ACK carrying its window.
            uint32_t k;
            if (!tcp_emit(n, f, f->probe ? f->snd_una - 1 : f->snd_nxt, 0, 0, &k))
                return false;
            f->probe = false;
            f->need_ack = false;
            break;
        } else {
            break;
        }
        sent_any = true;
        f->need_ack = false;
        if (seq_lt(f->snd_max, f->snd_nxt))
            f->snd_max = f->snd_nxt;
        if (!f->rto_at)
            f->rto_at = now + f->rto;
    }
    // Nothing in flight and data the window holds back: probe it later.
    if (!f->rto_at && f->out_len && f->snd_nxt == f->snd_una && !f->snd_wnd)
        f->rto_at = now + f->rto;
    return true;
}

// ---- host sockets ---------------------------------------------------------------
// Write what's buffered to the host. -1: the socket is gone.
// ---- the egress cap (net_set_tx_rate) --------------------------------------------------
// GCRA: tx_tat is when the bytes sent so far would have finished going out
// at tx_rate. Up to a second's worth may go at once.
static uint64_t tx_room(const net *n, uint64_t now)
{
    if (!n->tx_rate)
        return UINT64_MAX;
    const uint64_t tat = n->tx_tat > now ? n->tx_tat : now;
    return tat - now >= NS_S ? 0 : (NS_S - (tat - now)) * n->tx_rate / NS_S; // < 2^60: rate <= 10^9
}

static void tx_sent(net *n, uint64_t now, uint64_t bytes)
{
    n->st.tx += bytes;
    if (!n->tx_rate)
        return;
    const uint64_t tat = n->tx_tat > now ? n->tx_tat : now;
    n->tx_tat = tat + (bytes * NS_S + n->tx_rate - 1) / n->tx_rate;
}

// When a stopped flow has TX_RESUME bytes of room again.
static uint64_t tx_wake_at(const net *n)
{
    const uint64_t m = n->tx_rate < TX_RESUME ? n->tx_rate : TX_RESUME;
    return n->tx_tat - NS_S + m * NS_S / n->tx_rate;
}

static int tcp_flush(net *n, tflow *f, uint64_t now)
{
    while (f->in_len) {
        uint32_t chunk = min32(f->in_len, TCP_IN - f->in_head);
        const uint64_t room = tx_room(n, now);
        if (!room) {
            n->tx_blocked = true;
            break;
        }
        if (room < chunk)
            chunk = (uint32_t)room;
        const intptr_t w = sock_write(S(f->fd), f->in + f->in_head, chunk);
        if (w == SOCK_AGAIN)
            break;
        if (w < 0)
            return -1;
        tx_sent(n, now, (uint64_t)w);
        f->in_head = (f->in_head + (uint32_t)w) % TCP_IN;
        f->in_len -= (uint32_t)w;
    }
    if (!f->in_len)
        f->in_head = 0;
    // A window the guest may be waiting on opened up.
    if (TCP_IN - f->in_len >= f->adv_wnd + TCP_IN / 4)
        f->need_ack = true;
    if (!f->in_len && f->guest_fin && !f->shut_wr_done) {
        sock_shut_wr(S(f->fd));
        f->shut_wr_done = true;
    }
    return 0;
}

// Read from the host into the ring. -1: the socket failed.
static int tcp_read(net *n, tflow *f)
{
    while (f->out_len < TCP_OUT && !f->host_eof) {
        const uint32_t tail = (f->out_head + f->out_len) % TCP_OUT;
        const uint32_t first = min32(TCP_OUT - f->out_len, TCP_OUT - tail);
        sock_iov iov[2] = {SOCK_IOV(f->out + tail, first)};
        int k = 1;
        if (first < TCP_OUT - f->out_len)
            iov[k++] = SOCK_IOV(f->out, TCP_OUT - f->out_len - first);
        const intptr_t r = sock_readv(S(f->fd), iov, k);
        if (r == SOCK_AGAIN) {
            f->readable = false;
            return 0;
        }
        if (r < 0)
            return -1;
        if (r == 0) {
            f->host_eof = true;
            f->readable = false;
            return 0;
        }
        f->out_len += (uint32_t)r;
        n->st.rx += (uint64_t)r;
    }
    return 0;
}

// Both directions finished: nothing more to say.
static void tcp_maybe_done(net *n, tflow *f)
{
    if (f->state == T_EST && f->guest_fin && f->shut_wr_done && f->fin_acked)
        tcp_free(n, f);
}

// ---- frames from the guest ----------------------------------------------------------
// Segment iovecs: `len` bytes of the chain's readable part from `off`.
static int chain_iov(const virtq_chain *ch, uint32_t off, uint32_t len, sock_iov *iov)
{
    int k = 0;
    for (unsigned i = 0; i < ch->nr && len; i++) {
        if (off >= ch->r[i].len) {
            off -= ch->r[i].len;
            continue;
        }
        const uint32_t m = min32(ch->r[i].len - off, len);
        iov[k++] = SOCK_IOV(ch->r[i].p + off, m);
        len -= m;
        off = 0;
    }
    return k;
}

static void ctrl_queue(net *n, const uint8_t *frame, uint32_t len)
{
    if (n->nctrl < MAX_CTRL && len <= CTRL_MAX) {
        n->ctrl[n->nctrl].len = (uint16_t)len;
        memcpy(n->ctrl[n->nctrl].b, frame, len);
        n->nctrl++;
    } else {
        n->n_drop++;
    }
}

static void arp_in(net *n, const uint8_t *a, uint32_t len)
{
    // Ethernet/IPv4 requests only, for any address but the guest's own (a
    // probe for it must go unanswered).
    if (len < 28 || get_be16(a) != 1 || get_be16(a + 2) != 0x0800 || a[4] != 6 || a[5] != 4 ||
        get_be16(a + 6) != 1 || !memcmp(a + 24, NET_GUEST_IP, 4) || !memcmp(a + 24, "\0\0\0\0", 4))
        return;
    uint8_t f[ETH + 28];
    memcpy(f, a + 8, 6); // to the sender's hardware address
    memcpy(f + 6, GW_MAC, 6);
    put_be16(f + 12, 0x0806);
    uint8_t *r = f + ETH;
    put_be16(r, 1);
    put_be16(r + 2, 0x0800);
    r[4] = 6, r[5] = 4;
    put_be16(r + 6, 2);
    memcpy(r + 8, GW_MAC, 6);
    memcpy(r + 14, a + 24, 4); // "target is at our address"
    memcpy(r + 18, a + 8, 10); // sender hardware + protocol address
    ctrl_queue(n, f, sizeof f);
}

static void icmp_in(net *n, const virtq_chain *ch, uint32_t off, uint32_t len, const uint8_t dst[4])
{
    // Echo requests to the gateway or DNS address, answered here.
    if (len < 8 || len > CTRL_MAX - ETH - 20 ||
        (memcmp(dst, NET_GATEWAY_IP, 4) && memcmp(dst, NET_DNS_IP, 4)))
        return;
    uint8_t f[CTRL_MAX];
    uint8_t *ic = f + ETH + 20;
    if (virtq_gather(ch, off, ic, len) != len || ic[0] != 8 || ic[1] != 0)
        return;
    ip4_header(f, dst, 1, len);
    ic[0] = 0;
    put_be16(ic + 2, 0);
    csum c = {0};
    csum_add(&c, ic, len);
    put_be16(ic + 2, csum_fold(&c));
    ctrl_queue(n, f, ETH + 20 + len);
}

// The flow for k, opening it if it is new (*err: the open's error, if that failed).
// A flow the open callback refused, counted by why.
static void refusal(net *n, int err)
{
    n->n_refused++;
    if (err == -EPERM)
        n->st.denied++;
    else if (err == -EAGAIN)
        n->st.limited++;
    else
        n->st.refused++;
    // Denied and limited flows are what the host watches for: they're
    // written soon (0.2 s after the last write), not in up to 2 s.
    if ((err == -EPERM || err == -EAGAIN) && n->stats_last + STATS_NS / 10 < n->stats_at)
        n->stats_at = n->stats_last + STATS_NS / 10;
}

static uflow *udp_lookup(net *n, const flow_key *k, uint64_t now, int *err)
{
    for (int i = 0; i < MAX_UDP; i++)
        if (n->u[i].used && key_eq(&n->u[i].k, k))
            return &n->u[i];
    uflow *u = nullptr; // a free slot, or the one expiring first
    for (int i = 0; i < MAX_UDP; i++) {
        if (!n->u[i].used) {
            u = &n->u[i];
            break;
        }
        if (!u || (int64_t)(n->u[i].expire - u->expire) < 0)
            u = &n->u[i];
    }
    const net_dst d = {.proto = NET_UDP, .port = k->rport, .addr = {k->raddr[0], k->raddr[1], k->raddr[2], k->raddr[3]}};
    const int fd = n->open(n->open_ctx, &d);
    if (fd < 0) {
        refusal(n, fd);
        *err = fd;
        return nullptr;
    }
    n->st.flows++;
    if (u->used && n->udp_pending == (int)(u - n->u))
        n->udp_pending = -1;
    udp_free(n, u);
    *u = (uflow){.used = true, .fd = fd, .k = *k, .dns = k->rport == 53,
                 .expire = now + (k->rport == 53 ? DNS_IDLE_NS : UDP_IDLE_NS)};
    return u;
}

// A datagram the policy refused (uh: its UDP header, ulen its UDP length):
// tell the guest now instead of letting it time out.
// - A DNS query to the resolver gets NXDOMAIN: with no way out, no name
//   resolves. Resolvers that don't connect their socket (musl's) never see
//   ICMP errors, and musl ignores every rcode but NOERROR and NXDOMAIN
//   (REFUSED or SERVFAIL would leave it waiting out its timeout).
// - Anything else gets an ICMP "administratively prohibited" from the
//   gateway, which a connected socket reports as an error.
static void udp_refused(net *n, const virtq_chain *ch, uint32_t off, const uint8_t *uh, uint32_t ulen,
                        const uint8_t dst[4])
{
    uint8_t f[CTRL_MAX];
    if (!memcmp(dst, NET_DNS_IP, 4) && get_be16(uh + 2) == 53) {
        // A query: the header, one question (labels without compression, a
        // name of at most 255 bytes), QTYPE and QCLASS. The answer is the
        // question back with NXDOMAIN; anything else is dropped.
        uint8_t q[12 + 255 + 4];
        const uint32_t qn = min32(ulen - 8, sizeof q);
        if (qn < 12 + 1 + 4 || virtq_gather(ch, off + 8, q, qn) != qn || (q[2] & 0x80) || get_be16(q + 4) != 1)
            return;
        uint32_t i = 12;
        while (i < qn && q[i] && q[i] <= 63)
            i += 1u + q[i];
        if (i >= qn || q[i] || i + 1 + 4 > qn)
            return;
        const uint32_t dl = i + 1 + 4;
        uint8_t *u = f + ETH + 20, *d = u + 8;
        memcpy(d, q, dl);
        d[2] = (uint8_t)(0x80 | (q[2] & 0x79)); // QR; the opcode and RD kept; AA and TC clear
        d[3] = 0x80 | 3;                          // RA, NXDOMAIN
        memset(d + 6, 0, 6);                      // no answers, authority or additional records
        ip4_header(f, dst, NET_UDP, 8 + dl);
        put_be16(u, 53);
        put_be16(u + 2, get_be16(uh));
        put_be16(u + 4, (uint16_t)(8 + dl));
        put_be16(u + 6, 0); // no checksum (allowed over IPv4)
        ctrl_queue(n, f, ETH + 20 + 8 + dl);
        return;
    }
    // Type 3 code 13, quoting the datagram's IP header (as the guest sent
    // it, give or take its ID and TTL, which nobody matches on) and the
    // first 8 bytes after it.
    uint8_t *ic = f + ETH + 20, *ip = ic + 8;
    ic[0] = 3, ic[1] = 13;
    memset(ic + 2, 0, 6);
    ip[0] = 0x45, ip[1] = 0;
    put_be16(ip + 2, (uint16_t)(20 + ulen));
    put_be32(ip + 4, 0);
    ip[8] = 64, ip[9] = NET_UDP;
    put_be16(ip + 10, 0);
    memcpy(ip + 12, NET_GUEST_IP, 4);
    memcpy(ip + 16, dst, 4);
    csum c = {0};
    csum_add(&c, ip, 20);
    put_be16(ip + 10, csum_fold(&c));
    memcpy(ip + 20, uh, 8);
    c = (csum){0};
    csum_add(&c, ic, 8 + 28);
    put_be16(ic + 2, csum_fold(&c));
    ip4_header(f, NET_GATEWAY_IP, 1, 8 + 28);
    ctrl_queue(n, f, ETH + 20 + 8 + 28);
}

static void udp_in(net *n, const virtq_chain *ch, uint32_t off, const uint8_t *uh, uint32_t l4len,
                   const uint8_t dst[4], uint64_t now)
{
    if (l4len < 8)
        return;
    const uint32_t ulen = get_be16(uh + 4);
    if (ulen < 8 || ulen > l4len)
        return;
    flow_key k = {.gport = get_be16(uh), .rport = get_be16(uh + 2)};
    memcpy(k.raddr, dst, 4);
    if (!k.gport || !k.rport)
        return;
    int err = 0;
    uflow *u = udp_lookup(n, &k, now, &err);
    if (!u) {
        // Refused by the policy: say so. Anything else (no socket now) may
        // pass, so the datagram is lost and the guest retries as for any loss.
        if (err == -EACCES || err == -EPERM)
            udp_refused(n, ch, off, uh, ulen, dst);
        return;
    }
    if (tx_room(n, now) < ulen - 8) { // over the cap: UDP may lose it
        n->n_drop++;
        return;
    }
    sock_iov iov[VIRTQ_MAX_SEGS];
    const int nio = chain_iov(ch, off + 8, ulen - 8, iov);
    const intptr_t w = sock_writev(S(u->fd), iov, nio);
    if (w < 0)
        n->n_drop++; // full, or an ICMP error from an earlier datagram: UDP may lose it
    else
        tx_sent(n, now, (uint64_t)w);
    if (!u->dns)
        u->expire = now + UDP_IDLE_NS;
}

// Options of a SYN: MSS and window scale.
static void syn_options(tflow *f, const uint8_t *o, uint32_t len)
{
    f->mss = 536;
    for (uint32_t i = 0; i < len;) {
        if (o[i] == 0)
            break;
        if (o[i] == 1) {
            i++;
            continue;
        }
        if (i + 1 >= len || o[i + 1] < 2 || o[i + 1] > len - i)
            break;
        if (o[i] == 2 && o[i + 1] == 4)
            f->mss = get_be16(o + i + 2);
        else if (o[i] == 3 && o[i + 1] == 3) {
            f->wscale_ok = true;
            f->snd_wscale = o[i + 2] > 14 ? 14 : o[i + 2];
        }
        i += o[i + 1];
    }
    if (f->mss > MTU - 40)
        f->mss = MTU - 40;
    if (f->mss < 64)
        f->mss = 64;
}

static void tcp_syn(net *n, const flow_key *k, uint32_t seq, const uint8_t *opt, uint32_t optlen, uint32_t win)
{
    tflow *f = nullptr;
    for (int i = 0; i < MAX_TCP && !f; i++)
        if (n->t[i].state == T_FREE)
            f = &n->t[i];
    if (!f) {
        n->n_refused++;
        queue_rst(n, k, 0, seq + 1, TH_ACK);
        return;
    }
    const net_dst d = {.proto = NET_TCP, .port = k->rport, .addr = {k->raddr[0], k->raddr[1], k->raddr[2], k->raddr[3]}};
    const int fd = n->open(n->open_ctx, &d);
    if (fd < 0) {
        refusal(n, fd);
        queue_rst(n, k, 0, seq + 1, TH_ACK);
        return;
    }
    n->st.flows++;
    f->state = T_CONNECTING;
    f->fd = fd;
    f->k = *k;
    f->rcv_nxt = seq + 1;
    f->iss = rnd32(n);
    f->snd_una = f->snd_nxt = f->snd_max = f->iss;
    f->rto = RTO_NS;
    syn_options(f, opt, optlen);
    f->snd_wnd = win; // a SYN's window is never scaled
}

// A TCP segment from the guest; `pay`/`plen`: where its payload is in the chain.
static void tcp_in(net *n, const virtq_chain *ch, const uint8_t *th, uint32_t thl, uint32_t pay, uint32_t plen,
                   const uint8_t dst[4], uint64_t now)
{
    flow_key k = {.gport = get_be16(th), .rport = get_be16(th + 2)};
    memcpy(k.raddr, dst, 4);
    const uint32_t seq = get_be32(th + 4), ack = get_be32(th + 8);
    const uint8_t fl = th[13];
    const uint32_t win = get_be16(th + 14);
    tflow *f = tcp_find(n, &k);
    if (fl & TH_RST) {
        if (f)
            tcp_free(n, f);
        return;
    }
    if (fl & TH_SYN) {
        if (fl & TH_ACK) { // we never send a SYN
            queue_rst(n, &k, ack, 0, 0);
            return;
        }
        if (f && f->rcv_nxt == seq + 1 && f->state != T_EST) { // the guest resent its SYN
            if (f->state == T_SYNACK)
                f->synack_sent = false;
            return;
        }
        if (f) // a new connection on the same ports: the old one is gone
            tcp_free(n, f);
        if (!k.gport || !k.rport)
            return;
        tcp_syn(n, &k, seq, th + 20, thl - 20, win);
        return;
    }
    if (!f) {
        // Not ours: an RST the guest can't ignore (RFC 9293 3.10.7.1).
        if (fl & TH_ACK)
            queue_rst(n, &k, ack, 0, 0);
        else
            queue_rst(n, &k, 0, seq + plen + !!(fl & TH_FIN), TH_ACK);
        return;
    }
    if (!(fl & TH_ACK) || f->state == T_CONNECTING)
        return;
    // The acknowledgement.
    if (f->state == T_SYNACK) {
        if (!f->synack_sent || ack != f->iss + 1) {
            tcp_reset(n, f);
            return;
        }
        f->state = T_EST;
        f->snd_una = f->snd_nxt = f->snd_max = f->iss + 1;
        f->rto_at = 0;
        f->retries = 0;
        f->rto = RTO_NS;
    }
    const uint32_t acked = ack - f->snd_una, flight = f->snd_max - f->snd_una;
    if (acked && acked <= flight) {
        const uint32_t data = min32(acked, f->out_len);
        f->out_head = (f->out_head + data) % TCP_OUT;
        f->out_len -= data;
        if (!f->out_len)
            f->out_head = 0;
        if (acked > data)
            f->fin_acked = true;
        f->snd_una = ack;
        if (seq_lt(f->snd_nxt, f->snd_una))
            f->snd_nxt = f->snd_una;
        f->retries = 0;
        f->rto = RTO_NS;
        f->rto_at = f->snd_max != f->snd_una ? now + f->rto : 0;
    }
    if (!seq_lt(ack, f->snd_una)) // not an old segment: its window is current
        f->snd_wnd = win << f->snd_wscale;
    // A zero window that leaves data of ours unacknowledged: the guest
    // dropped it (it acknowledges what it keeps), short of memory. Send it
    // again from there once the window opens, not after a timeout.
    if (!f->snd_wnd && ack == f->snd_una && f->snd_nxt != f->snd_una)
        f->snd_nxt = f->snd_una;
    // Data and FIN, in order only.
    const bool fin = fl & TH_FIN;
    if (plen || fin) {
        const uint32_t done = f->rcv_nxt - seq; // of this segment, already taken
        if (f->guest_fin || (int32_t)done < 0 || done >= plen + fin) {
            f->need_ack = true; // ahead of what we expect, or old: say where we are
        } else {
            const uint32_t avail = plen - min32(done, plen);
            const uint32_t room = TCP_IN - f->in_len;
            const uint32_t take = min32(avail, room);
            uint32_t w = 0;
            const uint64_t txr = take && !f->in_len ? tx_room(n, now) : 0;
            const uint32_t direct = txr < take ? (uint32_t)txr : take;
            if (take && !f->in_len && direct < take)
                n->tx_blocked = true; // the rest waits in TCP_IN for room
            if (direct) { // straight to the host socket
                sock_iov iov[VIRTQ_MAX_SEGS];
                const int nio = chain_iov(ch, pay + (plen - avail), direct, iov);
                const intptr_t r = sock_writev(S(f->fd), iov, nio);
                if (r == SOCK_GONE) {
                    tcp_reset(n, f);
                    return;
                }
                if (r > 0) {
                    w = (uint32_t)r;
                    tx_sent(n, now, w);
                }
            }
            while (w < take) { // the rest waits in TCP_IN
                const uint32_t tail = (f->in_head + f->in_len) % TCP_IN;
                const uint32_t c = min32(take - w, TCP_IN - tail);
                virtq_gather(ch, pay + (plen - avail) + w, f->in + tail, c);
                f->in_len += c;
                w += c;
            }
            f->rcv_nxt += take;
            if (take == avail && fin) {
                f->rcv_nxt++;
                f->guest_fin = true;
            }
            f->unacked += take;
            if (fin || f->in_len || f->unacked >= TCP_IN / 4)
                f->need_ack = true;
            else if (!f->ack_at)
                f->ack_at = now + ACK_DELAY_NS;
            if (tcp_flush(n, f, now)) {
                tcp_reset(n, f);
                return;
            }
        }
    }
    tcp_maybe_done(n, f);
}

static void ip4_in(net *n, const virtq_chain *ch, const uint8_t *hb, uint32_t hblen, uint64_t now)
{
    const uint8_t *ip = hb + VHDR + ETH;
    const uint32_t frame = ch->rlen - VHDR - ETH; // bytes of IP the guest gave
    if (hblen < VHDR + ETH + 20 || (ip[0] >> 4) != 4)
        return;
    const uint32_t ihl = (ip[0] & 15) * 4u, tot = get_be16(ip + 2);
    if (ihl < 20 || tot < ihl || tot > frame || VHDR + ETH + ihl > hblen)
        return;
    if (get_be16(ip + 6) & 0x3fff) { // MF or an offset: fragments aren't reassembled
        n->n_drop++;
        return;
    }
    if (memcmp(ip + 12, NET_GUEST_IP, 4)) // only from the guest's own address
        return;
    const uint8_t *dst = ip + 16;
    if (dst[0] >= 224 || dst[0] == 0 || dst[0] == 127 || !memcmp(dst, NET_GUEST_IP, 4) ||
        (dst[0] == 10 && dst[1] == 0 && dst[2] == 2 && dst[3] == 255))
        return; // multicast, broadcast and nonsense
    const uint32_t l4off = VHDR + ETH + ihl, l4len = tot - ihl;
    const uint8_t *l4 = hb + l4off;
    const uint32_t l4have = hblen - l4off; // header bytes we copied
    switch (ip[9]) {
    case NET_TCP: {
        if (l4len < 20 || l4have < 20)
            return;
        const uint32_t thl = (l4[12] >> 4) * 4u;
        if (thl < 20 || thl > l4len || thl > l4have)
            return;
        tcp_in(n, ch, l4, thl, l4off + thl, l4len - thl, dst, now);
        break;
    }
    case NET_UDP:
        if (l4have >= 8)
            udp_in(n, ch, l4off, l4, l4len, dst, now);
        break;
    case 1:
        icmp_in(n, ch, l4off, l4len, dst);
        break;
    default:
        break;
    }
}

static void tx_frame(net *n, const virtq_chain *ch, uint64_t now)
{
    if (ch->rlen < VHDR + ETH)
        return;
    uint8_t hb[HB_MAX];
    const uint32_t hblen = (uint32_t)virtq_gather(ch, 0, hb, sizeof hb);
    if (hb[1] != 0) { // a GSO frame: never negotiated
        n->n_drop++;
        return;
    }
    const uint8_t *eth = hb + VHDR;
    if (memcmp(eth, GW_MAC, 6) && memcmp(eth, "\xff\xff\xff\xff\xff\xff", 6))
        return; // not to us
    switch (get_be16(eth + 12)) {
    case 0x0806:
        arp_in(n, eth + ETH, hblen - VHDR - ETH);
        break;
    case 0x0800:
        ip4_in(n, ch, hb, hblen, now);
        break;
    default:
        break; // IPv6 and everything else
    }
}

// The guest was interrupted: it looks at the transmit queue too.
static void tx_irq_done(net *n)
{
    n->tx_irq = false;
    n->tx_irq_bytes = n->tx_irq_descs = 0;
}

static void tx_drain(net *n, uint64_t now)
{
    virtio_dev *d = &n->dev;
    if (!virtq_usable(d, Q_TX))
        return;
    virtq_chain ch;
    bool any = false;
    while (virtq_pop(d, Q_TX, &ch) == 1) {
        tx_frame(n, &ch, now);
        virtq_push(d, Q_TX, ch.head, 0);
        n->tx_irq_bytes += ch.rlen;
        n->tx_irq_descs += ch.nr + ch.nw;
        any = true;
    }
    if (!any)
        return;
    if (!n->tx_irq) {
        n->tx_irq = true;
        n->tx_irq_at = now + TX_IRQ_DELAY_NS;
    }
    if (n->tx_irq_bytes >= TX_IRQ_BYTES || n->tx_irq_descs >= d->q[Q_TX].num / 2u) {
        (void)virtq_notify_driver(d, Q_TX);
        tx_irq_done(n);
    }
}

// ---- the receive side -----------------------------------------------------------------
// Fill the guest's receive queue: replies, RSTs, a waiting datagram, then
// the TCP flows round robin, then UDP sockets with data.
static void rx_fill(net *n, uint64_t now)
{
    virtio_dev *d = &n->dev;
    if (!virtq_usable(d, Q_RX))
        return;
    const uint16_t used0 = d->q[Q_RX].used_idx;
    bool room = true;
    while (room && n->nctrl) {
        if ((room = emit_ctrl(n, n->ctrl[0].b, n->ctrl[0].len))) {
            n->nctrl--;
            memmove(&n->ctrl[0], &n->ctrl[1], sizeof n->ctrl[0] * (size_t)n->nctrl);
        }
    }
    while (room && n->nrst) {
        if ((room = emit_rst(n, &n->rst[0]))) {
            n->nrst--;
            memmove(&n->rst[0], &n->rst[1], sizeof n->rst[0] * (size_t)n->nrst);
        }
    }
    if (room && n->udp_pending >= 0) {
        if ((room = emit_udp(n, &n->u[n->udp_pending], n->udp_buf, n->udp_len)))
            n->udp_pending = -1;
    }
    for (unsigned k = 0; room && k < MAX_TCP; k++) {
        tflow *f = &n->t[(n->rr + k) % MAX_TCP];
        if (f->state == T_FREE)
            continue;
        room = tcp_output(n, f, now);
        if (!room)
            n->rr = (unsigned)(f - n->t);
    }
    for (int i = 0; room && i < MAX_UDP; i++) {
        uflow *u = &n->u[i];
        while (room && u->used && u->readable && n->udp_pending < 0) {
            const intptr_t r = sock_read(S(u->fd), n->udp_buf, 65535);
            if (r < 0) {
                u->readable = false; // nothing there, or an ICMP error: either way, done
                continue;
            }
            n->st.rx += (uint64_t)r;
            u->expire = now + (u->dns ? DNS_IDLE_NS : UDP_IDLE_NS);
            if (!(room = emit_udp(n, u, n->udp_buf, (uint32_t)r))) {
                n->udp_pending = i;
                n->udp_len = (uint32_t)r;
            }
        }
    }
    if (d->q[Q_RX].used_idx != used0 && virtq_notify_driver(d, Q_RX))
        tx_irq_done(n);
}

// ---- timers ------------------------------------------------------------------------------
// The whole VMM's CPU time so far.
static uint64_t cpu_ns(void)
{
#if defined(_WIN32)
    FILETIME made, gone, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &made, &gone, &kernel, &user))
        return 0;
    return (((uint64_t)kernel.dwHighDateTime << 32 | kernel.dwLowDateTime) +
            ((uint64_t)user.dwHighDateTime << 32 | user.dwLowDateTime)) * 100;
#else
    struct timespec cpu = {0};
    (void)clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu);
    return (uint64_t)cpu.tv_sec * NS_S + (uint64_t)cpu.tv_nsec;
#endif
}

static void stats_write(const net *n)
{
    char b[256];
    const int len = snprintf(b, sizeof b, "cpu_ns %llu tx %llu rx %llu flows %llu refused %llu denied %llu limited %llu\n",
                             (unsigned long long)cpu_ns(),
                             (unsigned long long)n->st.tx, (unsigned long long)n->st.rx,
                             (unsigned long long)n->st.flows, (unsigned long long)n->st.refused,
                             (unsigned long long)n->st.denied, (unsigned long long)n->st.limited);
    // Counters only grow: each line is as long as the last or longer, so it
    // overwrites it whole.
    if (len > 0 && len < (int)sizeof b)
        (void)!os_file_pwrite((os_file){n->stats_fd}, b, (size_t)len, 0);
}

static void timers(net *n, uint64_t now)
{
    for (int i = 0; i < MAX_TCP; i++) {
        tflow *f = &n->t[i];
        if (f->state != T_FREE && f->ack_at && (int64_t)(now - f->ack_at) >= 0) {
            f->ack_at = 0;
            f->need_ack = true;
        }
        if (f->state == T_FREE || !f->rto_at || (int64_t)(now - f->rto_at) < 0)
            continue;
        f->rto_at = 0;
        if (++f->retries > MAX_RETRIES) {
            tcp_reset(n, f);
            continue;
        }
        f->rto = f->rto * 2 > RTO_MAX_NS ? RTO_MAX_NS : f->rto * 2;
        if (f->state == T_SYNACK) {
            f->synack_sent = false; // resend it
        } else if (!f->snd_wnd && f->out_len) {
            f->snd_nxt = f->snd_una;
            f->probe = true; // zero window: ask for it again
        } else if (f->snd_nxt != f->snd_una || f->snd_max != f->snd_una) {
            f->snd_nxt = f->snd_una; // go back to the oldest unacknowledged byte
        }
    }
    for (int i = 0; i < MAX_UDP; i++) {
        uflow *u = &n->u[i];
        if (u->used && (int64_t)(now - u->expire) >= 0) {
            if (n->udp_pending == i)
                n->udp_pending = -1;
            udp_free(n, u);
        }
    }
    if (n->tx_irq && (int64_t)(now - n->tx_irq_at) >= 0) {
        (void)virtq_notify_driver(&n->dev, Q_TX);
        tx_irq_done(n);
    }
    if (n->tx_blocked && (int64_t)(now - tx_wake_at(n)) >= 0) {
        n->tx_blocked = false;
        for (int i = 0; i < MAX_TCP; i++) {
            tflow *f = &n->t[i];
            if (f->state != T_FREE && f->in_len && tcp_flush(n, f, now))
                tcp_reset(n, f);
        }
    }
    if (n->stats_fd >= 0 && (int64_t)(now - n->stats_at) >= 0) {
        stats_write(n);
        n->stats_last = now;
        n->stats_at = now + STATS_NS;
    }
}

static uint64_t next_timer(const net *n)
{
    uint64_t t = UINT64_MAX;
    for (int i = 0; i < MAX_TCP; i++)
        if (n->t[i].state != T_FREE) {
            if (n->t[i].rto_at && n->t[i].rto_at < t)
                t = n->t[i].rto_at;
            if (n->t[i].ack_at && n->t[i].ack_at < t)
                t = n->t[i].ack_at;
        }
    for (int i = 0; i < MAX_UDP; i++)
        if (n->u[i].used && n->u[i].expire < t)
            t = n->u[i].expire;
    if (n->tx_irq && n->tx_irq_at < t)
        t = n->tx_irq_at;
    if (n->tx_blocked && tx_wake_at(n) < t)
        t = tx_wake_at(n);
    if (n->stats_fd >= 0 && n->stats_at < t)
        t = n->stats_at;
    return t;
}

// ---- the I/O loop ------------------------------------------------------------------------
void net_poll(net *n, int timeout_ms)
{
    sock_pollfd p[1 + MAX_TCP + MAX_UDP];
    int16_t slot[1 + MAX_TCP + MAX_UDP]; // flow: TCP i, or MAX_TCP + UDP i
    int np = 0;
    p[np++] = (sock_pollfd){.fd = n->wake_fd, .events = SOCK_POLLIN};
    virtio_lock(&n->dev);
    for (int i = 0; i < MAX_TCP; i++) {
        const tflow *f = &n->t[i];
        if (f->state == T_FREE)
            continue;
        short ev = 0;
        if (f->state == T_CONNECTING)
            ev = SOCK_POLLOUT;
        else if (f->state == T_EST) {
            if (!f->readable && !f->host_eof && f->out_len < TCP_OUT)
                ev |= SOCK_POLLIN;
            if (f->in_len && !n->tx_blocked) // capped: the timer flushes it
                ev |= SOCK_POLLOUT;
        }
        // Nothing to wait for: leave the socket out, or one that hung up
        // would report POLLHUP on every pass.
        if (!ev)
            continue;
        slot[np] = (int16_t)i;
        p[np++] = (sock_pollfd){.fd = S(f->fd), .events = ev};
    }
    for (int i = 0; i < MAX_UDP; i++) {
        const uflow *u = &n->u[i];
        if (!u->used || u->readable || n->udp_pending >= 0)
            continue;
        slot[np] = (int16_t)(MAX_TCP + i);
        p[np++] = (sock_pollfd){.fd = S(u->fd), .events = SOCK_POLLIN};
    }
    int64_t wait_ns = timeout_ms < 0 ? -1 : (int64_t)timeout_ms * 1000000;
    const uint64_t t = next_timer(n);
    if (t != UINT64_MAX) {
        const int64_t left = (int64_t)(t - mvm_now_ns());
        if (wait_ns < 0 || left < wait_ns)
            wait_ns = left < 0 ? 0 : left;
    }
#if defined(_WIN32)
    n->waiting = true;
#endif
    virtio_unlock(&n->dev);

    const int ready = sock_wait(p, np, wait_ns);

    virtio_lock(&n->dev);
#if defined(_WIN32)
    n->waiting = false;
    while (n->ndead)
        sock_close(n->dead[--n->ndead]);
#endif
    if (ready < 0) {
        virtio_unlock(&n->dev);
        return;
    }
    uint64_t now = mvm_now_ns();
    if (p[0].revents & SOCK_POLLIN) {
        wake_clear(n);
        tx_drain(n, now); // a guest kick through the doorbell, or a wake()
    }
    for (int k = 1; k < np; k++) {
        if (!p[k].revents)
            continue;
        if (slot[k] >= MAX_TCP) {
            uflow *u = &n->u[slot[k] - MAX_TCP];
            if (u->used && S(u->fd) == p[k].fd)
                u->readable = true;
            continue;
        }
        tflow *f = &n->t[slot[k]];
        // The guest may have reset it meanwhile (and the number been reused).
        if (f->state == T_FREE || S(f->fd) != p[k].fd)
            continue;
        const short ev = p[k].revents;
        if (ev & POLLNVAL) {
            tcp_reset(n, f);
        } else if (f->state == T_CONNECTING) {
            if (sock_connect_failed(S(f->fd), ev)) { // refused, unreachable, timed out
                n->n_refused++;
                tcp_reset(n, f);
            } else {
                f->state = T_SYNACK;
            }
        } else {
            if ((ev & SOCK_POLLOUT) && tcp_flush(n, f, now)) {
                tcp_reset(n, f);
                continue;
            }
            if (ev & (SOCK_POLLIN | POLLHUP | POLLERR))
                f->readable = true; // read() tells EOF and errors from data
        }
    }
    for (int i = 0; i < MAX_TCP; i++) {
        tflow *f = &n->t[i];
        if (f->state == T_EST && f->readable && tcp_read(n, f))
            tcp_reset(n, f);
        else if (f->state == T_EST)
            tcp_maybe_done(n, f);
    }
    timers(n, now);
    rx_fill(n, now);
    virtio_unlock(&n->dev);
}

static void io_main(void *arg)
{
    for (;;)
        net_poll(arg, -1);
}

// ---- virtio --------------------------------------------------------------------------------
// A kick that exited to the vCPU thread (no doorbell): the I/O thread does
// the work.
static void notify(virtio_dev *d, uint16_t q)
{
    (void)q;
    wake(d->priv);
}

static void activate(virtio_dev *d) { wake(d->priv); }

// The driver reset the device: every flow it had is gone.
static void reset(virtio_dev *d)
{
    net *n = d->priv;
    for (int i = 0; i < MAX_TCP; i++)
        if (n->t[i].state != T_FREE)
            tcp_free(n, &n->t[i]);
    for (int i = 0; i < MAX_UDP; i++)
        udp_free(n, &n->u[i]);
    n->nrst = n->nctrl = 0;
    n->udp_pending = -1;
    tx_irq_done(n);
}

static void config_read(virtio_dev *d, uint32_t off, uint8_t size, uint64_t *val)
{
    (void)d;
    uint8_t cfg[12] = {0}; // mac, status, max_virtqueue_pairs, mtu
    memcpy(cfg, GUEST_MAC, 6);
    put_le16(cfg + 8, 1);
    put_le16(cfg + 10, (uint16_t)MTU);
    *val = 0;
    if (off < sizeof cfg && size <= sizeof cfg - off)
        memcpy(val, cfg + off, size);
}

// Flows can't survive a restore (their host sockets belong to the old
// VMM): the guest gets an RST for each TCP connection it knew about.
static void save(virtio_dev *d, snap_w *w)
{
    net *n = d->priv;
    sw_u8(w, n->tx_irq);
    rst_entry r[MAX_RST];
    int k = 0;
    for (int i = 0; i < n->nrst && k < MAX_RST; i++)
        r[k++] = n->rst[i];
    for (int i = 0; i < MAX_TCP && k < MAX_RST; i++) {
        const tflow *f = &n->t[i];
        if (f->state == T_EST || (f->state == T_SYNACK && f->synack_sent))
            r[k++] = (rst_entry){f->k, f->snd_max, f->rcv_nxt, TH_RST | TH_ACK};
    }
    sw_u8(w, (uint8_t)k);
    for (int i = 0; i < k; i++) {
        sw_bytes(w, r[i].k.raddr, 4);
        sw_u16(w, r[i].k.gport);
        sw_u16(w, r[i].k.rport);
        sw_u32(w, r[i].seq);
        sw_u32(w, r[i].ack);
        sw_u8(w, r[i].flags);
    }
}

static bool load(virtio_dev *d, snap_r *r)
{
    net *n = d->priv;
    n->tx_irq = sr_bool(r);
    n->tx_irq_at = mvm_now_ns();
    const uint8_t k = sr_u8(r);
    if (k > MAX_RST)
        return false;
    for (int i = 0; i < k; i++) {
        rst_entry *e = &n->rst[i];
        sr_bytes(r, e->k.raddr, 4);
        e->k.gport = sr_u16(r);
        e->k.rport = sr_u16(r);
        e->seq = sr_u32(r);
        e->ack = sr_u32(r);
        e->flags = sr_u8(r);
        if (!(e->flags & TH_RST) || (e->flags & ~(TH_RST | TH_ACK)))
            return false;
    }
    n->nrst = k;
    return !r->bad;
}

static const virtio_ops OPS = {
    .device_id = 1,
    .features = F_CSUM | F_GUEST_CSUM | F_MTU | F_MAC | F_MRG_RXBUF,
    .nqueues = 2,
    // Linux fills the receive queue at probe time, with buffers big enough
    // that the whole ring holds one 64 KiB frame: 64 x ~1.5 KiB here. The
    // transmit ring costs no guest memory up front.
    .queue_max = {64, 256},
    .config_read = config_read,
    .notify = notify,
    .activate = activate,
    .reset = reset,
    .save = save,
    .load = load,
};

net *net_create(net_open_fn open, void *open_ctx, const guest_mem *mem, ioapic *irq, unsigned pin)
{
    net *n = calloc(1, sizeof *n);
    // Demand-paged: a flow touches only what it buffers, and gives it back.
    uint8_t *pool = os_mem_reserve((size_t)MAX_TCP * (TCP_IN + TCP_OUT) + 65536);
    if (!n || !pool) {
        free(n);
        return nullptr;
    }
#if defined(_WIN32)
    if (!sock_init() || !wake_pair(&n->wake_fd, &n->wake_wr)) {
        mvm_log("--net: cannot make the wake-up sockets (Winsock error %d)", WSAGetLastError());
        free(n);
        return nullptr;
    }
#else
    signal(SIGPIPE, SIG_IGN); // a host peer that hangs up must not kill us
    n->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (n->wake_fd < 0) {
        free(n);
        return nullptr;
    }
#endif
    n->open = open;
    n->open_ctx = open_ctx;
    for (int i = 0; i < MAX_TCP; i++)
        n->t[i] = (tflow){.fd = -1, .in = pool + (size_t)i * (TCP_IN + TCP_OUT),
                          .out = pool + (size_t)i * (TCP_IN + TCP_OUT) + TCP_IN};
    for (int i = 0; i < MAX_UDP; i++)
        n->u[i] = (uflow){.fd = -1};
    n->udp_buf = pool + (size_t)MAX_TCP * (TCP_IN + TCP_OUT);
    n->udp_pending = -1;
    n->stats_fd = -1;
    if (os_random(&n->prng, sizeof n->prng))
        n->prng = mvm_now_ns();
    virtio_dev_init(&n->dev, &OPS, n, mem, irq, pin);
    return n;
}

virtio_dev *net_dev(net *n) { return &n->dev; }
int net_start(net *n) { return os_thread_start(io_main, n); }
#if defined(_WIN32)
int net_doorbell_fd(const net *n) { (void)n; return -1; } // no hypervisor doorbells on WHP
#else
int net_doorbell_fd(const net *n) { return n->wake_fd; }
#endif
void net_set_tx_rate(net *n, uint64_t bytes_per_s) { n->tx_rate = bytes_per_s; }
void net_set_stats_fd(net *n, intptr_t fd) { n->stats_fd = fd; }
unsigned net_max_fds(void) { return MAX_TCP + MAX_UDP; }

int net_cmdline(char *buf, size_t len)
{
    // client::gateway:netmask::device:autoconf:dns0. The kernel lists dns0
    // in /proc/net/pnp, which /init copies to the image's /etc/resolv.conf.
    const uint8_t *g = NET_GUEST_IP, *gw = NET_GATEWAY_IP, *d = NET_DNS_IP;
    return snprintf(buf, len, "ip=%u.%u.%u.%u::%u.%u.%u.%u:255.255.255.0::eth0:off:%u.%u.%u.%u", g[0], g[1], g[2],
                    g[3], gw[0], gw[1], gw[2], gw[3], d[0], d[1], d[2], d[3]);
}
