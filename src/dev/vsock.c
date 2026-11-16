// SPDX-License-Identifier: MIT
// virtio-vsock device with a Unix-socket host side (see vsock.h).
//
// Flow control is virtio-vsock's credit scheme. Each side advertises how
// much it can buffer (buf_alloc) and how much it has passed on (fwd_cnt);
// a sender keeps at most buf_alloc - (sent - peer's fwd_cnt) bytes in
// flight. Our side buffers up to BUF_ALLOC bytes per connection for a host
// socket that isn't reading. A guest that sends more than its credit is
// reset. Toward the guest we read from the host socket straight into the
// guest's receive buffer, and only as much as the guest's credit allows.
//
// Connections the guest opens to the host never make the VMM connect
// anywhere (the sandbox has no connect()): the host opens them ahead of
// time with "LISTEN <port>", and each guest connection to that port takes
// one of those.
#include "vsock.h"

#include <stdio.h>
#include <stdlib.h>

#include "hostsock.h"

#include "../clock.h"
#include "../os.h"

constexpr uint64_t HOST_CID = 2;
constexpr int MAX_CONNS = 128; // an agent sandbox holds one per stream, watch and port
constexpr uint32_t BUF_ALLOC = 256 * 1024; // per connection, guest -> host
constexpr uint32_t HDR = 44;
constexpr uint32_t MAX_PKT = 64 * 1024;
constexpr int MAX_RST = 16;
// Transmit completions only let the guest free buffers: they wait for the
// next receive interrupt (one interrupt has the driver look at every
// queue), for this long at most, or until half the ring is waiting.
constexpr uint64_t TX_IRQ_DELAY_NS = 500 * 1000;
constexpr uint32_t FIRST_HOST_PORT = 1u << 30; // host ports of host-initiated connections
enum : uint16_t { Q_RX = 0, Q_TX = 1, Q_EVENT = 2 };
enum : uint16_t {
    OP_REQUEST = 1, OP_RESPONSE = 2, OP_RST = 3, OP_SHUTDOWN = 4, OP_RW = 5,
    OP_CREDIT_UPDATE = 6, OP_CREDIT_REQUEST = 7,
};
constexpr uint16_t TYPE_STREAM = 1;
enum : uint32_t { SHUT_RCV = 1, SHUT_SEND = 2 }; // SHUTDOWN flags

typedef struct {
    uint64_t src_cid, dst_cid;
    uint32_t src_port, dst_port, len;
    uint16_t type, op;
    uint32_t flags, buf_alloc, fwd_cnt;
} pkt_hdr;

static void hdr_decode(const uint8_t *b, pkt_hdr *h)
{
    h->src_cid = get_le64(b);
    h->dst_cid = get_le64(b + 8);
    h->src_port = get_le32(b + 16);
    h->dst_port = get_le32(b + 20);
    h->len = get_le32(b + 24);
    h->type = get_le16(b + 28);
    h->op = get_le16(b + 30);
    h->flags = get_le32(b + 32);
    h->buf_alloc = get_le32(b + 36);
    h->fwd_cnt = get_le32(b + 40);
}

static void hdr_encode(uint8_t *b, const pkt_hdr *h)
{
    put_le64(b, h->src_cid);
    put_le64(b + 8, h->dst_cid);
    put_le32(b + 16, h->src_port);
    put_le32(b + 20, h->dst_port);
    put_le32(b + 24, h->len);
    put_le16(b + 28, h->type);
    put_le16(b + 30, h->op);
    put_le32(b + 32, h->flags);
    put_le32(b + 36, h->buf_alloc);
    put_le32(b + 40, h->fwd_cnt);
}

typedef enum : uint8_t {
    C_FREE,
    C_HANDSHAKE, // host connected, reading its "CONNECT <port>" / "LISTEN <port>" line
    C_LISTEN,    // "LISTEN <port>": waiting for the guest to connect to that port
    C_REQUESTED, // REQUEST owed to / sent to the guest, waiting for RESPONSE
    C_OPEN,
} conn_state;

typedef struct {
    conn_state state;
    sock fd;
    uint32_t guest_port, host_port; // C_LISTEN: host_port is the port listened on
    uint32_t seq;                   // C_LISTEN: order of arrival
    char line[40];
    uint8_t linelen;
    // host -> guest
    uint32_t peer_buf_alloc, peer_fwd_cnt, tx_cnt;
    bool readable;  // poll said the host socket has data (or EOF)
    bool host_eof;  // the host shut its sending side
    // guest -> host
    uint32_t rx_cnt, fwd_cnt, fwd_sent; // received, written to the host, last told the guest
    uint8_t *buf;                       // BUF_ALLOC bytes of ring for what the host hasn't taken
    uint32_t head, len;
    bool guest_shut_send, guest_shut_rcv, shut_wr_done;
    // owed to the guest
    bool need_request, need_response, need_credit, need_shutdown;
} conn;

struct vsock {
    virtio_dev dev;
    sock listen_fd, wake_fd; // wake_fd: readable once wake() was called
#if defined(_WIN32)
    sock wake_wr; // the other end of wake_fd
    // A socket the vCPU thread drops while the I/O thread waits on it is
    // closed by the I/O thread once it is back: WSAPoll must not be handed
    // a closed socket (or whatever took its number since).
    bool waiting;
    sock dead[MAX_CONNS];
    int ndead;
#endif
    conn c[MAX_CONNS];
    struct {
        uint32_t gport, hport;
    } rst[MAX_RST];
    int nrst;
    uint32_t next_port, listen_seq;
    bool tx_irq;         // transmit completions the guest hasn't been interrupted for
    uint64_t tx_irq_at;  // ... when they get an interrupt of their own
    uint16_t tx_irq_idx; // the transmit used index at the last interrupt
    unsigned rr; // where the next receive pass starts, for fairness
};

static uint32_t min32(uint32_t a, uint32_t b) { return a < b ? a : b; }

#if defined(_WIN32)
static void wake(vsock *s) { (void)sock_write(s->wake_wr, "", 1); }

static void wake_clear(vsock *s)
{
    char buf[64];
    while (sock_read(s->wake_fd, buf, sizeof buf) == (intptr_t)sizeof buf) {
    }
}

static void host_close(vsock *s, sock fd)
{
    if (s->waiting) { // at most one per connection until the I/O thread is back
        s->dead[s->ndead++] = fd;
        wake(s);
    } else {
        sock_close(fd);
    }
}
#else
static void wake(vsock *s)
{
    const uint64_t one = 1;
    (void)!write(s->wake_fd, &one, sizeof one);
}

static void wake_clear(vsock *s)
{
    uint64_t v;
    (void)!read(s->wake_fd, &v, sizeof v);
}

static void host_close(vsock *s, sock fd)
{
    (void)s;
    sock_close(fd);
}
#endif

static void conn_drop(vsock *s, conn *c)
{
    if (c->fd != NOSOCK)
        host_close(s, c->fd);
    uint8_t *buf = c->buf;
    os_mem_discard(buf, BUF_ALLOC); // give the pages back
    *c = (conn){.fd = NOSOCK, .buf = buf};
}

static void queue_rst(vsock *s, uint32_t gport, uint32_t hport)
{
    if (s->nrst < MAX_RST)
        s->rst[s->nrst++] = (typeof(s->rst[0])){gport, hport};
}

// Close the connection and tell the guest.
static void conn_reset(vsock *s, conn *c)
{
    if (c->state == C_REQUESTED || c->state == C_OPEN)
        if (!c->need_request) // the guest never heard of it otherwise
            queue_rst(s, c->guest_port, c->host_port);
    conn_drop(s, c);
}

static conn *find(vsock *s, uint32_t gport, uint32_t hport)
{
    for (int i = 0; i < MAX_CONNS; i++) {
        conn *c = &s->c[i];
        if ((c->state == C_REQUESTED || c->state == C_OPEN) && c->guest_port == gport &&
            c->host_port == hport)
            return c;
    }
    return nullptr;
}

static uint32_t peer_credit(const conn *c)
{
    const uint32_t inflight = c->tx_cnt - c->peer_fwd_cnt;
    return inflight >= c->peer_buf_alloc ? 0 : c->peer_buf_alloc - inflight;
}

// iovecs for `len` bytes of segments starting `off` bytes in.
static int seg_iov(const virtq_seg *seg, unsigned nseg, size_t off, size_t len, sock_iov *iov)
{
    int n = 0;
    for (unsigned i = 0; i < nseg && len; i++) {
        if (off >= seg[i].len) {
            off -= seg[i].len;
            continue;
        }
        size_t k = seg[i].len - off;
        if (k > len)
            k = len;
        iov[n++] = SOCK_IOV(seg[i].p + off, k);
        len -= k;
        off = 0;
    }
    return n;
}

static void credit_check(conn *c)
{
    // Tell the guest about freed space once it could be short of it.
    if (c->fwd_cnt != c->fwd_sent && c->rx_cnt - c->fwd_sent > BUF_ALLOC / 2)
        c->need_credit = true;
}

// After the guest said it is done sending and the buffer has drained.
static void maybe_finish(vsock *s, conn *c)
{
    if (c->len || !c->guest_shut_send)
        return;
    if (!c->shut_wr_done) {
        sock_shut_wr(c->fd);
        c->shut_wr_done = true;
    }
    if (c->guest_shut_rcv) // closed both ways: the reply to that is RST
        conn_reset(s, c);
}

// Write what's buffered to the host socket. -1: the socket is gone.
static int flush(conn *c)
{
    while (c->len) {
        const uint32_t chunk = min32(c->len, BUF_ALLOC - c->head);
        const intptr_t w = sock_write(c->fd, c->buf + c->head, chunk);
        if (w == SOCK_AGAIN)
            break;
        if (w < 0)
            return -1;
        c->head = (c->head + (uint32_t)w) % BUF_ALLOC;
        c->len -= (uint32_t)w;
        c->fwd_cnt += (uint32_t)w;
    }
    if (!c->len)
        c->head = 0;
    credit_check(c);
    return 0;
}

// RW from the guest: straight to the host socket if nothing is queued,
// the rest into the buffer.
static int guest_data(conn *c, const virtq_chain *ch, uint32_t len)
{
    uint32_t done = 0;
    if (!c->len) {
        sock_iov iov[VIRTQ_MAX_SEGS];
        const int n = seg_iov(ch->r, ch->nr, HDR, len, iov);
        const intptr_t w = sock_writev(c->fd, iov, n);
        if (w == SOCK_GONE)
            return -1;
        if (w > 0) {
            done = (uint32_t)w;
            c->fwd_cnt += done;
        }
    }
    while (done < len) {
        const uint32_t tail = (c->head + c->len) % BUF_ALLOC;
        const uint32_t chunk = min32(len - done, BUF_ALLOC - tail);
        virtq_gather(ch, HDR + done, c->buf + tail, chunk);
        c->len += chunk;
        done += chunk;
    }
    credit_check(c);
    return 0;
}

// A REQUEST from the guest to host port h->dst_port, which no connection
// has: hand it to a host connection waiting in LISTEN on that port.
static bool guest_connect(vsock *s, const pkt_hdr *h)
{
    for (;;) {
        conn *c = nullptr; // the oldest LISTEN on the port
        for (int i = 0; i < MAX_CONNS; i++)
            if (s->c[i].state == C_LISTEN && s->c[i].host_port == h->dst_port &&
                (!c || (int32_t)(s->c[i].seq - c->seq) < 0))
                c = &s->c[i];
        if (!c)
            return false;
        char ok[24];
        const int n = snprintf(ok, sizeof ok, "OK %u\n", h->src_port);
        if (sock_write(c->fd, ok, (size_t)n) != n) { // the first bytes we send it
            conn_drop(s, c);
            continue;
        }
        c->guest_port = h->src_port;
        c->peer_buf_alloc = h->buf_alloc;
        c->peer_fwd_cnt = h->fwd_cnt;
        c->state = C_OPEN;
        c->need_response = true;
        return true;
    }
}

// One packet from the guest (vCPU thread, device lock held).
static void tx_packet(vsock *s, const virtq_chain *ch)
{
    if (ch->rlen < HDR)
        return;
    uint8_t hb[HDR];
    virtq_gather(ch, 0, hb, HDR);
    pkt_hdr h;
    hdr_decode(hb, &h);
    if (h.src_cid != VSOCK_GUEST_CID || h.dst_cid != HOST_CID)
        return; // not ours to answer
    conn *c = find(s, h.src_port, h.dst_port);
    if (h.type != TYPE_STREAM || h.len > ch->rlen - HDR || h.len > MAX_PKT) {
        if (c)
            conn_reset(s, c);
        else if (h.op != OP_RST)
            queue_rst(s, h.src_port, h.dst_port);
        return;
    }
    if (!c) {
        // The guest connecting to the host: a host LISTEN connection for
        // that port becomes this connection; with none waiting, refused.
        if (h.op == OP_REQUEST && guest_connect(s, &h))
            return;
        if (h.op != OP_RST)
            queue_rst(s, h.src_port, h.dst_port);
        return;
    }
    c->peer_buf_alloc = h.buf_alloc;
    c->peer_fwd_cnt = h.fwd_cnt;
    switch (h.op) {
    case OP_RESPONSE: {
        if (c->state != C_REQUESTED) {
            conn_reset(s, c);
            break;
        }
        c->state = C_OPEN;
        char ok[24];
        const int n = snprintf(ok, sizeof ok, "OK %u\n", c->host_port);
        if (sock_write(c->fd, ok, (size_t)n) != n) // the first bytes on a fresh socket
            conn_reset(s, c);
        break;
    }
    case OP_RST:
        conn_drop(s, c);
        break;
    case OP_SHUTDOWN:
        if (h.flags & SHUT_SEND)
            c->guest_shut_send = true;
        if (h.flags & SHUT_RCV)
            c->guest_shut_rcv = true;
        maybe_finish(s, c);
        break;
    case OP_RW:
        if (c->state != C_OPEN || c->guest_shut_send || h.len > BUF_ALLOC - c->len) {
            conn_reset(s, c); // data out of turn, or past the credit we gave
            break;
        }
        c->rx_cnt += h.len;
        if (guest_data(c, ch, h.len))
            conn_reset(s, c);
        break;
    case OP_CREDIT_UPDATE:
        break; // the header's credit fields were the point
    case OP_CREDIT_REQUEST:
        c->need_credit = true;
        break;
    default: // REQUEST on an existing connection, unknown ops
        conn_reset(s, c);
        break;
    }
}

// The guest was interrupted: it looks at the transmit queue too.
static void tx_irq_done(vsock *s)
{
    s->tx_irq = false;
    s->tx_irq_idx = s->dev.q[Q_TX].used_idx;
}

// Interrupt now for transmit completions that have waited long enough.
static void tx_irq_check(vsock *s, uint64_t now)
{
    if (s->tx_irq && (int64_t)(now - s->tx_irq_at) >= 0) {
        (void)virtq_notify_driver(&s->dev, Q_TX);
        tx_irq_done(s);
    }
}

// Fill the guest's receive queue: RSTs, then per connection REQUEST,
// SHUTDOWN, CREDIT_UPDATE and data (device lock held).
static void rx_fill(vsock *s)
{
    virtio_dev *d = &s->dev;
    bool pushed = false;
    for (;;) {
        virtq_chain ch;
        if (virtq_pop(d, Q_RX, &ch) != 1)
            break;
        if (ch.wlen < HDR) { // can't hold a header: hand it back empty
            virtq_push(d, Q_RX, ch.head, 0);
            pushed = true;
            continue;
        }
        pkt_hdr h = {.src_cid = HOST_CID, .dst_cid = VSOCK_GUEST_CID, .type = TYPE_STREAM};
        conn *c = nullptr;
        bool have = false;
        if (s->nrst) {
            s->nrst--;
            h.op = OP_RST;
            h.src_port = s->rst[s->nrst].hport;
            h.dst_port = s->rst[s->nrst].gport;
            have = true;
        }
        for (unsigned k = 0; !have && k < MAX_CONNS; k++) {
            c = &s->c[(s->rr + k) % MAX_CONNS];
            h.src_port = c->host_port;
            h.dst_port = c->guest_port;
            if (c->state == C_REQUESTED && c->need_request) {
                c->need_request = false;
                h.op = OP_REQUEST;
                have = true;
            } else if (c->state != C_OPEN) {
                continue;
            } else if (c->need_response) {
                c->need_response = false;
                h.op = OP_RESPONSE;
                have = true;
            } else if (c->need_shutdown) {
                c->need_shutdown = false;
                h.op = OP_SHUTDOWN;
                h.flags = SHUT_SEND;
                have = true;
            } else if (c->need_credit) {
                c->need_credit = false;
                h.op = OP_CREDIT_UPDATE;
                have = true;
            } else if (c->readable && !c->host_eof && !c->guest_shut_rcv && peer_credit(c)) {
                const uint32_t max = min32(min32(peer_credit(c), ch.wlen - HDR), MAX_PKT);
                sock_iov iov[VIRTQ_MAX_SEGS];
                const int n = seg_iov(ch.w, ch.nw, HDR, max, iov);
                const intptr_t r = sock_readv(c->fd, iov, n);
                if (r > 0) {
                    h.op = OP_RW;
                    h.len = (uint32_t)r;
                    c->tx_cnt += (uint32_t)r;
                    have = true;
                } else if (r == 0) {
                    c->readable = false;
                    c->host_eof = true;
                    h.op = OP_SHUTDOWN;
                    h.flags = SHUT_SEND;
                    have = true;
                } else if (r == SOCK_AGAIN) {
                    c->readable = false;
                } else {
                    conn_reset(s, c);
                    k = (unsigned)-1; // the RST goes first: start over
                    c = nullptr;
                    if (s->nrst) {
                        s->nrst--;
                        h = (pkt_hdr){.src_cid = HOST_CID, .dst_cid = VSOCK_GUEST_CID, .type = TYPE_STREAM,
                                      .op = OP_RST, .src_port = s->rst[s->nrst].hport,
                                      .dst_port = s->rst[s->nrst].gport};
                        have = true;
                    }
                }
            }
            if (have && c)
                s->rr = (unsigned)(c - s->c + 1) % MAX_CONNS;
        }
        if (!have) {
            virtq_unpop(d, Q_RX);
            break;
        }
        if (c && h.op != OP_RST) { // our credit rides on every packet
            h.buf_alloc = BUF_ALLOC;
            h.fwd_cnt = c->fwd_cnt;
            c->fwd_sent = c->fwd_cnt;
        }
        uint8_t hb[HDR];
        hdr_encode(hb, &h);
        virtq_scatter(&ch, 0, hb, HDR);
        virtq_push(d, Q_RX, ch.head, HDR + h.len);
        pushed = true;
    }
    if (pushed && virtq_notify_driver(d, Q_RX))
        tx_irq_done(s);
}

static void handshake(vsock *s, conn *c)
{
    const intptr_t n = sock_read(c->fd, c->line + c->linelen, sizeof c->line - 1u - c->linelen);
    if (n == SOCK_AGAIN)
        return;
    if (n <= 0) {
        conn_drop(s, c);
        return;
    }
    c->linelen = (uint8_t)(c->linelen + n);
    c->line[c->linelen] = 0;
    char *nl = memchr(c->line, '\n', c->linelen);
    if (!nl) {
        if (c->linelen == sizeof c->line - 1)
            conn_drop(s, c);
        return;
    }
    // Exactly "CONNECT <decimal port>\n" or "LISTEN <decimal port>\n",
    // nothing after it. Ports we listen on are below the ones we number
    // host-initiated connections with.
    const bool listen = !strncmp(c->line, "LISTEN ", 7);
    const char *p = c->line + (listen ? 7 : 8);
    uint64_t port = 0;
    bool ok = (listen || !strncmp(c->line, "CONNECT ", 8)) && p < nl && nl == c->line + c->linelen - 1;
    for (; ok && p < nl; p++) {
        ok = *p >= '0' && *p <= '9' && (port = port * 10 + (uint64_t)(*p - '0')) <= 0xffffffffu;
    }
    if (!ok || (listen && port >= FIRST_HOST_PORT)) {
        conn_drop(s, c);
        return;
    }
    if (listen) {
        c->host_port = (uint32_t)port;
        c->seq = s->listen_seq++;
        c->state = C_LISTEN;
        return;
    }
    c->guest_port = (uint32_t)port;
    c->host_port = s->next_port++;
    if (s->next_port == 0)
        s->next_port = FIRST_HOST_PORT;
    c->state = C_REQUESTED;
    c->need_request = true;
}

static void accept_new(vsock *s)
{
    for (int i = 0; i < MAX_CONNS; i++) {
        if (s->c[i].state != C_FREE)
            continue;
        const sock fd = sock_accept(s->listen_fd);
        if (fd == NOSOCK)
            return;
        conn *c = &s->c[i];
        c->fd = fd;
        c->state = C_HANDSHAKE;
    }
}

static bool tx_drain(vsock *s);

void vsock_poll(vsock *s, int timeout_ms)
{
    sock_pollfd p[2 + MAX_CONNS];
    int slot[2 + MAX_CONNS];
    int n = 0;
    p[n++] = (sock_pollfd){.fd = s->wake_fd, .events = SOCK_POLLIN};
    virtio_lock(&s->dev);
    bool room = false;
    for (int i = 0; i < MAX_CONNS; i++) {
        conn *c = &s->c[i];
        if (c->state == C_FREE) {
            room = true;
            continue;
        }
        short ev = 0;
        if (c->state == C_HANDSHAKE || c->state == C_LISTEN ||
            (c->state == C_OPEN && !c->readable && !c->host_eof && !c->guest_shut_rcv && peer_credit(c)))
            ev |= SOCK_POLLIN;
        if (c->len)
            ev |= SOCK_POLLOUT;
        // Nothing to wait for: leave the socket out, or a host socket that
        // hung up reports POLLHUP on every pass and the thread spins for as
        // long as the guest holds back credit.
        if (!ev)
            continue;
        slot[n] = i;
        p[n++] = (sock_pollfd){.fd = c->fd, .events = ev};
    }
    if (room) {
        slot[n] = -1;
        p[n++] = (sock_pollfd){.fd = s->listen_fd, .events = SOCK_POLLIN};
    }
    // Wake up in time for deferred transmit completions.
    int64_t wait_ns = timeout_ms < 0 ? -1 : (int64_t)timeout_ms * 1000000;
    if (s->tx_irq) {
        const int64_t left = (int64_t)(s->tx_irq_at - mvm_now_ns());
        if (wait_ns < 0 || left < wait_ns)
            wait_ns = left < 0 ? 0 : left;
    }
#if defined(_WIN32)
    s->waiting = true;
#endif
    virtio_unlock(&s->dev);

    const int ready = sock_wait(p, n, wait_ns);

    virtio_lock(&s->dev);
#if defined(_WIN32)
    s->waiting = false;
    while (s->ndead)
        sock_close(s->dead[--s->ndead]);
#endif
    if (ready < 0) {
        virtio_unlock(&s->dev);
        return;
    }
    if (p[0].revents & SOCK_POLLIN) {
        wake_clear(s);
        (void)tx_drain(s); // a guest kick through the doorbell (or a wake())
    }
    for (int k = 1; k < n; k++) {
        if (slot[k] < 0) {
            if (p[k].revents & SOCK_POLLIN)
                accept_new(s);
            continue;
        }
        conn *c = &s->c[slot[k]];
        // The vCPU thread may have closed it meanwhile (and accept may
        // have reused the number for another slot).
        if (c->state == C_FREE || c->fd != p[k].fd || !p[k].revents)
            continue;
        if (p[k].revents & POLLNVAL) {
            conn_reset(s, c);
            continue;
        }
        if (p[k].revents & SOCK_POLLOUT) {
            if (flush(c)) {
                conn_reset(s, c);
                continue;
            }
            maybe_finish(s, c);
            if (c->state == C_FREE)
                continue;
        }
        if (p[k].revents & (SOCK_POLLIN | POLLHUP | POLLERR)) {
            if (c->state == C_HANDSHAKE)
                handshake(s, c);
            else if (c->state == C_LISTEN) // hung up, or talking before it was connected
                conn_drop(s, c);
            else if (c->state == C_OPEN && !(p[k].revents & SOCK_POLLIN) && (p[k].revents & POLLERR))
                conn_reset(s, c);
            else
                c->readable = true; // read() tells EOF from data
        }
    }
    rx_fill(s);
    tx_irq_check(s, mvm_now_ns());
    virtio_unlock(&s->dev);
}

static void io_main(void *arg)
{
    for (;;)
        vsock_poll(arg, -1);
}

// Take what the guest queued for transmission. True if there was any.
static bool tx_drain(vsock *s)
{
    virtio_dev *d = &s->dev;
    if (!virtq_usable(d, Q_TX))
        return false;
    virtq_chain ch;
    bool any = false;
    while (virtq_pop(d, Q_TX, &ch) == 1) {
        tx_packet(s, &ch);
        virtq_push(d, Q_TX, ch.head, 0);
        any = true;
    }
    if (any) {
        if (!s->tx_irq) {
            s->tx_irq = true;
            s->tx_irq_at = mvm_now_ns() + TX_IRQ_DELAY_NS;
        }
        if ((uint16_t)(d->q[Q_TX].used_idx - s->tx_irq_idx) >= d->q[Q_TX].num / 2) {
            (void)virtq_notify_driver(d, Q_TX); // the ring is filling up: now
            tx_irq_done(s);
        }
    }
    return any;
}

// A kick that exited to the vCPU thread (no doorbell: see vsock_doorbell_fd).
static void notify(virtio_dev *d, uint16_t q)
{
    vsock *s = d->priv;
    if (q == Q_TX) {
        if (tx_drain(s))
            wake(s);
    } else if (q == Q_RX) {
        wake(s); // new receive buffers
    } // event queue: we never send transport events
}

static void activate(virtio_dev *d) { wake(d->priv); }

// The guest's driver reset the device (it does at probe, before it has
// seen anything): the connections it knew about are gone. Host connections
// it never heard of (still in their handshake, waiting in LISTEN, or with
// the REQUEST not sent yet) stay for the next driver.
static void reset(virtio_dev *d)
{
    vsock *s = d->priv;
    for (int i = 0; i < MAX_CONNS; i++) {
        conn *c = &s->c[i];
        if (c->state == C_OPEN || (c->state == C_REQUESTED && !c->need_request))
            conn_drop(s, c);
    }
    s->nrst = 0;
    s->tx_irq = false;
    s->tx_irq_idx = 0;
}

static void config_read(virtio_dev *d, uint32_t off, uint8_t size, uint64_t *val)
{
    (void)d;
    uint8_t cfg[8];
    put_le64(cfg, VSOCK_GUEST_CID);
    *val = 0;
    if (off < sizeof cfg && size <= sizeof cfg - off)
        memcpy(val, cfg + off, size);
}

// The guest's connections can't survive a restore (their host sockets
// belong to the old VMM): it gets an RST for each one it knew about.
static void save(virtio_dev *d, snap_w *w)
{
    vsock *s = d->priv;
    sw_u32(w, s->next_port);
    sw_u16(w, s->tx_irq_idx);
    sw_u8(w, s->tx_irq);
    uint32_t gp[MAX_RST], hp[MAX_RST];
    uint8_t n = 0;
    for (int i = 0; i < s->nrst && n < MAX_RST; i++, n++)
        gp[n] = s->rst[i].gport, hp[n] = s->rst[i].hport;
    for (int i = 0; i < MAX_CONNS && n < MAX_RST; i++) {
        const conn *c = &s->c[i];
        if (c->state == C_OPEN || (c->state == C_REQUESTED && !c->need_request))
            gp[n] = c->guest_port, hp[n++] = c->host_port;
    }
    sw_u8(w, n);
    for (uint8_t i = 0; i < n; i++) {
        sw_u32(w, gp[i]);
        sw_u32(w, hp[i]);
    }
}

static bool load(virtio_dev *d, snap_r *r)
{
    vsock *s = d->priv;
    s->next_port = sr_u32(r);
    s->tx_irq_idx = sr_u16(r);
    s->tx_irq = sr_bool(r);
    s->tx_irq_at = mvm_now_ns();
    const uint8_t n = sr_u8(r);
    if (n > MAX_RST || s->next_port < FIRST_HOST_PORT)
        return false;
    s->nrst = n;
    for (uint8_t i = 0; i < n; i++) {
        s->rst[i].gport = sr_u32(r);
        s->rst[i].hport = sr_u32(r);
    }
    return !r->bad;
}

static const virtio_ops OPS = {
    .device_id = 19,
    .features = 0, // stream only, no SEQPACKET
    .nqueues = 3,
    // Linux fills the receive queue with 4 KiB buffers at probe time: 32
    // of them is 128 KiB of guest memory (256 would be 1 MiB, and ~1 ms of
    // boot). Transmit buffers are allocated per packet; events are 8 bytes.
    .queue_max = {32, 64, 8},
    .config_read = config_read,
    .notify = notify,
    .activate = activate,
    .reset = reset,
    .save = save,
    .load = load,
};

#if defined(_WIN32)

// The listening socket at `path` and the wake-up. Logs on failure.
static bool host_open(vsock *s, const char *path)
{
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof a.sun_path) {
        mvm_log("--vsock %s: path too long", path);
        return false;
    }
    strcpy(a.sun_path, path);
    if (!sock_init()) {
        mvm_log("--vsock: no Winsock");
        return false;
    }
    s->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s->listen_fd == NOSOCK || bind(s->listen_fd, (const struct sockaddr *)&a, sizeof a) ||
        listen(s->listen_fd, MAX_CONNS) || !sock_nonblock(s->listen_fd)) {
        mvm_log("--vsock %s: Winsock error %d", path, WSAGetLastError());
        if (s->listen_fd != NOSOCK)
            sock_close(s->listen_fd);
        return false;
    }
    if (!wake_pair(&s->wake_fd, &s->wake_wr)) {
        mvm_log("--vsock: cannot make the wake-up sockets (Winsock error %d)", WSAGetLastError());
        sock_close(s->listen_fd);
        return false;
    }
    return true;
}

int vsock_listen_fd(const vsock *s) { (void)s; return -1; }
int vsock_doorbell_fd(const vsock *s) { (void)s; return -1; } // no hypervisor doorbells on WHP

#else

static bool host_open(vsock *s, const char *path)
{
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof a.sun_path) {
        mvm_log("--vsock %s: path too long", path);
        return false;
    }
    strcpy(a.sun_path, path);
    // A host peer that hangs up must not kill us on the next write.
    signal(SIGPIPE, SIG_IGN);
    s->listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (s->listen_fd < 0 || bind(s->listen_fd, (const struct sockaddr *)&a, sizeof a) ||
        listen(s->listen_fd, MAX_CONNS)) {
        mvm_log("--vsock %s: %s", path, strerror(errno));
        if (s->listen_fd >= 0)
            close(s->listen_fd);
        return false;
    }
    s->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (s->wake_fd < 0) {
        close(s->listen_fd);
        return false;
    }
    return true;
}

int vsock_listen_fd(const vsock *s) { return s->listen_fd; }
int vsock_doorbell_fd(const vsock *s) { return s->wake_fd; }

#endif

vsock *vsock_create(const char *uds_path, const guest_mem *mem, ioapic *irq, unsigned pin)
{
    vsock *s = calloc(1, sizeof *s);
    uint8_t *pool = os_mem_reserve((size_t)MAX_CONNS * BUF_ALLOC); // demand-paged
    if (!s || !pool || !host_open(s, uds_path)) {
        if (pool)
            os_mem_release(pool, (size_t)MAX_CONNS * BUF_ALLOC);
        free(s);
        return nullptr;
    }
    for (int i = 0; i < MAX_CONNS; i++)
        s->c[i] = (conn){.fd = NOSOCK, .buf = pool + (size_t)i * BUF_ALLOC};
    s->next_port = FIRST_HOST_PORT;
    virtio_dev_init(&s->dev, &OPS, s, mem, irq, pin);
    return s;
}

virtio_dev *vsock_dev(vsock *s) { return &s->dev; }
int vsock_start(vsock *s) { return os_thread_start(io_main, s); }
unsigned vsock_max_fds(void) { return MAX_CONNS; }
