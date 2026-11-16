// SPDX-License-Identifier: MIT
// Fuzz the virtio-vsock device (Linux): a hostile guest driver sends
// arbitrary packets (any op, flags, ports, CIDs, credit, lengths, split
// across descriptors), offers receive buffers or not, resets the device,
// and pokes memory, while host clients connect, write, half-close and hang
// up. Everything runs on this thread: vsock_poll() stands in for the I/O
// thread. Includes vsock.c to check the device's own state as it goes.
//
// Input: 9-byte records {op, a[8]}; see run_record().
#include "dev/vsock.c"

#include <fcntl.h>
#include <stdlib.h>

#include "fuzz.h"

enum : uint64_t {
    RX_DESC = 0x0000, RX_AVAIL = 0x0400, RX_USED = 0x0800,
    TX_DESC = 0x1000, TX_AVAIL = 0x1400, TX_USED = 0x1800,
    EV_DESC = 0x2000, EV_AVAIL = 0x2400, EV_USED = 0x2800,
    TX_BUF = 0x4000, // 16 slots of 0x400
    RX_BUF = 0x8000, // 16 slots of 0x800
    MEM_SIZE = 0x10000,
};
enum : uint16_t { RXN = 16, TXN = 32 };
enum { NCL = 4, NPORT = 8 };

static guest_mem mem;
static ioapic irq;
static vsock *dev;
static int cl[NCL] = {-1, -1, -1, -1};
static uint16_t rx_avail, rx_seen, tx_avail;
static uint32_t ports[NPORT], rxcnt[NPORT];
static int nports;
// The guest rewrote memory or registers behind the driver's back: what is
// in the receive buffers is no longer only what the device put there.
static bool tainted;
static uint16_t rx_len[RXN];
static char sock_dir[] = "/tmp/mvm-fuzz-vsock-XXXXXX", sock_path[64];

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

static void bring_up(void)
{
    vw(0x070, 0);
    memset(mem.base, 0, MEM_SIZE);
    vw(0x070, 3);
    vw(0x024, 1);
    vw(0x020, 1);
    vw(0x024, 0);
    vw(0x020, 0);
    vw(0x070, 11);
    queue(0, RXN, RX_DESC, RX_AVAIL, RX_USED);
    queue(1, TXN, TX_DESC, TX_AVAIL, TX_USED);
    queue(2, 4, EV_DESC, EV_AVAIL, EV_USED);
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

static void offer_rx(unsigned count, uint8_t small)
{
    for (unsigned k = 0; k < count && (uint16_t)(rx_avail - rx_seen) < RXN; k++) {
        const uint16_t slot = rx_avail % RXN;
        // Mostly full-size buffers; now and then one too small for a header.
        const uint32_t len = small & (1u << (k & 7)) ? (small % 64) : 0x800;
        rx_len[slot] = (uint16_t)len;
        desc(RX_DESC, slot, RX_BUF + 0x800u * slot, len, 2, 0);
        put_le16(mem.base + RX_AVAIL + 4 + 2u * slot, slot);
        rx_avail++;
        __atomic_store_n((uint16_t *)(mem.base + RX_AVAIL + 2), rx_avail, __ATOMIC_RELEASE);
    }
    vw(0x050, 0);
}

static void tx(const pkt_hdr *h, uint32_t payload, bool split)
{
    const uint16_t slot = tx_avail % 16;
    uint8_t *b = mem.base + TX_BUF + 0x400u * slot;
    if (payload > 0x400 - HDR)
        payload = 0x400 - HDR;
    hdr_encode(b, h);
    for (uint32_t i = 0; i < payload; i++)
        b[HDR + i] = (uint8_t)(i * 7 + slot);
    const uint64_t at = TX_BUF + 0x400u * slot;
    if (split) { // header split across two descriptors, payload in a third
        desc(TX_DESC, 2 * slot, at, 20, 1, (uint16_t)(2 * slot + 1));
        desc(TX_DESC, 2 * slot + 1, at + 20, HDR - 20 + payload, 0, 0);
    } else {
        desc(TX_DESC, 2 * slot, at, HDR + payload, 0, 0);
    }
    put_le16(mem.base + TX_AVAIL + 4 + 2u * (tx_avail % TXN), (uint16_t)(2 * slot));
    tx_avail++;
    __atomic_store_n((uint16_t *)(mem.base + TX_AVAIL + 2), tx_avail, __ATOMIC_RELEASE);
    vw(0x050, 1);
}

static int port_index(uint32_t hport)
{
    for (int i = 0; i < nports; i++)
        if (ports[i] == hport)
            return i;
    return -1;
}

// Read what the device returned on the receive queue, as the guest would;
// with `respond`, accept every connection request.
static void consume_rx(bool respond)
{
    const uint16_t used = __atomic_load_n((uint16_t *)(mem.base + RX_USED + 2), __ATOMIC_ACQUIRE);
    FUZZ_ASSERT(tainted || (uint16_t)(used - rx_seen) <= RXN);
    if ((uint16_t)(used - rx_seen) > RXN)
        rx_seen = (uint16_t)(used - RXN);
    while (rx_seen != used) {
        const uint8_t *e = mem.base + RX_USED + 4 + 8u * (rx_seen % RXN);
        const uint32_t id = get_le32(e), len = get_le32(e + 4);
        FUZZ_ASSERT(tainted || (id < RXN && len <= rx_len[id]));
        rx_seen++;
        if (id >= RXN || len < HDR || len > 0x800)
            continue;
        pkt_hdr h;
        hdr_decode(mem.base + RX_BUF + 0x800u * id, &h);
        if (!tainted) {
            FUZZ_ASSERT(h.src_cid == HOST_CID && h.dst_cid == VSOCK_GUEST_CID && h.type == TYPE_STREAM);
            FUZZ_ASSERT(h.len == len - HDR && h.len <= MAX_PKT);
            FUZZ_ASSERT(h.op == OP_RW ? h.len > 0 : h.len == 0);
        }
        int pi = port_index(h.src_port);
        if (h.op == OP_REQUEST && pi < 0 && nports < NPORT) {
            pi = nports++;
            ports[pi] = h.src_port;
            rxcnt[pi] = 0;
        }
        if (pi >= 0 && h.op == OP_RW)
            rxcnt[pi] += h.len;
        if (h.op == OP_REQUEST && respond)
            tx(&(pkt_hdr){.src_cid = VSOCK_GUEST_CID, .dst_cid = HOST_CID, .src_port = h.dst_port,
                          .dst_port = h.src_port, .type = TYPE_STREAM, .op = OP_RESPONSE,
                          .buf_alloc = 64 * 1024},
               0, false);
    }
}

static void check_state(void)
{
    FUZZ_ASSERT(dev->nrst >= 0 && dev->nrst <= MAX_RST);
    for (int i = 0; i < MAX_CONNS; i++) {
        const conn *c = &dev->c[i];
        FUZZ_ASSERT(c->state <= C_OPEN);
        FUZZ_ASSERT((c->state == C_FREE) == (c->fd < 0));
        FUZZ_ASSERT(c->len <= BUF_ALLOC && c->head < BUF_ALLOC);
        FUZZ_ASSERT(c->linelen < sizeof c->line);
        FUZZ_ASSERT(c->state != C_LISTEN || (c->host_port < FIRST_HOST_PORT && c->guest_port == 0));
        FUZZ_ASSERT(c->buf == dev->c[0].buf + (size_t)i * BUF_ALLOC);
        // What we buffered never exceeds the credit we gave.
        FUZZ_ASSERT(c->rx_cnt - c->fwd_cnt == c->len);
    }
}

static void client(const uint8_t *a)
{
    const int k = a[0] % NCL;
    switch (a[1] % 6) {
    case 0: // connect and ask for the guest's port
    case 1: { // ... or say something else
        if (cl[k] >= 0)
            close(cl[k]);
        cl[k] = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        struct sockaddr_un sa = {.sun_family = AF_UNIX};
        strcpy(sa.sun_path, sock_path);
        if (connect(cl[k], (struct sockaddr *)&sa, sizeof sa)) {
            close(cl[k]);
            cl[k] = -1;
            break;
        }
        char line[16];
        int n;
        if (a[1] % 6 == 0 && (a[3] & 1)) // wait for the guest to connect to port 2000..2003
            n = snprintf(line, sizeof line, "LISTEN %u\n", 2000u + a[2] % 4);
        else if (a[1] % 6 == 0)
            n = snprintf(line, sizeof line, "CONNECT %u\n", 1000u + a[2] % 4);
        else
            n = (int)(memcpy(line, a + 2, 6), 6);
        (void)!write(cl[k], line, (size_t)n);
        break;
    }
    case 2: // write
        if (cl[k] >= 0) {
            static uint8_t junk[64 << 10];
            (void)!write(cl[k], junk, (size_t)(a[2] | a[3] << 8) % sizeof junk + 1);
        }
        break;
    case 3:
        if (cl[k] >= 0)
            shutdown(cl[k], SHUT_WR);
        break;
    case 4:
        if (cl[k] >= 0)
            close(cl[k]);
        cl[k] = -1;
        break;
    default: // read what is there
        if (cl[k] >= 0) {
            static uint8_t sink[64 << 10];
            (void)!read(cl[k], sink, sizeof sink);
        }
        break;
    }
}

static void run_record(const uint8_t *r)
{
    const uint8_t *a = r + 1;
    switch (r[0] % 8) {
    case 0:
    case 1: { // a packet from the guest
        const int pi = nports ? a[4] % nports : -1;
        const bool raw_port = a[4] >= 0xe0 || pi < 0;
        pkt_hdr h = {
            .src_cid = a[7] & 1 ? (uint64_t)a[5] << 32 | a[6] : VSOCK_GUEST_CID,
            .dst_cid = a[7] & 2 ? a[6] : HOST_CID,
            .src_port = 1000u + a[2] % 4,
            .dst_port = a[7] & 128 ? 2000u + a[4] % 4 // a port the host may LISTEN on
                        : raw_port   ? (1u << 30) + a[4] % 8
                                     : ports[pi],
            .type = a[7] & 4 ? a[5] : TYPE_STREAM,
            .op = (uint16_t)(a[0] % 9),
            .flags = a[1] % 4,
            .buf_alloc = a[5] ? (uint32_t)a[5] << 12 : BUF_ALLOC,
            .fwd_cnt = pi >= 0 && !(a[7] & 32) ? rxcnt[pi] : (uint32_t)a[6] << 8,
        };
        uint32_t payload = (uint32_t)(a[3] << 2);
        if (payload > 0x400 - HDR) // what fits in a transmit slot
            payload = 0x400 - HDR;
        h.len = a[7] & 8 ? payload + a[6] : payload; // a length that lies, now and then
        if (h.op == OP_REQUEST && !(a[7] & 64))
            h.op = OP_RW;
        tx(&h, payload, a[7] & 16);
        break;
    }
    case 2:
        offer_rx(a[0] % 17, a[1]);
        break;
    case 3:
        consume_rx(a[0] & 1);
        break;
    case 4:
        client(a);
        break;
    case 5:
        vsock_poll(dev, 0);
        // Small socket buffers on the device's side, so a host that doesn't
        // read backs data up into the device's own buffer within a few
        // packets (the default would take hundreds).
        for (int i = 0; i < MAX_CONNS; i++)
            if (dev->c[i].state == C_HANDSHAKE)
                (void)setsockopt(dev->c[i].fd, SOL_SOCKET, SO_SNDBUF, &(int){1}, sizeof(int));
        break;
    case 6:
        if (a[0] == 0) {
            bring_up();
            nports = 0;
            tainted = false;
        } else if (a[0] == 1) { // a raw register write
            static const uint16_t regs[] = {0x030, 0x038, 0x044, 0x050, 0x064, 0x070, 0x080, 0x0a0};
            vw(regs[a[1] % 8], get_le32(a + 2));
            tainted = true;
        } else {
            vsock_poll(dev, 0);
        }
        break;
    default: // the guest rewrites its own memory, rings included
        mem.base[get_le16(a) % MEM_SIZE] = a[2];
        tainted = true;
        break;
    }
    check_state();
}

static void cleanup(void)
{
    unlink(sock_path);
    rmdir(sock_dir);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!dev) {
        FUZZ_ASSERT(mkdtemp(sock_dir));
        snprintf(sock_path, sizeof sock_path, "%s/v.sock", sock_dir);
        atexit(cleanup);
        mem = (guest_mem){.base = os_mem_reserve(MEM_SIZE), .size = MEM_SIZE};
        ioapic_init(&irq, 1, no_msi, nullptr);
        dev = vsock_create(sock_path, &mem, &irq, 5);
        FUZZ_ASSERT(mem.base && dev);
    }
    // A fresh device, no host clients, nothing left in the accept backlog.
    for (int k = 0; k < NCL; k++)
        if (cl[k] >= 0)
            close(cl[k]), cl[k] = -1;
    for (int i = 0; i < MAX_CONNS; i++) // what a reset leaves (host-side state)
        if (dev->c[i].state != C_FREE)
            conn_drop(dev, &dev->c[i]);
    bring_up();
    for (int fd; (fd = accept4(dev->listen_fd, nullptr, nullptr, SOCK_CLOEXEC)) >= 0;)
        close(fd);
    uint64_t v;
    (void)!read(dev->wake_fd, &v, sizeof v);
    dev->next_port = 1u << 30;
    nports = 0;
    tainted = false;
    check_state();
    offer_rx(8, 0);
    for (size_t i = 0; i + 9 <= size; i += 9)
        run_record(data + i);
    // A reset ends every connection the guest knew about.
    vw(0x070, 0);
    for (int i = 0; i < MAX_CONNS; i++)
        FUZZ_ASSERT(dev->c[i].state != C_OPEN && (dev->c[i].state != C_REQUESTED || dev->c[i].need_request));
    return 0;
}

// Seed: a host client asks for port 1000, the guest accepts, data both ways,
// both sides shut down.
static uint8_t seed[40 * 9], seed2[40 * 9], seed3[40 * 9];
static uint8_t *out;
static size_t at;

static void r(uint8_t op, uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3, uint8_t a4, uint8_t a5,
              uint8_t a6, uint8_t a7)
{
    const uint8_t rec[9] = {op, a0, a1, a2, a3, a4, a5, a6, a7};
    memcpy(out + at, rec, 9);
    at += 9;
}

const fuzz_seed *fuzz_seeds(size_t *n)
{
    out = seed, at = 0;
    r(4, 0, 0, 0, 0, 0, 0, 0, 0);       // client 0: CONNECT 1000
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);       // accept
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);       // handshake -> REQUEST
    r(3, 1, 0, 0, 0, 0, 0, 0, 0);       // guest reads it, RESPONSE
    r(4, 0, 2, 100, 0, 0, 0, 0, 0);     // client writes 101 bytes
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    r(3, 0, 0, 0, 0, 0, 0, 0, 0);       // guest reads the data
    r(0, 5, 0, 0, 20, 0, 0, 0, 0);      // guest sends 80 bytes
    r(0, 5, 0, 0, 20, 0, 0, 0, 16);     // ... split across descriptors
    r(4, 0, 5, 0, 0, 0, 0, 0, 0);       // client reads
    r(0, 6, 0, 0, 0, 0, 0, 0, 0);       // CREDIT_UPDATE
    r(0, 7, 0, 0, 0, 0, 0, 0, 0);       // CREDIT_REQUEST
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    r(2, 8, 0, 0, 0, 0, 0, 0, 0);       // more receive buffers
    r(4, 0, 3, 0, 0, 0, 0, 0, 0);       // client shuts its side
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    r(3, 0, 0, 0, 0, 0, 0, 0, 0);
    r(0, 4, 3, 0, 0, 0, 0, 0, 0);       // guest SHUTDOWN both
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    r(3, 0, 0, 0, 0, 0, 0, 0, 0);
    r(4, 1, 1, 'C', 'O', 'N', 'N', 'X', '\n'); // a bad handshake
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    r(0, 3, 0, 0, 0, 0xf0, 0, 0, 0);    // RST to a port nobody has
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    static fuzz_seed s[3];
    s[0] = (fuzz_seed){seed, at};
    // Seed 2: a host that never reads while the guest keeps sending, until
    // the device's buffer holds what the socket won't take.
    out = seed2, at = 0;
    r(4, 0, 0, 0, 0, 0, 0, 0, 0);
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    r(3, 1, 0, 0, 0, 0, 0, 0, 0);
    for (int i = 0; i < 24; i++)
        r(0, 5, 0, 0, 0xff, 0, 0, 0, 0); // 980 bytes of RW
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    r(4, 0, 5, 0, 0, 0, 0, 0, 0);       // the host reads at last: flush
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    r(0, 4, 3, 0, 0, 0, 0, 0, 0);
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    s[1] = (fuzz_seed){seed2, at};
    // Seed 3: the host listens on 2000 (twice), the guest connects to it,
    // sends, the host answers; then a connect to a port nobody listens on.
    out = seed3, at = 0;
    r(4, 0, 0, 0, 1, 0, 0, 0, 0);        // client 0: LISTEN 2000
    r(4, 1, 0, 0, 1, 0, 0, 0, 0);        // client 1: LISTEN 2000
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    r(0, 1, 0, 0, 0, 0, 0, 0, 64 | 128); // guest 1000 -> host 2000: REQUEST
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    r(3, 0, 0, 0, 0, 0, 0, 0, 0);        // the RESPONSE
    r(0, 5, 0, 0, 30, 0, 0, 0, 128);     // RW 120 bytes
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    r(4, 0, 5, 0, 0, 0, 0, 0, 0);        // client 0 reads
    r(4, 0, 2, 50, 0, 0, 0, 0, 0);       // and writes back
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    r(3, 0, 0, 0, 0, 0, 0, 0, 0);
    r(0, 1, 0, 1, 0, 1, 0, 0, 64 | 128); // guest 1001 -> host 2001: refused
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    r(3, 0, 0, 0, 0, 0, 0, 0, 0);
    r(4, 1, 4, 0, 0, 0, 0, 0, 0);        // client 1 gives up its LISTEN
    r(5, 0, 0, 0, 0, 0, 0, 0, 0);
    s[2] = (fuzz_seed){seed3, at};
    *n = 3;
    return s;
}
