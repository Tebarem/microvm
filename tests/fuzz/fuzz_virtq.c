// SPDX-License-Identifier: MIT
// Fuzz the virtio-mmio transport and split-virtqueue parser: the guest
// controls every register write and every byte of the rings, and can
// rewrite the rings between (or during) our reads.
//
// Input: u16 n, then n bytes (at most 8 KiB) placed at guest address 0
// (rings and descriptors live there), then 5-byte records {op, u32 value}:
//   op < 0x40        write `value` to register REGS[op % NREG]
//   0x40 <= op < 0x80 read register REGS[op % NREG]
//   0x80 <= op < 0xc0 the guest writes guest memory: byte (value >> 16) at
//                    offset value & 0x7fff
//   op >= 0xc0       the device's I/O thread pops and pushes every queue
// The test device takes every chain it is given, checks what virtq_pop
// returned against guest memory's bounds, fills the writable part, returns it.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dev/virtio.h"
#include "fuzz.h"
#include "os.h"

static guest_mem mem;
static uint64_t n_msi;

static void count_msi(void *ctx, uint64_t addr, uint32_t data)
{
    (void)ctx, (void)addr, (void)data;
    n_msi++;
}

static void check_chain(const virtio_dev *d, uint16_t q, const virtq_chain *c)
{
    FUZZ_ASSERT(c->nr <= VIRTQ_MAX_SEGS && c->nw <= VIRTQ_MAX_SEGS);
    FUZZ_ASSERT(c->nr + c->nw <= VIRTQ_MAX_SEGS);
    uint64_t rl = 0, wl = 0;
    for (unsigned i = 0; i < c->nr + c->nw; i++) {
        const virtq_seg *s = i < c->nr ? &c->r[i] : &c->w[i - c->nr];
        FUZZ_ASSERT(s->len > 0);
        FUZZ_ASSERT(s->p >= d->mem->base && s->p <= d->mem->base + d->mem->size);
        FUZZ_ASSERT((uint64_t)(d->mem->base + d->mem->size - s->p) >= s->len);
        *(i < c->nr ? &rl : &wl) += s->len;
    }
    FUZZ_ASSERT(rl == c->rlen && wl == c->wlen);
    FUZZ_ASSERT(c->head < d->q[q].num);
}

static void drain(virtio_dev *d, uint16_t q)
{
    for (int budget = 0; budget < 2 * VIRTQ_MAX_SIZE; budget++) {
        virtq_chain c;
        const bool was_broken = d->broken;
        const int r = virtq_pop(d, q, &c);
        FUZZ_ASSERT(r >= -1 && r <= 1);
        if (r != 1) {
            FUZZ_ASSERT(r == 0 || d->broken);
            break;
        }
        FUZZ_ASSERT(!was_broken);
        check_chain(d, q, &c);
        static uint8_t scratch[1 << 16];
        FUZZ_ASSERT(virtq_gather(&c, 0, scratch, sizeof scratch) <= c.rlen);
        FUZZ_ASSERT(virtq_scatter(&c, 3, scratch, sizeof scratch) <= c.wlen);
        // Now and then hand one back, as a device with nothing to say does.
        if ((c.head & 7) == 7) {
            virtq_unpop(d, q);
            break;
        }
        virtq_push(d, q, c.head, c.wlen);
    }
    virtq_notify_driver(d, q);
}

static void notify(virtio_dev *d, uint16_t q) { drain(d, q); }

static void config_read(virtio_dev *d, uint32_t off, uint8_t size, uint64_t *val)
{
    (void)d;
    static const uint8_t cfg[8] = {3};
    if (off < sizeof cfg && size <= sizeof cfg - off)
        memcpy(val, cfg + off, size);
}

static const virtio_ops OPS = {.device_id = 19, .nqueues = 2, .config_read = config_read, .notify = notify};

static const uint16_t REGS[] = {
    0x000, 0x004, 0x008, 0x010, 0x014, 0x020, 0x024, 0x030, 0x034, 0x038, 0x044, 0x050,
    0x060, 0x064, 0x070, 0x080, 0x084, 0x090, 0x094, 0x0a0, 0x0a4, 0x0fc, 0x100, 0x104,
};
constexpr unsigned NREG = sizeof REGS / sizeof REGS[0];
constexpr uint64_t MEM_SIZE = 32 << 10;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!mem.base) {
        mem = (guest_mem){.base = os_mem_reserve(MEM_SIZE), .size = MEM_SIZE};
        FUZZ_ASSERT(mem.base);
    }
    memset(mem.base, 0, MEM_SIZE);
    if (size < 2)
        return 0;
    size_t n = (size_t)(data[0] | data[1] << 8) % 8193;
    if (n > size - 2)
        n = size - 2;
    memcpy(mem.base, data + 2, n);
    static ioapic a;
    ioapic_init(&a, 1, count_msi, nullptr);
    uint64_t rte = 0x30; // pin 5: vector 0x30, unmasked
    uint64_t x = 0x10 + 2 * 5;
    ioapic_mmio(&a, 0x00, 4, true, &x);
    ioapic_mmio(&a, 0x10, 4, true, &rte);
    static virtio_dev d;
    virtio_dev_init(&d, &OPS, nullptr, &mem, &a, 5);

    for (size_t i = 2 + n; i + 5 <= size; i += 5) {
        const uint8_t op = data[i];
        const uint32_t v = (uint32_t)data[i + 1] | (uint32_t)data[i + 2] << 8 |
                           (uint32_t)data[i + 3] << 16 | (uint32_t)data[i + 4] << 24;
        if (op < 0x80) {
            uint64_t val = v;
            const uint16_t off = REGS[op % NREG];
            virtio_mmio_access(&d, off, op & 0x20 ? 2 : 4, op < 0x40, &val);
            if (op >= 0x40 && !(op & 0x20) && off < 0x100)
                FUZZ_ASSERT(val <= 0xffffffffu);
        } else if (op < 0xc0) {
            mem.base[v & 0x7fff] = (uint8_t)(v >> 16);
        } else {
            virtio_lock(&d);
            drain(&d, 0);
            drain(&d, 1);
            virtio_unlock(&d);
        }
        // What the transport holds stays sane whatever the guest wrote.
        for (int q = 0; q < OPS.nqueues; q++) {
            const virtq *vq = &d.q[q];
            if (!vq->ready)
                continue;
            FUZZ_ASSERT(vq->num && vq->num <= VIRTQ_MAX_SIZE && !(vq->num & (vq->num - 1)));
            FUZZ_ASSERT(vq->desc && vq->desc + 16u * vq->num <= mem.base + MEM_SIZE);
            FUZZ_ASSERT(vq->avail && vq->avail + 6 + 2u * vq->num <= mem.base + MEM_SIZE);
            FUZZ_ASSERT(vq->used && vq->used + 6 + 8u * vq->num <= mem.base + MEM_SIZE);
        }
    }
    return 0;
}

// A driver bringing the device up the way Linux does, with one chain in
// queue 0 (two readable segments and a writable one), then a kick.
static uint8_t seed_buf[2 + 0x200 + 64 * 5];

static size_t rec(size_t at, uint8_t op, uint32_t v)
{
    seed_buf[at] = op;
    put_le32(seed_buf + at + 1, v);
    return at + 5;
}

static uint8_t reg(uint16_t off)
{
    for (unsigned i = 0; i < NREG; i++)
        if (REGS[i] == off)
            return (uint8_t)i;
    return 0;
}

const fuzz_seed *fuzz_seeds(size_t *n)
{
    // Ring memory: desc at 0x000 (8 entries), avail at 0x080, used at 0x0c0.
    uint8_t *m = seed_buf + 2;
    put_le16(seed_buf, 0x200);
    put_le64(m + 0, 0x1000), put_le32(m + 8, 44), put_le16(m + 12, 1), put_le16(m + 14, 1);
    put_le64(m + 16, 0x1100), put_le32(m + 24, 20), put_le16(m + 28, 1), put_le16(m + 30, 2);
    put_le64(m + 32, 0x2000), put_le32(m + 40, 4096), put_le16(m + 44, 2);
    put_le16(m + 0x80 + 2, 1); // avail idx 1, ring[0] = 0
    size_t at = 2 + 0x200;
    at = rec(at, reg(0x070), 0);
    at = rec(at, reg(0x070), 3);
    at = rec(at, reg(0x024), 1);
    at = rec(at, reg(0x020), 1);
    at = rec(at, reg(0x070), 11);
    at = rec(at, reg(0x030), 0);
    at = rec(at, reg(0x038), 8);
    at = rec(at, reg(0x080), 0x000);
    at = rec(at, reg(0x090), 0x080);
    at = rec(at, reg(0x0a0), 0x0c0);
    at = rec(at, reg(0x044), 1);
    at = rec(at, reg(0x070), 15);
    at = rec(at, reg(0x050), 0);
    at = rec(at, 0x40 + reg(0x060), 0);
    at = rec(at, reg(0x064), 1);
    at = rec(at, 0x80, 0x00020082); // avail idx = 2: the same head again
    at = rec(at, 0xc0, 0);
    static fuzz_seed s[1];
    s[0] = (fuzz_seed){seed_buf, at};
    *n = 1;
    return s;
}
