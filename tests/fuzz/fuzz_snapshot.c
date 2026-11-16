// SPDX-License-Identifier: MIT
// Fuzz restoring a snapshot: the header, and the device state a restore
// loads before the guest runs again (I/O APIC, UART, CMOS, a virtio device
// with its queues). A snapshot file is input like any other: whatever it
// says, the loaded devices must be as safe as ones a guest programmed.
//
// Input: u16 s, s bytes of state section; u16 n, n bytes of guest memory
// (at most 8 KiB, at address 0), which are also a diff's runs; the rest is
// the header page (zero-padded).
// The state comes first so that the mutator's inserts and deletes in the
// larger parts don't shift it.
// Once loaded, the test device's queues are drained like fuzz_virtq's,
// with the guest rewriting a byte of its rings between passes.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dev/devices.h"
#include "dev/virtio.h"
#include "fuzz.h"
#include "os.h"
#include "snapshot.h"

static guest_mem mem;

static void no_msi(void *ctx, uint64_t addr, uint32_t data) { (void)ctx, (void)addr, (void)data; }

static struct {
    uint32_t counter;
    bool flag;
} tstate;

static void tsave(virtio_dev *d, snap_w *w)
{
    (void)d;
    sw_u32(w, tstate.counter);
    sw_u8(w, tstate.flag);
}

static bool tload(virtio_dev *d, snap_r *r)
{
    (void)d;
    tstate.counter = sr_u32(r);
    tstate.flag = sr_bool(r);
    return tstate.counter < 1000;
}

static void drain(virtio_dev *d, uint16_t q)
{
    for (int budget = 0; budget < 2 * VIRTQ_MAX_SIZE; budget++) {
        virtq_chain c;
        const int r = virtq_pop(d, q, &c);
        FUZZ_ASSERT(r >= -1 && r <= 1);
        if (r != 1)
            break;
        FUZZ_ASSERT(c.head < d->q[q].num && c.nr + c.nw <= VIRTQ_MAX_SEGS);
        for (unsigned i = 0; i < c.nr + c.nw; i++) {
            const virtq_seg *s = i < c.nr ? &c.r[i] : &c.w[i - c.nr];
            FUZZ_ASSERT(s->p >= mem.base && (uint64_t)(mem.base + mem.size - s->p) >= s->len);
        }
        static uint8_t scratch[1 << 16];
        FUZZ_ASSERT(virtq_scatter(&c, 0, scratch, sizeof scratch) <= c.wlen);
        virtq_push(d, q, c.head, c.wlen);
    }
    (void)virtq_notify_driver(d, q);
}

static void notify(virtio_dev *d, uint16_t q) { drain(d, q); }

static const virtio_ops OPS = {.device_id = 19, .features = 1ull << 2, .nqueues = 2, .notify = notify,
                               .save = tsave, .load = tload};

constexpr uint64_t MEM_SIZE = 32 << 10;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!mem.base) {
        mem = (guest_mem){.base = os_mem_reserve(MEM_SIZE), .size = MEM_SIZE};
        FUZZ_ASSERT(mem.base);
    }
    if (size < 4)
        return 0;
    size_t sl = (size_t)(data[0] | data[1] << 8);
    if (sl > size - 4)
        sl = size - 4;
    const uint8_t *state = data + 2;
    size_t n = (size_t)(data[2 + sl] | data[3 + sl] << 8) % 8193;
    if (n > size - 4 - sl)
        n = size - 4 - sl;
    const uint8_t *gmem = data + 4 + sl;
    const uint8_t *hdr = gmem + n;
    const size_t hlen = size - 4 - sl - n;

    // 1. the header
    static uint8_t page[4096];
    memset(page, 0, sizeof page);
    memcpy(page, hdr, hlen < sizeof page ? hlen : sizeof page);
    snap_header h;
    const uint64_t file_size = (uint64_t)size << 20;
    if (snap_header_decode(page, file_size, &h) == 0) {
        uint64_t end;
        FUZZ_ASSERT(h.mem_off % SNAP_MEM_ALIGN == 0 && h.mem_off >= SNAP_STATE_OFF + h.state_len);
        FUZZ_ASSERT(h.state_len <= SNAP_STATE_MAX && h.ndev <= SNAP_MAX_DEVICES);
        FUZZ_ASSERT(h.ncpus >= 1 && h.ncpus <= MVM_MAX_VCPUS); // vm_restore loads this many blobs
        FUZZ_ASSERT(h.mem_size >= 2 * MiB && h.mem_size % MiB == 0);
        if (!h.diff)
            FUZZ_ASSERT(!ckd_add(&end, h.mem_off, h.mem_size) && end <= file_size);
        else {
            FUZZ_ASSERT((h.base_id[0] | h.base_id[1]) && h.nruns && h.nruns <= SNAP_MAX_RUNS);
            FUZZ_ASSERT(h.runs_off % 8 == 0 && h.runs_off >= SNAP_STATE_OFF + h.state_len);
            FUZZ_ASSERT(!ckd_add(&end, h.runs_off, 8ull * h.nruns) && end <= h.mem_off && h.mem_off <= file_size);
            // Its runs: whatever the decoder takes is safe to map.
            static snap_run runs[SNAP_MAX_RUNS];
            if (8ull * h.nruns <= n && snap_runs_decode(gmem, &h, file_size, runs) == 0) {
                uint64_t next = 0;
                for (uint32_t i = 0; i < h.nruns; i++) {
                    const uint64_t first = runs[i].first, count = runs[i].count;
                    FUZZ_ASSERT(count && first >= next && first + count <= h.mem_size / 4096);
                    FUZZ_ASSERT(h.mem_off + (first + count) * 4096 <= file_size);
                    next = first + count + 1;
                }
            }
        }
    }

    // 2. guest memory, then the state
    memset(mem.base, 0, MEM_SIZE);
    memcpy(mem.base, gmem, n);
    snap_r r = {.p = state, .len = sl};

    static ioapic a;
    ioapic_init(&a, 1, no_msi, nullptr);
    static uart8250 u;
    uart_init(&u);
    static cmos_rtc c;
    memset(&c, 0, sizeof c);
    static virtio_dev d;
    virtio_dev_init(&d, &OPS, nullptr, &mem, &a, 5);
    ioapic_load(&a, &r);
    uart_load(&u, &r);
    cmos_load(&c, &r);
    for (int i = 0; i < IOAPIC_PINS; i++)
        FUZZ_ASSERT(!(a.redir[i] & ((1ull << 12) | (1ull << 14)))); // never set from outside
    FUZZ_ASSERT(c.index < 128 && !c.have_time);
    (void)cmos_read(&c, 0x71);

    const bool ok = virtio_load(&d, &r);
    if (!ok) {
        // Refused: left as a reset device.
        FUZZ_ASSERT(d.status == 0 && !d.broken);
        for (int q = 0; q < OPS.nqueues; q++)
            FUZZ_ASSERT(!d.q[q].ready);
        return 0;
    }
    for (int q = 0; q < OPS.nqueues; q++) {
        const virtq *vq = &d.q[q];
        if (!vq->ready)
            continue;
        FUZZ_ASSERT(!d.broken);
        FUZZ_ASSERT(vq->num && vq->num <= VIRTQ_MAX_SIZE && !(vq->num & (vq->num - 1)));
        FUZZ_ASSERT(vq->desc && vq->desc + 16u * vq->num <= mem.base + MEM_SIZE);
        FUZZ_ASSERT(vq->avail && vq->avail + 6 + 2u * vq->num <= mem.base + MEM_SIZE);
        FUZZ_ASSERT(vq->used && vq->used + 6 + 8u * vq->num <= mem.base + MEM_SIZE);
    }
    // The restored guest runs on: its rings change under us.
    for (int pass = 0; pass < 4; pass++) {
        virtio_lock(&d);
        drain(&d, 0);
        drain(&d, 1);
        virtio_unlock(&d);
        if (n)
            mem.base[(pass * 977u) % n] ^= (uint8_t)(0x5a + pass);
    }
    uint64_t isr = 0;
    virtio_mmio_access(&d, 0x060, 4, false, &isr);
    FUZZ_ASSERT(isr <= 3);
    return 0;
}

// Seed: a device the way Linux leaves it (two ready queues, one chain
// offered), saved with the real save functions.
static uint8_t seed_buf[2 + 1024 + 2 + 0x200 + 4096];

static void vw(virtio_dev *d, uint64_t off, uint32_t v)
{
    uint64_t x = v;
    virtio_mmio_access(d, off, 4, true, &x);
}

const fuzz_seed *fuzz_seeds(size_t *n)
{
    static guest_mem m;
    m = (guest_mem){.base = os_mem_reserve(MEM_SIZE), .size = MEM_SIZE};
    FUZZ_ASSERT(m.base);
    // Header: a 64 MiB VM with one device.
    snap_header h = {.mem_size = 64 * MiB, .mem_off = SNAP_MEM_ALIGN, .state_len = 512, .ndev = 1,
                     .dev_id = {19}};
    static uint8_t g[0x200];
    // Rings: queue 0 desc 0x000 avail 0x080 used 0x0c0 (8 entries);
    // queue 1 desc 0x100 avail 0x180 used 0x1c0.
    put_le64(g + 0, 0x1000), put_le32(g + 8, 64), put_le16(g + 12, 2);
    put_le16(g + 0x80 + 2, 1);
    memcpy(m.base, g, 0x200);
    static ioapic a;
    ioapic_init(&a, 1, no_msi, nullptr);
    static uart8250 u;
    uart_init(&u);
    static cmos_rtc c;
    static virtio_dev d;
    virtio_dev_init(&d, &OPS, nullptr, &m, &a, 5);
    vw(&d, 0x070, 0);
    vw(&d, 0x070, 3);
    vw(&d, 0x024, 1);
    vw(&d, 0x020, 1);
    vw(&d, 0x070, 11);
    for (uint32_t q = 0; q < 2; q++) {
        vw(&d, 0x030, q);
        vw(&d, 0x038, 8);
        vw(&d, 0x080, 0x100 * q);
        vw(&d, 0x090, 0x100 * q + 0x80);
        vw(&d, 0x0a0, 0x100 * q + 0xc0);
        vw(&d, 0x044, 1);
    }
    vw(&d, 0x070, 15);
    snap_w w = {.p = seed_buf + 2, .cap = 1024};
    ioapic_save(&a, &w);
    uart_save(&u, &w);
    cmos_save(&c, &w);
    virtio_lock(&d);
    virtio_save(&d, &w);
    virtio_unlock(&d);
    FUZZ_ASSERT(!w.bad);
    put_le16(seed_buf, (uint16_t)w.len);
    uint8_t *at = seed_buf + 2 + w.len;
    put_le16(at, 0x200);
    memcpy(at + 2, g, 0x200);
    snap_header_encode(&h, at + 2 + 0x200);
    static fuzz_seed s[2];
    s[0] = (fuzz_seed){seed_buf, 2 + w.len + 2 + 0x200 + 4096};
    // The same as a diff: runs at the start of the memory bytes.
    static uint8_t diff_buf[sizeof seed_buf];
    memcpy(diff_buf, seed_buf, s[0].len);
    uint8_t *dm = diff_buf + 2 + w.len + 2;
    static const snap_run runs[3] = {{0, 2}, {5, 1}, {100, 7}};
    snap_runs_encode(runs, 3, dm);
    snap_header dh = h;
    dh.diff = true, dh.base_id[0] = 1, dh.nruns = 3, dh.runs_off = SNAP_STATE_OFF + 512;
    snap_header_encode(&dh, dm + 0x200);
    s[1] = (fuzz_seed){diff_buf, s[0].len};
    *n = 2;
    return s;
}
