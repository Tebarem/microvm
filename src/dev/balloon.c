// SPDX-License-Identifier: MIT
// virtio-balloon for free page reporting (see balloon.h).
#include "balloon.h"

#include <stdlib.h>

#include "../os.h"

enum : uint16_t { Q_INFLATE, Q_DEFLATE, Q_REPORTING, NQUEUES };
constexpr uint64_t F_REPORTING = 1ull << 5; // VIRTIO_BALLOON_F_REPORTING

struct balloon {
    virtio_dev dev;
    _Atomic uint64_t discarded;
};

// The pages wholly inside [p, p + len): a range that isn't page-aligned
// gives up its partial pages, which stay as they are.
static void discard(balloon *b, const uint8_t *p, uint32_t len)
{
    const guest_mem *m = b->dev.mem;
    const uint64_t off = (uint64_t)(p - m->base); // inside guest RAM: virtq_pop checked it
    const uint64_t start = (off + 4095) & ~4095ull, end = (off + len) & ~4095ull;
    if (end <= start)
        return;
    os_mem_discard(m->base + start, end - start);
    b->discarded += end - start;
}

static void notify(virtio_dev *d, uint16_t q)
{
    balloon *b = d->priv;
    for (int budget = 0; budget < VIRTQ_MAX_SIZE; budget++) {
        virtq_chain c;
        if (virtq_pop(d, q, &c) != 1)
            break;
        // The driver reports through device-writable buffers; a readable
        // one is taken the same way.
        if (q == Q_REPORTING) {
            for (unsigned i = 0; i < c.nr; i++)
                discard(b, c.r[i].p, c.r[i].len);
            for (unsigned i = 0; i < c.nw; i++)
                discard(b, c.w[i].p, c.w[i].len);
        }
        virtq_push(d, q, c.head, 0);
    }
    (void)virtq_notify_driver(d, q);
}

// num_pages, actual, free_page_hint_cmd_id, poison_val: all 0.
static void config_read(virtio_dev *d, uint32_t off, uint8_t size, uint64_t *val)
{
    (void)d, (void)off, (void)size;
    *val = 0;
}

static const virtio_ops OPS = {
    .device_id = 5,
    .features = F_REPORTING,
    .nqueues = NQUEUES,
    // The driver sends 32 ranges per report (PAGE_REPORTING_CAPACITY) and
    // needs a queue that size; inflate and deflate take one buffer each.
    .queue_max = {16, 16, 32},
    .max_segs = 32,
    .config_read = config_read,
    .notify = notify,
};

balloon *balloon_create(const guest_mem *mem, ioapic *irq, unsigned pin)
{
    balloon *b = calloc(1, sizeof *b);
    if (!b)
        return nullptr;
    virtio_dev_init(&b->dev, &OPS, b, mem, irq, pin);
    return b;
}

virtio_dev *balloon_dev(balloon *b) { return &b->dev; }

uint64_t balloon_discarded(const balloon *b) { return b->discarded; }
