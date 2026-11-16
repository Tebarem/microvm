// SPDX-License-Identifier: MIT
// virtio-mmio transport and split virtqueues (see virtio.h for the rules).
#include "virtio.h"

#include <stdio.h>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
static void relax(void) { SwitchToThread(); }
#else
#  include <sched.h>
static void relax(void) { sched_yield(); }
#endif

// Register offsets (virtio 1.2, 4.2.2).
enum : uint32_t {
    R_MAGIC = 0x000, R_VERSION = 0x004, R_DEVICE_ID = 0x008, R_VENDOR_ID = 0x00c,
    R_DEV_FEATURES = 0x010, R_DEV_FEATURES_SEL = 0x014, R_DRV_FEATURES = 0x020,
    R_DRV_FEATURES_SEL = 0x024, R_QUEUE_SEL = 0x030, R_QUEUE_NUM_MAX = 0x034, R_QUEUE_NUM = 0x038,
    R_QUEUE_READY = 0x044, R_QUEUE_NOTIFY = VIRTIO_MMIO_QUEUE_NOTIFY, R_INT_STATUS = 0x060, R_INT_ACK = VIRTIO_MMIO_INT_ACK,
    R_STATUS = 0x070, R_QUEUE_DESC_LO = 0x080, R_QUEUE_DESC_HI = 0x084, R_QUEUE_AVAIL_LO = 0x090,
    R_QUEUE_AVAIL_HI = 0x094, R_QUEUE_USED_LO = 0x0a0, R_QUEUE_USED_HI = 0x0a4,
    R_CONFIG_GEN = 0x0fc, R_CONFIG = 0x100,
};
constexpr uint32_t VIRTIO_MAGIC = 0x74726976; // "virt"
constexpr uint32_t VENDOR_ID = 0x004d564d;    // "MVM"
enum : uint16_t { VRING_DESC_F_NEXT = 1, VRING_DESC_F_WRITE = 2, VRING_DESC_F_INDIRECT = 4 };
constexpr uint16_t VRING_AVAIL_F_NO_INTERRUPT = 1;
enum : uint32_t { VIRTIO_INT_USED = 1, VIRTIO_INT_CONFIG = 2 };

void virtio_lock(virtio_dev *d)
{
    for (unsigned spins = 0; atomic_flag_test_and_set_explicit(&d->lock, memory_order_acquire);)
        if (++spins > 64) // the holder may be in a syscall: don't burn the core
            relax();
}

void virtio_unlock(virtio_dev *d) { atomic_flag_clear_explicit(&d->lock, memory_order_release); }

void virtio_dev_init(virtio_dev *d, const virtio_ops *ops, void *priv, const guest_mem *mem,
                     ioapic *irq, unsigned pin)
{
    memset(d, 0, sizeof *d);
    atomic_flag_clear(&d->lock);
    atomic_init(&d->isr, 0);
    d->ops = ops;
    d->priv = priv;
    d->mem = mem;
    d->irq = irq;
    d->pin = pin;
}

int virtio_cmdline(char *buf, size_t len, int i)
{
    return snprintf(buf, len, "virtio_mmio.device=4K@0x%llx:%u",
                    (unsigned long long)(VIRTIO_MMIO_BASE + (uint64_t)i * VIRTIO_MMIO_SIZE),
                    VIRTIO_IRQ_FIRST + (unsigned)i);
}

constexpr unsigned ISR_RAISED_SHIFT = 16;
constexpr uint32_t ISR_BITS = (1u << ISR_RAISED_SHIFT) - 1;

// The driver acknowledges the interrupt bits it read. On KVM that write
// doesn't exit: it is applied when the vCPU next exits, which is always
// before the driver reads the status again, but may be after we raised the
// same bit for new work. Clearing it then would lose that interrupt (the
// driver would read 0 and skip the queues), so a bit raised since the last
// read survives the acknowledgement. At worst the driver looks at its
// queues once more than it had to.
static void ack(virtio_dev *d, uint32_t w)
{
    unsigned old = atomic_load(&d->isr);
    while (!atomic_compare_exchange_weak(&d->isr, &old,
                                         old & ~(w & ISR_BITS & ~(old >> ISR_RAISED_SHIFT))))
        ;
}

static void raise(virtio_dev *d, uint32_t bit)
{
    atomic_fetch_or(&d->isr, bit | bit << ISR_RAISED_SHIFT);
    d->n_irq++;
    ioapic_raise(d->irq, d->pin);
}

void virtio_fail(virtio_dev *d, const char *why)
{
    if (d->broken)
        return;
    d->broken = true;
    d->status |= VIRTIO_STATUS_NEEDS_RESET;
    if (d->n_fail++ < 4) // the guest decides how often: don't let it fill the log
        mvm_log("virtio device %u: %s; stopped until the driver resets it", d->ops->device_id, why);
    raise(d, VIRTIO_INT_CONFIG);
}

static void reset(virtio_dev *d)
{
    d->status = 0;
    d->dev_feat_sel = d->drv_feat_sel = d->queue_sel = 0;
    d->driver_features = 0;
    atomic_store(&d->isr, 0);
    memset(d->q, 0, sizeof d->q);
    d->broken = false;
    if (d->ops->reset)
        d->ops->reset(d);
}

bool virtq_usable(const virtio_dev *d, uint16_t q)
{
    return q < d->ops->nqueues && !d->broken && (d->status & VIRTIO_STATUS_DRIVER_OK) &&
           d->q[q].ready;
}

static uint16_t queue_max(const virtio_dev *d, const virtq *vq)
{
    const uint16_t m = d->ops->queue_max[vq - d->q];
    return m ? m : VIRTQ_MAX_SIZE;
}

// QueueReady = 1: check the driver's layout and take host views of it.
static void queue_ready(virtio_dev *d, virtq *vq)
{
    const uint16_t n = vq->num;
    if (n == 0 || n > queue_max(d, vq) || (n & (n - 1))) {
        virtio_fail(d, "bad queue size");
        return;
    }
    if ((vq->desc_gpa & 15) || (vq->avail_gpa & 1) || (vq->used_gpa & 3)) {
        virtio_fail(d, "misaligned ring");
        return;
    }
    vq->desc = guest_slice(d->mem, vq->desc_gpa, 16ull * n);
    vq->avail = guest_slice(d->mem, vq->avail_gpa, 6 + 2ull * n);
    vq->used = guest_slice(d->mem, vq->used_gpa, 6 + 8ull * n);
    if (!vq->desc || !vq->avail || !vq->used) {
        virtio_fail(d, "ring outside guest RAM");
        return;
    }
    vq->last_avail = 0;
    vq->used_idx = 0;
    vq->ready = true;
}

static uint16_t load16_acq(const uint8_t *p) { return __atomic_load_n((const uint16_t *)p, __ATOMIC_ACQUIRE); }

int virtq_pop(virtio_dev *d, uint16_t q, virtq_chain *c)
{
    if (!virtq_usable(d, q))
        return 0;
    virtq *vq = &d->q[q];
    const uint16_t avail_idx = load16_acq(vq->avail + 2);
    if (avail_idx == vq->last_avail)
        return 0;
    if ((uint16_t)(avail_idx - vq->last_avail) > vq->num) {
        virtio_fail(d, "available index ran past the ring");
        return -1;
    }
    const uint16_t head = get_le16(vq->avail + 4 + 2u * (vq->last_avail % vq->num));
    if (head >= vq->num) {
        virtio_fail(d, "descriptor index out of range");
        return -1;
    }
    c->head = head;
    c->nr = c->nw = 0;
    c->rlen = c->wlen = 0;
    uint16_t idx = head;
    const unsigned max_segs = d->ops->max_segs && d->ops->max_segs <= VIRTQ_MAX_SEGS ? d->ops->max_segs
                                                                                     : VIRTQ_DEFAULT_SEGS;
    for (unsigned count = 0;; count++) {
        if (count >= vq->num || count >= max_segs) {
            virtio_fail(d, "descriptor chain too long, or a loop");
            return -1;
        }
        uint8_t desc[16];
        memcpy(desc, vq->desc + 16u * idx, sizeof desc); // once: this copy is what we use
        const uint64_t addr = get_le64(desc);
        const uint32_t len = get_le32(desc + 8);
        const uint16_t flags = get_le16(desc + 12), next = get_le16(desc + 14);
        if (flags & VRING_DESC_F_INDIRECT) {
            virtio_fail(d, "indirect descriptor (not negotiated)");
            return -1;
        }
        if (len) {
            uint8_t *p = guest_slice(d->mem, addr, len);
            if (!p) {
                virtio_fail(d, "buffer outside guest RAM");
                return -1;
            }
            if (flags & VRING_DESC_F_WRITE) {
                c->w[c->nw++] = (virtq_seg){p, len};
                if (ckd_add(&c->wlen, c->wlen, len)) {
                    virtio_fail(d, "chain too large");
                    return -1;
                }
            } else {
                if (c->nw) {
                    virtio_fail(d, "readable descriptor after a writable one");
                    return -1;
                }
                c->r[c->nr++] = (virtq_seg){p, len};
                if (ckd_add(&c->rlen, c->rlen, len)) {
                    virtio_fail(d, "chain too large");
                    return -1;
                }
            }
        }
        if (!(flags & VRING_DESC_F_NEXT))
            break;
        if (next >= vq->num) {
            virtio_fail(d, "next descriptor out of range");
            return -1;
        }
        idx = next;
    }
    vq->last_avail++;
    return 1;
}

void virtq_unpop(virtio_dev *d, uint16_t q) { d->q[q].last_avail--; }

void virtq_push_n(virtio_dev *d, uint16_t q, const uint16_t *head, const uint32_t *written, unsigned n)
{
    virtq *vq = &d->q[q];
    if (!vq->ready)
        return;
    for (unsigned i = 0; i < n; i++) {
        uint8_t *e = vq->used + 4 + 8u * (vq->used_idx % vq->num);
        put_le32(e, head[i]);
        put_le32(e + 4, written[i]);
        vq->used_idx++;
    }
    __atomic_store_n((uint16_t *)(vq->used + 2), vq->used_idx, __ATOMIC_RELEASE);
}

void virtq_push(virtio_dev *d, uint16_t q, uint16_t head, uint32_t written)
{
    virtq_push_n(d, q, &head, &written, 1);
}

bool virtq_notify_driver(virtio_dev *d, uint16_t q)
{
    if (!virtq_usable(d, q))
        return false;
    // Our used index must be visible before we read the driver's flags,
    // or a driver that just turned interrupts back on could miss this one.
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    if (load16_acq(d->q[q].avail) & VRING_AVAIL_F_NO_INTERRUPT)
        return false;
    raise(d, VIRTIO_INT_USED);
    return true;
}

size_t virtq_gather(const virtq_chain *c, size_t off, void *dst, size_t len)
{
    size_t done = 0;
    for (unsigned i = 0; i < c->nr && done < len; i++) {
        if (off >= c->r[i].len) {
            off -= c->r[i].len;
            continue;
        }
        size_t n = c->r[i].len - off;
        if (n > len - done)
            n = len - done;
        memcpy((uint8_t *)dst + done, c->r[i].p + off, n);
        done += n;
        off = 0;
    }
    return done;
}

size_t virtq_scatter(const virtq_chain *c, size_t off, const void *src, size_t len)
{
    size_t done = 0;
    for (unsigned i = 0; i < c->nw && done < len; i++) {
        if (off >= c->w[i].len) {
            off -= c->w[i].len;
            continue;
        }
        size_t n = c->w[i].len - off;
        if (n > len - done)
            n = len - done;
        memcpy(c->w[i].p + off, (const uint8_t *)src + done, n);
        done += n;
        off = 0;
    }
    return done;
}

static uint64_t features(const virtio_dev *d) { return d->ops->features | VIRTIO_F_VERSION_1; }

static void write_status(virtio_dev *d, uint32_t val)
{
    if (val == 0) {
        reset(d);
        return;
    }
    const uint32_t was = d->status;
    if ((val & VIRTIO_STATUS_FEATURES_OK) && !(was & VIRTIO_STATUS_FEATURES_OK)) {
        // Only what we offered, and the modern interface.
        if ((d->driver_features & ~features(d)) || !(d->driver_features & VIRTIO_F_VERSION_1))
            val &= ~VIRTIO_STATUS_FEATURES_OK;
    }
    d->status = val | (was & VIRTIO_STATUS_NEEDS_RESET);
    if ((val & VIRTIO_STATUS_DRIVER_OK) && !(was & VIRTIO_STATUS_DRIVER_OK) && d->ops->activate)
        d->ops->activate(d);
}

void virtio_save(virtio_dev *d, snap_w *w)
{
    sw_u32(w, d->ops->device_id);
    sw_u32(w, d->status);
    sw_u32(w, d->dev_feat_sel);
    sw_u32(w, d->drv_feat_sel);
    sw_u32(w, d->queue_sel);
    sw_u64(w, d->driver_features);
    sw_u32(w, atomic_load(&d->isr));
    sw_u8(w, d->broken);
    sw_u8(w, (uint8_t)d->ops->nqueues);
    for (int i = 0; i < d->ops->nqueues; i++) {
        const virtq *q = &d->q[i];
        sw_u16(w, q->num);
        sw_u8(w, q->ready);
        sw_u64(w, q->desc_gpa);
        sw_u64(w, q->avail_gpa);
        sw_u64(w, q->used_gpa);
        sw_u16(w, q->last_avail);
        sw_u16(w, q->used_idx);
    }
    if (d->ops->save)
        d->ops->save(d, w);
}

bool virtio_load(virtio_dev *d, snap_r *r)
{
    virtio_lock(d);
    bool ok = sr_u32(r) == d->ops->device_id;
    d->status = sr_u32(r);
    d->dev_feat_sel = sr_u32(r);
    d->drv_feat_sel = sr_u32(r);
    d->queue_sel = sr_u32(r);
    d->driver_features = sr_u64(r);
    const uint32_t isr = sr_u32(r);
    atomic_store(&d->isr, isr & (VIRTIO_INT_USED | VIRTIO_INT_CONFIG));
    d->broken = sr_bool(r);
    ok &= sr_u8(r) == d->ops->nqueues;
    // Features as write_status() would have taken them; a broken device
    // must say so.
    if ((d->status & VIRTIO_STATUS_FEATURES_OK) &&
        ((d->driver_features & ~features(d)) || !(d->driver_features & VIRTIO_F_VERSION_1)))
        ok = false;
    if (d->broken != !!(d->status & VIRTIO_STATUS_NEEDS_RESET))
        ok = false;
    for (int i = 0; ok && i < d->ops->nqueues; i++) {
        virtq *q = &d->q[i];
        q->num = sr_u16(r);
        const bool ready = sr_bool(r);
        q->desc_gpa = sr_u64(r);
        q->avail_gpa = sr_u64(r);
        q->used_gpa = sr_u64(r);
        const uint16_t last_avail = sr_u16(r), used_idx = sr_u16(r);
        q->ready = false;
        if (ready && !d->broken) {
            // The same checks as the driver's QUEUE_READY write.
            queue_ready(d, q);
            if (!q->ready)
                ok = false;
            q->last_avail = last_avail;
            q->used_idx = used_idx;
        }
    }
    if (ok && d->ops->load)
        ok = d->ops->load(d, r);
    ok &= !r->bad;
    if (!ok) // leave it as a reset device rather than half loaded
        reset(d);
    virtio_unlock(d);
    return ok;
}

static void set_half(uint64_t *v, bool hi, uint32_t val)
{
    *v = hi ? (*v & 0xffffffffull) | ((uint64_t)val << 32) : (*v & ~0xffffffffull) | val;
}

void virtio_mmio_access(virtio_dev *d, uint64_t off, uint8_t size, bool write, uint64_t *val)
{
    virtio_lock(d);
    if (off >= R_CONFIG) {
        if (!write) {
            *val = 0;
            if (d->ops->config_read)
                d->ops->config_read(d, (uint32_t)(off - R_CONFIG), size, val);
        } // config space is read-only for every device we have
        virtio_unlock(d);
        return;
    }
    if (size != 4) {
        if (!write)
            *val = 0;
        virtio_unlock(d);
        return;
    }
    const uint32_t w = (uint32_t)*val;
    virtq *vq = d->queue_sel < (uint32_t)d->ops->nqueues ? &d->q[d->queue_sel] : nullptr;
    int kick = -1;
    if (!write) {
        uint32_t r = 0;
        switch ((uint32_t)off) {
        case R_MAGIC: r = VIRTIO_MAGIC; break;
        case R_VERSION: r = 2; break;
        case R_DEVICE_ID: r = d->ops->device_id; break;
        case R_VENDOR_ID: r = VENDOR_ID; break;
        case R_DEV_FEATURES:
            r = d->dev_feat_sel == 0 ? (uint32_t)features(d)
                : d->dev_feat_sel == 1 ? (uint32_t)(features(d) >> 32) : 0;
            break;
        case R_QUEUE_NUM_MAX: r = vq ? queue_max(d, vq) : 0; break;
        case R_QUEUE_READY: r = vq && vq->ready; break;
        case R_INT_STATUS: r = atomic_fetch_and(&d->isr, ISR_BITS) & ISR_BITS; break;
        case R_STATUS: r = d->status; break;
        case R_CONFIG_GEN: r = 0; break;
        default: break;
        }
        *val = r;
    } else {
        switch ((uint32_t)off) {
        case R_DEV_FEATURES_SEL: d->dev_feat_sel = w; break;
        case R_DRV_FEATURES_SEL: d->drv_feat_sel = w; break;
        case R_DRV_FEATURES:
            if (!(d->status & VIRTIO_STATUS_FEATURES_OK) && d->drv_feat_sel < 2)
                set_half(&d->driver_features, d->drv_feat_sel == 1, w);
            break;
        case R_QUEUE_SEL: d->queue_sel = w; break;
        case R_QUEUE_NUM:
            if (vq && !vq->ready)
                vq->num = (uint16_t)(w > 0xffff ? 0 : w); // checked when made ready
            break;
        case R_QUEUE_READY:
            if (vq && w == 1 && !vq->ready && !d->broken)
                queue_ready(d, vq);
            else if (vq && w == 0)
                vq->ready = false;
            break;
        case R_QUEUE_DESC_LO: case R_QUEUE_DESC_HI:
            if (vq && !vq->ready)
                set_half(&vq->desc_gpa, off == R_QUEUE_DESC_HI, w);
            break;
        case R_QUEUE_AVAIL_LO: case R_QUEUE_AVAIL_HI:
            if (vq && !vq->ready)
                set_half(&vq->avail_gpa, off == R_QUEUE_AVAIL_HI, w);
            break;
        case R_QUEUE_USED_LO: case R_QUEUE_USED_HI:
            if (vq && !vq->ready)
                set_half(&vq->used_gpa, off == R_QUEUE_USED_HI, w);
            break;
        case R_QUEUE_NOTIFY:
            if (w < d->ops->nqueues)
                kick = (int)w;
            break;
        case R_INT_ACK: ack(d, w); break;
        case R_STATUS: write_status(d, w); break;
        default: break;
        }
    }
    if (kick >= 0 && virtq_usable(d, (uint16_t)kick)) {
        d->n_notify++;
        d->ops->notify(d, (uint16_t)kick);
    }
    virtio_unlock(d);
}
