// SPDX-License-Identifier: MIT
// virtio over MMIO (virtio 1.2, section 4.2: the "modern" register layout,
// version 2), with split virtqueues.
//
// Everything a guest writes into a ring is hostile. The rules here:
// - A ring address becomes a host pointer only through guest_slice(), once,
//   when the guest marks the queue ready (sizes and alignment checked then).
// - Each descriptor is copied out of guest memory once and validated as a
//   copy (index in range, no loops, length bounds, readable before
//   writable, no indirect tables: the feature isn't offered). The guest can
//   rewrite the ring while we look; what we act on is our copy.
// - The guest's ring indices are read once per pass; a used index we
//   publish is never taken back from the guest.
// - A malformed chain stops the device (DEVICE_NEEDS_RESET), not the VMM.
#pragma once

#include <stdatomic.h>

#include "../mem.h"
#include "devices.h"

// Where virtio-mmio devices go: above guest RAM (at most 3 GiB), below the
// I/O APIC. Device i is at VIRTIO_MMIO_BASE + i * VIRTIO_MMIO_SIZE, IRQ
// VIRTIO_IRQ_FIRST + i.
constexpr uint64_t VIRTIO_MMIO_BASE = 0xd0000000;
constexpr uint64_t VIRTIO_MMIO_SIZE = 0x1000;
// The queue notify register: the driver's doorbell.
constexpr uint64_t VIRTIO_MMIO_QUEUE_NOTIFY = 0x050;
// The interrupt acknowledge register, whose writes may be applied late.
constexpr uint64_t VIRTIO_MMIO_INT_ACK = 0x064;
constexpr unsigned VIRTIO_IRQ_FIRST = 5;
constexpr int VIRTIO_MAX_DEVICES = 3; // IRQs 5-7: the I/O APIC has 8 pins
constexpr int VIRTQ_MAX = 4;          // queues per device
constexpr uint16_t VIRTQ_MAX_SIZE = 256;
// Descriptors per chain we accept: VIRTQ_DEFAULT_SEGS, or a device's
// max_segs. Linux's virtio-net uses up to MAX_SKB_FRAGS + 2 = 19 (a
// frame's 17 fragments, its linear part, and the header if it doesn't fit
// in front); free page reporting sends 32 ranges at once.
constexpr int VIRTQ_DEFAULT_SEGS = 20;
constexpr int VIRTQ_MAX_SEGS = 32; // the most any device takes

// Device status bits.
enum : uint32_t {
    VIRTIO_STATUS_ACK = 1, VIRTIO_STATUS_DRIVER = 2, VIRTIO_STATUS_DRIVER_OK = 4,
    VIRTIO_STATUS_FEATURES_OK = 8, VIRTIO_STATUS_NEEDS_RESET = 64, VIRTIO_STATUS_FAILED = 128,
};
constexpr uint64_t VIRTIO_F_VERSION_1 = 1ull << 32;

// One buffer segment of a chain, already a host pointer.
typedef struct {
    uint8_t *p;
    uint32_t len;
} virtq_seg;

// A popped chain: readable segments first, then writable ones.
typedef struct {
    uint16_t head;
    uint8_t nr, nw;
    virtq_seg r[VIRTQ_MAX_SEGS], w[VIRTQ_MAX_SEGS];
    uint32_t rlen, wlen; // total bytes
} virtq_chain;

typedef struct {
    // as programmed by the driver
    uint16_t num;
    bool ready;
    uint64_t desc_gpa, avail_gpa, used_gpa;
    // host views, set when the queue becomes ready
    uint8_t *desc, *avail, *used;
    uint16_t last_avail; // next avail entry we haven't taken
    uint16_t used_idx;   // our copy of used->idx
} virtq;

typedef struct virtio_dev virtio_dev;

typedef struct {
    uint32_t device_id;
    uint64_t features; // device feature bits; VIRTIO_F_VERSION_1 is added
    uint16_t nqueues;
    // QueueNumMax per queue (a power of 2; 0: VIRTQ_MAX_SIZE). Drivers that
    // fill a receive queue up front allocate a buffer per entry, so this is
    // guest memory spent at boot.
    uint16_t queue_max[VIRTQ_MAX];
    // Descriptors per chain, at most VIRTQ_MAX_SEGS (0: VIRTQ_DEFAULT_SEGS).
    uint8_t max_segs;
    // Device-specific config space, offset from 0x100. Reads past it give 0.
    void (*config_read)(virtio_dev *d, uint32_t off, uint8_t size, uint64_t *val);
    // The driver kicked queue q (vCPU thread, device lock held).
    void (*notify)(virtio_dev *d, uint16_t q);
    // DRIVER_OK was set (device lock held).
    void (*activate)(virtio_dev *d);
    // Snapshots: the device's own state, after the transport's (device
    // lock held). load returns false for state the device can't take.
    void (*save)(virtio_dev *d, snap_w *w);
    bool (*load)(virtio_dev *d, snap_r *r);
    // The driver reset the device (device lock held); queues are already
    // cleared.
    void (*reset)(virtio_dev *d);
} virtio_ops;

struct virtio_dev {
    const virtio_ops *ops;
    void *priv;
    const guest_mem *mem;
    ioapic *irq;
    unsigned pin;
    // Held by whichever thread touches the device: the vCPU (registers,
    // notify) or the device's I/O thread.
    atomic_flag lock;
    // transport registers
    uint32_t status, dev_feat_sel, drv_feat_sel, queue_sel;
    uint64_t driver_features;
    // Interrupt status in the low 16 bits; the high 16 say which of them
    // were raised since the driver last read it (see the INT_ACK write).
    atomic_uint isr;
    virtq q[VIRTQ_MAX];
    bool broken; // a malformed chain: nothing more is processed until reset
    uint64_t n_notify, n_irq;
    uint32_t n_fail; // not cleared by a reset: a guest can break and reset in a loop
};

void virtio_dev_init(virtio_dev *d, const virtio_ops *ops, void *priv, const guest_mem *mem,
                     ioapic *irq, unsigned pin);
void virtio_lock(virtio_dev *d);
void virtio_unlock(virtio_dev *d);
// Snapshots: the transport, queues and device state. Save with the device
// lock held (the caller keeps it while guest RAM is copied). Load into a device
// just created (before its I/O thread starts); every value is checked as
// the driver's register writes would be. Returns false if it can't be.
void virtio_save(virtio_dev *d, snap_w *w);
[[nodiscard]] bool virtio_load(virtio_dev *d, snap_r *r);
// A guest access to the device's 4 KiB window (vCPU thread).
void virtio_mmio_access(virtio_dev *d, uint64_t off, uint8_t size, bool write, uint64_t *val);

// The following need the device lock.
// Is the device running (DRIVER_OK, not broken) with queue q ready?
bool virtq_usable(const virtio_dev *d, uint16_t q);
// Take the next available chain. Returns 1 with *c filled, 0 if the queue
// is empty, -1 if the chain was malformed (the device is then broken).
[[nodiscard]] int virtq_pop(virtio_dev *d, uint16_t q, virtq_chain *c);
// Put back the chain virtq_pop() just returned, untouched (nothing to say).
void virtq_unpop(virtio_dev *d, uint16_t q);
// Return a chain to the driver with `written` bytes in its writable part.
void virtq_push(virtio_dev *d, uint16_t q, uint16_t head, uint32_t written);
// The same for several chains, which the driver sees all at once: a
// mergeable receive frame spans several buffers (virtio 1.2, 5.1.6.4).
void virtq_push_n(virtio_dev *d, uint16_t q, const uint16_t *head, const uint32_t *written, unsigned n);
// Interrupt the driver for used buffers on q, unless it asked not to be.
// True if it did. (One interrupt has the driver look at every queue.)
bool virtq_notify_driver(virtio_dev *d, uint16_t q);
// Mark the device broken: the driver sees DEVICE_NEEDS_RESET and a config
// change interrupt.
void virtio_fail(virtio_dev *d, const char *why);

// Copy between a chain's segments and a flat buffer, starting `off` bytes
// into the readable (gather) or writable (scatter) part. Return bytes copied.
size_t virtq_gather(const virtq_chain *c, size_t off, void *dst, size_t len);
size_t virtq_scatter(const virtq_chain *c, size_t off, const void *src, size_t len);

// The kernel command-line option declaring device i (for the guest's
// virtio_mmio driver). Returns the length written.
int virtio_cmdline(char *buf, size_t len, int i);
