// SPDX-License-Identifier: MIT
// I/O APIC (82093AA register model), emulated in the VMM. Only the local
// APIC is in the hypervisor (KVM's split irqchip, WHP's xAPIC), so device
// interrupts go through here: a pin's redirection entry, programmed by the
// guest, becomes an MSI that the backend delivers to the local APIC.
//
// Edge-triggered only. That is all virtio-mmio needs (the driver reads and
// acks InterruptStatus, and a new event raises a new edge), and it means
// no remote IRR and no EOI round trip. An edge on a masked pin is latched
// and delivered when the guest unmasks it.
//
// Pins are raised from any thread (the vCPU's MMIO handlers, the I/O
// thread), so the state is behind a spinlock; the MSI is sent outside it.
#include "devices.h"

static void lock(ioapic *a)
{
    while (atomic_flag_test_and_set_explicit(&a->lock, memory_order_acquire))
        ;
}

static void unlock(ioapic *a) { atomic_flag_clear_explicit(&a->lock, memory_order_release); }

constexpr uint64_t RTE_MASKED = 1ull << 16;
// Bits the guest can't write: delivery status (12), remote IRR (14), and
// the reserved middle of the entry.
constexpr uint64_t RTE_WRITABLE = 0xff000000000000ffull | (7ull << 8) | (1ull << 11) | (1ull << 13) |
                                  (1ull << 15) | RTE_MASKED;

void ioapic_init(ioapic *a, uint8_t id, ioapic_send_fn send, void *ctx)
{
    memset(a, 0, sizeof *a);
    atomic_flag_clear(&a->lock);
    a->id = id;
    for (int i = 0; i < IOAPIC_PINS; i++)
        a->redir[i] = RTE_MASKED;
    a->send = send;
    a->ctx = ctx;
}

// The MSI a redirection entry asks for; false if it can't be one (no
// vector, or a delivery mode a device must not use: SMI, ExtINT, ...).
bool ioapic_rte_to_msi(uint64_t rte, uint64_t *addr, uint32_t *data)
{
    const uint32_t vector = rte & 0xff, mode = (rte >> 8) & 7;
    if (vector < 16 || (mode != 0 && mode != 1 && mode != 4))
        return false; // fixed, lowest priority and NMI only
    *addr = 0xfee00000u | (((rte >> 56) & 0xff) << 12) | (((rte >> 11) & 1) << 2);
    *data = vector | (mode << 8); // edge, assert
    return true;
}

static void send_rte(ioapic *a, uint64_t rte)
{
    uint64_t addr;
    uint32_t data;
    if (ioapic_rte_to_msi(rte, &addr, &data)) {
        a->n_sent++;
        a->send(a->ctx, addr, data);
    }
}

void ioapic_raise(ioapic *a, unsigned pin)
{
    if (pin >= IOAPIC_PINS)
        return;
    lock(a);
    const uint64_t rte = a->redir[pin];
    const bool masked = rte & RTE_MASKED;
    if (masked)
        a->pending |= 1u << pin;
    unlock(a);
    if (!masked)
        send_rte(a, rte);
}

void ioapic_save(ioapic *a, snap_w *w)
{
    lock(a);
    sw_u8(w, a->id);
    sw_u8(w, a->sel);
    sw_u32(w, a->pending);
    for (int i = 0; i < IOAPIC_PINS; i++)
        sw_u64(w, a->redir[i]);
    unlock(a);
}

// As the guest could have written them: only writable entry bits, only
// edges on pins that exist.
void ioapic_load(ioapic *a, snap_r *r)
{
    lock(a);
    a->id = sr_u8(r) & 0x0f;
    a->sel = sr_u8(r);
    a->pending = sr_u32(r) & ((1u << IOAPIC_PINS) - 1);
    for (int i = 0; i < IOAPIC_PINS; i++)
        a->redir[i] = sr_u64(r) & RTE_WRITABLE;
    unlock(a);
}

static uint32_t read_reg(const ioapic *a, uint32_t r)
{
    switch (r) {
    case 0x00: // ID
    case 0x02: // arbitration ID
        return (uint32_t)a->id << 24;
    case 0x01: // version 0x11, highest redirection entry
        return 0x11 | ((uint32_t)(IOAPIC_PINS - 1) << 16);
    default:
        if (r >= 0x10 && r < 0x10 + 2 * IOAPIC_PINS) {
            const uint64_t e = a->redir[(r - 0x10) / 2];
            return (r & 1) ? (uint32_t)(e >> 32) : (uint32_t)e;
        }
        return 0;
    }
}

void ioapic_mmio(ioapic *a, uint64_t off, uint8_t size, bool write, uint64_t *val)
{
    if (size != 4) { // the registers are 32-bit; anything else is dropped
        if (!write)
            *val = 0;
        return;
    }
    uint64_t deliver = 0;
    bool send = false;
    lock(a);
    if (off == 0x00) { // IOREGSEL
        if (write)
            a->sel = (uint8_t)*val;
        else
            *val = a->sel;
    } else if (off == 0x10) { // IOWIN
        const uint32_t r = a->sel;
        if (!write) {
            *val = read_reg(a, r);
        } else if (r == 0x00) {
            a->id = (uint8_t)((*val >> 24) & 0x0f);
        } else if (r >= 0x10 && r < 0x10 + 2 * IOAPIC_PINS) {
            const unsigned pin = (r - 0x10) / 2;
            uint64_t e = a->redir[pin];
            e = (r & 1) ? (e & 0xffffffffull) | ((uint64_t)(uint32_t)*val << 32)
                        : (e & ~0xffffffffull) | (uint32_t)*val;
            e &= RTE_WRITABLE;
            a->redir[pin] = e;
            if (!(e & RTE_MASKED) && (a->pending & (1u << pin))) {
                a->pending &= ~(1u << pin);
                deliver = e;
                send = true;
            }
        }
    } else if (!write) { // EOI register (0x40) and everything else
        *val = 0;
    }
    unlock(a);
    if (send)
        send_rte(a, deliver);
}
