// SPDX-License-Identifier: MIT
// Platform devices, fully emulated in the VMM: the legacy port I/O ones and
// the I/O APIC. Every guest access is one VM exit, so the set is kept tiny.
#pragma once

#include <stdatomic.h>

#include "../common.h"
#include "../snapshot.h"

// ---- 16550A UART (COM1, 0x3f8) ---------------------------------------------
constexpr uint16_t COM1_BASE = 0x3f8;

typedef struct {
    uint8_t ier, lcr, mcr, scr, dll, dlm;
    bool fifo;
    bool line_start;
    uint64_t ts_base; // if nonzero, prefix each output line with host time since ts_base
    uint16_t outlen;
    uint8_t out[512];
} uart8250;

void uart_init(uart8250 *u);
uint8_t uart_read(uart8250 *u, uint16_t off);
void uart_write(uart8250 *u, uint16_t off, uint8_t val);
void uart_flush(uart8250 *u);
// Append one byte to the console output stream (THR writes end up here).
void uart_emit(uart8250 *u, uint8_t val);
// Snapshots: registers only (the output buffer is flushed first).
void uart_save(const uart8250 *u, snap_w *w);
void uart_load(uart8250 *u, snap_r *r);

// ---- MC146818 CMOS RTC (0x70/0x71) -----------------------------------------
typedef struct {
    uint8_t index;
    bool have_time;
    uint8_t regs[128];
} cmos_rtc;

uint8_t cmos_read(cmos_rtc *c, uint16_t port);
void cmos_write(cmos_rtc *c, uint16_t port, uint8_t val);
// Snapshots: the index and NVRAM; the clock is read again when restored.
void cmos_save(const cmos_rtc *c, snap_w *w);
void cmos_load(cmos_rtc *c, snap_r *r);

// ---- I/O APIC (ioapic.c) ------------------------------------------------------
constexpr uint64_t IOAPIC_BASE = 0xfec00000;
constexpr uint64_t IOAPIC_SIZE = 0x1000;
// Few pins: Linux reads and masks every one at boot, ~6 exits each.
constexpr int IOAPIC_PINS = 8;

typedef void (*ioapic_send_fn)(void *ctx, uint64_t msi_addr, uint32_t msi_data);

typedef struct {
    atomic_flag lock;
    uint8_t id, sel;
    uint32_t pending; // edges seen while the pin was masked
    uint64_t redir[IOAPIC_PINS];
    ioapic_send_fn send;
    void *ctx;
    uint64_t n_sent;
} ioapic;

void ioapic_init(ioapic *a, uint8_t id, ioapic_send_fn send, void *ctx);
void ioapic_mmio(ioapic *a, uint64_t off, uint8_t size, bool write, uint64_t *val);
// An edge on PIN (any thread).
void ioapic_raise(ioapic *a, unsigned pin);
[[nodiscard]] bool ioapic_rte_to_msi(uint64_t rte, uint64_t *addr, uint32_t *data);
void ioapic_save(ioapic *a, snap_w *w);
void ioapic_load(ioapic *a, snap_r *r);

// ---- microvm control ports ---------------------------------------------------
// 0x700 write: boot-phase marker (low byte = event id), timestamped by VMM.
// 0x701 write: guest exit status (low byte); the VMM stops immediately.
// 0x702 write: 1, 2 or 4 console bytes (the access width, little-endian),
//              appended to COM1's output. The UART costs two exits per
//              byte (data + status poll); this is one exit per 4 bytes.
constexpr uint16_t MVM_PORT_MARK = 0x700;
constexpr uint16_t MVM_PORT_EXIT = 0x701;
constexpr uint16_t MVM_PORT_CONSOLE = 0x702;
// 0x706 write: snapshot here. With --snapshot FILE the VMM saves the VM
//              and stops (status 0); a VM restored from FILE continues
//              after this instruction. Without --snapshot: nothing.
// 0x707 write: latch a record; then 1-byte reads (rep insb) return it,
//              and 0 past its end. Written 0: the resume record, s64
//              wall-clock seconds, u32 nanoseconds, u32 flags (bit 0:
//              restored from a snapshot), 32 bytes of fresh host
//              randomness for the guest's RNG. Written 1: the --env
//              strings, u32 length then NUL-terminated strings (none:
//              length 0).
constexpr uint16_t MVM_PORT_SNAPSHOT = 0x706;
constexpr uint16_t MVM_PORT_RESUME = 0x707;
constexpr size_t MVM_RESUME_LEN = 48;
// --env limits (guest/init/image.c has them too).
enum { MVM_ENV_MAX = 1 << 20, MVM_ENV_MAX_STRINGS = 4096 };
