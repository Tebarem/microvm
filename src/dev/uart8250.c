// SPDX-License-Identifier: MIT
// Minimal 16550A: enough for Linux's 8250 probe and polled console output.
// No interrupt line yet (no IOAPIC), so input is not supported.
#include "devices.h"

#include <stdio.h>

#include "../clock.h"

enum : uint8_t {
    LCR_DLAB = 0x80,
    MCR_LOOP = 0x10,
    LSR_THRE = 0x20,
    LSR_TEMT = 0x40,
    IIR_NONE = 0x01,
    IIR_FIFO = 0xc0,
};

void uart_init(uart8250 *u)
{
    memset(u, 0, sizeof *u);
    u->lcr = 0x03;
    u->mcr = 0x08;
    u->line_start = true;
}

void uart_save(const uart8250 *u, snap_w *w)
{
    const uint8_t regs[6] = {u->ier, u->lcr, u->mcr, u->scr, u->dll, u->dlm};
    sw_bytes(w, regs, sizeof regs);
    sw_u8(w, u->fifo);
}

void uart_load(uart8250 *u, snap_r *r)
{
    uint8_t regs[6];
    sr_bytes(r, regs, sizeof regs);
    u->ier = regs[0] & 0x0f;
    u->lcr = regs[1];
    u->mcr = regs[2] & 0x1f;
    u->scr = regs[3];
    u->dll = regs[4];
    u->dlm = regs[5];
    u->fifo = sr_bool(r);
}

void uart_flush(uart8250 *u)
{
    if (u->outlen) {
        mvm_write_out(u->out, u->outlen);
        u->outlen = 0;
    }
}

static uint8_t modem_status(const uart8250 *u)
{
    if (u->mcr & MCR_LOOP) {
        // Loopback: DTR->DSR, RTS->CTS, OUT1->RI, OUT2->DCD.
        uint8_t m = u->mcr;
        return (uint8_t)(((m & 0x01) << 5) | ((m & 0x02) << 3) | ((m & 0x04) << 4) |
                         ((m & 0x08) << 4));
    }
    return 0xb0; // DCD | DSR | CTS
}

uint8_t uart_read(uart8250 *u, uint16_t off)
{
    const bool dlab = u->lcr & LCR_DLAB;
    switch (off) {
    case 0: return dlab ? u->dll : 0; // RBR: no input
    case 1: return dlab ? u->dlm : u->ier;
    case 2: return (uint8_t)(IIR_NONE | (u->fifo ? IIR_FIFO : 0));
    case 3: return u->lcr;
    case 4: return u->mcr;
    case 5: return LSR_THRE | LSR_TEMT; // transmitter always empty
    case 6: return modem_status(u);
    case 7: return u->scr;
    default: return 0xff;
    }
}

void uart_emit(uart8250 *u, uint8_t val)
{
    if (u->ts_base && u->line_start) {
        const uint64_t t = mvm_now_ns() - u->ts_base;
        char ts[32];
        int n = snprintf(ts, sizeof ts, "[%8.3f ms] ", (double)t / 1e6);
        if (n > 0 && (size_t)n < sizeof ts && u->outlen + (size_t)n < sizeof u->out) {
            memcpy(u->out + u->outlen, ts, (size_t)n);
            u->outlen = (uint16_t)(u->outlen + n);
        }
    }
    u->line_start = val == '\n';
    u->out[u->outlen++] = val;
    if (val == '\n' || u->outlen >= sizeof u->out - 32)
        uart_flush(u);
}

void uart_write(uart8250 *u, uint16_t off, uint8_t val)
{
    const bool dlab = u->lcr & LCR_DLAB;
    switch (off) {
    case 0:
        if (dlab)
            u->dll = val;
        else if (!(u->mcr & MCR_LOOP))
            uart_emit(u, val);
        break;
    case 1:
        if (dlab)
            u->dlm = val;
        else
            u->ier = val & 0x0f;
        break;
    case 2: u->fifo = val & 0x01; break;
    case 3: u->lcr = val; break;
    case 4: u->mcr = val & 0x1f; break;
    case 7: u->scr = val; break;
    default: break;
    }
}
