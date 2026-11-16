// SPDX-License-Identifier: MIT
// CMOS RTC: gives the guest the real wall-clock time. Status A always reads
// "no update in progress" so the guest's UIP wait loop exits immediately.
#include "devices.h"

#include <time.h>

static uint8_t bcd(int v) { return (uint8_t)(((v / 10) << 4) | (v % 10)); }

static void cmos_latch_time(cmos_rtc *c)
{
    time_t t = time(nullptr);
    struct tm tm;
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    c->regs[0x00] = bcd(tm.tm_sec);
    c->regs[0x02] = bcd(tm.tm_min);
    c->regs[0x04] = bcd(tm.tm_hour);
    c->regs[0x06] = bcd(tm.tm_wday + 1);
    c->regs[0x07] = bcd(tm.tm_mday);
    c->regs[0x08] = bcd(tm.tm_mon + 1);
    c->regs[0x09] = bcd(tm.tm_year % 100);
    c->regs[0x32] = bcd((tm.tm_year + 1900) / 100);
    c->regs[0x0a] = 0x26; // UIP clear, 32.768 kHz base
    c->regs[0x0b] = 0x02; // 24h, BCD
    c->regs[0x0d] = 0x80; // valid RAM and time
    c->have_time = true;
}

uint8_t cmos_read(cmos_rtc *c, uint16_t port)
{
    if (port == 0x70)
        return c->index;
    if (!c->have_time)
        cmos_latch_time(c);
    return c->regs[c->index & 0x7f];
}

void cmos_save(const cmos_rtc *c, snap_w *w)
{
    sw_u8(w, c->index);
    sw_bytes(w, c->regs + 0x0e, sizeof c->regs - 0x0e);
}

void cmos_load(cmos_rtc *c, snap_r *r)
{
    c->index = sr_u8(r) & 0x7f;
    sr_bytes(r, c->regs + 0x0e, sizeof c->regs - 0x0e);
    c->have_time = false; // the clock is the host's now, not the snapshot's
}

void cmos_write(cmos_rtc *c, uint16_t port, uint8_t val)
{
    if (port == 0x70)
        c->index = val & 0x7f; // bit 7 is NMI mask
    else if ((c->index & 0x7f) >= 0x0e)
        c->regs[c->index & 0x7f] = val; // NVRAM bytes only; clock is read-only
}
