// SPDX-License-Identifier: MIT
// Unit tests for the host-independent parts: boot structures, ELF loader
// (including hostile inputs), device models.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "boot/elf.h"
#include "boot/x86.h"
#include "dev/balloon.h"
#include "dev/devices.h"
#include "dev/virtio.h"
#include "os.h"
#include "snapshot.h"

static int failures, checks;
#define CHECK(cond)                                                            \
    do {                                                                       \
        checks++;                                                              \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                      \
    } while (0)

static guest_mem new_mem(uint64_t size)
{
    guest_mem m = {.base = os_mem_reserve(size), .size = size};
    if (!m.base) {
        fprintf(stderr, "cannot reserve %llu bytes\n", (unsigned long long)size);
        exit(1);
    }
    return m;
}

static uint8_t sum8(const uint8_t *p, size_t n)
{
    uint8_t s = 0;
    for (size_t i = 0; i < n; i++)
        s = (uint8_t)(s + p[i]);
    return s;
}

static void test_guest_slice(void)
{
    guest_mem m = {.base = (uint8_t *)0x1000, .size = 0x10000};
    CHECK(guest_slice(&m, 0, 0x10000) == m.base);
    CHECK(guest_slice(&m, 0xfff0, 0x10) != nullptr);
    CHECK(guest_slice(&m, 0xfff0, 0x11) == nullptr);
    CHECK(guest_slice(&m, UINT64_MAX - 1, 4) == nullptr); // wraps
    CHECK(guest_slice(&m, 0x10000, 0) != nullptr);
    CHECK(guest_slice(&m, 0x10001, 0) == nullptr);
}

static void test_boot_params(void)
{
    guest_mem m = new_mem(64 * MiB);
    x86_boot_cfg cfg = {.cmdline = "console=ttyS0", .entry = 0x1000000, .ncpus = 1};
    hv_regs r;
    hv_sregs s;
    CHECK(x86_setup_boot(&m, &cfg, &r, &s) == 0);
    const uint8_t *bp = m.base + X86_ZERO_PAGE;
    CHECK(get_le16(bp + BP_BOOT_FLAG) == 0xaa55);
    CHECK(get_le32(bp + BP_HEADER) == 0x53726448);
    CHECK(get_le32(bp + BP_CMD_LINE_PTR) == X86_CMDLINE_ADDR);
    CHECK(get_le32(bp + BP_CMDLINE_SIZE) == strlen("console=ttyS0"));
    CHECK(!strcmp((const char *)m.base + X86_CMDLINE_ADDR, "console=ttyS0"));
    CHECK(bp[BP_E820_ENTRIES] == 3);
    uint64_t ram = 0, last_end = 0;
    for (int i = 0; i < bp[BP_E820_ENTRIES]; i++) {
        const uint8_t *e = bp + BP_E820_TABLE + i * 20;
        CHECK(get_le64(e) >= last_end); // sorted, non-overlapping
        last_end = get_le64(e) + get_le64(e + 8);
        if (get_le32(e + 16) == E820_RAM)
            ram += get_le64(e + 8);
    }
    CHECK(last_end == m.size);
    CHECK(ram == m.size - (X86_HIMEM_START - X86_EBDA_START));

    // page tables: identity map, 2 MiB pages
    CHECK(get_le64(m.base + X86_PML4_ADDR) == (X86_PDPT_ADDR | 3));
    CHECK(get_le64(m.base + X86_PD_ADDR + 8 * 8) == ((8ull << 21) | 0x83));

    // MP table checksums
    const uint8_t *mpf = m.base + X86_MPTABLE_ADDR;
    CHECK(!memcmp(mpf, "_MP_", 4));
    CHECK(sum8(mpf, 16) == 0);
    const uint8_t *mpc = m.base + get_le32(mpf + 4);
    CHECK(!memcmp(mpc, "PCMP", 4));
    CHECK(sum8(mpc, get_le16(mpc + 4)) == 0);
    // walk the entries: lengths must add up to the table length
    size_t at = 44;
    for (uint16_t i = 0; i < get_le16(mpc + 34) && at < get_le16(mpc + 4); i++)
        at += mpc[at] == 0 ? 20 : 8;
    CHECK(at == get_le16(mpc + 4));

    // initial state
    CHECK(r.rip == 0x1000000 && r.rsi == X86_ZERO_PAGE);
    CHECK(s.cs.l == 1 && s.cr3 == X86_PML4_ADDR && (s.efer & 0x500) == 0x500);

    // oversized command line is rejected, not truncated
    char big[X86_CMDLINE_MAX + 1];
    memset(big, 'a', sizeof big - 1);
    big[sizeof big - 1] = 0;
    cfg.cmdline = big;
    CHECK(x86_write_boot_params(&m, &cfg) != 0);
    os_mem_release(m.base, m.size);
}

// Root filesystem layers: each its own e820 persistent-memory range, apart.
static void test_pmem_layers(void)
{
    uint64_t size[X86_PMEM_MAX + 1], gpa[X86_PMEM_MAX + 1], span = 0;
    for (int i = 0; i <= (int)X86_PMEM_MAX; i++)
        size[i] = 4096;
    CHECK(x86_pmem_layout(1, size, gpa, &span) == 0 && gpa[0] == X86_PMEM_GPA && span == 4096);
    size[0] = 3 * MiB;
    size[1] = 8192;
    size[2] = 2 * MiB;
    CHECK(x86_pmem_layout(3, size, gpa, &span) == 0);
    CHECK(gpa[0] == X86_PMEM_GPA && gpa[1] == X86_PMEM_GPA + 6 * MiB && gpa[2] == X86_PMEM_GPA + 10 * MiB &&
          span == 12 * MiB);
    CHECK(x86_pmem_layout(0, size, gpa, &span) != 0);
    CHECK(x86_pmem_layout(X86_PMEM_MAX + 1, size, gpa, &span) != 0);
    size[1] = 4095;
    CHECK(x86_pmem_layout(3, size, gpa, &span) != 0);
    size[1] = 0;
    CHECK(x86_pmem_layout(3, size, gpa, &span) != 0);
    size[0] = X86_PMEM_SPAN_MAX; // one at the limit; two over it
    CHECK(x86_pmem_layout(1, size, gpa, &span) == 0 && span == X86_PMEM_SPAN_MAX);
    size[1] = 4096;
    CHECK(x86_pmem_layout(2, size, gpa, &span) != 0);

    guest_mem m = new_mem(64 * MiB);
    x86_boot_cfg cfg = {.cmdline = "", .entry = 0x1000000, .ncpus = 1, .npmem = 3};
    size[0] = 3 * MiB, size[1] = 8192, size[2] = 2 * MiB;
    CHECK(x86_pmem_layout(3, size, cfg.pmem_gpa, &span) == 0);
    memcpy(cfg.pmem_size, size, 3 * sizeof size[0]);
    CHECK(x86_write_boot_params(&m, &cfg) == 0);
    const uint8_t *bp = m.base + X86_ZERO_PAGE;
    CHECK(bp[BP_E820_ENTRIES] == 6);
    for (int i = 0; i < 3; i++) {
        const uint8_t *e = bp + BP_E820_TABLE + (3 + i) * 20;
        CHECK(get_le64(e) == cfg.pmem_gpa[i] && get_le64(e + 8) == size[i] && get_le32(e + 16) == E820_PRAM);
    }
    // Touching ranges would be one to the guest; over RAM, or too many: refused.
    x86_boot_cfg bad = cfg;
    bad.pmem_gpa[1] = bad.pmem_gpa[0] + bad.pmem_size[0];
    CHECK(x86_write_boot_params(&m, &bad) != 0);
    bad = cfg;
    bad.pmem_gpa[0] = 32 * MiB;
    CHECK(x86_write_boot_params(&m, &bad) != 0);
    bad = cfg;
    bad.pmem_gpa[2] = bad.pmem_gpa[1];
    CHECK(x86_write_boot_params(&m, &bad) != 0);
    bad = cfg;
    bad.npmem = X86_PMEM_MAX + 1;
    CHECK(x86_write_boot_params(&m, &bad) != 0);
    bad = cfg;
    bad.pmem_size[2] = 0;
    CHECK(x86_write_boot_params(&m, &bad) != 0);
    os_mem_release(m.base, m.size);
}

// ---- ELF ---------------------------------------------------------------
typedef struct {
    uint8_t *buf;
    size_t len;
} membuf;

static int mem_reader(void *ctx, void *dst, size_t len, uint64_t off)
{
    membuf *b = ctx;
    if (off > b->len || len > b->len - off)
        return -1;
    memcpy(dst, b->buf + off, len);
    return 0;
}

// One PT_LOAD with 16 payload bytes at file offset 0x100.
static void make_elf(uint8_t *f, uint64_t paddr, uint64_t entry, uint64_t off, uint64_t filesz,
                     uint64_t memsz)
{
    memset(f, 0, 0x200);
    memcpy(f, "\x7f" "ELF", 4);
    f[4] = 2;
    f[5] = 1;
    put_le16(f + 18, 62);
    put_le64(f + 24, entry);
    put_le64(f + 32, 64); // phoff
    put_le16(f + 54, 56);
    put_le16(f + 56, 1);
    uint8_t *ph = f + 64;
    put_le32(ph, 1);
    put_le64(ph + 8, off);
    put_le64(ph + 24, paddr);
    put_le64(ph + 32, filesz);
    put_le64(ph + 40, memsz);
    for (int i = 0; i < 16; i++)
        f[0x100 + i] = (uint8_t)(0xa0 + i);
}

static void test_elf(void)
{
    guest_mem m = new_mem(32 * MiB);
    uint8_t f[0x200];
    membuf b = {f, sizeof f};
    elf_info info;

    make_elf(f, 0x1000000, 0x1000004, 0x100, 16, 0x1000);
    CHECK(elf_load(mem_reader, &b, sizeof f, &m, X86_HIMEM_START, &info) == 0);
    CHECK(info.entry == 0x1000004 && info.load_lo == 0x1000000 && info.load_hi == 0x1001000);
    CHECK(m.base[0x1000000] == 0xa0 && m.base[0x100000f] == 0xaf && m.base[0x1000010] == 0);

    make_elf(f, 0x1000000, 0x2000000, 0x100, 16, 16); // entry outside segment
    CHECK(elf_load(mem_reader, &b, sizeof f, &m, X86_HIMEM_START, &info) != 0);
    make_elf(f, 0x1000000, 0x1000000, 0x100, 32, 16); // filesz > memsz
    CHECK(elf_load(mem_reader, &b, sizeof f, &m, X86_HIMEM_START, &info) != 0);
    make_elf(f, 0x1000000, 0x1000000, UINT64_MAX - 4, 16, 16); // offset overflow
    CHECK(elf_load(mem_reader, &b, sizeof f, &m, X86_HIMEM_START, &info) != 0);
    make_elf(f, 0x1000000, 0x1000000, 0x100, 0x1000, 0x1000); // past end of file
    CHECK(elf_load(mem_reader, &b, sizeof f, &m, X86_HIMEM_START, &info) != 0);
    make_elf(f, 0x8000, 0x8000, 0x100, 16, 16); // would clobber boot structures
    CHECK(elf_load(mem_reader, &b, sizeof f, &m, X86_HIMEM_START, &info) != 0);
    make_elf(f, 0x1fffff0, 0x1fffff0, 0x100, 16, 32); // bss past guest RAM
    CHECK(elf_load(mem_reader, &b, sizeof f, &m, X86_HIMEM_START, &info) != 0);
    make_elf(f, UINT64_MAX - 8, UINT64_MAX - 8, 0x100, 16, 16); // paddr wraps
    CHECK(elf_load(mem_reader, &b, sizeof f, &m, X86_HIMEM_START, &info) != 0);
    make_elf(f, 0x1000000, 0x1000000, 0x100, 16, 16);
    put_le16(f + 56, 60000); // absurd phnum
    CHECK(elf_load(mem_reader, &b, sizeof f, &m, X86_HIMEM_START, &info) != 0);
    make_elf(f, 0x1000000, 0x1000000, 0x100, 16, 16);
    f[4] = 1; // 32-bit
    CHECK(elf_load(mem_reader, &b, sizeof f, &m, X86_HIMEM_START, &info) != 0);
    CHECK(elf_load(mem_reader, &b, 10, &m, X86_HIMEM_START, &info) != 0); // truncated
    make_elf(f, 0x1000000, 0x1000000, 0x100, 16, 0x1000);
    put_le16(f + 56, 2); // second PT_LOAD overlapping the first
    memcpy(f + 64 + 56, f + 64, 56);
    put_le64(f + 64 + 56 + 24, 0x1000800);
    CHECK(elf_load(mem_reader, &b, sizeof f, &m, X86_HIMEM_START, &info) != 0);
    put_le64(f + 64 + 56 + 24, 0x1001000); // adjacent is fine
    CHECK(elf_parse(mem_reader, &b, sizeof f, m.size, X86_HIMEM_START, &info) == 0);
    CHECK(info.nseg == 2 && info.load_hi == 0x1002000);
    os_mem_release(m.base, m.size);
}

// ---- devices ---------------------------------------------------------------
static void test_uart(void)
{
    uart8250 u;
    uart_init(&u);
    // Linux autoconfig: IER scratch test
    uart_write(&u, 1, 0);
    CHECK(uart_read(&u, 1) == 0);
    uart_write(&u, 1, 0x0f);
    CHECK((uart_read(&u, 1) & 0x0f) == 0x0f);
    // loopback test expects CTS|DCD for MCR = LOOP|RTS|OUT2
    uart_write(&u, 4, 0x10 | 0x0a);
    CHECK((uart_read(&u, 6) & 0xf0) == 0x90);
    uart_write(&u, 4, 0x08);
    // FIFO enable shows up in IIR
    uart_write(&u, 2, 0x07);
    CHECK((uart_read(&u, 2) & 0xc0) == 0xc0);
    CHECK((uart_read(&u, 5) & 0x60) == 0x60);
    // DLAB access doesn't emit output
    uart_write(&u, 3, 0x83);
    uart_write(&u, 0, 0x01);
    uart_write(&u, 3, 0x03);
    CHECK(u.outlen == 0);
    uart_write(&u, 0, 'x');
    CHECK(u.outlen == 1 && u.out[0] == 'x');
    u.outlen = 0;
}

static void test_cmos(void)
{
    cmos_rtc c = {0};
    cmos_write(&c, 0x70, 0x0a);
    CHECK((cmos_read(&c, 0x71) & 0x80) == 0); // no update in progress
    cmos_write(&c, 0x70, 0x08);
    uint8_t mon = cmos_read(&c, 0x71);
    CHECK((mon >> 4) <= 1 && (mon & 0xf) <= 9 && mon >= 1 && mon <= 0x12);
    cmos_write(&c, 0x70, 0x00);
    cmos_write(&c, 0x71, 0xff); // clock registers are read-only (0xff isn't valid BCD)
    CHECK(cmos_read(&c, 0x71) != 0xff);
    cmos_write(&c, 0x70, 0x20);
    cmos_write(&c, 0x71, 0x42); // NVRAM is writable
    CHECK(cmos_read(&c, 0x71) == 0x42);
}

// ---- I/O APIC -----------------------------------------------------------------
static struct {
    int n;
    uint64_t addr;
    uint32_t data;
} msi;

static void record_msi(void *ctx, uint64_t addr, uint32_t data)
{
    (void)ctx;
    msi.n++;
    msi.addr = addr;
    msi.data = data;
}

static void ioa_write(ioapic *a, uint32_t reg, uint32_t v)
{
    uint64_t x = reg;
    ioapic_mmio(a, 0x00, 4, true, &x);
    x = v;
    ioapic_mmio(a, 0x10, 4, true, &x);
}

static uint32_t ioa_read(ioapic *a, uint32_t reg)
{
    uint64_t x = reg;
    ioapic_mmio(a, 0x00, 4, true, &x);
    ioapic_mmio(a, 0x10, 4, false, &x);
    return (uint32_t)x;
}

static void test_ioapic(void)
{
    ioapic a;
    msi.n = 0;
    ioapic_init(&a, 1, record_msi, nullptr);
    CHECK(ioa_read(&a, 0x00) == 1u << 24);
    CHECK(ioa_read(&a, 0x01) == (0x11 | (IOAPIC_PINS - 1) << 16));
    for (unsigned pin = 0; pin < IOAPIC_PINS; pin++)
        CHECK(ioa_read(&a, 0x10 + 2 * pin) & (1u << 16)); // masked out of reset

    // An edge on a masked pin waits for the unmask.
    ioapic_raise(&a, 5);
    CHECK(msi.n == 0);
    ioa_write(&a, 0x10 + 2 * 5 + 1, 0x03u << 24);     // destination APIC 3
    ioa_write(&a, 0x10 + 2 * 5, 0x41 | (1u << 16));   // vector 0x41, still masked
    CHECK(msi.n == 0);
    ioa_write(&a, 0x10 + 2 * 5, 0x41);                // unmask: the latched edge
    CHECK(msi.n == 1 && msi.addr == (0xfee00000u | 3u << 12) && msi.data == 0x41);
    ioa_write(&a, 0x10 + 2 * 5, 0x41);                // only once
    CHECK(msi.n == 1);
    ioapic_raise(&a, 5);
    CHECK(msi.n == 2);
    ioapic_raise(&a, IOAPIC_PINS); // no such pin
    ioapic_raise(&a, 1000);
    CHECK(msi.n == 2);

    // Read-only bits (delivery status, remote IRR) stay clear.
    ioa_write(&a, 0x10 + 2 * 6, 0x50 | (1u << 12) | (1u << 14) | (1u << 16));
    CHECK(ioa_read(&a, 0x10 + 2 * 6) == (0x50 | (1u << 16)));
    // Registers past the last pin read 0; writes there go nowhere.
    ioa_write(&a, 0x10 + 2 * IOAPIC_PINS, 0x1234);
    CHECK(ioa_read(&a, 0x10 + 2 * IOAPIC_PINS) == 0);
    // Only 32-bit accesses.
    uint64_t x = 0x01;
    ioapic_mmio(&a, 0x00, 1, true, &x);
    x = 0xff;
    ioapic_mmio(&a, 0x10, 2, false, &x);
    CHECK(x == 0);

    // Redirection entries a device must not turn into MSIs.
    uint64_t addr;
    uint32_t data;
    CHECK(!ioapic_rte_to_msi(0x0f, &addr, &data));             // vector < 16
    CHECK(!ioapic_rte_to_msi(0x40 | 2u << 8, &addr, &data));   // SMI
    CHECK(!ioapic_rte_to_msi(0x40 | 7u << 8, &addr, &data));   // ExtINT
    CHECK(!ioapic_rte_to_msi(0x40 | 5u << 8, &addr, &data));   // INIT
    CHECK(ioapic_rte_to_msi(0x40 | 4u << 8, &addr, &data) && data == (0x40 | 4u << 8)); // NMI
    CHECK(ioapic_rte_to_msi(0x40 | 1u << 8 | 1u << 11 | 0xffull << 56, &addr, &data) &&
          addr == 0xfeeff004u && data == (0x40 | 1u << 8)); // lowest priority, logical
    // A pin whose entry can't be an MSI sends nothing.
    ioa_write(&a, 0x10 + 2 * 7, 0x05);
    ioapic_raise(&a, 7);
    CHECK(msi.n == 2);
}

// ---- MP table with the I/O APIC -------------------------------------------------
static void test_mptable_ioapic(void)
{
    guest_mem m = new_mem(16 << 20);
    CHECK(x86_write_mptable(&m, 1, 1u << 5 | 1u << 6) == 0);
    const uint8_t *mpf = m.base + X86_MPTABLE_ADDR;
    const uint8_t *mpc = m.base + get_le32(mpf + 4);
    CHECK(sum8(mpf, 16) == 0 && sum8(mpc, get_le16(mpc + 4)) == 0);
    CHECK(get_le16(mpc + 34) == 1 + 1 + 1 + 2 + 2);
    size_t at = 44;
    int ioapics = 0, ints = 0;
    for (uint16_t i = 0; i < get_le16(mpc + 34) && at < get_le16(mpc + 4); i++) {
        const uint8_t *e = mpc + at;
        if (e[0] == 2) {
            ioapics++;
            CHECK(e[1] == 1 && e[3] == 1 && get_le32(e + 4) == IOAPIC_BASE);
        } else if (e[0] == 3) {
            CHECK(e[5] == e[7] && (e[7] == 5 || e[7] == 6) && e[6] == 1 && get_le16(e + 2) == 5);
            ints++;
        }
        at += e[0] == 0 ? 20 : 8;
    }
    CHECK(at == get_le16(mpc + 4) && ioapics == 1 && ints == 2);
    CHECK(x86_write_mptable(&m, 1, 1u << IOAPIC_PINS) != 0); // no such pin
    // Without devices: no I/O APIC entry (the guest finds none to probe).
    CHECK(x86_write_mptable(&m, 1, 0) == 0);
    mpc = m.base + get_le32(mpf + 4);
    at = 44;
    for (uint16_t i = 0; i < get_le16(mpc + 34); i++) {
        CHECK(mpc[at] != 2);
        at += mpc[at] == 0 ? 20 : 8;
    }
    os_mem_release(m.base, m.size);
}

// ---- virtio-mmio and split virtqueues -------------------------------------------
enum : uint64_t { Q_DESC = 0x1000, Q_AVAIL = 0x2000, Q_USED = 0x3000, BUF = 0x4000 };
constexpr uint16_t QN = 8;

static struct {
    int pops[8], npops;
    virtq_chain last;
    int notified, activated, resets;
} tdev;

// A test device: pops every chain it is kicked for, returns each with all
// its writable bytes filled.
static void tdev_notify(virtio_dev *d, uint16_t q)
{
    tdev.notified++;
    for (;;) {
        virtq_chain c;
        const int r = virtq_pop(d, q, &c);
        if (tdev.npops < 8)
            tdev.pops[tdev.npops++] = r;
        if (r != 1)
            break;
        tdev.last = c;
        virtq_push(d, q, c.head, c.wlen);
    }
    virtq_notify_driver(d, q);
}

static void tdev_activate(virtio_dev *d) { (void)d, tdev.activated++; }
static void tdev_reset(virtio_dev *d) { (void)d, tdev.resets++; }

static void tdev_config(virtio_dev *d, uint32_t off, uint8_t size, uint64_t *val)
{
    (void)d;
    static const uint8_t cfg[4] = {0x11, 0x22, 0x33, 0x44};
    if (off < sizeof cfg && size <= sizeof cfg - off)
        memcpy(val, cfg + off, size);
}

static const virtio_ops TDEV = {.device_id = 99, .features = 1ull << 3, .nqueues = 1,
                                .config_read = tdev_config, .notify = tdev_notify,
                                .activate = tdev_activate, .reset = tdev_reset};

static void vw(virtio_dev *d, uint64_t off, uint32_t v)
{
    uint64_t x = v;
    virtio_mmio_access(d, off, 4, true, &x);
}

static uint32_t vr(virtio_dev *d, uint64_t off)
{
    uint64_t x = 0;
    virtio_mmio_access(d, off, 4, false, &x);
    return (uint32_t)x;
}

static void put_desc(guest_mem *m, uint16_t i, uint64_t addr, uint32_t len, uint16_t flags, uint16_t next)
{
    uint8_t *e = m->base + Q_DESC + 16u * i;
    put_le64(e, addr);
    put_le32(e + 8, len);
    put_le16(e + 12, flags);
    put_le16(e + 14, next);
}

// Offer the chain at `head` to the device and kick it.
static void offer(virtio_dev *d, guest_mem *m, uint16_t head)
{
    uint8_t *avail = m->base + Q_AVAIL;
    const uint16_t idx = get_le16(avail + 2);
    put_le16(avail + 4 + 2u * (idx % QN), head);
    put_le16(avail + 2, (uint16_t)(idx + 1));
    tdev.npops = 0;
    vw(d, 0x050, 0);
}

// Bring the device up the way Linux's virtio_mmio driver does.
static void bring_up(virtio_dev *d, guest_mem *m)
{
    memset(m->base, 0, 0x8000);
    vw(d, 0x070, 0); // reset
    vw(d, 0x070, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);
    vw(d, 0x024, 1);
    vw(d, 0x020, 1); // VERSION_1
    vw(d, 0x024, 0);
    vw(d, 0x020, 0);
    vw(d, 0x070, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);
    vw(d, 0x030, 0);
    vw(d, 0x038, QN);
    vw(d, 0x080, Q_DESC);
    vw(d, 0x090, Q_AVAIL);
    vw(d, 0x0a0, Q_USED);
    vw(d, 0x044, 1);
    vw(d, 0x070, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK |
                     VIRTIO_STATUS_DRIVER_OK);
}

static void test_virtio(void)
{
    guest_mem m = new_mem(64 << 10);
    ioapic a;
    msi.n = 0;
    ioapic_init(&a, 1, record_msi, nullptr);
    ioa_write(&a, 0x10 + 2 * 5, 0x30); // pin 5 -> vector 0x30
    static virtio_dev d;
    virtio_dev_init(&d, &TDEV, nullptr, &m, &a, 5);

    CHECK(vr(&d, 0x000) == 0x74726976 && vr(&d, 0x004) == 2 && vr(&d, 0x008) == 99);
    CHECK(vr(&d, 0x034) == VIRTQ_MAX_SIZE);
    vw(&d, 0x030, 1); // a queue that doesn't exist
    CHECK(vr(&d, 0x034) == 0);
    vw(&d, 0x030, 0);
    uint64_t x = 0;
    virtio_mmio_access(&d, 0x100, 2, false, &x);
    CHECK(x == 0x2211);
    x = 0;
    virtio_mmio_access(&d, 0x103, 2, false, &x); // past the end
    CHECK(x == 0);

    // Feature negotiation: only what is offered, and VERSION_1 required.
    vw(&d, 0x070, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);
    vw(&d, 0x014, 1);
    CHECK(vr(&d, 0x010) == 1); // VERSION_1 is bit 32
    vw(&d, 0x014, 0);
    CHECK(vr(&d, 0x010) == 1u << 3);
    vw(&d, 0x024, 0);
    vw(&d, 0x020, 1u << 3);
    vw(&d, 0x070, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);
    CHECK(!(vr(&d, 0x070) & VIRTIO_STATUS_FEATURES_OK)); // no VERSION_1
    vw(&d, 0x070, 0);
    vw(&d, 0x070, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);
    vw(&d, 0x024, 1);
    vw(&d, 0x020, 1 | 2); // bit 33: not offered
    vw(&d, 0x070, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);
    CHECK(!(vr(&d, 0x070) & VIRTIO_STATUS_FEATURES_OK));

    tdev.activated = 0;
    bring_up(&d, &m);
    CHECK(vr(&d, 0x070) & VIRTIO_STATUS_FEATURES_OK);
    CHECK(tdev.activated == 1 && vr(&d, 0x044) == 1);

    // A good chain: two readable segments, one writable.
    memcpy(m.base + BUF, "hello ", 6);
    memcpy(m.base + BUF + 0x100, "world", 5);
    put_desc(&m, 0, BUF, 6, 1, 3);
    put_desc(&m, 3, BUF + 0x100, 5, 1, 5);
    put_desc(&m, 5, BUF + 0x200, 32, 2, 0);
    offer(&d, &m, 0);
    CHECK(tdev.npops == 2 && tdev.pops[0] == 1 && tdev.pops[1] == 0);
    CHECK(tdev.last.head == 0 && tdev.last.nr == 2 && tdev.last.nw == 1);
    CHECK(tdev.last.rlen == 11 && tdev.last.wlen == 32);
    char buf[16] = {0};
    CHECK(virtq_gather(&tdev.last, 4, buf, sizeof buf) == 7 && !memcmp(buf, "o world", 7));
    CHECK(virtq_scatter(&tdev.last, 30, "xyz", 3) == 2 && !memcmp(m.base + BUF + 0x200 + 30, "xy", 2));
    CHECK(get_le16(m.base + Q_USED + 2) == 1);
    CHECK(get_le32(m.base + Q_USED + 4) == 0 && get_le32(m.base + Q_USED + 8) == 32);
    CHECK(msi.n == 1 && msi.data == 0x30);
    CHECK(vr(&d, 0x060) == 1);
    vw(&d, 0x064, 1);
    CHECK(vr(&d, 0x060) == 0);
    // An acknowledgement can arrive late (KVM queues it): one for a status
    // read before the device raised the bit again must not clear it.
    offer(&d, &m, 0);
    CHECK(msi.n == 2 && vr(&d, 0x060) == 1); // the driver reads 1 ...
    offer(&d, &m, 0);                        // ... new work raises it again ...
    vw(&d, 0x064, 1);                        // ... then the ack for the first read lands
    CHECK(msi.n == 3 && vr(&d, 0x060) == 1); // still set for the new work
    vw(&d, 0x064, 1);
    CHECK(vr(&d, 0x060) == 0);
    vw(&d, 0x064, 1); // nothing set: nothing changes
    CHECK(vr(&d, 0x060) == 0);
    // The driver asked for no interrupts: none.
    put_le16(m.base + Q_AVAIL, 1);
    offer(&d, &m, 0);
    CHECK(tdev.pops[0] == 1 && msi.n == 3);
    put_le16(m.base + Q_AVAIL, 0);
    // Queue layout can't change while the queue is live.
    vw(&d, 0x080, 0x7000);
    CHECK(d.q[0].desc_gpa == Q_DESC);
    // A kick for a queue that doesn't exist does nothing.
    tdev.notified = 0;
    vw(&d, 0x050, 3);
    CHECK(tdev.notified == 0);


    // Malformed chains: the device stops and asks for a reset; nothing more
    // is taken from the ring until the driver resets it.
    static const char *const bad[] = {
        "a loop", "a chain longer than the ring", "readable after writable",
        "a buffer past guest RAM", "a buffer wrapping the address space", "next out of range",
        "indirect", "head out of range", "avail index past the ring",
    };
    for (int k = 0; k < (int)(sizeof bad / sizeof bad[0]); k++) {
        bring_up(&d, &m);
        uint16_t head = 0;
        switch (k) {
        case 0: put_desc(&m, 0, BUF, 8, 1, 1); put_desc(&m, 1, BUF, 8, 1, 0); break;
        case 1:
            for (uint16_t i = 0; i < QN; i++) // through every descriptor, then around
                put_desc(&m, i, BUF, 8, 1, (uint16_t)((i + 1) % QN));
            break;
        case 2: put_desc(&m, 0, BUF, 8, 3, 1); put_desc(&m, 1, BUF, 8, 0, 0); break;
        case 3: put_desc(&m, 0, m.size - 4, 8, 0, 0); break;
        case 4: put_desc(&m, 0, UINT64_MAX - 3, 8, 0, 0); break;
        case 5: put_desc(&m, 0, BUF, 8, 1, QN); break;
        case 6: put_desc(&m, 0, BUF, 16, 4, 0); break;
        case 7: head = QN; break;
        case 8: put_le16(m.base + Q_AVAIL + 2, QN); break; // + 1 from offer()
        }
        msi.n = 0;
        offer(&d, &m, head);
        CHECK(tdev.npops == 1 && tdev.pops[0] == -1);
        CHECK((vr(&d, 0x070) & VIRTIO_STATUS_NEEDS_RESET) && (vr(&d, 0x060) & 2) && msi.n == 1);
        CHECK(get_le16(m.base + Q_USED + 2) == 0); // nothing was returned
        if (tdev.npops != 1 || tdev.pops[0] != -1)
            fprintf(stderr, "  (malformed case: %s)\n", bad[k]);
        // Broken: further kicks pop nothing.
        put_desc(&m, 0, BUF, 8, 0, 0);
        offer(&d, &m, 0);
        CHECK(tdev.npops == 0 || tdev.pops[0] == 0);
    }
    // A reset makes it usable again.
    tdev.resets = 0;
    bring_up(&d, &m);
    CHECK(tdev.resets == 1 && !(vr(&d, 0x070) & VIRTIO_STATUS_NEEDS_RESET));
    put_desc(&m, 0, BUF, 8, 0, 0);
    offer(&d, &m, 0);
    CHECK(tdev.pops[0] == 1 && get_le16(m.base + Q_USED + 2) == 1);

    // Bad queue layouts are refused when the queue is made ready.
    static const uint64_t layouts[][4] = {
        {3, Q_DESC, Q_AVAIL, Q_USED},           // size not a power of two
        {512, Q_DESC, Q_AVAIL, Q_USED},         // bigger than we offer
        {0, Q_DESC, Q_AVAIL, Q_USED},
        {QN, Q_DESC + 8, Q_AVAIL, Q_USED},      // misaligned
        {QN, Q_DESC, Q_AVAIL + 1, Q_USED},
        {QN, Q_DESC, Q_AVAIL, Q_USED + 2},
        {QN, (64 << 10) - 64, Q_AVAIL, Q_USED}, // runs past RAM
        {QN, Q_DESC, Q_AVAIL, 0xfffffffffffffff0ull},
    };
    for (int k = 0; k < (int)(sizeof layouts / sizeof layouts[0]); k++) {
        vw(&d, 0x070, 0);
        vw(&d, 0x030, 0);
        vw(&d, 0x038, (uint32_t)layouts[k][0]);
        vw(&d, 0x080, (uint32_t)layouts[k][1]);
        vw(&d, 0x084, (uint32_t)(layouts[k][1] >> 32));
        vw(&d, 0x090, (uint32_t)layouts[k][2]);
        vw(&d, 0x0a0, (uint32_t)layouts[k][3]);
        vw(&d, 0x0a4, (uint32_t)(layouts[k][3] >> 32));
        vw(&d, 0x044, 1);
        CHECK(vr(&d, 0x044) == 0 && (vr(&d, 0x070) & VIRTIO_STATUS_NEEDS_RESET));
    }
    // Sub-word register accesses are ignored.
    vw(&d, 0x070, 0);
    x = 0xff;
    virtio_mmio_access(&d, 0x070, 1, true, &x);
    CHECK(vr(&d, 0x070) == 0);
    virtio_mmio_access(&d, 0x000, 2, false, &x);
    CHECK(x == 0);

    // A device with a smaller queue: advertised, and enforced.
    static const virtio_ops SMALL = {.device_id = 98, .nqueues = 1, .queue_max = {4}, .notify = tdev_notify};
    virtio_dev_init(&d, &SMALL, nullptr, &m, &a, 5);
    CHECK(vr(&d, 0x034) == 4);
    bring_up(&d, &m); // asks for QN = 8
    CHECK(vr(&d, 0x044) == 0 && (vr(&d, 0x070) & VIRTIO_STATUS_NEEDS_RESET));
    vw(&d, 0x070, 0);
    vw(&d, 0x038, 4);
    vw(&d, 0x080, Q_DESC);
    vw(&d, 0x090, Q_AVAIL);
    vw(&d, 0x0a0, Q_USED);
    vw(&d, 0x044, 1);
    CHECK(vr(&d, 0x044) == 1);

    char cl[64];
    CHECK(virtio_cmdline(cl, sizeof cl, 1) > 0 && !strcmp(cl, "virtio_mmio.device=4K@0xd0001000:6"));
    os_mem_release(m.base, m.size);
}

// ---- snapshots: header and device state ---------------------------------------
static void test_snapshot(void)
{
    static uint8_t page[4096];
    const snap_header h = {.mem_size = 64 * MiB, .mem_off = 128 << 10, .state_len = 9000,
                           .rootfs_size = 8192, .tsc_khz = 3000000, .cpuid_hash = 0x1234,
                           .ncpus = 1, .ndev = 1, .dev_id = {19}};
    snap_header_encode(&h, page);
    snap_header g;
    const uint64_t fsize = h.mem_off + h.mem_size;
    CHECK(snap_header_decode(page, fsize, &g) == 0 && !memcmp(&g, &h, sizeof g));
    CHECK(snap_header_decode(page, fsize - 1, &g) != 0); // RAM past the end of the file
    page[0] ^= 1;
    CHECK(snap_header_decode(page, fsize, &g) != 0); // magic
    page[0] ^= 1;
    snap_header bad = h;
    bad.mem_off = 4096 + 9000; // not 64 KiB aligned
    snap_header_encode(&bad, page);
    CHECK(snap_header_decode(page, UINT64_MAX, &g) != 0);
    bad = h;
    bad.mem_off = 64 << 10; // overlaps the state
    bad.state_len = 64 << 10;
    snap_header_encode(&bad, page);
    CHECK(snap_header_decode(page, UINT64_MAX, &g) != 0);
    bad = h;
    bad.mem_off = UINT64_MAX - (UINT64_MAX % SNAP_MEM_ALIGN); // offset + size wraps
    snap_header_encode(&bad, page);
    CHECK(snap_header_decode(page, UINT64_MAX, &g) != 0);
    bad = h;
    bad.ndev = 4;
    snap_header_encode(&bad, page);
    CHECK(snap_header_decode(page, fsize, &g) != 0);
    // vCPUs: 0 (a VMM before SMP wrote none) is one; at most MVM_MAX_VCPUS.
    bad = h;
    bad.ncpus = 0;
    snap_header_encode(&bad, page);
    CHECK(snap_header_decode(page, fsize, &g) == 0 && g.ncpus == 1);
    bad.ncpus = MVM_MAX_VCPUS;
    snap_header_encode(&bad, page);
    CHECK(snap_header_decode(page, fsize, &g) == 0 && g.ncpus == MVM_MAX_VCPUS);
    bad.ncpus = MVM_MAX_VCPUS + 1;
    snap_header_encode(&bad, page);
    CHECK(snap_header_decode(page, fsize, &g) != 0);
    bad.ncpus = UINT32_MAX;
    snap_header_encode(&bad, page);
    CHECK(snap_header_decode(page, fsize, &g) != 0);

    // Layers: their sizes round-trip; at most SNAP_MAX_LAYERS, each a
    // nonzero multiple of 4 KiB inside the span. None (files from before
    // layers) is what the VMM reads as one, rootfs_size bytes.
    snap_header lh = h;
    lh.rootfs_size = 12 * MiB;
    lh.nlayers = 3;
    lh.layer_size[0] = 3 * MiB, lh.layer_size[1] = 8192, lh.layer_size[2] = 2 * MiB;
    snap_header_encode(&lh, page);
    CHECK(snap_header_decode(page, fsize, &g) == 0 && !memcmp(&g, &lh, sizeof g));
    bad = lh;
    bad.nlayers = SNAP_MAX_LAYERS + 1;
    snap_header_encode(&bad, page);
    CHECK(snap_header_decode(page, fsize, &g) != 0);
    bad = lh;
    bad.layer_size[1] = 4097;
    snap_header_encode(&bad, page);
    CHECK(snap_header_decode(page, fsize, &g) != 0);
    bad = lh;
    bad.layer_size[2] = 0;
    snap_header_encode(&bad, page);
    CHECK(snap_header_decode(page, fsize, &g) != 0);
    bad = lh;
    bad.layer_size[0] = 16 * MiB; // past the span
    snap_header_encode(&bad, page);
    CHECK(snap_header_decode(page, fsize, &g) != 0);
    bad = lh;
    bad.rootfs_size = 0; // layers, but no root filesystem
    snap_header_encode(&bad, page);
    CHECK(snap_header_decode(page, fsize, &g) != 0);

    // A diff: its base's id and runs, between the state and RAM. RAM ends
    // at the last run, not at mem_off + mem_size.
    static const snap_header dh = {.mem_size = 64 * MiB, .mem_off = 128 << 10, .state_len = 9000,
                                   .ncpus = 2, .ndev = 1, .dev_id = {19}, .id = {1, 2}, .diff = true,
                                   .base_id = {3, 4}, .runs_off = 4096 + 9000, .nruns = 3};
    snap_header_encode(&dh, page);
    CHECK(get_le32(page + 8) == SNAP_VERSION_DIFF);
    CHECK(snap_header_decode(page, dh.mem_off, &g) == 0 && !memcmp(&g, &dh, sizeof g));
    CHECK(snap_header_decode(page, dh.mem_off - 1, &g) != 0); // RAM starts past the end
    static const snap_header bad_diffs[] = {
        {.base_id = {0, 0}, .nruns = 3, .runs_off = 13096},               // no base
        {.base_id = {3, 4}, .nruns = 0, .runs_off = 13096},               // no runs
        {.base_id = {3, 4}, .nruns = SNAP_MAX_RUNS + 1, .runs_off = 13096},
        {.base_id = {3, 4}, .nruns = 3, .runs_off = 13097},               // unaligned
        {.base_id = {3, 4}, .nruns = 3, .runs_off = 13088},               // over the state
        {.base_id = {3, 4}, .nruns = 3, .runs_off = (128 << 10) - 16},    // into RAM
        {.base_id = {3, 4}, .nruns = 3, .runs_off = UINT64_MAX - 7},      // wraps
    };
    for (size_t i = 0; i < sizeof bad_diffs / sizeof bad_diffs[0]; i++) {
        snap_header x = dh;
        memcpy(x.base_id, bad_diffs[i].base_id, sizeof x.base_id);
        x.nruns = bad_diffs[i].nruns;
        x.runs_off = bad_diffs[i].runs_off;
        snap_header_encode(&x, page);
        CHECK(snap_header_decode(page, UINT64_MAX / 2, &g) != 0);
    }
    // A full snapshot keeps version 1 (older VMMs read it), with its id.
    snap_header fh = h;
    fh.id[0] = 7, fh.id[1] = 8;
    snap_header_encode(&fh, page);
    CHECK(get_le32(page + 8) == SNAP_VERSION && snap_header_decode(page, fsize, &g) == 0 && g.id[1] == 8 &&
          !g.diff);

    // Runs: in order, apart, nonempty, inside RAM and the file.
    const snap_run runs[3] = {{0, 2}, {5, 1}, {16383, 1}};
    uint8_t enc[24];
    snap_runs_encode(runs, 3, enc);
    snap_run got[3];
    const uint64_t dsize = dh.mem_off + 16384ull * 4096;
    CHECK(snap_runs_decode(enc, &dh, dsize, got) == 0 && !memcmp(got, runs, sizeof runs));
    CHECK(snap_runs_decode(enc, &dh, dsize - 1, got) != 0); // the last page past the end
    static const snap_run bad_runs[][3] = {
        {{0, 2}, {2, 1}, {9, 1}},            // touching
        {{0, 2}, {1, 1}, {9, 1}},            // overlapping
        {{5, 1}, {0, 2}, {9, 1}},            // out of order
        {{0, 2}, {5, 0}, {9, 1}},            // empty
        {{0, 2}, {5, 1}, {16383, 2}},        // past RAM
        {{0, 2}, {5, 1}, {UINT32_MAX, 1}},   // far past RAM
        {{0, 2}, {5, UINT32_MAX}, {9, 1}},
    };
    for (size_t i = 0; i < sizeof bad_runs / sizeof bad_runs[0]; i++) {
        snap_runs_encode(bad_runs[i], 3, enc);
        CHECK(snap_runs_decode(enc, &dh, UINT64_MAX / 2, got) != 0);
    }

    // A running device, saved and loaded into a new one: the same rings,
    // the same position in them, and it keeps working.
    guest_mem m = new_mem(64 << 10);
    ioapic a;
    msi.n = 0;
    ioapic_init(&a, 1, record_msi, nullptr);
    ioa_write(&a, 0x10 + 2 * 5, 0x30);
    static virtio_dev d, e;
    virtio_dev_init(&d, &TDEV, nullptr, &m, &a, 5);
    bring_up(&d, &m);
    put_desc(&m, 0, BUF, 8, 0, 0);
    offer(&d, &m, 0);
    offer(&d, &m, 0);
    static uint8_t buf[4096];
    snap_w w = {.p = buf, .cap = sizeof buf};
    ioapic_save(&a, &w);
    virtio_lock(&d);
    virtio_save(&d, &w);
    virtio_unlock(&d);
    CHECK(!w.bad);
    ioapic b;
    ioapic_init(&b, 1, record_msi, nullptr);
    virtio_dev_init(&e, &TDEV, nullptr, &m, &b, 5);
    snap_r r = {.p = buf, .len = w.len};
    ioapic_load(&b, &r);
    CHECK(virtio_load(&e, &r) && !r.bad && r.at == r.len);
    CHECK(b.redir[5] == a.redir[5] && e.status == d.status && e.q[0].ready);
    CHECK(e.q[0].desc == d.q[0].desc && e.q[0].last_avail == 2 && e.q[0].used_idx == 2);
    offer(&e, &m, 0);
    CHECK(tdev.pops[0] == 1 && get_le16(m.base + Q_USED + 2) == 3);
    // Refused: cut short, a queue outside RAM, features never offered.
    r = (snap_r){.p = buf, .len = w.len - 1};
    ioapic_load(&b, &r);
    CHECK(!virtio_load(&e, &r) && e.status == 0 && !e.q[0].ready);
    const size_t qoff = 4 + 2 + 8 * 8 + 4 * 5 + 8 + 4 + 1 + 1; // ioapic, transport, then queue 0
    uint8_t keep[8];
    memcpy(keep, buf + qoff + 3, 8);
    put_le64(buf + qoff + 3, (64 << 10) - 16); // descriptor table past RAM
    r = (snap_r){.p = buf, .len = w.len};
    ioapic_load(&b, &r);
    CHECK(!virtio_load(&e, &r) && !e.q[0].ready);
    memcpy(buf + qoff + 3, keep, 8);
    const size_t foff = 4 + 2 + 8 * 8 + 4 * 5; // driver_features
    buf[foff] |= 1 << 5;
    r = (snap_r){.p = buf, .len = w.len};
    ioapic_load(&b, &r);
    CHECK(!virtio_load(&e, &r));
    os_mem_release(m.base, m.size);
}

// Free page reporting: the pages wholly inside each reported range are
// discarded (zero again), partial pages and other queues' buffers stay.
static void test_balloon(void)
{
    guest_mem m = new_mem(64 << 10);
    ioapic a;
    msi.n = 0;
    ioapic_init(&a, 1, record_msi, nullptr);
    ioa_write(&a, 0x10 + 2 * 5, 0x30);
    balloon *b = balloon_create(&m, &a, 5);
    CHECK(b != nullptr);
    if (!b)
        return;
    virtio_dev *d = balloon_dev(b);
    CHECK(vr(d, 0x008) == 5);
    vw(d, 0x014, 0);
    CHECK(vr(d, 0x010) == 1u << 5); // VIRTIO_BALLOON_F_REPORTING only
    uint64_t x = 1;
    virtio_mmio_access(d, 0x100, 4, false, &x);
    CHECK(x == 0); // num_pages: never inflated
    vw(d, 0x030, 2);
    CHECK(vr(d, 0x034) == 32); // a report is 32 ranges
    vw(d, 0x030, 3);
    CHECK(vr(d, 0x034) == 0);

    memset(m.base, 0, 0x8000);
    vw(d, 0x070, 0);
    vw(d, 0x070, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);
    vw(d, 0x024, 1);
    vw(d, 0x020, 1);
    vw(d, 0x024, 0);
    vw(d, 0x020, 1u << 5);
    vw(d, 0x070, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);
    CHECK(vr(d, 0x070) & VIRTIO_STATUS_FEATURES_OK);
    for (uint32_t q = 0; q < 3; q++) { // queue q's rings at Q_* + q * 0x400
        vw(d, 0x030, q);
        vw(d, 0x038, QN);
        vw(d, 0x080, Q_DESC + q * 0x400);
        vw(d, 0x090, Q_AVAIL + q * 0x400);
        vw(d, 0x0a0, Q_USED + q * 0x400);
        vw(d, 0x044, 1);
    }
    vw(d, 0x070, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK |
                     VIRTIO_STATUS_DRIVER_OK);

    memset(m.base + 0x8000, 0xab, 0x8000);
    // Reporting queue (2): two pages at 0x8000, and 0xc800..0xe000 (whose
    // first, partial page stays): the guest's writable buffers.
    uint8_t *desc = m.base + Q_DESC + 0x800, *avail = m.base + Q_AVAIL + 0x800;
    put_le64(desc, 0x8000), put_le32(desc + 8, 0x2000), put_le16(desc + 12, 3), put_le16(desc + 14, 1);
    put_le64(desc + 16, 0xc800), put_le32(desc + 24, 0x1800), put_le16(desc + 28, 2);
    put_le16(avail + 4, 0);
    put_le16(avail + 2, 1);
    vw(d, 0x050, 2);
    CHECK(get_le16(m.base + Q_USED + 0x800 + 2) == 1);
    CHECK(balloon_discarded(b) == 0x3000);
#if !defined(_WIN32) // discarding is a no-op there
    static const uint8_t zero[0x2000];
    CHECK(!memcmp(m.base + 0x8000, zero, 0x2000) && !memcmp(m.base + 0xd000, zero, 0x1000));
    CHECK(m.base[0xa000] == 0xab && m.base[0xcfff] == 0xab && m.base[0xe000] == 0xab);
#endif
    // The inflate queue (0) hands its buffer back untouched.
    desc = m.base + Q_DESC, avail = m.base + Q_AVAIL;
    put_le64(desc, 0xe000), put_le32(desc + 8, 0x1000), put_le16(desc + 12, 0);
    put_le16(avail + 4, 0);
    put_le16(avail + 2, 1);
    vw(d, 0x050, 0);
    CHECK(get_le16(m.base + Q_USED + 2) == 1);
    CHECK(balloon_discarded(b) == 0x3000 && m.base[0xe000] == 0xab);
    free(b); // one calloc
    os_mem_release(m.base, m.size);
}

int main(void)
{
    test_guest_slice();
    test_boot_params();
    test_pmem_layers();
    test_elf();
    test_uart();
    test_cmos();
    test_ioapic();
    test_mptable_ioapic();
    test_virtio();
    test_balloon();
    test_snapshot();
    printf("%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
