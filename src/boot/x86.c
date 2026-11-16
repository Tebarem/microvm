// SPDX-License-Identifier: MIT
#include "x86.h"

#include "../dev/devices.h"

// ---- page tables: identity map the first 1 GiB with 2 MiB pages --------
int x86_write_page_tables(guest_mem *m)
{
    uint8_t *pml4 = guest_slice(m, X86_PML4_ADDR, 4096);
    uint8_t *pdpt = guest_slice(m, X86_PDPT_ADDR, 4096);
    uint8_t *pd = guest_slice(m, X86_PD_ADDR, 4096);
    if (!pml4 || !pdpt || !pd)
        return -1;
    constexpr uint64_t P = 1;
    constexpr uint64_t RW = 2;
    constexpr uint64_t PS = 0x80;
    put_le64(pml4, X86_PDPT_ADDR | P | RW);
    put_le64(pdpt, X86_PD_ADDR | P | RW);
    for (uint64_t i = 0; i < 512; i++)
        put_le64(pd + i * 8, (i << 21) | P | RW | PS);
    return 0;
}

// ---- GDT ------------------------------------------------------------------
#define GDT_ENTRY(flags, base, limit)                                                   \
    ((((uint64_t)(base) & 0xff000000ull) << 32) | (((uint64_t)(flags) & 0x0000f0ffull) << 40) | \
     (((uint64_t)(limit) & 0x000f0000ull) << 32) | (((uint64_t)(base) & 0x00ffffffull) << 16) | \
     ((uint64_t)(limit) & 0x0000ffffull))

static constexpr uint64_t GDT[] = {
    0,                                // null
    GDT_ENTRY(0xa09b, 0, 0xfffff),    // 0x08: 64-bit code
    GDT_ENTRY(0xc093, 0, 0xfffff),    // 0x10: data
    GDT_ENTRY(0x808b, 0, 0xfffff),    // 0x18: TSS
};

int x86_write_gdt(guest_mem *m)
{
    uint8_t *g = guest_slice(m, X86_GDT_ADDR, sizeof GDT);
    uint8_t *idt = guest_slice(m, X86_IDT_ADDR, 8);
    if (!g || !idt)
        return -1;
    for (size_t i = 0; i < MVM_ARRAY_LEN(GDT); i++)
        put_le64(g + i * 8, GDT[i]);
    put_le64(idt, 0);
    return 0;
}

// ---- Linux zero page ------------------------------------------------------
static void e820_add(uint8_t *bp, uint64_t addr, uint64_t size, uint32_t type)
{
    uint8_t n = bp[BP_E820_ENTRIES];
    uint8_t *e = bp + BP_E820_TABLE + (size_t)n * 20;
    put_le64(e, addr);
    put_le64(e + 8, size);
    put_le32(e + 16, type);
    bp[BP_E820_ENTRIES] = (uint8_t)(n + 1);
}

int x86_write_boot_params(guest_mem *m, const x86_boot_cfg *cfg)
{
    uint8_t *bp = guest_slice(m, X86_ZERO_PAGE, BP_SIZE);
    if (!bp || m->size <= X86_HIMEM_START)
        return -1;
    memset(bp, 0, BP_SIZE);

    size_t len = cfg->cmdline ? strlen(cfg->cmdline) : 0;
    if (len + 1 > X86_CMDLINE_MAX)
        return -1;
    uint8_t *cl = guest_slice(m, X86_CMDLINE_ADDR, len + 1);
    if (!cl)
        return -1;
    if (len)
        memcpy(cl, cfg->cmdline, len);
    cl[len] = 0;

    put_le16(bp + BP_BOOT_FLAG, 0xaa55);
    put_le32(bp + BP_HEADER, 0x53726448); // "HdrS"
    put_le16(bp + BP_VERSION, 0x020f);
    bp[BP_TYPE_OF_LOADER] = 0xff;
    bp[BP_LOADFLAGS] = 0x01; // LOADED_HIGH
    put_le32(bp + BP_CMD_LINE_PTR, (uint32_t)X86_CMDLINE_ADDR);
    put_le32(bp + BP_CMDLINE_SIZE, (uint32_t)len);
    put_le32(bp + BP_KERNEL_ALIGNMENT, 0x01000000);
    if (cfg->initrd_size) {
        if (cfg->initrd_gpa > UINT32_MAX || cfg->initrd_size > UINT32_MAX)
            return -1;
        put_le32(bp + BP_RAMDISK_IMAGE, (uint32_t)cfg->initrd_gpa);
        put_le32(bp + BP_RAMDISK_SIZE, (uint32_t)cfg->initrd_size);
    }

    e820_add(bp, 0, X86_EBDA_START, E820_RAM);
    e820_add(bp, X86_EBDA_START, X86_HIMEM_START - X86_EBDA_START, E820_RESERVED);
    e820_add(bp, X86_HIMEM_START, m->size - X86_HIMEM_START, E820_RAM);
    // Each image its own range, apart from the last: touching ranges of one
    // type become one in the guest's e820 table.
    if (cfg->npmem > X86_PMEM_MAX)
        return -1;
    uint64_t prev_end = m->size;
    for (uint32_t i = 0; i < cfg->npmem; i++) {
        uint64_t end;
        if (cfg->pmem_gpa[i] < prev_end || (i && cfg->pmem_gpa[i] == prev_end) || cfg->pmem_gpa[i] % 4096 ||
            !cfg->pmem_size[i] || cfg->pmem_size[i] % 4096 || ckd_add(&end, cfg->pmem_gpa[i], cfg->pmem_size[i]))
            return -1;
        e820_add(bp, cfg->pmem_gpa[i], cfg->pmem_size[i], E820_PRAM);
        prev_end = end;
    }
    return 0;
}

int x86_pmem_layout(uint32_t n, const uint64_t *size, uint64_t *gpa, uint64_t *span)
{
    constexpr uint64_t A = 2ull << 20;
    if (!n || n > X86_PMEM_MAX)
        return -1;
    uint64_t at = X86_PMEM_GPA;
    for (uint32_t i = 0; i < n; i++) {
        if (!size[i] || size[i] % 4096 || size[i] > X86_PMEM_SPAN_MAX)
            return -1;
        gpa[i] = at;
        at += size[i]; // both under 2^37: no overflow
        if (at - X86_PMEM_GPA > X86_PMEM_SPAN_MAX)
            return -1;
        *span = at - X86_PMEM_GPA;
        at = (at + A - 1) / A * A + A;
    }
    return 0;
}

// ---- Intel MP table (MP spec 1.4) -----------------------------------------
// Lists the CPUs and, if devices need interrupts, the I/O APIC with one
// entry per pin in use. Without devices the guest runs in APIC mode with the
// local APIC timer and never touches an I/O APIC, PIC or PIT.
static uint8_t checksum(const uint8_t *p, size_t n)
{
    uint8_t s = 0;
    for (size_t i = 0; i < n; i++)
        s = (uint8_t)(s + p[i]);
    return (uint8_t)(0 - s);
}

int x86_write_mptable(guest_mem *m, uint32_t ncpus, uint32_t irq_pins)
{
    if (ncpus == 0 || ncpus > 254 || (irq_pins >> IOAPIC_PINS))
        return -1;
    constexpr size_t MPF_SIZE = 16;
    constexpr size_t MPC_HDR = 44;
    constexpr size_t PROC = 20;
    constexpr size_t BUS = 8;
    constexpr size_t IOAPIC_E = 8;
    constexpr size_t LINT = 8;
    constexpr size_t INTSRC = 8;
    const size_t nint = irq_pins ? (size_t)__builtin_popcount(irq_pins) : 1;
    const size_t mpc_len =
        MPC_HDR + ncpus * PROC + BUS + (irq_pins ? IOAPIC_E : 0) + nint * INTSRC + 2 * LINT;
    uint8_t *mpf = guest_slice(m, X86_MPTABLE_ADDR, MPF_SIZE + mpc_len);
    if (!mpf || X86_MPTABLE_ADDR + MPF_SIZE + mpc_len > X86_HIMEM_START)
        return -1;
    memset(mpf, 0, MPF_SIZE + mpc_len);
    const uint64_t mpc_addr = X86_MPTABLE_ADDR + MPF_SIZE;
    uint8_t *mpc = mpf + MPF_SIZE;

    memcpy(mpf, "_MP_", 4);
    put_le32(mpf + 4, (uint32_t)mpc_addr);
    mpf[8] = 1; // length in 16-byte units
    mpf[9] = 4; // spec rev 1.4

    memcpy(mpc, "PCMP", 4);
    put_le16(mpc + 4, (uint16_t)mpc_len);
    mpc[6] = 4;
    memcpy(mpc + 8, "MICROVM ", 8);
    memcpy(mpc + 16, "000000000000", 12);
    put_le16(mpc + 34, (uint16_t)(ncpus + 1 + (irq_pins ? 1 : 0) + nint + 2)); // entry count
    put_le32(mpc + 36, 0xfee00000);            // LAPIC base

    uint8_t *e = mpc + MPC_HDR;
    for (uint32_t i = 0; i < ncpus; i++, e += PROC) {
        e[0] = 0;                          // processor
        e[1] = (uint8_t)i;                 // APIC id
        e[2] = 0x14;                       // APIC version
        e[3] = (uint8_t)(1 | (i == 0 ? 2 : 0)); // enabled | BSP
        put_le32(e + 4, 0x600);            // signature: family 6
        put_le32(e + 8, 0x201);            // features: APIC | FPU
    }
    e[0] = 1; // bus
    e[1] = 0;
    memcpy(e + 2, "ISA   ", 6);
    e += BUS;
    const uint8_t ioapic_id = (uint8_t)ncpus; // after the local APICs
    if (irq_pins) {
        e[0] = 2; // I/O APIC
        e[1] = ioapic_id;
        e[2] = 0x11; // version
        e[3] = 1;    // enabled
        put_le32(e + 4, (uint32_t)IOAPIC_BASE);
        e += IOAPIC_E;
        for (unsigned pin = 0; pin < IOAPIC_PINS; pin++) {
            if (!(irq_pins & (1u << pin)))
                continue;
            e[0] = 3; // I/O interrupt
            e[1] = 0; // INT
            put_le16(e + 2, 0x5); // active high (01), edge (01)
            e[4] = 0; // ISA bus
            e[5] = (uint8_t)pin;
            e[6] = ioapic_id;
            e[7] = (uint8_t)pin;
            e += INTSRC;
        }
    } else {
        // One I/O interrupt source (ISA IRQ 0 -> I/O APIC 0 pin 2, the PC
        // default). There is no I/O APIC, so it is never used, but without
        // any I/O interrupt entry Linux prints an 80-byte "BIOS bug" warning
        // even under `quiet` (~160 VM exits on the serial console) and
        // builds a default table instead.
        e[0] = 3; // I/O interrupt
        e[1] = 0; // INT
        e[4] = 0; // ISA bus
        e[5] = 0; // IRQ 0
        e[6] = 0; // I/O APIC id
        e[7] = 2; // pin
        e += INTSRC;
    }
    // Local interrupt sources: LINT0 = ExtINT, LINT1 = NMI.
    for (int lint = 0; lint < 2; lint++, e += LINT) {
        e[0] = 4;
        e[1] = lint == 0 ? 3 : 1;
        e[6] = 0xff; // all local APICs
        e[7] = (uint8_t)lint;
    }
    mpc[7] = checksum(mpc, mpc_len);
    mpf[10] = checksum(mpf, MPF_SIZE);
    return 0;
}

// ---- initial vCPU state: 64-bit long mode, paging on ------------------------
void x86_initial_state(uint64_t entry, hv_regs *r, hv_sregs *s)
{
    memset(r, 0, sizeof *r);
    memset(s, 0, sizeof *s);
    r->rip = entry;
    r->rsp = r->rbp = X86_BOOT_STACK;
    r->rsi = X86_ZERO_PAGE;
    r->rflags = 0x2;

    const hv_segment code = {.selector = 0x08, .limit = 0xfffff, .type = 0xb, .present = 1,
                             .s = 1, .l = 1, .g = 1};
    const hv_segment data = {.selector = 0x10, .limit = 0xfffff, .type = 0x3, .present = 1,
                             .s = 1, .db = 1, .g = 1};
    s->cs = code;
    s->ds = s->es = s->fs = s->gs = s->ss = data;
    s->tr = (hv_segment){.selector = 0x18, .limit = 0xfffff, .type = 0xb, .present = 1, .g = 1};
    s->ldt = (hv_segment){.type = 0x2, .present = 1, .limit = 0xffff};
    s->gdt = (hv_dtable){.base = X86_GDT_ADDR, .limit = sizeof GDT - 1};
    s->idt = (hv_dtable){.base = X86_IDT_ADDR, .limit = 7};
    s->cr3 = X86_PML4_ADDR;
    s->cr4 = 1u << 5;                       // PAE
    s->cr0 = (1u << 0) | (1u << 4) | (1u << 31); // PE | ET | PG
    s->efer = (1u << 8) | (1u << 10);       // LME | LMA
}

int x86_setup_boot(guest_mem *m, const x86_boot_cfg *cfg, hv_regs *regs, hv_sregs *sregs)
{
    if (x86_write_page_tables(m) || x86_write_gdt(m) || x86_write_boot_params(m, cfg) ||
        x86_write_mptable(m, cfg->ncpus ? cfg->ncpus : 1, cfg->irq_pins))
        return -1;
    x86_initial_state(cfg->entry, regs, sregs);
    return 0;
}
