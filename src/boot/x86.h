// SPDX-License-Identifier: MIT
// x86-64 direct boot: long-mode entry straight into the kernel's startup_64,
// Linux boot protocol "zero page", e820 map and an MP table.
#pragma once

#include "../hv.h"
#include "../mem.h"

// Guest-physical layout of the boot structures (all below 1 MiB).
constexpr uint64_t X86_GDT_ADDR = 0x500;
constexpr uint64_t X86_IDT_ADDR = 0x520;
constexpr uint64_t X86_ZERO_PAGE = 0x7000;
constexpr uint64_t X86_BOOT_STACK = 0x8ff0;
constexpr uint64_t X86_PML4_ADDR = 0x9000;
constexpr uint64_t X86_PDPT_ADDR = 0xa000;
constexpr uint64_t X86_PD_ADDR = 0xb000;
constexpr uint64_t X86_CMDLINE_ADDR = 0x20000;
constexpr uint64_t X86_CMDLINE_MAX = 2048; // Linux x86 COMMAND_LINE_SIZE
constexpr uint64_t X86_EBDA_START = 0x9fc00;
constexpr uint64_t X86_MPTABLE_ADDR = X86_EBDA_START;
constexpr uint64_t X86_HIMEM_START = 0x100000;

// Offsets inside struct boot_params (Documentation/arch/x86/zero-page.rst).
constexpr size_t BP_E820_ENTRIES = 0x1e8;
constexpr size_t BP_BOOT_FLAG = 0x1fe;
constexpr size_t BP_HEADER = 0x202;
constexpr size_t BP_VERSION = 0x206;
constexpr size_t BP_TYPE_OF_LOADER = 0x210;
constexpr size_t BP_LOADFLAGS = 0x211;
constexpr size_t BP_RAMDISK_IMAGE = 0x218;
constexpr size_t BP_RAMDISK_SIZE = 0x21c;
constexpr size_t BP_CMD_LINE_PTR = 0x228;
constexpr size_t BP_KERNEL_ALIGNMENT = 0x230;
constexpr size_t BP_CMDLINE_SIZE = 0x238;
constexpr size_t BP_E820_TABLE = 0x2d0;
constexpr size_t BP_E820_MAX = 128;
constexpr size_t BP_SIZE = 4096;

constexpr uint32_t E820_RAM = 1;
constexpr uint32_t E820_RESERVED = 2;
constexpr uint32_t E820_PRAM = 12; // legacy persistent memory: Linux's pmem driver

// Where --rootfs images appear in guest-physical memory: above the 32-bit
// hole, clear of RAM (at most 3 GiB) and the LAPIC. Each layer is its own
// e820 persistent-memory range (the guest's /dev/pmem0, 1, ... in order),
// 2 MiB-aligned with a 2 MiB hole between them so the guest never merges
// two into one (x86_pmem_layout).
constexpr uint64_t X86_PMEM_GPA = 0x100000000ull;
constexpr uint32_t X86_PMEM_MAX = 8;
constexpr uint64_t X86_PMEM_SPAN_MAX = 64ull << 30;

typedef struct {
    const char *cmdline;
    uint64_t entry;       // guest-physical kernel entry (startup_64)
    uint64_t initrd_gpa;  // 0 if none
    uint64_t initrd_size;
    // Read-only images at [pmem_gpa[i], +pmem_size[i]), ascending and apart.
    uint32_t npmem;
    uint64_t pmem_gpa[X86_PMEM_MAX];
    uint64_t pmem_size[X86_PMEM_MAX];
    uint32_t ncpus;
    uint32_t irq_pins;    // I/O APIC pins devices use (bit n = pin n); 0: no I/O APIC
} x86_boot_cfg;

// Where n layers of these sizes (each a nonzero multiple of 4 KiB) go:
// gpa[i], from X86_PMEM_GPA up, and the span they take, from X86_PMEM_GPA
// to the end of the last. Fails if n is 0 or over X86_PMEM_MAX, a size is
// bad, or the span is over X86_PMEM_SPAN_MAX.
[[nodiscard]] int x86_pmem_layout(uint32_t n, const uint64_t *size, uint64_t *gpa, uint64_t *span);

[[nodiscard]] int x86_write_page_tables(guest_mem *m);
[[nodiscard]] int x86_write_gdt(guest_mem *m);
[[nodiscard]] int x86_write_boot_params(guest_mem *m, const x86_boot_cfg *cfg);
// With irq_pins nonzero, the I/O APIC (IOAPIC_BASE) is listed too, each of
// those pins as an edge-triggered, active-high ISA interrupt of the same
// number (Linux IRQ n = pin n).
[[nodiscard]] int x86_write_mptable(guest_mem *m, uint32_t ncpus, uint32_t irq_pins);
void x86_initial_state(uint64_t entry, hv_regs *regs, hv_sregs *sregs);

// All of the above.
[[nodiscard]] int x86_setup_boot(guest_mem *m, const x86_boot_cfg *cfg, hv_regs *regs,
                                 hv_sregs *sregs);
