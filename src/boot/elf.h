// SPDX-License-Identifier: MIT
// Loader for an uncompressed x86-64 vmlinux (ELF64, PT_LOAD at p_paddr).
#pragma once

#include "../mem.h"

// Reads exactly len bytes at off from the image; returns 0 on success.
typedef int (*elf_read_fn)(void *ctx, void *buf, size_t len, uint64_t off);

constexpr uint16_t ELF_MAX_SEGMENTS = 64;

typedef struct {
    uint64_t gpa;    // p_paddr
    uint64_t off;    // p_offset
    uint64_t filesz; // bytes taken from the file
    uint64_t memsz;  // filesz + zero-filled tail
    bool writable;   // PF_W
} elf_segment;

typedef struct {
    uint64_t entry;    // guest-physical entry point
    uint64_t load_lo;  // lowest loaded GPA
    uint64_t load_hi;  // one past the highest loaded GPA (incl. bss)
    uint16_t nseg;
    elf_segment seg[ELF_MAX_SEGMENTS];
} elf_info;

// Parse and validate the image without loading it. The image is untrusted
// input: every offset/size is bounds-checked against the file size and
// guest_size, segments must sit at or above min_gpa (so they can't clobber
// the boot structures), must not overlap, and the entry point must be
// inside a segment.
[[nodiscard]] int elf_parse(elf_read_fn rd, void *ctx, uint64_t file_size, uint64_t guest_size,
                            uint64_t min_gpa, elf_info *out);

// elf_parse + copy every segment into guest memory. Guest RAM must be
// fresh (zero-filled): the bss tail is not cleared.
[[nodiscard]] int elf_load(elf_read_fn rd, void *ctx, uint64_t file_size, guest_mem *m,
                           uint64_t min_gpa, elf_info *out);
