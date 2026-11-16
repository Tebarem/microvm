// SPDX-License-Identifier: MIT
#include "elf.h"

constexpr size_t EHDR_SIZE = 64;
constexpr size_t PHDR_SIZE = 56;
constexpr uint32_t PT_LOAD = 1;
constexpr uint16_t EM_X86_64 = 62;

int elf_parse(elf_read_fn rd, void *ctx, uint64_t file_size, uint64_t guest_size,
              uint64_t min_gpa, elf_info *out)
{
    uint8_t eh[EHDR_SIZE];
    if (file_size < EHDR_SIZE || rd(ctx, eh, EHDR_SIZE, 0))
        return -1;
    if (memcmp(eh, "\x7f" "ELF", 4) || eh[4] != 2 /* 64-bit */ || eh[5] != 1 /* LE */)
        return -1;
    if (get_le16(eh + 18) != EM_X86_64)
        return -1;

    const uint64_t entry = get_le64(eh + 24);
    const uint64_t phoff = get_le64(eh + 32);
    const uint16_t phentsize = get_le16(eh + 54);
    const uint16_t phnum = get_le16(eh + 56);
    if (phentsize != PHDR_SIZE || phnum == 0 || phnum > ELF_MAX_SEGMENTS)
        return -1;
    uint64_t ph_end;
    if (ckd_add(&ph_end, phoff, (uint64_t)phnum * PHDR_SIZE) || ph_end > file_size)
        return -1;

    uint8_t ph[ELF_MAX_SEGMENTS * PHDR_SIZE];
    if (rd(ctx, ph, (size_t)phnum * PHDR_SIZE, phoff))
        return -1;

    elf_info info = {.entry = entry, .load_lo = UINT64_MAX, .load_hi = 0};
    bool entry_ok = false;
    for (uint16_t i = 0; i < phnum; i++) {
        const uint8_t *p = ph + (size_t)i * PHDR_SIZE;
        if (get_le32(p) != PT_LOAD)
            continue;
        const elf_segment s = {
            .off = get_le64(p + 8),
            .gpa = get_le64(p + 24),
            .filesz = get_le64(p + 32),
            .memsz = get_le64(p + 40),
            .writable = (get_le32(p + 4) & 2) != 0, // PF_W
        };
        uint64_t fend, mend;
        if (s.filesz > s.memsz || ckd_add(&fend, s.off, s.filesz) || fend > file_size)
            return -1;
        if (s.gpa < min_gpa || ckd_add(&mend, s.gpa, s.memsz) || mend > guest_size)
            return -1;
        if (s.memsz == 0)
            continue;
        for (uint16_t j = 0; j < info.nseg; j++) {
            const elf_segment *o = &info.seg[j];
            if (s.gpa < o->gpa + o->memsz && o->gpa < mend)
                return -1; // overlapping segments
        }
        info.seg[info.nseg++] = s;
        if (s.gpa < info.load_lo)
            info.load_lo = s.gpa;
        if (mend > info.load_hi)
            info.load_hi = mend;
        if (entry >= s.gpa && entry < mend)
            entry_ok = true;
    }
    if (!entry_ok)
        return -1;
    *out = info;
    return 0;
}

int elf_load(elf_read_fn rd, void *ctx, uint64_t file_size, guest_mem *m, uint64_t min_gpa,
             elf_info *out)
{
    elf_info info;
    if (elf_parse(rd, ctx, file_size, m->size, min_gpa, &info))
        return -1;
    for (uint16_t i = 0; i < info.nseg; i++) {
        const elf_segment *s = &info.seg[i];
        uint8_t *dst = guest_slice(m, s->gpa, s->memsz);
        if (!dst || (s->filesz && rd(ctx, dst, (size_t)s->filesz, s->off)))
            return -1;
        // Guest RAM starts zero-filled and demand-paged, so the bss
        // (memsz - filesz) is already zero: touching it would only cost
        // memory. Callers loading into reused memory must clear it.
    }
    *out = info;
    return 0;
}
