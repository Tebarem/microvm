// SPDX-License-Identifier: MIT
// Fuzz the vmlinux ELF loader: the image is untrusted input.
//
// Guest RAM is a small malloc'd buffer (not mmap) so AddressSanitizer
// catches any write the loader makes outside it.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "boot/elf.h"
#include "boot/x86.h"
#include "fuzz.h"

constexpr size_t GUEST = 4 * 1024 * 1024; // segments must land in [1 MiB, 4 MiB)

typedef struct {
    const uint8_t *p;
    size_t n;
} src;

static int rd(void *ctx, void *dst, size_t len, uint64_t off)
{
    const src *s = ctx;
    if (off > s->n || len > s->n - off)
        return -1;
    memcpy(dst, s->p + off, len);
    return 0;
}

static unsigned long long n_inputs, n_accepted;

static void stats(void)
{
    fprintf(stderr, "fuzz_elf: %llu inputs, %llu accepted\n", n_inputs, n_accepted);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static uint8_t *ram;
    if (!ram) {
        if (!(ram = malloc(GUEST)))
            abort();
        if (getenv("MVM_FUZZ_STATS"))
            atexit(stats);
    }
    n_inputs++;
    src s = {data, size};
    elf_info info;
    if (elf_parse(rd, &s, size, GUEST, X86_HIMEM_START, &info) != 0)
        return 0;
    n_accepted++;
    // Everything elf_parse accepted must be inside guest RAM, above the boot
    // structures, non-overlapping, backed by the file, with the entry inside.
    bool entry_ok = false;
    for (uint16_t i = 0; i < info.nseg; i++) {
        const elf_segment *g = &info.seg[i];
        FUZZ_ASSERT(g->gpa >= X86_HIMEM_START);
        FUZZ_ASSERT(g->memsz <= GUEST && g->gpa <= GUEST - g->memsz);
        FUZZ_ASSERT(g->filesz <= g->memsz);
        FUZZ_ASSERT(g->off <= size && g->filesz <= size - g->off);
        for (uint16_t j = 0; j < i; j++) {
            const elf_segment *h = &info.seg[j];
            FUZZ_ASSERT(g->gpa + g->memsz <= h->gpa || h->gpa + h->memsz <= g->gpa);
        }
        entry_ok |= info.entry >= g->gpa && info.entry < g->gpa + g->memsz;
    }
    FUZZ_ASSERT(entry_ok);
    guest_mem m = {.base = ram, .size = GUEST};
    elf_info again;
    FUZZ_ASSERT(elf_load(rd, &s, size, &m, X86_HIMEM_START, &again) == 0);
    FUZZ_ASSERT(again.nseg == info.nseg && again.entry == info.entry);
    return 0;
}

// ---- seeds -------------------------------------------------------------------
static uint8_t seed_two[0x400], seed_one[0x200], seed_bss[0x200];

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v, p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)v), put16(p + 2, (uint16_t)(v >> 16)); }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)v), put32(p + 4, (uint32_t)(v >> 32)); }

static void elf(uint8_t *f, size_t fsz, uint64_t entry, int nph, const uint64_t (*ph)[4])
{
    memset(f, 0, fsz);
    memcpy(f, "\x7f" "ELF", 4);
    f[4] = 2, f[5] = 1, f[6] = 1;
    put16(f + 16, 2);  // ET_EXEC
    put16(f + 18, 62); // x86-64
    put64(f + 24, entry);
    put64(f + 32, 64);
    put16(f + 52, 64);
    put16(f + 54, 56);
    put16(f + 56, (uint16_t)nph);
    for (int i = 0; i < nph; i++) {
        uint8_t *p = f + 64 + 56 * i;
        put32(p, 1);
        put32(p + 4, 5);
        put64(p + 8, ph[i][0]);  // offset
        put64(p + 16, ph[i][1] | 0xffffffff80000000ull);
        put64(p + 24, ph[i][1]); // paddr
        put64(p + 32, ph[i][2]); // filesz
        put64(p + 40, ph[i][3]); // memsz
        put64(p + 48, 0x1000);
    }
    for (size_t i = 0x180; i < fsz; i++)
        f[i] = (uint8_t)(i * 7);
}

const fuzz_seed *fuzz_seeds(size_t *n)
{
    static const uint64_t two[2][4] = {{0x200, 0x100000, 0x100, 0x100}, {0x300, 0x200000, 0x100, 0x3000}};
    static const uint64_t one[1][4] = {{0x180, 0x180000, 0x80, 0x80}};
    static const uint64_t bss[1][4] = {{0x100, 0x3ff000, 0x10, 0x1000}};
    elf(seed_two, sizeof seed_two, 0x100010, 2, two);
    elf(seed_one, sizeof seed_one, 0x180000, 1, one);
    elf(seed_bss, sizeof seed_bss, 0x3ff000, 1, bss);
    static fuzz_seed s[3];
    s[0] = (fuzz_seed){seed_two, sizeof seed_two};
    s[1] = (fuzz_seed){seed_one, sizeof seed_one};
    s[2] = (fuzz_seed){seed_bss, sizeof seed_bss};
    *n = 3;
    return s;
}
