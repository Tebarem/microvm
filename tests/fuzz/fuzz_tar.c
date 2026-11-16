// SPDX-License-Identifier: MIT
// Fuzz the tar layer reader and the EROFS writer: image layers are
// untrusted input. The input is split at its first 0xA5 0x5A pair into two
// layers (a lower and an upper one), so whiteouts and replacements across
// layers get exercised too.
//
// Invariants on every accepted input: the image is a whole number of 4 KiB
// blocks, starts with an EROFS superblock whose block count covers exactly
// the image, and the same layers always give the same bytes.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"
#include "image/fstree.h"

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

typedef struct {
    uint8_t *p;
    size_t n, cap;
} sink;

static int wr(void *ctx, const void *data, size_t len)
{
    sink *s = ctx;
    if (len > (64u << 20) - s->n) // writes past 64 MiB: refuse (and test that path)
        return -1;
    if (s->n + len > s->cap) {
        size_t c = s->cap ? s->cap : 65536;
        while (c < s->n + len)
            c *= 2;
        uint8_t *np = realloc(s->p, c);
        if (!np)
            abort();
        s->p = np;
        s->cap = c;
    }
    memcpy(s->p + s->n, data, len);
    s->n += len;
    return 0;
}

static unsigned long long n_inputs, n_accepted;

static void stats(void)
{
    fprintf(stderr, "fuzz_tar: %llu inputs, %llu accepted\n", n_inputs, n_accepted);
}

static int build(const src *layers, size_t nl, sink *out)
{
    fs_tree t;
    if (fs_tree_init(&t))
        abort();
    const char *err = "";
    int rc = 0;
    for (size_t i = 0; i < nl && !rc; i++) {
        const fs_source s = {rd, (void *)&layers[i], layers[i].n};
        rc = fs_import_tar(&t, &s, &err);
    }
    if (!rc)
        rc = erofs_write(&t, &(fs_sink){wr, out}, &err);
    FUZZ_ASSERT(!rc || err != nullptr);
    fs_tree_free(&t);
    return rc;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static bool init;
    if (!init) {
        init = true;
        if (getenv("MVM_FUZZ_STATS"))
            atexit(stats);
    }
    n_inputs++;
    src layers[2] = {{data, size}, {nullptr, 0}};
    size_t nl = 1;
    for (size_t i = 0; i + 1 < size; i++) {
        if (data[i] == 0xA5 && data[i + 1] == 0x5A) {
            layers[0].n = i;
            layers[1] = (src){data + i + 2, size - i - 2};
            nl = 2;
            break;
        }
    }
    sink a = {0}, b = {0};
    if (build(layers, nl, &a) == 0) {
        n_accepted++;
        FUZZ_ASSERT(a.n >= 4096 && a.n % 4096 == 0);
        const uint8_t *sb = a.p + 1024;
        FUZZ_ASSERT((sb[0] | sb[1] << 8 | sb[2] << 16 | (uint32_t)sb[3] << 24) == 0xE0F5E1E2u);
        const uint32_t blocks = sb[36] | sb[37] << 8 | sb[38] << 16 | (uint32_t)sb[39] << 24;
        FUZZ_ASSERT((uint64_t)blocks * 4096 == a.n);
        FUZZ_ASSERT(build(layers, nl, &b) == 0);
        FUZZ_ASSERT(a.n == b.n && !memcmp(a.p, b.p, a.n));
    }
    free(a.p);
    free(b.p);
    return 0;
}

// Seeds: small valid layers (ustar file + dir + symlink + hard link; pax;
// a whiteout in an upper layer).
static uint8_t seed_buf[3][8192];
static fuzz_seed seeds[3];

static size_t hdr(uint8_t *p, const char *name, char type, size_t size, const char *link)
{
    memset(p, 0, 512);
    memcpy(p, name, strlen(name));
    memcpy(p + 100, "0000644", 7);
    memcpy(p + 108, "0000000", 7);
    memcpy(p + 116, "0000000", 7);
    snprintf((char *)p + 124, 12, "%011zo", size);
    memcpy(p + 136, "00000000000", 11);
    p[156] = (uint8_t)type;
    if (link)
        memcpy(p + 157, link, strlen(link));
    memcpy(p + 257, "ustar\0" "00", 8);
    memset(p + 148, ' ', 8);
    unsigned s = 0;
    for (int i = 0; i < 512; i++)
        s += p[i];
    snprintf((char *)p + 148, 8, "%06o", s);
    return 512;
}

const fuzz_seed *fuzz_seeds(size_t *n)
{
    uint8_t *p = seed_buf[0];
    size_t k = 0;
    k += hdr(p + k, "bin/", '5', 0, nullptr);
    k += hdr(p + k, "bin/sh", '0', 5, nullptr);
    memcpy(p + k, "hello", 5);
    k += 512;
    k += hdr(p + k, "bin/ash", '2', 0, "sh");
    k += hdr(p + k, "bin/sh2", '1', 0, "bin/sh");
    seeds[0] = (fuzz_seed){p, k + 1024};

    p = seed_buf[1];
    k = 0;
    const char rec[] = "20 path=long/pax/nm\n";
    k += hdr(p + k, "PaxHeader", 'x', sizeof rec - 1, nullptr);
    memcpy(p + k, rec, sizeof rec - 1);
    k += 512;
    k += hdr(p + k, "short", '0', 2, nullptr);
    memcpy(p + k, "ok", 2);
    k += 512;
    seeds[1] = (fuzz_seed){p, k + 1024};

    p = seed_buf[2];
    k = 0;
    k += hdr(p + k, "d/a", '0', 0, nullptr);
    k += hdr(p + k, "d/b", '0', 0, nullptr);
    k += 1024;
    p[k++] = 0xA5;
    p[k++] = 0x5A;
    k += hdr(p + k, "d/.wh.a", '0', 0, nullptr);
    k += hdr(p + k, "d/.wh..wh..opq", '0', 0, nullptr);
    seeds[2] = (fuzz_seed){p, k + 1024};
    *n = 3;
    return seeds;
}
