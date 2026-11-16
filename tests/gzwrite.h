// SPDX-License-Identifier: MIT
// A small DEFLATE / gzip writer for tests and test-image tools: stored
// blocks, or fixed-Huffman blocks with greedy LZ77 matching. Written from
// RFC 1951/1952 independently of src/image/inflate.c, which it tests. Not
// fast and not a good compressor; it doesn't need to be.
#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "image/inflate.h" // crc32_update
#include "image_util.h"

typedef struct {
    buf *b;
    uint64_t bits;
    unsigned n;
} gz_bits;

static inline void gz_bits_put(gz_bits *w, uint32_t v, unsigned n)
{
    w->bits |= (uint64_t)v << w->n;
    w->n += n;
    while (w->n >= 8) {
        const uint8_t c = (uint8_t)w->bits;
        buf_put(w->b, &c, 1);
        w->bits >>= 8;
        w->n -= 8;
    }
}

static inline void gz_bits_align(gz_bits *w)
{
    if (w->n)
        gz_bits_put(w, 0, 8 - w->n);
}

// A Huffman code: sent most significant bit first.
static inline void gz_code(gz_bits *w, uint32_t code, unsigned len)
{
    uint32_t r = 0;
    for (unsigned i = 0; i < len; i++)
        r = r << 1 | ((code >> i) & 1);
    gz_bits_put(w, r, len);
}

static inline void gz_fixed_sym(gz_bits *w, unsigned v)
{
    if (v < 144)
        gz_code(w, 0x30 + v, 8);
    else if (v < 256)
        gz_code(w, 0x190 + (v - 144), 9);
    else if (v < 280)
        gz_code(w, v - 256, 7);
    else
        gz_code(w, 0xc0 + (v - 280), 8);
}

static const uint16_t gz_lbase[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                                      31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
static const uint8_t gz_lext[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                    2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
static const uint16_t gz_dbase[30] = {1,    2,    3,    4,    5,    7,    9,    13,    17,    25,
                                      33,   49,   65,   97,   129,  193,  257,  385,   513,   769,
                                      1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
static const uint8_t gz_dext[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
                                    6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

static inline void gz_match(gz_bits *w, unsigned len, unsigned dist)
{
    int i = 28;
    while (gz_lbase[i] > len)
        i--;
    if (len == 258)
        i = 28;
    else if (i == 28)
        i = 27; // 258 has its own code; 227..257 use 284
    gz_fixed_sym(w, 257 + (unsigned)i);
    gz_bits_put(w, len - gz_lbase[i], gz_lext[i]);
    int d = 29;
    while (gz_dbase[d] > dist)
        d--;
    gz_code(w, (uint32_t)d, 5);
    gz_bits_put(w, dist - gz_dbase[d], gz_dext[d]);
}

typedef enum { GZ_STORED, GZ_FIXED, GZ_MIXED } gz_mode;

// Raw DEFLATE of in[0..n) into b. GZ_MIXED alternates stored and fixed
// blocks of varying sizes (seeded by n), to exercise block boundaries.
static inline void gz_deflate(buf *b, const uint8_t *in, size_t n, gz_mode mode)
{
    gz_bits w = {b, 0, 0};
    enum { HBITS = 15 };
    int32_t *head = malloc(sizeof(int32_t) << HBITS);
    if (!head)
        abort();
    for (size_t i = 0; i < (1u << HBITS); i++)
        head[i] = -1;
    uint64_t rng = n * 0x9e3779b97f4a7c15ull + 1;
    size_t pos = 0;
    do {
        size_t blk = n - pos;
        bool fixed = mode != GZ_STORED;
        if (mode == GZ_MIXED) {
            rng ^= rng << 13, rng ^= rng >> 7, rng ^= rng << 17;
            fixed = rng & 1;
            const size_t cap = 1 + (size_t)(rng >> 8) % 70000;
            if (blk > cap)
                blk = cap;
        }
        if (!fixed && blk > 65535)
            blk = 65535;
        const bool final = pos + blk == n;
        gz_bits_put(&w, final | (fixed ? 1u : 0u) << 1, 3);
        if (!fixed) {
            gz_bits_align(&w);
            const uint16_t len = (uint16_t)blk, nlen = (uint16_t)~len;
            const uint8_t h[4] = {(uint8_t)len, (uint8_t)(len >> 8), (uint8_t)nlen, (uint8_t)(nlen >> 8)};
            buf_put(b, h, 4);
            buf_put(b, in + pos, blk);
            pos += blk;
            continue;
        }
        const size_t end = pos + blk;
        while (pos < end) {
            unsigned best = 0, bdist = 0;
            if (end - pos >= 3) {
                const uint32_t h = ((uint32_t)in[pos] << 16 | (uint32_t)in[pos + 1] << 8 | in[pos + 2]) *
                                   2654435761u >> (32 - HBITS);
                const int32_t cand = head[h];
                head[h] = (int32_t)pos;
                if (cand >= 0 && pos - (size_t)cand <= 32768) {
                    unsigned l = 0;
                    while (l < 258 && pos + l < end && in[(size_t)cand + l] == in[pos + l])
                        l++;
                    if (l >= 3)
                        best = l, bdist = (unsigned)(pos - (size_t)cand);
                }
            }
            if (best) {
                gz_match(&w, best, bdist);
                pos += best;
            } else {
                gz_fixed_sym(&w, in[pos++]);
            }
        }
        gz_fixed_sym(&w, 256);
    } while (pos < n);
    gz_bits_align(&w);
    free(head);
}

static inline void gz_le32(buf *b, uint32_t v)
{
    const uint8_t x[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
    buf_put(b, x, 4);
}

// One gzip member.
static inline void gz_gzip(buf *b, const uint8_t *in, size_t n, gz_mode mode)
{
    static const uint8_t h[10] = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3};
    buf_put(b, h, sizeof h);
    gz_deflate(b, in, n, mode);
    gz_le32(b, crc32_update(0, in, n));
    gz_le32(b, (uint32_t)n);
}
