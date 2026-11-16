// SPDX-License-Identifier: MIT
// Fuzz the zstd decoder: layers are untrusted input. The first byte picks
// how many bytes each pull hands over; the rest is the stream.
//
// Invariants: output stays under the caps; the same input gives the same
// output (and the same verdict) however its bytes are handed over and
// however much of each peek is consumed; and an accepted stream's output,
// written again as a zstd frame of raw and RLE blocks with a content size
// and a checksum, decodes back to itself.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"
#include "image/zstd.h"
#include "image_util.h"
#include "zstd_vectors.h"

typedef struct {
    const uint8_t *p;
    size_t n, step;
} src;

static int pull(void *ctx, uint8_t *b, size_t cap, size_t *got)
{
    src *s = ctx;
    size_t k = s->n < cap ? s->n : cap;
    if (s->step && k > s->step)
        k = s->step;
    memcpy(b, s->p, k);
    s->p += k;
    s->n -= k;
    *got = k;
    return 0;
}

static const inflate_limits LIM = {.max_out = 4 << 20, .max_ratio = 300, .ratio_slack = 1 << 20},
                            LIM_SIZE = {.max_out = 4 << 20}; // for RLE rewrites

// 0 and the output in *out (malloc'ed), or -1.
static int run(const inflate_limits *lim, const uint8_t *p, size_t n, size_t step, uint8_t **out, size_t *outn)
{
    src s = {p, n, step};
    zstd_stream *z = zstd_new(lim);
    if (!z)
        abort();
    zstd_start(z, pull, &s);
    size_t cap = 4096, len = 0;
    uint8_t *o = malloc(cap);
    int rc = 0;
    for (;;) {
        const uint8_t *q;
        size_t k;
        if (zstd_peek(z, &q, &k)) {
            FUZZ_ASSERT(zstd_error(z) != nullptr);
            rc = -1;
            break;
        }
        if (!k)
            break;
        // ask for less than is there sometimes: consume must cope
        const size_t take = step > 1 && k > step ? step : k;
        if (len + take > cap) { // only when it grows: realloc is a copy under ASan
            while (len + take > cap)
                cap *= 2;
            o = realloc(o, cap);
            if (!o)
                abort();
        }
        memcpy(o + len, q, take);
        len += take;
        zstd_consume(z, take);
        FUZZ_ASSERT(len <= LIM.max_out + (128u << 10));
    }
    FUZZ_ASSERT(zstd_total_out(z) == len || rc);
    zstd_free(z);
    *out = o;
    *outn = len;
    return rc;
}

static void put_le(buf *b, uint64_t v, int n)
{
    for (int i = 0; i < n; i++)
        buf_put(b, &(uint8_t){(uint8_t)(v >> (8 * i))}, 1);
}

// p as one frame: 8-byte content size, checksum, raw blocks (RLE for runs).
static void rewrite(buf *b, const uint8_t *p, size_t n)
{
    buf_put(b, "\x28\xb5\x2f\xfd\xc4\x88", 6); // FCS 8 bytes, checksum, 128 MiB window
    put_le(b, n, 8);
    size_t i = 0;
    do {
        const size_t k = n - i < (128 << 10) ? n - i : 128 << 10;
        bool run = k > 0;
        for (size_t j = 1; run && j < k; j++)
            run = p[i + j] == p[i];
        const bool last = i + k == n;
        put_le(b, (uint64_t)last | (uint64_t)(run ? 1 : 0) << 1 | (uint64_t)k << 3, 3);
        buf_put(b, p + i, run ? 1 : k);
        i += k;
    } while (i < n);
    put_le(b, (uint32_t)zstd_xxh64(p, n, 0), 4);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!size)
        return 0;
    const size_t step = data[0] % 9; // 0: everything at once
    uint8_t *a, *b;
    size_t an, bn;
    const int ra = run(&LIM, data + 1, size - 1, 0, &a, &an);
    const int rb = run(&LIM, data + 1, size - 1, step ? step : 1, &b, &bn);
    FUZZ_ASSERT(ra == rb);
    if (!ra) {
        FUZZ_ASSERT(an == bn && (!an || !memcmp(a, b, an)));
        buf re = {0};
        rewrite(&re, a, an);
        uint8_t *c;
        size_t cn;
        FUZZ_ASSERT(!run(&LIM_SIZE, re.p, re.n, 0, &c, &cn) && cn == an && (!an || !memcmp(c, a, an)));
        free(c);
        free(re.p);
    }
    free(a);
    free(b);
    return 0;
}

static fuzz_seed seeds[32];

const fuzz_seed *fuzz_seeds(size_t *n)
{
    size_t k = 0;
    for (size_t i = 0; i < sizeof zstd_vectors / sizeof *zstd_vectors && k < 32; i++) {
        const zstd_vector *v = &zstd_vectors[i];
        if (v->zn + 1 > 4096)
            continue;
        uint8_t *s = malloc(v->zn + 1);
        if (!s)
            abort();
        s[0] = (uint8_t)(i * 5);
        memcpy(s + 1, v->z, v->zn);
        seeds[k++] = (fuzz_seed){s, v->zn + 1};
    }
    // sequences with RLE tables: literals "abcd", LL 4, offset 4, ML 3
    static const uint8_t seq[] = {3, 0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x20, 'a', 'b',
                                  'c', 'd', 0x01, 0x54, 0x04, 0x02, 0x00, 0x07};
    seeds[k++] = (fuzz_seed){seq, sizeof seq};
    *n = k;
    return seeds;
}
