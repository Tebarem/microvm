// SPDX-License-Identifier: MIT
// Fuzz the DEFLATE / gzip inflater: layers are untrusted input. The first
// byte picks raw DEFLATE or gzip and how many bytes each pull hands over;
// the rest is the stream.
//
// Invariants: output stays under the caps; the same input gives the same
// output (and the same verdict) however its bytes are handed over; and an
// accepted stream's output, compressed again by tests/gzwrite.h, inflates
// back to itself.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"
#include "gzwrite.h"
#include "image/inflate.h"
#include "inflate_vectors.h"

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

static const inflate_limits LIM = {.max_out = 4 << 20, .max_ratio = 300, .ratio_slack = 1 << 20};

// 0 and the output in *out (malloc'ed), or -1.
static int run(inflate_format f, const uint8_t *p, size_t n, size_t step, uint8_t **out, size_t *outn)
{
    src s = {p, n, step};
    inflate_stream *z = inflate_new(f, &LIM);
    if (!z)
        abort();
    inflate_start(z, pull, &s);
    size_t cap = 4096, len = 0;
    uint8_t *o = malloc(cap);
    int rc = 0;
    for (;;) {
        const uint8_t *q;
        size_t k;
        if (inflate_peek(z, &q, &k)) {
            FUZZ_ASSERT(inflate_error(z) != nullptr);
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
        inflate_consume(z, take);
        FUZZ_ASSERT(len <= LIM.max_out + (512u << 10));
    }
    FUZZ_ASSERT(inflate_total_out(z) == len || rc);
    inflate_free(z);
    *out = o;
    *outn = len;
    return rc;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!size)
        return 0;
    const inflate_format f = data[0] & 1 ? INFLATE_GZIP : INFLATE_RAW;
    const size_t step = (data[0] >> 1) % 9; // 0: everything at once
    uint8_t *a, *b;
    size_t an, bn;
    const int ra = run(f, data + 1, size - 1, 0, &a, &an);
    const int rb = run(f, data + 1, size - 1, step ? step : 1, &b, &bn);
    FUZZ_ASSERT(ra == rb);
    if (!ra) {
        FUZZ_ASSERT(an == bn && (!an || !memcmp(a, b, an)));
        buf re = {0};
        if (f == INFLATE_GZIP)
            gz_gzip(&re, a, an, GZ_MIXED);
        else
            gz_deflate(&re, a, an, GZ_MIXED);
        uint8_t *c;
        size_t cn;
        FUZZ_ASSERT(!run(f, re.p, re.n, 0, &c, &cn) && cn == an && (!an || !memcmp(c, a, an)));
        free(c);
        free(re.p);
    }
    free(a);
    free(b);
    return 0;
}

static uint8_t sbuf[4][4096];
static fuzz_seed seeds[4];

const fuzz_seed *fuzz_seeds(size_t *n)
{
    sbuf[0][0] = 1;
    memcpy(sbuf[0] + 1, zlib_gz, sizeof zlib_gz);
    seeds[0] = (fuzz_seed){sbuf[0], 1 + sizeof zlib_gz};
    sbuf[1][0] = 2;
    memcpy(sbuf[1] + 1, zlib_raw, sizeof zlib_raw);
    seeds[1] = (fuzz_seed){sbuf[1], 1 + sizeof zlib_raw};
    // fixed and stored blocks, two gzip members
    const char text[] = "aaaaaaaaaabbbbbbbbbbabababababab hello hello hello world";
    buf g = {0};
    gz_gzip(&g, (const uint8_t *)text, sizeof text, GZ_FIXED);
    gz_gzip(&g, (const uint8_t *)text, 20, GZ_STORED);
    sbuf[2][0] = 5;
    memcpy(sbuf[2] + 1, g.p, g.n);
    seeds[2] = (fuzz_seed){sbuf[2], 1 + g.n};
    free(g.p);
    buf r = {0};
    gz_deflate(&r, (const uint8_t *)text, sizeof text, GZ_MIXED);
    sbuf[3][0] = 0;
    memcpy(sbuf[3] + 1, r.p, r.n);
    seeds[3] = (fuzz_seed){sbuf[3], 1 + r.n};
    free(r.p);
    *n = 4;
    return seeds;
}
