// SPDX-License-Identifier: MIT
// Tests for the zstd decoder (src/image/zstd.c): XXH64, vectors made by the
// zstd CLI (tests/zstd_vectors.h), streaming with small pulls and partial
// consumes, every truncation and bit flip of some vectors, and hand-made
// frames for each error and limit.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "image/sha256.h"
#include "image/zstd.h"
#include "image_util.h"
#include "zstd_vectors.h"

static const inflate_limits NOLIM = {0};

// Decompress; returns the error, or nullptr with the output in *out (if out).
static const char *unz(const void *in, size_t n, const inflate_limits *lim, buf *out)
{
    uint8_t *o;
    size_t on;
    const char *err = nullptr;
    if (zstd_mem(in, n, lim ? lim : &NOLIM, &o, &on, &err))
        return err;
    if (out) {
        *out = (buf){0};
        buf_put(out, o, on);
    }
    free(o);
    return nullptr;
}

static bool sha_is(const uint8_t *p, size_t n, const char *want)
{
    uint8_t d[32];
    char hex[65];
    sha256(p, n, d);
    sha256_hex(d, hex);
    return !strcmp(hex, want);
}

#define CHECK_ERR(expr, sub)                                                             \
    do {                                                                                 \
        const char *e_ = (expr);                                                         \
        CHECK(e_ && strstr(e_, sub));                                                    \
        if (!e_ || !strstr(e_, sub))                                                     \
            fprintf(stderr, "  wanted an error with \"%s\", got \"%s\"\n", sub,          \
                    e_ ? e_ : "(success)");                                              \
    } while (0)

static void test_xxh64(void)
{
    CHECK(zstd_xxh64("", 0, 0) == 0xEF46DB3751D8E999ull);
    CHECK(zstd_xxh64("a", 1, 0) == 0xD24EC4F1A98C6E5Bull);
    CHECK(zstd_xxh64("abc", 3, 0) == 0x44BC2CF5AD770999ull);
    const char *s = "Nobody inspects the spammish repetition";
    CHECK(zstd_xxh64(s, strlen(s), 0) == 0xFBCEA83C8A378BF1ull);
}

static void test_vectors(void)
{
    for (size_t i = 0; i < sizeof zstd_vectors / sizeof *zstd_vectors; i++) {
        const zstd_vector *v = &zstd_vectors[i];
        buf o = {0};
        const char *e = unz(v->z, v->zn, nullptr, &o);
        const bool ok = !e && o.n == v->n && sha_is(o.p, o.n, v->sha256);
        CHECK(ok);
        if (!ok)
            fprintf(stderr, "  vector %s: %s (%zu bytes, wanted %zu)\n", v->name, e ? e : "wrong output",
                    o.n, v->n);
        free(o.p);
    }
}

typedef struct {
    const uint8_t *p;
    size_t n, step; // at most step bytes per pull
} pull_src;

static int pull_mem(void *ctx, uint8_t *b, size_t cap, size_t *got)
{
    pull_src *s = ctx;
    size_t k = s->n < cap ? s->n : cap;
    if (k > s->step)
        k = s->step;
    memcpy(b, s->p, k);
    s->p += k, s->n -= k;
    *got = k;
    return 0;
}

// Pull step bytes at a time, consume at most take bytes per peek.
static bool stream_ok(const zstd_vector *v, size_t step, size_t take)
{
    zstd_stream *s = zstd_new(&NOLIM);
    pull_src src = {v->z, v->zn, step};
    zstd_start(s, pull_mem, &src);
    sha256_ctx h;
    sha256_init(&h);
    size_t total = 0;
    bool ok = true;
    for (;;) {
        const uint8_t *p;
        size_t n;
        if (zstd_peek(s, &p, &n)) {
            fprintf(stderr, "  %s: %s\n", v->name, zstd_error(s));
            ok = false;
            break;
        }
        if (!n)
            break;
        if (n > take)
            n = take;
        sha256_update(&h, p, n);
        zstd_consume(s, n);
        total += n;
    }
    // restarting gives the same again, through zstd_read
    pull_src again = {v->z, v->zn, v->zn + 1};
    zstd_start(s, pull_mem, &again);
    uint8_t *all = malloc(v->n + 1);
    size_t got = 0;
    ok = ok && all && !zstd_read(s, all, v->n + 1, &got) && got == v->n &&
         sha_is(all, got, v->sha256) && zstd_total_out(s) == v->n && zstd_total_in(s) == v->zn;
    free(all);
    zstd_free(s);
    uint8_t d[32];
    char hex[65];
    sha256_final(&h, d);
    sha256_hex(d, hex);
    return ok && total == v->n && !strcmp(hex, v->sha256);
}

[[gnu::noinline]] static const zstd_vector *vec(const char *name)
{
    for (size_t i = 0; i < sizeof zstd_vectors / sizeof *zstd_vectors; i++)
        if (!strcmp(zstd_vectors[i].name, name))
            return &zstd_vectors[i];
    abort();
}

static void test_streaming(void)
{
    CHECK(stream_ok(vec("small_l22"), 1, 1));
    CHECK(stream_ok(vec("text_l19"), 7, 100));
    CHECK(stream_ok(vec("period_wlog17"), 4093, 1 << 20));
    CHECK(stream_ok(vec("short_period_wlog10"), 1, 333));
    CHECK(stream_ok(vec("concatenated"), 3, 17));
    CHECK(stream_ok(vec("zeros"), 1, 65536));
}

// Every strict prefix of a one-frame vector is an error, and so is every
// bit flip of a checksummed one unless the output is still right (a flip
// in a field that doesn't change it, such as a window size).
static void test_damage(void)
{
    static const char *const names[] = {"small_l22", "small_nocheck", "one", "noise", "mixed_l7"};
    for (size_t k = 0; k < sizeof names / sizeof *names; k++) {
        const zstd_vector *v = vec(names[k]);
        bool all_fail = true;
        for (size_t n = 0; n < v->zn; n++)
            all_fail &= unz(v->z, n, nullptr, nullptr) != nullptr;
        CHECK(all_fail);
        if (!all_fail)
            fprintf(stderr, "  %s: a truncation decoded\n", v->name);
    }
    for (int k = 0; k < 2; k++) {
        const zstd_vector *v = vec(k ? "small_nocheck" : "small_l22");
        uint8_t *m = malloc(v->zn);
        size_t bad = 0, decoded = 0;
        for (size_t i = 0; i < v->zn; i++)
            for (int b = 0; b < 8; b++) {
                memcpy(m, v->z, v->zn);
                m[i] ^= (uint8_t)(1 << b);
                buf o = {0};
                if (!unz(m, v->zn, nullptr, &o)) {
                    decoded++;
                    if (!k && (o.n != v->n || !sha_is(o.p, o.n, v->sha256)))
                        bad++;
                }
                free(o.p);
            }
        CHECK(!bad);
        fprintf(stderr, "  %s: %zu of %zu bit flips still decode\n", v->name, decoded, v->zn * 8);
        free(m);
    }
}

// ---- hand-made frames ----------------------------------------------------------------
static void put(buf *b, const char *bytes, size_t n) { buf_put(b, bytes, n); }
#define PUT(b, s) put(b, s, sizeof s - 1)

static void frame(buf *b, const char *hdr, size_t n) // magic + header
{
    *b = (buf){0};
    PUT(b, "\x28\xb5\x2f\xfd");
    put(b, hdr, n);
}

[[gnu::noinline]] static void block_hdr(buf *b, bool last, unsigned type, size_t size)
{
    const uint32_t v = (uint32_t)last | type << 1 | (uint32_t)size << 3;
    const uint8_t h[3] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16)};
    buf_put(b, h, 3);
}

static const char *one_block(const char *content, size_t n, buf *out)
{
    buf f;
    frame(&f, "\x00\x00", 2); // no size, no checksum, a 1 KiB window
    block_hdr(&f, true, 2, n);
    put(&f, content, n);
    const char *e = unz(f.p, f.n, nullptr, out);
    free(f.p);
    return e;
}

static void test_handmade(void)
{
    buf f, o = {0};
    // Sequences with RLE tables (no state bits): the extra bits alone.
    // literals "abcd" (raw); a sequence of LL 4, offset 4 (code 2 + 3), ML 3.
    CHECK(!one_block("\x20" "abcd" "\x01\x54\x04\x02\x00\x07", 11, &o) && o.n == 7 &&
          !memcmp(o.p, "abcdabc", 7));
    free(o.p);
    // offset 1, match length 8 (code 5): an overlapping copy
    CHECK(!one_block("\x20" "abcd" "\x01\x54\x04\x02\x05\x04", 11, &o) && o.n == 12 &&
          !memcmp(o.p, "abcddddddddd", 12));
    free(o.p);
    // RLE literals (5 of them), no sequences
    CHECK(!one_block("\x29q\x00", 3, &o) && o.n == 5 && !memcmp(o.p, "qqqqq", 5));
    free(o.p);
    // 3-byte literal headers (5000 literals), raw and RLE, in a 128 KiB window
    for (int k = 0; k < 2; k++) {
        frame(&f, "\x00\x38", 2);
        block_hdr(&f, true, 2, k ? 5 : 5004);
        put(&f, k ? "\x8d\x38\x01" "r" : "\x8c\x38\x01", k ? 4 : 3);
        if (!k)
            for (int i = 0; i < 5000; i++)
                buf_put(&f, &(uint8_t){(uint8_t)(i * 13)}, 1);
        PUT(&f, "\x00");
        bool ok = !unz(f.p, f.n, nullptr, &o) && o.n == 5000;
        for (int i = 0; ok && i < 5000; i++)
            ok = o.p[i] == (k ? 'r' : (uint8_t)(i * 13));
        CHECK(ok);
        free(o.p);
        free(f.p);
    }
    // 0x7f00 sequences (the 3-byte count), each 1 literal and a 3-byte
    // match at repeat offset 1: no extra bits at all
    {
        enum { N = 0x7f00 };
        frame(&f, "\x00\x38", 2);
        block_hdr(&f, true, 2, 3 + N + 3 + 1 + 3 + 1);
        PUT(&f, "\x0c\xf0\x07"); // N raw literals
        for (int i = 0; i < N; i++)
            buf_put(&f, &(uint8_t){(uint8_t)(i * 13)}, 1);
        PUT(&f, "\xff\x00\x00" "\x54" "\x01\x00\x00" "\x01");
        bool ok = !unz(f.p, f.n, nullptr, &o) && o.n == 4 * N;
        for (int i = 0; ok && i < 4 * N; i++)
            ok = o.p[i] == (uint8_t)(i / 4 * 13);
        CHECK(ok);
        free(o.p);
        free(f.p);
    }
    CHECK_ERR(one_block("\x00\x01\x54\x00\x05\x00\x20", 7, nullptr), "past the window");
    CHECK_ERR(one_block("\x00\x01\x54\x24\x05\x00\x20", 7, nullptr), "bad RLE sequence table");
    CHECK_ERR(one_block("\x00\x01\xfc\x01", 4, nullptr), "repeats one there isn't");
    CHECK_ERR(one_block("\x00\x01\x01\x01", 4, nullptr), "reserved bits");
    CHECK_ERR(one_block("\x00\x00\x00", 3, nullptr), "bytes after an empty sequences section");
    CHECK_ERR(one_block("\x13\x40\x00\x02\x00", 5, nullptr), "reuse a Huffman tree");
    CHECK_ERR(one_block("\x00", 1, nullptr), "without a sequences section");
    CHECK_ERR(one_block("", 0, nullptr), "without a literals section");
    // literals running past the block
    CHECK_ERR(one_block("\x30" "abcd" "\x00", 6, nullptr), "raw literals run past"); // 6 of them

    // Offsets are bounded by the window, not just the output: two 1000-byte
    // raw blocks in a 1 KiB window, then offset 1000 (fine) and 1500 (not).
    for (int k = 0; k < 2; k++) {
        frame(&f, "\x00\x00", 2);
        uint8_t raw[1000];
        for (int r = 0; r < 2; r++) {
            for (int i = 0; i < 1000; i++)
                raw[i] = (uint8_t)(i * 7 + r);
            block_hdr(&f, false, 0, 1000);
            buf_put(&f, raw, 1000);
        }
        block_hdr(&f, true, 2, 8);
        if (k)
            PUT(&f, "\x00\x01\x54\x00\x0a\x00\xdf\x05"); // offset 1503 - 3
        else
            PUT(&f, "\x00\x01\x54\x00\x09\x00\xeb\x03"); // offset 1003 - 3
        const char *e = unz(f.p, f.n, nullptr, &o);
        if (k)
            CHECK_ERR(e, "past the window");
        else
            CHECK(!e && o.n == 2003 && o.p[2000] == 1 && o.p[2001] == 8 && o.p[2002] == 15);
        if (!e)
            free(o.p);
        free(f.p);
    }

    // frame headers
    frame(&f, "\x08\x00", 2);
    block_hdr(&f, true, 0, 0);
    CHECK_ERR(unz(f.p, f.n, nullptr, nullptr), "reserved bit");
    free(f.p);
    frame(&f, "\x01\x00\x05", 3);
    block_hdr(&f, true, 0, 0);
    CHECK_ERR(unz(f.p, f.n, nullptr, nullptr), "dictionary");
    free(f.p);
    frame(&f, "\x01\x00\x00", 3); // dictionary id 0: none
    block_hdr(&f, true, 0, 0);
    CHECK(!unz(f.p, f.n, nullptr, nullptr));
    free(f.p);
    frame(&f, "\x00\x88", 2); // exactly 128 MiB
    block_hdr(&f, true, 1, 5);
    PUT(&f, "z");
    CHECK(!unz(f.p, f.n, nullptr, &o) && o.n == 5 && !memcmp(o.p, "zzzzz", 5));
    free(o.p);
    free(f.p);
    frame(&f, "\x00\x89", 2); // 144 MiB
    block_hdr(&f, true, 0, 0);
    CHECK_ERR(unz(f.p, f.n, nullptr, nullptr), "larger than 128 MiB");
    free(f.p);
    frame(&f, "\x00\x00", 2);
    block_hdr(&f, true, 3, 0);
    CHECK_ERR(unz(f.p, f.n, nullptr, nullptr), "reserved block type");
    free(f.p);
    frame(&f, "\x00\x00", 2);
    block_hdr(&f, true, 0, 1025);
    buf_zero(&f, 1025);
    CHECK_ERR(unz(f.p, f.n, nullptr, nullptr), "larger than the maximum");
    free(f.p);
    // content sizes (single segment, 1 byte)
    frame(&f, "\x20\x05", 2);
    block_hdr(&f, true, 0, 3);
    PUT(&f, "abc");
    CHECK_ERR(unz(f.p, f.n, nullptr, nullptr), "shorter than its header says");
    free(f.p);
    frame(&f, "\x20\x02", 2);
    block_hdr(&f, true, 0, 3);
    PUT(&f, "abc");
    CHECK_ERR(unz(f.p, f.n, nullptr, nullptr), "larger than the maximum"); // the window is 2 bytes
    free(f.p);
    frame(&f, "\x60\x01\x00", 3); // 2-byte size: 257 + 1
    block_hdr(&f, false, 1, 200);
    PUT(&f, "a");
    block_hdr(&f, true, 1, 100);
    PUT(&f, "b");
    CHECK_ERR(unz(f.p, f.n, nullptr, nullptr), "longer than its header says");
    free(f.p);
    frame(&f, "\x60\x02\x00", 3); // 258: right
    block_hdr(&f, false, 1, 200);
    PUT(&f, "a");
    block_hdr(&f, true, 1, 58);
    PUT(&f, "b");
    CHECK(!unz(f.p, f.n, nullptr, &o) && o.n == 258 && o.p[199] == 'a' && o.p[200] == 'b');
    free(o.p);
    free(f.p);

    // checksums, and what may follow a frame
    const zstd_vector *v = vec("small_l22");
    uint8_t *m = malloc(v->zn + 4);
    memcpy(m, v->z, v->zn);
    m[v->zn - 1] ^= 1;
    CHECK_ERR(unz(m, v->zn, nullptr, nullptr), "checksum mismatch");
    memcpy(m, v->z, v->zn);
    memcpy(m + v->zn, "\x28\xb5\x2f", 3);
    CHECK_ERR(unz(m, v->zn + 3, nullptr, nullptr), "trailing bytes");
    memcpy(m + v->zn, "\x00\x00\x00\x00", 4);
    CHECK_ERR(unz(m, v->zn + 4, nullptr, nullptr), "trailing bytes");
    free(m);
    CHECK_ERR(unz("hello", 5, nullptr, nullptr), "not zstd");
    CHECK_ERR(unz("", 0, nullptr, nullptr), "no frame");
    CHECK_ERR(unz("\x50\x2a\x4d\x18\x00\x00\x00\x00", 8, nullptr, nullptr), "no frame");
    CHECK_ERR(unz("\x50\x2a\x4d\x18\x0a\x00\x00\x00" "abc", 11, nullptr, nullptr), "truncated skippable");
    CHECK_ERR(unz("\x28\xb5\x2f\xfd\x00", 5, nullptr, nullptr), "truncated frame header");
}

static void test_limits(void)
{
    // RLE blocks: 4 bytes make 128 KiB
    buf f;
    frame(&f, "\x00\x38", 2); // a 128 KiB window
    for (int i = 0; i < 200; i++) {
        block_hdr(&f, i == 199, 1, 128 << 10);
        PUT(&f, "x");
    }
    CHECK_ERR(unz(f.p, f.n, &(inflate_limits){.max_ratio = 200, .ratio_slack = 1 << 20}, nullptr), "ratio");
    CHECK_ERR(unz(f.p, f.n, &(inflate_limits){.max_out = 1 << 20}, nullptr), "size cap");
    buf o = {0};
    CHECK(!unz(f.p, f.n, nullptr, &o) && o.n == 200ull * (128 << 10));
    free(o.p);
    free(f.p);
    // a frame that says it is bigger than the cap is refused at its header
    frame(&f, "\x80\x00\x00\x00\x00\x40", 6); // a 4-byte size: 1 GiB
    CHECK_ERR(unz(f.p, f.n, &(inflate_limits){.max_out = 1 << 20}, nullptr), "says it decompresses past");
    free(f.p);
    // a new Huffman tree per byte of output (direct weights: two 1-bit codes)
    frame(&f, "\x00\x00", 2);
    for (int i = 0; i < 6000; i++) {
        block_hdr(&f, false, 2, 7);
        PUT(&f, "\x12\xc0\x00\x80\x10\x02\x00");
    }
    block_hdr(&f, true, 0, 0);
    CHECK_ERR(unz(f.p, f.n, nullptr, nullptr), "too many table builds");
    free(f.p);
    // ... which decodes when there are few of them
    frame(&f, "\x00\x00", 2);
    for (int i = 0; i < 100; i++) {
        block_hdr(&f, false, 2, 7);
        PUT(&f, "\x12\xc0\x00\x80\x10\x02\x00");
    }
    block_hdr(&f, true, 0, 0);
    CHECK(!unz(f.p, f.n, nullptr, &o) && o.n == 100 && !o.p[0] && !o.p[99]);
    free(o.p);
    free(f.p);
}

int main(void)
{
    test_xxh64();
    test_vectors();
    test_streaming();
    test_damage();
    test_handmade();
    test_limits();
    printf("%d checks, %d failures\n", checks, failures);
    return failures != 0;
}
