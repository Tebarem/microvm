// SPDX-License-Identifier: MIT
// Tests for container images: SHA-256, the gzip/DEFLATE inflater, the JSON
// parser, and OCI image layouts / docker-archives to EROFS, hostile images
// included. Every image is built here (tests/ociwrite.h, tests/gzwrite.h):
// no network, no external tools.
//
//   mvm_oci_tests                      run the tests
//   mvm_oci_tests --write-sample DIR   write DIR/layout (an OCI layout) and
//                                      DIR/docker.tar (a docker-archive)
//   mvm_oci_tests --check-sample IMG.erofs [CONFIG]
//                                      check an image made from either
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <direct.h>
#  define mkdir_one(p) _mkdir(p)
#else
#  include <sys/stat.h>
#  define mkdir_one(p) mkdir((p), 0755)
#endif

#include "gzwrite.h"
#include "image/inflate.h"
#include "image/json.h"
#include "image/oci.h"
#include "image/sha256.h"
#include "image_util.h"
#include "inflate_vectors.h"
#include "zstd_vectors.h"
#include "ociwrite.h"

static bool has(const char *s, const char *sub) { return s && strstr(s, sub); }

#define CHECK_ERR(err, sub)                                                                   \
    do {                                                                                      \
        const char *e_ = (err);                                                               \
        CHECK(has(e_, sub));                                                                  \
        if (!has(e_, sub))                                                                    \
            fprintf(stderr, "  error was: %s (wanted '%s')\n", e_ ? e_ : "(none)", sub);       \
    } while (0)

static uint64_t rng = 0x243f6a8885a308d3ull;
static uint64_t rnd(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

// ---- SHA-256 ------------------------------------------------------------------------
static void hex_of(const void *p, size_t n, char out[65])
{
    uint8_t d[32];
    sha256(p, n, d);
    sha256_hex(d, out);
}

static void test_sha256(void)
{
    static const struct {
        const char *in, *out;
    } v[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrl"
         "mnopqrsmnopqrstnopqrstu",
         "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
    };
    for (int pass = 0; pass < 2; pass++) {
        sha256_force_portable(pass == 0);
        char h[65];
        for (size_t i = 0; i < MVM_ARRAY_LEN(v); i++) {
            hex_of(v[i].in, strlen(v[i].in), h);
            CHECK(!strcmp(h, v[i].out));
        }
        // a million 'a', in uneven pieces
        static uint8_t a[1000];
        memset(a, 'a', sizeof a);
        sha256_ctx c;
        sha256_init(&c);
        for (size_t done = 0, k = 1; done < 1000000; k = k % 999 + 1) {
            const size_t n = done + k > 1000000 ? 1000000 - done : k;
            sha256_update(&c, a, n);
            done += n;
        }
        uint8_t d[32];
        sha256_final(&c, d);
        sha256_hex(d, h);
        CHECK(!strcmp(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    }
    // the CPU's implementation against the portable one
    uint8_t data[1500];
    for (size_t i = 0; i < sizeof data; i++)
        data[i] = (uint8_t)rnd();
    bool same = true;
    for (size_t n = 0; n <= sizeof data; n += 1 + n / 8) {
        uint8_t x[32], y[32];
        sha256_force_portable(true);
        sha256(data, n, x);
        sha256_force_portable(false);
        sha256_ctx c;
        sha256_init(&c);
        const size_t cut = n ? (size_t)(rnd() % n) : 0;
        sha256_update(&c, data, cut);
        sha256_update(&c, data + cut, n - cut);
        sha256_final(&c, y);
        same &= !memcmp(x, y, 32);
    }
    CHECK(same);
    fprintf(stderr, "sha256: %s\n", sha256_impl());
    CHECK(crc32_update(0, "123456789", 9) == 0xcbf43926u);
    CHECK(crc32_update(crc32_update(0, "1234", 4), "56789", 5) == 0xcbf43926u);
}

// ---- inflate ------------------------------------------------------------------------
static void text_vector(buf *b)
{
    for (int i = 0; i < 120; i++)
        ow_printf(b, "line %d: the quick brown fox jumps over the lazy dog %d\n", i, i * i % 97);
}

// Decompress; returns the error, or nullptr with the output in *out.
static const char *infl(inflate_format f, const void *in, size_t n, const inflate_limits *lim, buf *out)
{
    uint8_t *o;
    size_t on;
    const char *err = nullptr;
    if (inflate_mem(f, in, n, lim, &o, &on, &err))
        return err;
    if (out) {
        *out = (buf){0};
        buf_put(out, o, on);
    }
    free(o);
    return nullptr;
}

static bool infl_eq(inflate_format f, const void *in, size_t n, const void *want, size_t wn)
{
    buf o = {0};
    const char *e = infl(f, in, n, nullptr, &o);
    const bool ok = !e && o.n == wn && (!wn || !memcmp(o.p, want, wn));
    if (!ok)
        fprintf(stderr, "  inflate: %s (%zu bytes, wanted %zu)\n", e ? e : "wrong output", o.n, wn);
    free(o.p);
    return ok;
}

typedef struct {
    const uint8_t *p;
    size_t n, step; // step: at most this many bytes per pull (0: all)
} pull_src;

static int pull_mem(void *ctx, uint8_t *b, size_t cap, size_t *got)
{
    pull_src *s = ctx;
    size_t k = s->n < cap ? s->n : cap;
    if (s->step && k > s->step)
        k = s->step;
    memcpy(b, s->p, k);
    s->p += k;
    s->n -= k;
    *got = k;
    return 0;
}

// Stream through without keeping the output: the error or nullptr. *total:
// bytes out; *crc: their CRC-32.
static const char *drain(inflate_format f, const void *in, size_t n, size_t step,
                         const inflate_limits *lim, uint64_t *total, uint32_t *crc)
{
    pull_src s = {in, n, step};
    inflate_stream *z = inflate_new(f, lim);
    if (!z)
        abort();
    inflate_start(z, pull_mem, &s);
    const char *err = nullptr;
    *total = 0;
    if (crc)
        *crc = 0;
    for (;;) {
        const uint8_t *p;
        size_t k;
        if (inflate_peek(z, &p, &k)) {
            err = inflate_error(z);
            break;
        }
        if (!k)
            break;
        if (crc)
            *crc = crc32_update(*crc, p, k);
        *total += k;
        inflate_consume(z, k);
    }
    inflate_free(z);
    return err;
}

static void fill_data(uint8_t *p, size_t n, int kind)
{
    for (size_t i = 0; i < n; i++) {
        switch (kind) {
        case 0: p[i] = 0; break;
        case 1: p[i] = (uint8_t)rnd(); break;
        case 2: p[i] = "abcabcabd hello world\n"[i % 22] ^ (uint8_t)(i % 4099 == 0); break;
        default: p[i] = (i / 1000) % 2 ? (uint8_t)rnd() : (uint8_t)(i % 7); break;
        }
    }
}

static void test_inflate_vectors(void)
{
    buf t = {0};
    text_vector(&t);
    CHECK(infl_eq(INFLATE_RAW, zlib_raw, sizeof zlib_raw, t.p, t.n));
    CHECK(infl_eq(INFLATE_GZIP, zlib_gz, sizeof zlib_gz, t.p, t.n));
    // one byte per pull: every refill takes the slow path
    uint64_t total;
    uint32_t crc;
    CHECK(!drain(INFLATE_GZIP, zlib_gz, sizeof zlib_gz, 1, nullptr, &total, &crc) && total == t.n &&
          crc == crc32_update(0, t.p, t.n));
    // every strict prefix of a valid stream is an error
    bool all = true;
    for (size_t k = 0; k < sizeof zlib_gz; k++)
        all &= infl(INFLATE_GZIP, zlib_gz, k, nullptr, nullptr) != nullptr;
    CHECK(all);
    // any single flipped bit is caught (CRC-32 at the latest)
    all = true;
    uint8_t m[sizeof zlib_gz];
    for (size_t k = 0; k < sizeof m * 8; k += 7) {
        memcpy(m, zlib_gz, sizeof m);
        m[k / 8] ^= (uint8_t)(1u << (k % 8));
        if (k / 8 >= 4 && k / 8 < 9)
            continue; // MTIME, XFL: not checked (no FHCRC)
        if (k / 8 == 9 || k == 3 * 8)
            continue; // OS byte, FTEXT
        // refused, or (a padding bit after the last block) the same output
        buf o = {0};
        if (!infl(INFLATE_GZIP, m, sizeof m, nullptr, &o)) {
            all &= o.n == t.n && !memcmp(o.p, t.p, t.n);
            free(o.p);
        }
    }
    CHECK(all);
    // two members: their outputs concatenated
    buf two = {0};
    buf_put(&two, zlib_gz, sizeof zlib_gz);
    buf_put(&two, zlib_gz, sizeof zlib_gz);
    buf tt = {0};
    buf_put(&tt, t.p, t.n);
    buf_put(&tt, t.p, t.n);
    CHECK(infl_eq(INFLATE_GZIP, two.p, two.n, tt.p, tt.n));
    // data after the last member
    buf_put(&two, "\0", 1);
    CHECK_ERR(infl(INFLATE_GZIP, two.p, two.n, nullptr, nullptr), "after the end");
    free(two.p);
    free(tt.p);
    free(t.p);
}

static void test_inflate_roundtrip(void)
{
    static const size_t sizes[] = {0, 1, 2, 3, 4, 100, 258, 259, 32768, 32769, 65535, 65536,
                                   70000, 300001, 1u << 21};
    for (size_t si = 0; si < MVM_ARRAY_LEN(sizes); si++) {
        for (int kind = 0; kind < 4; kind++) {
            const size_t n = sizes[si];
            uint8_t *d = malloc(n + 1);
            fill_data(d, n, kind);
            for (int mode = 0; mode < 3; mode++) {
                buf raw = {0}, gz = {0};
                gz_deflate(&raw, d, n, (gz_mode)mode);
                gz_gzip(&gz, d, n, (gz_mode)mode);
                if (!infl_eq(INFLATE_RAW, raw.p, raw.n, d, n) ||
                    !infl_eq(INFLATE_GZIP, gz.p, gz.n, d, n)) {
                    fprintf(stderr, "  roundtrip size %zu kind %d mode %d\n", n, kind, mode);
                    CHECK(false);
                }
                uint64_t total;
                uint32_t crc;
                CHECK(!drain(INFLATE_GZIP, gz.p, gz.n, 13, nullptr, &total, &crc) && total == n &&
                      crc == crc32_update(0, d, n));
                free(raw.p);
                free(gz.p);
            }
            free(d);
        }
    }
}

// ---- hand-made dynamic blocks -----------------------------------------------------
static void canon(const uint8_t *len, unsigned n, uint16_t *code)
{
    unsigned count[16] = {0}, next[16];
    for (unsigned i = 0; i < n; i++)
        count[len[i]]++;
    count[0] = 0;
    unsigned c = 0;
    for (unsigned l = 1; l < 16; l++) {
        c = (c + count[l - 1]) << 1;
        next[l] = c;
    }
    for (unsigned i = 0; i < n; i++)
        code[i] = len[i] ? (uint16_t)next[len[i]]++ : 0;
}

static const uint8_t CL_ORDER[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

// A dynamic block header: code-length code with 4-bit codes for 0..12 and
// 5-bit codes for 13..18 (complete), lengths sent one symbol each.
static void dyn_header(gz_bits *w, bool final, const uint8_t *ll, unsigned hlit, const uint8_t *dl,
                       unsigned hdist, uint16_t *llc, uint16_t *dlc)
{
    uint8_t cl[19];
    for (int i = 0; i < 19; i++)
        cl[i] = i <= 12 ? 4 : 5;
    uint16_t clc[19];
    canon(cl, 19, clc);
    gz_bits_put(w, (final ? 1u : 0u) | 2u << 1, 3);
    gz_bits_put(w, hlit - 257, 5);
    gz_bits_put(w, hdist - 1, 5);
    gz_bits_put(w, 19 - 4, 4);
    for (int i = 0; i < 19; i++)
        gz_bits_put(w, cl[CL_ORDER[i]], 3);
    for (unsigned i = 0; i < hlit; i++)
        gz_code(w, clc[ll[i]], cl[ll[i]]);
    for (unsigned i = 0; i < hdist; i++)
        gz_code(w, clc[dl[i]], cl[dl[i]]);
    canon(ll, hlit, llc);
    canon(dl, hdist, dlc);
}

// A deflate bomb: one dynamic block whose length-258 code and distance-1
// code are 1 bit each, so 2 bits make 258 bytes (~1032:1).
static void make_bomb(buf *b, size_t matches)
{
    uint8_t ll[286] = {0}, dl[1] = {1};
    ll[0] = 2, ll[256] = 2, ll[285] = 1;
    uint16_t llc[286], dlc[1];
    gz_bits w = {b, 0, 0};
    dyn_header(&w, true, ll, 286, dl, 1, llc, dlc);
    gz_code(&w, llc[0], 2);
    for (size_t i = 0; i < matches; i++) {
        gz_code(&w, llc[285], 1);
        gz_code(&w, dlc[0], 1);
    }
    gz_code(&w, llc[256], 2);
    gz_bits_align(&w);
}

static const char *raw_bits(void (*fn)(gz_bits *))
{
    buf b = {0};
    gz_bits w = {&b, 0, 0};
    fn(&w);
    gz_bits_align(&w);
    const char *e = infl(INFLATE_RAW, b.p, b.n, nullptr, nullptr);
    free(b.p);
    return e;
}

static void bad_type(gz_bits *w) { gz_bits_put(w, 1 | 3 << 1, 3); }
static void bad_sym286(gz_bits *w)
{
    gz_bits_put(w, 1 | 1 << 1, 3);
    gz_fixed_sym(w, 286);
}
static void bad_dist30(gz_bits *w)
{
    gz_bits_put(w, 1 | 1 << 1, 3);
    gz_fixed_sym(w, 'a');
    gz_fixed_sym(w, 257);
    gz_code(w, 30, 5);
}
static void too_far0(gz_bits *w)
{
    gz_bits_put(w, 1 | 1 << 1, 3);
    gz_match(w, 3, 1); // nothing before it
}
static void too_far1(gz_bits *w)
{
    gz_bits_put(w, 1 | 1 << 1, 3);
    gz_fixed_sym(w, 'a');
    gz_match(w, 3, 2);
}
static void oversubscribed_cl(gz_bits *w)
{
    gz_bits_put(w, 1 | 2 << 1, 3);
    gz_bits_put(w, 0, 5);
    gz_bits_put(w, 0, 5);
    gz_bits_put(w, 15, 4);
    for (int i = 0; i < 19; i++)
        gz_bits_put(w, 1, 3); // 19 one-bit codes
}
static void incomplete_cl(gz_bits *w)
{
    gz_bits_put(w, 1 | 2 << 1, 3);
    gz_bits_put(w, 0, 5);
    gz_bits_put(w, 0, 5);
    gz_bits_put(w, 0, 4);
    gz_bits_put(w, 0, 3), gz_bits_put(w, 0, 3), gz_bits_put(w, 0, 3);
    gz_bits_put(w, 1, 3); // only symbol 0, one bit: incomplete
}
static void no_eob(gz_bits *w)
{
    uint8_t ll[257] = {0}, dl[1] = {0};
    ll[0] = 1, ll[1] = 1;
    uint16_t a[257], b[1];
    dyn_header(w, true, ll, 257, dl, 1, a, b);
}
static void incomplete_ll(gz_bits *w)
{
    uint8_t ll[257] = {0}, dl[1] = {0};
    ll[0] = 2, ll[1] = 2, ll[256] = 2;
    uint16_t a[257], b[1];
    dyn_header(w, true, ll, 257, dl, 1, a, b);
}
static void oversubscribed_dist(gz_bits *w)
{
    uint8_t ll[257] = {0}, dl[3] = {1, 1, 1};
    ll[0] = 1, ll[256] = 1;
    uint16_t a[257], b[3];
    dyn_header(w, true, ll, 257, dl, 3, a, b);
}
static void too_many_codes(gz_bits *w)
{
    gz_bits_put(w, 1 | 2 << 1, 3);
    gz_bits_put(w, 30, 5); // 287 literal/length codes
    gz_bits_put(w, 0, 5);
    gz_bits_put(w, 0, 4);
}
static void repeat_first(gz_bits *w)
{
    // code-length code: symbols 16 and 0, one bit each
    gz_bits_put(w, 1 | 2 << 1, 3);
    gz_bits_put(w, 0, 5);
    gz_bits_put(w, 0, 5);
    gz_bits_put(w, 0, 4);
    gz_bits_put(w, 1, 3); // 16
    gz_bits_put(w, 0, 3); // 17
    gz_bits_put(w, 0, 3); // 18
    gz_bits_put(w, 1, 3); // 0
    gz_code(w, 1, 1);     // 16 first: nothing to repeat
}
static void repeat_past_end(gz_bits *w)
{
    // symbols 18 and 1 (one bit each): 1, then 138 zeros twice = past 258
    gz_bits_put(w, 1 | 2 << 1, 3);
    gz_bits_put(w, 0, 5);
    gz_bits_put(w, 0, 5);
    gz_bits_put(w, 14, 4); // through symbol 1
    for (int i = 0; i < 18; i++)
        gz_bits_put(w, CL_ORDER[i] == 18 || CL_ORDER[i] == 1 ? 1 : 0, 3);
    gz_code(w, 0, 1); // symbol 1 (lower symbol: code 0)
    gz_code(w, 1, 1);
    gz_bits_put(w, 127, 7);
    gz_code(w, 1, 1);
    gz_bits_put(w, 127, 7);
}
static void tiny_blocks(gz_bits *w)
{
    uint8_t ll[257] = {0}, dl[1] = {0};
    ll[256] = 1;
    uint16_t a[257], b[1];
    for (int i = 0; i < 2000; i++) {
        dyn_header(w, i == 1999, ll, 257, dl, 1, a, b);
        gz_code(w, a[256], 1);
    }
}

static void test_inflate_errors(void)
{
    static const uint8_t stored_bad[] = {0x01, 5, 0, 0xfa, 0xfe, 'h', 'e', 'l', 'l', 'o'};
    static const uint8_t stored_ok[] = {0x01, 5, 0, 0xfa, 0xff, 'h', 'e', 'l', 'l', 'o'};
    static const uint8_t stored_short[] = {0x01, 5, 0, 0xfa, 0xff, 'h', 'e'};
    CHECK(infl_eq(INFLATE_RAW, stored_ok, sizeof stored_ok, "hello", 5));
    CHECK_ERR(infl(INFLATE_RAW, stored_bad, sizeof stored_bad, nullptr, nullptr), "length check");
    CHECK_ERR(infl(INFLATE_RAW, stored_short, sizeof stored_short, nullptr, nullptr), "ends early");
    CHECK_ERR(infl(INFLATE_RAW, "", 0, nullptr, nullptr), "ends early");
    CHECK_ERR(raw_bits(bad_type), "block type");
    CHECK_ERR(raw_bits(bad_sym286), "length symbol");
    CHECK_ERR(raw_bits(bad_dist30), "distance symbol");
    CHECK_ERR(raw_bits(too_far0), "too far back");
    CHECK_ERR(raw_bits(too_far1), "too far back");
    CHECK_ERR(raw_bits(oversubscribed_cl), "code-length code");
    CHECK_ERR(raw_bits(incomplete_cl), "code-length code");
    CHECK_ERR(raw_bits(no_eob), "end-of-block");
    CHECK_ERR(raw_bits(incomplete_ll), "literal/length code");
    CHECK_ERR(raw_bits(oversubscribed_dist), "distance code");
    CHECK_ERR(raw_bits(too_many_codes), "too many");
    CHECK_ERR(raw_bits(repeat_first), "nothing to repeat");
    CHECK_ERR(raw_bits(repeat_past_end), "past the end");
    CHECK_ERR(raw_bits(tiny_blocks), "tiny Huffman blocks");

    // gzip headers and trailers
    buf g = {0};
    gz_gzip(&g, (const uint8_t *)"hello", 5, GZ_FIXED);
    uint8_t *m = malloc(g.n + 64);
#define MUTATE(off, val, sub)                                                \
    do {                                                                     \
        memcpy(m, g.p, g.n);                                                 \
        m[(off) < 0 ? (long)g.n + (off) : (off)] = (uint8_t)(val);           \
        CHECK_ERR(infl(INFLATE_GZIP, m, g.n, nullptr, nullptr), sub);        \
    } while (0)
    MUTATE(0, 0x1e, "not gzip");
    MUTATE(2, 7, "compression method");
    MUTATE(3, 0x20, "reserved");
    MUTATE(-8, g.p[g.n - 8] ^ 1, "CRC-32");
    MUTATE(-4, g.p[g.n - 4] ^ 1, "size");
#undef MUTATE
    // every optional header field, with a header CRC
    buf h = {0};
    const uint8_t h0[10] = {0x1f, 0x8b, 8, 4 | 8 | 16 | 2, 1, 2, 3, 4, 0, 3};
    buf_put(&h, h0, 10);
    buf_put(&h, "\3\0abc", 5);       // FEXTRA
    buf_put(&h, "name.tar\0", 9);    // FNAME
    buf_put(&h, "a comment\0", 10);  // FCOMMENT
    const uint32_t hc = crc32_update(0, h.p, h.n);
    const uint8_t hcrc[2] = {(uint8_t)hc, (uint8_t)(hc >> 8)};
    buf_put(&h, hcrc, 2);
    buf_put(&h, g.p + 10, g.n - 10);
    CHECK(infl_eq(INFLATE_GZIP, h.p, h.n, "hello", 5));
    h.p[h.n - (g.n - 10) - 1] ^= 1; // the header CRC
    CHECK_ERR(infl(INFLATE_GZIP, h.p, h.n, nullptr, nullptr), "header CRC");
    free(h.p);
    free(m);
    free(g.p);
}

static void test_inflate_bombs(void)
{
    // ~1032:1, 128 KiB in: stopped by the ratio cap long before its 270 MB
    buf b = {0};
    make_bomb(&b, 128 * 1024 * 4);
    uint64_t total;
    const inflate_limits lim = {.max_out = 16 * GiB, .max_ratio = 200, .ratio_slack = 1 * MiB};
    CHECK_ERR(drain(INFLATE_RAW, b.p, b.n, 0, &lim, &total, nullptr), "ratio");
    CHECK(total < 200ull * b.n + 2 * MiB);
    // without the ratio cap it is valid, and the size cap stops it
    const inflate_limits size = {.max_out = 8 * MiB};
    CHECK_ERR(drain(INFLATE_RAW, b.p, b.n, 0, &size, &total, nullptr), "size cap");
    CHECK(total <= 8 * MiB + 512 * KiB);
    buf small = {0};
    make_bomb(&small, 1000);
    CHECK(!drain(INFLATE_RAW, small.p, small.n, 0, nullptr, &total, nullptr) && total == 1 + 258000);
    free(small.p);
    free(b.p);
}

// ---- JSON ---------------------------------------------------------------------------
static const char *jerr(const char *text)
{
    const char *err = nullptr;
    json_doc *d = json_parse(text, strlen(text), nullptr, &err);
    json_free(d);
    return d ? nullptr : err;
}

static void test_json(void)
{
    const char *err;
    const char *doc = " {\"a\": [1, -2.5e+3, true, false, null, \"x\\u00e9\\ud83d\\ude00\\n\"],"
                      " \"b\": {\"c\": \"\"}, \"n\": 18446744073709551615, \"z\": \"a\\u0000b\"} ";
    json_doc *d = json_parse(doc, strlen(doc), nullptr, &err);
    CHECK(d);
    if (d) {
        const json_value *r = json_root(d);
        const json_value *a = json_get(r, "a");
        CHECK(a && a->type == JSON_ARRAY && a->len == 6);
        CHECK(a && a->kids[2].type == JSON_TRUE && a->kids[4].type == JSON_NULL);
        CHECK(a && !strcmp(a->kids[1].str, "-2.5e+3"));
        CHECK(a && !strcmp(json_cstr(&a->kids[5]), "x\xc3\xa9\xf0\x9f\x98\x80\n"));
        uint64_t v;
        CHECK(json_u64(json_get(r, "n"), &v) && v == UINT64_MAX);
        CHECK(!json_u64(&a->kids[1], &v));
        CHECK(json_u64(&a->kids[0], &v) && v == 1);
        CHECK(json_get(r, "z")->len == 3 && !json_cstr(json_get(r, "z"))); // NUL inside
        CHECK(json_cstr(json_get(json_get(r, "b"), "c")) && !json_get(r, "missing"));
        json_free(d);
    }
    CHECK(!jerr("[]") && !jerr("{}") && !jerr("0") && !jerr("\"\"") && !jerr("[[[]]]"));
    CHECK_ERR(jerr("{\"a\":1,\"a\":2}"), "duplicate key");
    CHECK_ERR(jerr("{\"b\":1,\"a\":{\"x\":1,\"y\":2,\"x\":3}}"), "duplicate key");
    CHECK(!jerr("{\"a\":{\"x\":1},\"b\":{\"x\":1}}")); // same key in different objects
    CHECK_ERR(jerr("[1,]"), "expected a value");
    CHECK_ERR(jerr("{\"a\":1,}"), "expected a key");
    CHECK_ERR(jerr("01"), "after the document");
    CHECK_ERR(jerr("1."), "number");
    CHECK_ERR(jerr("-"), "number");
    CHECK_ERR(jerr("+1"), "expected a value");
    CHECK_ERR(jerr("NaN"), "expected a value");
    CHECK_ERR(jerr("\xef\xbb\xbf{}"), "expected a value"); // BOM
    CHECK_ERR(jerr("{} {}"), "after the document");
    CHECK_ERR(jerr("\"a\tb\""), "control character");
    CHECK_ERR(jerr("\"\\x\""), "invalid escape");
    CHECK_ERR(jerr("\"\\u12\""), "\\u escape");
    CHECK_ERR(jerr("\"\\ud800\""), "lone high surrogate");
    CHECK_ERR(jerr("\"\\udc00\""), "lone low surrogate");
    CHECK_ERR(jerr("\"\\ud800\\u0041\""), "lone high surrogate");
    CHECK_ERR(jerr("\"\xc0\xaf\""), "UTF-8");     // overlong '/'
    CHECK_ERR(jerr("\"\xed\xa0\x80\""), "UTF-8"); // a surrogate
    CHECK_ERR(jerr("\"\xf4\x90\x80\x80\""), "UTF-8"); // past U+10FFFF
    CHECK_ERR(jerr("\"\xe2\x82\""), "UTF-8");     // truncated
    CHECK_ERR(jerr("\"abc"), "unterminated");
    CHECK_ERR(jerr("\"abc\\"), "unterminated");
    CHECK_ERR(jerr("tru"), "literal");
    CHECK_ERR(jerr("[1 2]"), "expected ','");
    CHECK_ERR(jerr(""), "expected a value");
    // depth: 64 levels are fine, 65 are not
    char deep[200];
    memset(deep, '[', 64);
    memset(deep + 64, ']', 64);
    deep[128] = 0;
    CHECK(!jerr(deep));
    memset(deep, '[', 65);
    memset(deep + 65, ']', 65);
    deep[130] = 0;
    CHECK_ERR(jerr(deep), "nested too deeply");
    // a million levels: refused at 65, no stack overflow
    const size_t big = 1000000;
    char *dd = malloc(big + 1);
    memset(dd, '[', big);
    dd[big] = 0;
    CHECK_ERR(jerr(dd), "nested too deeply");
    free(dd);
    // size and value caps
    const json_limits lim = {.max_size = 10, .max_depth = 8, .max_values = 3};
    CHECK(!json_parse("[1,2,3,4,5,6]", 13, &lim, &err) && has(err, "too big"));
    CHECK(!json_parse("[1,2,3]", 7, &lim, &err) && has(err, "too many values"));
    json_doc *ok = json_parse("[1,2]", 5, &lim, &err);
    CHECK(ok);
    json_free(ok);
}

// ---- images in memory ----------------------------------------------------------------
typedef struct {
    char path[160];
    buf data;
} mfile;

typedef struct {
    mfile f[128];
    size_t n;
} mstore;

static mfile *ms_find(mstore *m, const char *path)
{
    for (size_t i = 0; i < m->n; i++)
        if (!strcmp(m->f[i].path, path))
            return &m->f[i];
    return nullptr;
}

static void ms_put(void *ctx, const char *path, const uint8_t *data, size_t n)
{
    mstore *m = ctx;
    mfile *f = ms_find(m, path);
    if (!f) {
        if (m->n == MVM_ARRAY_LEN(m->f))
            abort();
        f = &m->f[m->n++];
        f->data = (buf){0};
        snprintf(f->path, sizeof f->path, "%s", path);
    }
    free(f->data.p);
    f->data = (buf){0};
    buf_put(&f->data, data, n);
}

static void ms_del(mstore *m, const char *path)
{
    mfile *f = ms_find(m, path);
    if (f) {
        free(f->data.p);
        *f = m->f[--m->n];
    }
}

static int ms_open(void *ctx, const char *path, fs_source *out)
{
    mfile *f = ms_find(ctx, path);
    if (!f)
        return -1;
    *out = (fs_source){buf_read, &f->data, f->data.n};
    return 0;
}

static void ms_free(mstore *m)
{
    for (size_t i = 0; i < m->n; i++)
        free(m->f[i].data.p), m->f[i].data = (buf){0};
    m->n = 0;
}

static const ow_out *ms_out(mstore *m)
{
    static ow_out o;
    o = (ow_out){ms_put, m};
    return &o;
}

// The blob path a manifest's layer i lives at (found by scanning manifests).
static mfile *layer_blob(mstore *m, size_t i)
{
    for (size_t k = 0; k < m->n; k++) {
        const char *s = (const char *)m->f[k].data.p;
        if (!has(m->f[k].path, "blobs/") || m->f[k].data.n < 20 || !s || memcmp(s, "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest", 60))
            continue;
        char tmp[8192];
        snprintf(tmp, sizeof tmp, "%.*s", (int)m->f[k].data.n, s);
        const char *p = strstr(tmp, "\"layers\":[");
        for (size_t j = 0; p && j <= i; j++)
            p = strstr(p + 1, "\"digest\":\"sha256:");
        if (!p)
            return nullptr;
        char path[96];
        snprintf(path, sizeof path, "blobs/sha256/%.64s", p + 17);
        return ms_find(m, path);
    }
    return nullptr;
}

typedef struct {
    buf img, cfg;
    char err[512];
} result;

static void result_free(result *r)
{
    free(r->img.p);
    free(r->cfg.p);
    *r = (result){0};
}

// Store -> EROFS image; false (and r->err) on error.
static bool convert_store(const oci_store *st, const oci_opts *o, result *r)
{
    *r = (result){0};
    fs_tree t;
    if (fs_tree_init(&t))
        abort();
    oci_image *im = oci_new(o);
    const char *err = "";
    int rc = oci_build(im, st, &t, &err);
    if (!rc)
        rc = erofs_write(&t, &(fs_sink){buf_write, &r->img}, &err);
    if (rc) {
        snprintf(r->err, sizeof r->err, "%s", err && err[0] ? err : "failed");
    } else {
        size_t n;
        const uint8_t *c = oci_config(im, &n);
        buf_put(&r->cfg, c, n);
    }
    oci_free(im);
    fs_tree_free(&t);
    return rc == 0;
}

static bool convert(mstore *m, const char *ref, result *r)
{
    const oci_store st = {ms_open, m};
    return convert_store(&st, &(oci_opts){.ref = ref}, r);
}

static bool convert_tar(const buf *tar, const char *ref, result *r)
{
    oci_archive *a;
    const char *err;
    const fs_source s = {buf_read, (void *)tar, tar->n};
    if (oci_archive_open(&a, &s, &err)) {
        *r = (result){0};
        snprintf(r->err, sizeof r->err, "%s", err);
        return false;
    }
    const oci_store st = oci_archive_store(a);
    const bool ok = convert_store(&st, &(oci_opts){.ref = ref}, r);
    oci_archive_free(a);
    return ok;
}

// The config as "k=v;" pairs, digests left out.
static void cfg_fn(void *ctx, const char *k, const char *v)
{
    if (!strcmp(k, "config-digest") || !strcmp(k, "manifest-digest")) {
        CHECK(!strncmp(v, "sha256:", 7) && strlen(v) == 71);
        return;
    }
    ow_printf(ctx, "%s=%s;", k, v);
}

static bool config_is(const result *r, const char *want)
{
    buf s = {0};
    if (oci_config_walk(r->cfg.p, r->cfg.n, cfg_fn, &s))
        return false;
    buf_put(&s, "", 1);
    const bool ok = !strcmp((const char *)s.p, want);
    if (!ok)
        fprintf(stderr, "  config: %s\n  wanted: %s\n", (const char *)s.p, want);
    free(s.p);
    // the same bytes are in the image
    img m;
    inode in;
    if (!img_open(&m, &r->img) || !stat_path(&m, ".microvm/image-config", &in) ||
        in.size != r->cfg.n || memcmp(data_of(&m, &in), r->cfg.p, r->cfg.n))
        return false;
    return ok;
}

// A three-layer image: base files, an app layer (gzip), and a layer that
// deletes and replaces things with whiteouts (gzip, mixed blocks).
static void sample_layers(buf tars[3])
{
    for (int i = 0; i < 3; i++)
        tars[i] = (buf){0};
    tar_dir(&tars[0], "etc/", 0755);
    tar_file(&tars[0], "etc/passwd", "root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000::/app:/bin/sh\n");
    tar_file(&tars[0], "etc/group", "root:x:0:\nwheel:x:10:app,other\napp:x:1000:\naudio:x:29:\n");
    tar_dir(&tars[0], "bin/", 0755);
    tar_file(&tars[0], "bin/sh", "#!fake shell\n");
    tar_dir(&tars[0], "var/cache/", 0755);
    tar_file(&tars[0], "var/cache/a", "cached a");
    tar_file(&tars[0], "var/cache/b", "cached b");
    tar_file(&tars[0], "old", "to be removed");
    tar_end(&tars[0]);

    tar_dir(&tars[1], "app/", 0755);
    tar_file(&tars[1], "app/run", "#!/bin/sh\necho hello\n");
    tar_link(&tars[1], "app/sh", '2', "/bin/sh");
    tar_file(&tars[1], "old2", "removed too");
    // a few hundred files of assorted sizes, so the data streams in many pieces
    for (int i = 0; i < 300; i++) {
        char name[64];
        snprintf(name, sizeof name, "app/data/f%03d", i);
        const size_t n = (size_t)(rnd() % 20000);
        uint8_t *d = malloc(n + 1);
        for (size_t k = 0; k < n; k++)
            d[k] = (uint8_t)(k % 251 ^ (size_t)i);
        tar_raw(&tars[1], name, '0', 0644, n, d, n, nullptr, 0, 0);
        free(d);
    }
    tar_end(&tars[1]);

    tar_file(&tars[2], ".wh.old", "");
    tar_file(&tars[2], ".wh.old2", "");
    tar_file(&tars[2], "var/cache/.wh..wh..opq", "");
    tar_file(&tars[2], "var/cache/c", "new c");
    tar_file(&tars[2], "app/run", "#!/bin/sh\necho replaced\n");
    tar_end(&tars[2]);
}

static const char SAMPLE_CONFIG[] =
    "{\"User\":\"app\",\"Env\":[\"PATH=/usr/bin:/bin\",\"MODE=test\"],"
    "\"Entrypoint\":[\"/app/run\"],\"Cmd\":[\"--flag\",\"a b\"],\"WorkingDir\":\"/app\","
    "\"Labels\":{\"x\":\"y\"}}";
static const char SAMPLE_CFG_WANT[] =
    "entrypoint=/app/run;cmd=--flag;cmd=a b;env=PATH=/usr/bin:/bin;env=MODE=test;workdir=/app;"
    "user=app;uid=1000;gid=1000;group=10;";

static bool sample_ok(const buf *image)
{
    img m;
    if (!img_open(&m, image))
        return false;
    bool ok = file_is(&m, "bin/sh", "#!fake shell\n") && file_is(&m, "app/run", "#!/bin/sh\necho replaced\n") &&
              !exists(&m, "old") && !exists(&m, "old2") && !exists(&m, "var/cache/a") &&
              !exists(&m, "var/cache/b") && file_is(&m, "var/cache/c", "new c") &&
              exists(&m, "app/sh") && exists(&m, ".microvm/image-config");
    for (int i = 0; i < 300 && ok; i += 7) {
        char name[64];
        snprintf(name, sizeof name, "app/data/f%03d", i);
        inode in;
        ok = stat_path(&m, name, &in);
        const uint8_t *d = ok ? data_of(&m, &in) : nullptr;
        for (size_t k = 0; ok && k < in.size; k++)
            ok = d && d[k] == (uint8_t)(k % 251 ^ (size_t)i);
    }
    return ok;
}

typedef struct {
    buf tars[3], gz[3];
    ow_layer l[3];
} sample;

static void sample_make(sample *s)
{
    sample_layers(s->tars);
    ow_layer_set(&s->l[0], &s->gz[0], &s->tars[0], -1);       // uncompressed
    ow_layer_set(&s->l[1], &s->gz[1], &s->tars[1], GZ_FIXED);
    ow_layer_set(&s->l[2], &s->gz[2], &s->tars[2], GZ_MIXED);
    if (s->l[0].data != s->tars[0].p)
        abort();
    s->gz[0] = (buf){0};
}

static void sample_free(sample *s)
{
    for (int i = 0; i < 3; i++) {
        free(s->tars[i].p);
        free(s->gz[i].p);
    }
}

static void oci_sample(mstore *m, const sample *s, const ow_image *im)
{
    char *d = ow_image_blobs(ms_out(m), s->l, 3, im);
    ow_index(ms_out(m), &d, 1);
    free(d);
}

static void test_oci_layout(void)
{
    sample s;
    sample_make(&s);
    mstore m = {0};
    oci_sample(&m, &s, &(ow_image){.config = SAMPLE_CONFIG});
    result r;
    CHECK(convert(&m, nullptr, &r));
    if (r.err[0])
        fprintf(stderr, "  %s\n", r.err);
    CHECK(sample_ok(&r.img));
    CHECK(config_is(&r, SAMPLE_CFG_WANT));
    // deterministic
    result r2;
    CHECK(convert(&m, nullptr, &r2) && r2.img.n == r.img.n && !memcmp(r2.img.p, r.img.p, r.img.n));
    result_free(&r2);
    result_free(&r);

    // the same layout inside a tar (as `docker save` writes since Docker 25)
    buf tar = {0};
    for (size_t i = 0; i < m.n; i++)
        ow_tar_put(&tar, m.f[i].path, m.f[i].data.p, m.f[i].data.n);
    tar_end(&tar);
    CHECK(convert_tar(&tar, nullptr, &r) && sample_ok(&r.img) && config_is(&r, SAMPLE_CFG_WANT));
    result_free(&r);
    free(tar.p);
    ms_free(&m);

    // no config at all: root, nothing to run
    oci_sample(&m, &s, &(ow_image){0});
    CHECK(convert(&m, nullptr, &r) && config_is(&r, "uid=0;gid=0;"));
    result_free(&r);
    ms_free(&m);
    sample_free(&s);
}

static void test_docker_archive(void)
{
    sample s;
    sample_make(&s);
    // four layers: the fourth repeats the first (a symlink in the archive)
    ow_layer l4[4] = {s.l[0], s.l[1], s.l[2], s.l[0]};
    buf tar = {0};
    ow_docker(&(ow_out){ow_tar_put, &tar}, l4, 4, &(ow_image){.config = SAMPLE_CONFIG}, "test:latest", &tar);
    tar_end(&tar);
    result r;
    CHECK(convert_tar(&tar, nullptr, &r));
    if (r.err[0])
        fprintf(stderr, "  %s\n", r.err);
    // layer 4 (the first again) brings "old" back; "old2" (layer 2) stays deleted
    img mi;
    CHECK(img_open(&mi, &r.img) && file_is(&mi, "old", "to be removed") && !exists(&mi, "old2"));
    CHECK(config_is(&r, SAMPLE_CFG_WANT));
    result_free(&r);
    CHECK(convert_tar(&tar, "test:latest", &r));
    result_free(&r);
    CHECK(!convert_tar(&tar, "other:tag", &r));
    CHECK_ERR(r.err, "no image is tagged");
    free(tar.p);

    // three layers, as written: the same image as the OCI layout
    tar = (buf){0};
    ow_docker(&(ow_out){ow_tar_put, &tar}, s.l, 3, &(ow_image){.config = SAMPLE_CONFIG}, "t:1", nullptr);
    tar_end(&tar);
    CHECK(convert_tar(&tar, nullptr, &r) && sample_ok(&r.img));
    result_free(&r);
    // a layer changed in the archive: its diff_id no longer matches
    for (size_t off = 0; off + 512 <= tar.n; off += 512) {
        if (has((const char *)tar.p + off, "/layer.tar") && tar.p[off + 156] == '0') {
            tar.p[off + 512 + 600] ^= 1; // inside the first layer's data
            break;
        }
    }
    CHECK(!convert_tar(&tar, nullptr, &r));
    CHECK_ERR(r.err, "diff_id");
    free(tar.p);

    // the config not named by its digest
    mstore m = {0};
    ow_docker(ms_out(&m), s.l, 3, &(ow_image){0}, "t:1", nullptr);
    mfile *mf = ms_find(&m, "manifest.json");
    char *txt = calloc(1, mf->data.n + 32);
    memcpy(txt, mf->data.p, mf->data.n);
    char *cfgname = strstr(txt, "\"Config\":\"") + 10;
    char old[70];
    memcpy(old, cfgname, 69);
    old[69] = 0;
    memcpy(cfgname, "config.json\",\"Pad\":\"", 20); // same length, different name
    mfile *cf = ms_find(&m, old);
    ms_put(&m, "config.json", cf->data.p, cf->data.n);
    ms_put(&m, "manifest.json", (const uint8_t *)txt, strlen(txt));
    CHECK(!convert(&m, nullptr, &r));
    CHECK_ERR(r.err, "can't be verified");
    free(txt);
    ms_free(&m);
    sample_free(&s);
}

// A tar+zstd layer made by the zstd CLI (tests/gen_zstd_vectors.py), on
// top of the sample image, in an OCI layout and in a docker-archive.
static const zstd_vector *zstd_layer(ow_layer *l)
{
    const zstd_vector *v = nullptr;
    for (size_t i = 0; i < sizeof zstd_vectors / sizeof *zstd_vectors; i++)
        if (!strcmp(zstd_vectors[i].name, "layer_tar"))
            v = &zstd_vectors[i];
    if (!v)
        abort();
    *l = (ow_layer){.data = v->z, .n = v->zn};
    memcpy(l->diff, v->sha256, 65);
    return v;
}

static bool zstd_image_ok(const buf *image)
{
    img m;
    inode in;
    return sample_ok(image) && img_open(&m, image) && file_is(&m, "zst/hello", "hello from a zstd layer\n") &&
           stat_path(&m, "zst/text", &in) && in.size == 29606 && stat_path(&m, "zst/bits", &in) &&
           in.size == 50000;
}

static void test_zstd_layers(void)
{
    sample s;
    sample_make(&s);
    ow_layer l[4] = {s.l[0], s.l[1], s.l[2]};
    zstd_layer(&l[3]);
    CHECK(!strcmp(ow_media(&l[3]), "application/vnd.oci.image.layer.v1.tar+zstd"));
    mstore m = {0};
    char *d = ow_image_blobs(ms_out(&m), l, 4, &(ow_image){.config = SAMPLE_CONFIG});
    ow_index(ms_out(&m), &d, 1);
    free(d);
    result r;
    CHECK(convert(&m, nullptr, &r) && zstd_image_ok(&r.img));
    if (r.err[0])
        fprintf(stderr, "  %s\n", r.err);
    result_free(&r);
    ms_free(&m);
    // docker-archive layers have no media type: zstd is told by its bytes
    buf tar = {0};
    ow_docker(&(ow_out){ow_tar_put, &tar}, l, 4, &(ow_image){.config = SAMPLE_CONFIG}, "z:1", nullptr);
    tar_end(&tar);
    CHECK(convert_tar(&tar, nullptr, &r) && zstd_image_ok(&r.img));
    if (r.err[0])
        fprintf(stderr, "  %s\n", r.err);
    result_free(&r);
    free(tar.p);
    sample_free(&s);
}

static void test_platforms(void)
{
    // an index with arm64, an attestation, amd64: amd64 is taken
    buf t1 = {0}, t2 = {0};
    tar_file(&t1, "which", "arm64");
    tar_end(&t1);
    tar_file(&t2, "which", "amd64");
    tar_end(&t2);
    ow_layer la, lb;
    buf ga, gb;
    ow_layer_set(&la, &ga, &t1, GZ_FIXED);
    ow_layer_set(&lb, &gb, &t2, GZ_FIXED);
    mstore m = {0};
    char *d[3];
    d[0] = ow_image_blobs(ms_out(&m), &la, 1, &(ow_image){.arch = "arm64", .platform = "linux/arm64"});
    d[1] = strdup("{\"mediaType\":\"application/vnd.in-toto+json\",\"digest\":\"sha256:"
                  "0000000000000000000000000000000000000000000000000000000000000000\",\"size\":1,"
                  "\"platform\":{\"os\":\"unknown\",\"architecture\":\"unknown\"}}");
    d[2] = ow_image_blobs(ms_out(&m), &lb, 1, &(ow_image){.platform = "linux/amd64"});
    ow_index(ms_out(&m), d, 3);
    result r;
    img mi;
    CHECK(convert(&m, nullptr, &r) && img_open(&mi, &r.img) && file_is(&mi, "which", "amd64"));
    result_free(&r);

    // nested: index.json -> an index blob -> the platform manifests
    buf idx = {0};
    ow_printf(&idx, "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\","
                    "\"manifests\":[%s,%s,%s]}", d[0], d[1], d[2]);
    char hex[65];
    ow_blob(ms_out(&m), idx.p, idx.n, hex);
    char *top;
    buf tb = {0};
    ow_printf(&tb, "{\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"digest\":\"sha256:%s\","
                   "\"size\":%zu}", hex, idx.n);
    buf_put(&tb, "", 1);
    top = (char *)tb.p;
    ow_index(ms_out(&m), &top, 1);
    CHECK(convert(&m, nullptr, &r) && img_open(&mi, &r.img) && file_is(&mi, "which", "amd64"));
    result_free(&r);
    free(top);
    free(idx.p);

    // only arm64: refused
    ow_index(ms_out(&m), d, 1);
    CHECK(!convert(&m, nullptr, &r));
    CHECK_ERR(r.err, "no linux/amd64 image");
    // a manifest that claims amd64 but whose config says arm64
    char *bad = ow_image_blobs(ms_out(&m), &la, 1, &(ow_image){.arch = "arm64", .platform = "linux/amd64"});
    ow_index(ms_out(&m), &bad, 1);
    CHECK(!convert(&m, nullptr, &r));
    CHECK_ERR(r.err, "not amd64");
    free(bad);

    // two images without platforms: tags pick one
    char *e[2];
    e[0] = ow_image_blobs(ms_out(&m), &la, 1, &(ow_image){.ref = "one"});
    e[1] = ow_image_blobs(ms_out(&m), &lb, 1, &(ow_image){.ref = "two"});
    ow_index(ms_out(&m), e, 2);
    CHECK(!convert(&m, nullptr, &r));
    CHECK_ERR(r.err, "--ref");
    CHECK(!convert(&m, "three", &r));
    CHECK_ERR(r.err, "tagged 'three'");
    CHECK(convert(&m, "two", &r) && img_open(&mi, &r.img) && file_is(&mi, "which", "amd64"));
    result_free(&r);
    for (int i = 0; i < 3; i++)
        free(d[i]);
    free(e[0]);
    free(e[1]);
    ms_free(&m);
    free(t1.p), free(t2.p), free(ga.p), free(gb.p);
}

static void test_users(void)
{
    sample s;
    sample_make(&s);
    static const struct {
        const char *user, *want, *err;
    } v[] = {
        {"app", "user=app;uid=1000;gid=1000;group=10;", nullptr},
        {"1000", "user=1000;uid=1000;gid=1000;group=10;", nullptr},
        {"app:audio", "user=app:audio;uid=1000;gid=29;group=10;", nullptr},
        {"app:7", "user=app:7;uid=1000;gid=7;group=10;", nullptr},
        {"4242", "user=4242;uid=4242;gid=0;", nullptr},
        {"4242:4243", "user=4242:4243;uid=4242;gid=4243;", nullptr},
        {"root", "user=root;uid=0;gid=0;", nullptr},
        {"nobody", nullptr, "isn't in its /etc/passwd"},
        {"app:nogroup", nullptr, "isn't in its /etc/group"},
        {"99999999999", nullptr, "isn't in its /etc/passwd"},
    };
    for (size_t i = 0; i < MVM_ARRAY_LEN(v); i++) {
        char cfg[128];
        snprintf(cfg, sizeof cfg, "{\"User\":\"%s\"}", v[i].user);
        mstore m = {0};
        oci_sample(&m, &s, &(ow_image){.config = cfg});
        result r;
        const bool ok = convert(&m, nullptr, &r);
        CHECK(ok == !v[i].err);
        if (v[i].err)
            CHECK_ERR(r.err, v[i].err);
        else
            CHECK(config_is(&r, v[i].want));
        result_free(&r);
        ms_free(&m);
    }
    sample_free(&s);
}

// Layers of the caller's on top of an image (mkrootfs --add-layer): they
// see the image's files, their users count for its User, and they can't
// replace the config file.
static void test_added_layers(void)
{
    sample s;
    sample_make(&s);
    mstore m = {0};
    oci_sample(&m, &s, &(ow_image){.config = "{\"User\":\"fn\",\"Cmd\":[\"/app/handler.py\"]}"});
    const oci_store st = {ms_open, &m};
    result r;
    CHECK(!convert_store(&st, &(oci_opts){0}, &r));
    CHECK_ERR(r.err, "isn't in its /etc/passwd");

    buf a = {0}, b = {0}, bgz = {0}, bad = {0};
    tar_file(&a, "etc/passwd", "root:x:0:0:root:/root:/bin/sh\nfn:x:2000:2001::/app:/bin/sh\n");
    tar_file(&a, "etc/group", "root:x:0:\nfn:x:2001:\n");
    tar_file(&a, "app/handler.py", "first");
    tar_file(&a, "bin/.wh.sh", "");
    tar_dir(&a, ".microvm/", 0755);
    tar_file(&a, ".microvm/image-config", "forged");
    tar_end(&a);
    tar_file(&b, "app/handler.py", "def handler(event): return event\n");
    tar_end(&b);
    ow_layer lb;
    ow_layer_set(&lb, &bgz, &b, GZ_FIXED); // bgz: the gzip'ed layer
    const fs_source add[2] = {{buf_read, &a, a.n}, {buf_read, &bgz, bgz.n}};
    CHECK(convert_store(&st, &(oci_opts){.add = add, .nadd = 2}, &r));
    if (r.err[0])
        fprintf(stderr, "  %s\n", r.err);
    char ha[65], hb[65], want[512];
    hex_of(a.p, a.n, ha);
    hex_of(bgz.p, bgz.n, hb);
    snprintf(want, sizeof want,
             "added-layer=sha256:%s;added-layer=sha256:%s;cmd=/app/handler.py;user=fn;uid=2000;gid=2001;",
             ha, hb);
    CHECK(config_is(&r, want)); // also: the image holds the real config file, not the forged one
    img mi;
    CHECK(img_open(&mi, &r.img) && file_is(&mi, "app/handler.py", "def handler(event): return event\n") &&
          !exists(&mi, "bin/sh") && file_is(&mi, "app/run", "#!/bin/sh\necho replaced\n"));
    result_free(&r);

    // an added layer is as untrusted as the image's own
    tar_file(&bad, "app/../../etc/x", "x");
    tar_end(&bad);
    const fs_source add3[1] = {{buf_read, &bad, bad.n}};
    CHECK(!convert_store(&st, &(oci_opts){.add = add3, .nadd = 1}, &r));
    CHECK_ERR(r.err, "\"..\"");
    result_free(&r);

    // a build's ENV, WORKDIR and USER (mkrootfs --env, --workdir, --user):
    // an ENV of the image's name replaces it in its place, the last of the
    // build's for a name wins, new names come after the image's
    mstore m2 = {0};
    oci_sample(&m2, &s, &(ow_image){.config = "{\"User\":\"fn\",\"WorkingDir\":\"/app\","
                                              "\"Env\":[\"PATH=/bin\",\"A=1\",\"B=2\"]}"});
    const oci_store st2 = {ms_open, &m2};
    const char *env[] = {"B=3", "C=4", "PATH=/usr/bin:/bin", "C=5"};
    CHECK(convert_store(&st2, &(oci_opts){.add = add, .nadd = 1, .env = env, .nenv = 4, .workdir = "/srv",
                                          .user = "root"}, &r));
    snprintf(want, sizeof want,
             "added-layer=sha256:%s;env=PATH=/usr/bin:/bin;env=A=1;env=B=3;env=C=5;workdir=/srv;user=root;"
             "uid=0;gid=0;", ha);
    CHECK(config_is(&r, want));
    result_free(&r);
    // an empty WORKDIR or USER override drops the image's
    CHECK(convert_store(&st2, &(oci_opts){.add = add, .nadd = 1, .workdir = "", .user = ""}, &r));
    snprintf(want, sizeof want, "added-layer=sha256:%s;env=PATH=/bin;env=A=1;env=B=2;uid=0;gid=0;", ha);
    CHECK(config_is(&r, want));
    result_free(&r);
    ms_free(&m2);

    // Dockerfile COPY (mkrootfs --copy), from a tar of the build context
    buf ctx = {0};
    tar_dir(&ctx, "app/", 0755);
    tar_file(&ctx, "app/main.py", "main");
    tar_dir(&ctx, "app/lib/", 0700);
    tar_file(&ctx, "app/lib/util.py", "util");
    tar_file(&ctx, "app/.env", "SECRET=1");
    tar_link(&ctx, "app/hard.py", '1', "app/main.py");
    tar_link(&ctx, "app/sym", '2', "main.py");
    tar_file(&ctx, "req.txt", "flask");
    tar_dir(&ctx, "data/", 0755);
    tar_file(&ctx, "data/a.csv", "a");
    tar_file(&ctx, "data/b.csv", "b");
    tar_file(&ctx, "data/c.json", "c");
    tar_end(&ctx);
    struct copy_case {
        const char *src, *dest, *owner;
        int32_t mode;
    };
    const struct copy_case cc[] = {
        {"app", "/srv/app", "fn", -1},            // a directory's contents, owned by fn
        {"req.txt", "/srv/", "", -1},             // into a directory (trailing /)
        {"./req.txt", "/srv/requirements.txt", "", -1}, // to a new name
        {"data/*.csv", "/d", "", -1},             // a glob: into /d
        {".", "/ctx", "", 0600},                  // all of it, --chmod
        {"req.txt", "/srv/app", "", -1},          // into what is a directory now
    };
    fs_source cadd[1 + MVM_ARRAY_LEN(cc)];
    struct oci_copy cops[1 + MVM_ARRAY_LEN(cc)];
    cadd[0] = add[0], cops[0] = (struct oci_copy){.mode = -1}; // layer a: fn's passwd entry
    for (size_t i = 0; i < MVM_ARRAY_LEN(cc); i++) {
        cadd[i + 1] = (fs_source){buf_read, &ctx, ctx.n};
        cops[i + 1] = (struct oci_copy){cc[i].src, cc[i].dest, cc[i].owner, cc[i].mode};
    }
    CHECK(convert_store(&st, &(oci_opts){.add = cadd, .nadd = MVM_ARRAY_LEN(cadd), .copy = cops}, &r));
    if (r.err[0])
        fprintf(stderr, "  %s\n", r.err);
    img ci;
    inode in, in2, dn;
    CHECK(img_open(&ci, &r.img));
    CHECK(file_is(&ci, "srv/app/main.py", "main") && file_is(&ci, "srv/app/lib/util.py", "util") &&
          file_is(&ci, "srv/app/.env", "SECRET=1") && !exists(&ci, "srv/app/app"));
    CHECK(stat_path(&ci, "srv/app/main.py", &in) && in.uid == 2000 && in.gid == 2001 && (in.mode & 07777) == 0644);
    CHECK(stat_path(&ci, "srv/app/lib", &dn) && (dn.mode & 07777) == 0700 && dn.uid == 2000);
    CHECK(stat_path(&ci, "srv/app/hard.py", &in2) && in2.ino == in.ino && in.nlink == 2); // still one file
    CHECK(stat_path(&ci, "srv/app/sym", &in2) && (in2.mode & FS_IFMT) == FS_IFLNK);
    CHECK(file_is(&ci, "srv/req.txt", "flask") && file_is(&ci, "srv/requirements.txt", "flask"));
    CHECK(file_is(&ci, "d/a.csv", "a") && file_is(&ci, "d/b.csv", "b") && !exists(&ci, "d/c.json"));
    CHECK(file_is(&ci, "ctx/app/main.py", "main") && file_is(&ci, "ctx/data/c.json", "c"));
    CHECK(stat_path(&ci, "ctx/req.txt", &in) && (in.mode & 07777) == 0600 && in.uid == 0);
    CHECK(file_is(&ci, "srv/app/req.txt", "flask"));
    result_free(&r);
    // what COPY refuses
    const struct copy_case bad_cc[] = {
        {"nope", "/x", "", -1}, {"../etc", "/x", "", -1}, {"req.txt", "/app/run/x", "", -1},
        {"req.txt", "/x", "nobody", -1},
    };
    const char *bad_err[] = {"nothing in the build context", "\"..\"", "isn't a directory", "isn't in its /etc/passwd"};
    for (size_t i = 0; i < MVM_ARRAY_LEN(bad_cc); i++) {
        cops[1] = (struct oci_copy){bad_cc[i].src, bad_cc[i].dest, bad_cc[i].owner, bad_cc[i].mode};
        CHECK(!convert_store(&st, &(oci_opts){.add = cadd, .nadd = 2, .copy = cops}, &r));
        CHECK_ERR(r.err, bad_err[i]);
        result_free(&r);
    }
    free(ctx.p);

    free(a.p), free(b.p), free(bgz.p), free(bad.p);
    ms_free(&m);
    sample_free(&s);
}

// A hostile variant of the sample image: fn changes the store; the
// conversion must fail with `want` in its error.
static void hostile(const char *what, void (*fn)(mstore *, const sample *), const char *want)
{
    sample s;
    sample_make(&s);
    mstore m = {0};
    oci_sample(&m, &s, &(ow_image){.config = SAMPLE_CONFIG});
    fn(&m, &s);
    result r;
    const bool ok = convert(&m, nullptr, &r);
    CHECK(!ok);
    if (!has(r.err, want))
        fprintf(stderr, "  %s: error '%s', wanted '%s'\n", what, ok ? "(accepted)" : r.err, want);
    CHECK(has(r.err, want));
    result_free(&r);
    ms_free(&m);
    sample_free(&s);
}

static void flip_layer(mstore *m, const sample *s) { (void)s, layer_blob(m, 1)->data.p[40] ^= 1; }
static void grow_layer(mstore *m, const sample *s) { (void)s, buf_put(&layer_blob(m, 2)->data, "x", 1); }
static void drop_layer(mstore *m, const sample *s) { (void)s, ms_del(m, layer_blob(m, 0)->path); }
static void flip_manifest(mstore *m, const sample *s)
{
    (void)s;
    char path[96];
    const char *ix = (const char *)ms_find(m, "index.json")->data.p;
    snprintf(path, sizeof path, "blobs/sha256/%.64s", strstr(ix, "sha256:") + 7);
    mfile *f = ms_find(m, path);
    f->data.p[f->data.n - 2] = ' '; // "]}" -> " }": still JSON-ish, different digest
}
static void no_layout_file(mstore *m, const sample *s) { (void)s, ms_del(m, "oci-layout"); }

// Rebuild with a modified image: layer tars, config text.
static void rebuild(mstore *m, ow_layer *l, size_t n, const char *config)
{
    ms_free(m);
    char *d = ow_image_blobs(ms_out(m), l, n, &(ow_image){.config = config});
    ow_index(ms_out(m), &d, 1);
    free(d);
}

static void with_tar(mstore *m, const sample *s, void (*add)(buf *), int mode)
{
    buf t = {0}, g = {0};
    add(&t);
    tar_end(&t);
    ow_layer l[4] = {s->l[0], s->l[1], s->l[2]};
    ow_layer_set(&l[3], &g, &t, mode);
    rebuild(m, l, 4, nullptr);
    free(t.p);
    free(g.p);
}

static void t_dotdot(buf *t) { tar_file(t, "app/../../etc/x", "x"); }
static void t_wh_dotdot(buf *t) { tar_file(t, "app/../../.wh.etc", ""); }
static void t_wh_through_link(buf *t) { tar_file(t, "app/sh/.wh.passwd", ""); }   // app/sh -> /bin/sh
static void t_file_through_link(buf *t) { tar_file(t, "app/sh/evil", "x"); }
static void t_hardlink_out(buf *t) { tar_link(t, "app/h", '1', "../../etc/shadow"); }
static void t_hardlink_missing(buf *t) { tar_link(t, "app/h", '1', "etc/shadow"); }
static void t_root_file(buf *t) { tar_file(t, "./", "x"); }

static void dotdot(mstore *m, const sample *s) { with_tar(m, s, t_dotdot, GZ_FIXED); }
static void wh_dotdot(mstore *m, const sample *s) { with_tar(m, s, t_wh_dotdot, GZ_FIXED); }
static void wh_link(mstore *m, const sample *s) { with_tar(m, s, t_wh_through_link, -1); }
static void file_link(mstore *m, const sample *s) { with_tar(m, s, t_file_through_link, GZ_FIXED); }
static void hardlink_out(mstore *m, const sample *s) { with_tar(m, s, t_hardlink_out, GZ_FIXED); }
static void hardlink_missing(mstore *m, const sample *s) { with_tar(m, s, t_hardlink_missing, -1); }
static void root_file(mstore *m, const sample *s) { with_tar(m, s, t_root_file, GZ_FIXED); }

static void bad_diff_id(mstore *m, const sample *s)
{
    ow_layer l[3] = {s->l[0], s->l[1], s->l[2]};
    memcpy(l[1].diff, l[2].diff, 65);
    rebuild(m, l, 3, nullptr);
}
static void bad_diff_id_raw(mstore *m, const sample *s)
{
    ow_layer l[3] = {s->l[0], s->l[1], s->l[2]};
    l[0].diff[0] = l[0].diff[0] == 'a' ? 'b' : 'a';
    rebuild(m, l, 3, nullptr);
}

static void bomb_layer(mstore *m, const sample *s)
{
    buf raw = {0}, g = {0};
    make_bomb(&raw, 400 * 1024 * 4); // 400 KiB -> 420 MB
    static const uint8_t h[10] = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3};
    buf_put(&g, h, 10);
    buf_put(&g, raw.p, raw.n);
    buf_put(&g, "\0\0\0\0\0\0\0\0", 8);
    ow_layer l[4] = {s->l[0], s->l[1], s->l[2]};
    l[3] = (ow_layer){.data = g.p, .n = g.n};
    memcpy(l[3].diff, l[0].diff, 65);
    rebuild(m, l, 4, nullptr);
    free(raw.p);
    free(g.p);
}

static void zstd_media(mstore *m, const sample *s)
{
    ow_layer l[3] = {s->l[0], s->l[1], s->l[2]};
    l[1].media = "application/vnd.oci.image.layer.v1.tar+zstd"; // but it's gzip
    rebuild(m, l, 3, nullptr);
}
static void zstd_bomb(mstore *m, const sample *s)
{
    // RLE blocks: 4 bytes make 128 KiB, 8 KiB make 256 MiB
    buf z = {0};
    buf_put(&z, "\x28\xb5\x2f\xfd\x00\x38", 6);
    for (int i = 0; i < 2048; i++)
        buf_put(&z, i == 2047 ? "\x03\x00\x10x" : "\x02\x00\x10x", 4);
    ow_layer l[4] = {s->l[0], s->l[1], s->l[2]};
    l[3] = (ow_layer){.data = z.p, .n = z.n};
    memcpy(l[3].diff, l[0].diff, 65);
    rebuild(m, l, 4, nullptr);
    free(z.p);
}
static void zstd_corrupt(mstore *m, const sample *s)
{
    ow_layer l[4] = {s->l[0], s->l[1], s->l[2]};
    zstd_layer(&l[3]);
    uint8_t *c = malloc(l[3].n);
    memcpy(c, l[3].data, l[3].n);
    c[l[3].n - 1] ^= 0x40; // the checksum
    l[3].data = c;
    rebuild(m, l, 4, nullptr);
    free(c);
}
static void zstd_diff_id(mstore *m, const sample *s)
{
    ow_layer l[4] = {s->l[0], s->l[1], s->l[2]};
    zstd_layer(&l[3]);
    l[3].diff[5] = l[3].diff[5] == '0' ? '1' : '0';
    rebuild(m, l, 4, nullptr);
}
static void zstd_magic(mstore *m, const sample *s)
{
    static const uint8_t z[16] = {0x28, 0xb5, 0x2f, 0xfd, 4, 0, 0, 0};
    ow_layer l[4] = {s->l[0], s->l[1], s->l[2]};
    l[3] = (ow_layer){.data = z, .n = sizeof z, .media = "application/vnd.oci.image.layer.v1.tar"};
    memcpy(l[3].diff, l[0].diff, 65);
    rebuild(m, l, 4, nullptr);
}
static void media_mismatch(mstore *m, const sample *s)
{
    ow_layer l[3] = {s->l[0], s->l[1], s->l[2]};
    l[1].media = "application/vnd.oci.image.layer.v1.tar";
    rebuild(m, l, 3, nullptr);
}
static void unknown_media(mstore *m, const sample *s)
{
    ow_layer l[3] = {s->l[0], s->l[1], s->l[2]};
    l[1].media = "application/x-tar";
    rebuild(m, l, 3, nullptr);
}

static void put_index(mstore *m, const char *text) { ms_put(m, "index.json", (const uint8_t *)text, strlen(text)); }

static void deep_index(mstore *m, const sample *s)
{
    (void)s;
    buf b = {0};
    ow_printf(&b, "{\"schemaVersion\":2,\"manifests\":[],\"annotations\":{\"x\":");
    for (int i = 0; i < 100; i++)
        buf_put(&b, "[", 1);
    for (int i = 0; i < 100; i++)
        buf_put(&b, "]", 1);
    ow_printf(&b, "}}");
    buf_put(&b, "", 1);
    put_index(m, (const char *)b.p);
    free(b.p);
}
static void dup_key_index(mstore *m, const sample *s)
{
    (void)s;
    put_index(m, "{\"schemaVersion\":2,\"manifests\":[],\"manifests\":[]}");
}
static void sha512_index(mstore *m, const sample *s)
{
    (void)s;
    put_index(m, "{\"schemaVersion\":2,\"manifests\":[{\"mediaType\":"
                 "\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha512:abcd\",\"size\":1}]}");
}
static void upper_hex(mstore *m, const sample *s)
{
    (void)s;
    mfile *f = ms_find(m, "index.json");
    char *p = strstr((char *)f->data.p, "sha256:") + 7;
    for (int i = 0; i < 64; i++)
        if (p[i] >= 'a' && p[i] <= 'f')
            p[i] = (char)(p[i] - 32);
}
static void dup_key_config(mstore *m, const sample *s)
{
    rebuild(m, (ow_layer *)s->l, 3, "{\"User\":\"app\",\"User\":\"root\"}");
}
static void nul_in_env(mstore *m, const sample *s)
{
    rebuild(m, (ow_layer *)s->l, 3, "{\"Env\":[\"A=b\\u0000c\"]}");
}
static void cmd_not_strings(mstore *m, const sample *s) { rebuild(m, (ow_layer *)s->l, 3, "{\"Cmd\":[1]}"); }
static void diff_count(mstore *m, const sample *s)
{
    // a manifest with 3 layers, a config with 2 diff_ids
    ow_layer l[3] = {s->l[0], s->l[1], s->l[2]};
    char *cfg = ow_config_json(l, 2, &(ow_image){0});
    char hex[65];
    ow_blob(ms_out(m), cfg, strlen(cfg), hex);
    // point the manifest at it: rewrite the manifest by hand
    buf man = {0};
    ow_printf(&man, "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
                    "\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":"
                    "\"sha256:%s\",\"size\":%zu},\"layers\":[", hex, strlen(cfg));
    for (int i = 0; i < 3; i++) {
        char lh[65];
        ow_hex(l[i].data, l[i].n, lh);
        ow_printf(&man, "%s{\"mediaType\":\"%s\",\"digest\":\"sha256:%s\",\"size\":%zu}", i ? "," : "",
                  ow_media(&l[i]), lh, l[i].n);
    }
    ow_printf(&man, "]}");
    char mh[65];
    ow_blob(ms_out(m), man.p, man.n, mh);
    char ix[512];
    snprintf(ix, sizeof ix, "{\"schemaVersion\":2,\"manifests\":[{\"mediaType\":\"application/vnd.oci."
                            "image.manifest.v1+json\",\"digest\":\"sha256:%s\",\"size\":%zu}]}", mh, man.n);
    put_index(m, ix);
    free(man.p);
    free(cfg);
}

static void test_hostile_images(void)
{
    hostile("layer digest", flip_layer, "digest is sha256:");
    hostile("layer size", grow_layer, "its descriptor says");
    hostile("missing layer", drop_layer, "is missing");
    hostile("manifest digest", flip_manifest, "manifest blob's digest");
    hostile("no oci-layout", no_layout_file, "oci-layout is missing");
    hostile("diff_id", bad_diff_id, "diff_id");
    hostile("diff_id of an uncompressed layer", bad_diff_id_raw, "diff_id");
    hostile("gzip bomb", bomb_layer, "ratio");
    hostile("path with ..", dotdot, "\"..\"");
    hostile("whiteout with ..", wh_dotdot, "\"..\"");
    hostile("whiteout through a symlink", wh_link, "non-directory");
    hostile("file through a symlink", file_link, "non-directory");
    hostile("hard link out", hardlink_out, "hard link");
    hostile("hard link to nothing", hardlink_missing, "hard link");
    hostile("root replaced", root_file, "root directory");
    hostile("zstd media type on gzip", zstd_media, "media type says zstd but it is gzip");
    hostile("zstd bytes as tar", zstd_magic, "media type says uncompressed tar but it is zstd");
    hostile("zstd bomb", zstd_bomb, "ratio");
    hostile("zstd checksum", zstd_corrupt, "checksum mismatch");
    hostile("zstd diff_id", zstd_diff_id, "diff_id");
    hostile("gzip as tar", media_mismatch, "media type says uncompressed tar");
    hostile("unknown layer type", unknown_media, "unsupported media type");
    hostile("deep JSON", deep_index, "nested too deeply");
    hostile("duplicate keys", dup_key_index, "duplicate key");
    hostile("sha512", sha512_index, "unsupported digest algorithm");
    hostile("uppercase digest", upper_hex, "malformed");
    hostile("duplicate config keys", dup_key_config, "duplicate key");
    hostile("NUL in Env", nul_in_env, "NUL");
    hostile("Cmd of numbers", cmd_not_strings, "non-string");
    hostile("diff_id count", diff_count, "diff_ids");
}

// The decompressed-size cap applies to all layers together. (The ratio cap:
// "gzip bomb" in test_hostile_images.)
static void test_caps(void)
{
    sample s;
    sample_make(&s);
    mstore m = {0};
    oci_sample(&m, &s, &(ow_image){0});
    const oci_store st = {ms_open, &m};
    result r;
    const uint64_t total = s.tars[0].n + s.tars[1].n + s.tars[2].n;
    CHECK(convert_store(&st, &(oci_opts){.max_bytes = total}, &r));
    result_free(&r);
    CHECK(!convert_store(&st, &(oci_opts){.max_bytes = total - 1}, &r));
    CHECK_ERR(r.err, "cap");
    result_free(&r);
    ms_free(&m);
    sample_free(&s);
}

// ---- sample on disk, for the CLI tests ----------------------------------------------
static void mkdirs(const char *path)
{
    char p[1024];
    snprintf(p, sizeof p, "%s", path);
    for (char *c = p + 1; *c; c++) {
        if (*c == '/' || *c == '\\') {
            const char k = *c;
            *c = 0;
            mkdir_one(p);
            *c = k;
        }
    }
    mkdir_one(p);
}

typedef struct {
    const char *root;
} disk;

static void disk_put(void *ctx, const char *path, const uint8_t *data, size_t n)
{
    const disk *d = ctx;
    char full[1024];
    snprintf(full, sizeof full, "%s/%s", d->root, path);
    char *slash = strrchr(full, '/');
    *slash = 0;
    mkdirs(full);
    *slash = '/';
    FILE *f = fopen(full, "wb");
    if (!f || fwrite(data, 1, n, f) != n || fclose(f)) {
        fprintf(stderr, "cannot write %s\n", full);
        exit(1);
    }
}

static int write_sample(const char *dir)
{
    sample s;
    sample_make(&s);
    char path[1024];
    snprintf(path, sizeof path, "%s/layout", dir);
    disk d = {path};
    mkdirs(path);
    char *desc = ow_image_blobs(&(ow_out){disk_put, &d}, s.l, 3, &(ow_image){.config = SAMPLE_CONFIG});
    ow_index(&(ow_out){disk_put, &d}, &desc, 1);
    free(desc);
    buf tar = {0};
    ow_docker(&(ow_out){ow_tar_put, &tar}, s.l, 3, &(ow_image){.config = SAMPLE_CONFIG}, "sample:1", nullptr);
    tar_end(&tar);
    disk dd = {dir};
    disk_put(&dd, "docker.tar", tar.p, tar.n);
    free(tar.p);
    sample_free(&s);
    return 0;
}

static int read_file(const char *path, buf *b)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    uint8_t tmp[65536];
    size_t n;
    while ((n = fread(tmp, 1, sizeof tmp, f)) > 0)
        buf_put(b, tmp, n);
    fclose(f);
    return 0;
}

static int check_sample(const char *image, const char *config)
{
    result r = {0};
    if (read_file(image, &r.img)) {
        fprintf(stderr, "cannot read %s\n", image);
        return 1;
    }
    CHECK(sample_ok(&r.img));
    img m;
    inode in;
    if (img_open(&m, &r.img) && stat_path(&m, ".microvm/image-config", &in))
        buf_put(&r.cfg, data_of(&m, &in), in.size);
    CHECK(config_is(&r, SAMPLE_CFG_WANT));
    if (config) {
        buf c = {0};
        CHECK(!read_file(config, &c) && c.n == r.cfg.n && !memcmp(c.p, r.cfg.p, c.n));
        free(c.p);
    }
    result_free(&r);
    fprintf(stderr, "%s: %d checks, %d failures\n", image, checks, failures);
    return failures != 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--write-sample"))
        return write_sample(argv[2]);
    if ((argc == 3 || argc == 4) && !strcmp(argv[1], "--check-sample"))
        return check_sample(argv[2], argc == 4 ? argv[3] : nullptr);
    test_sha256();
    test_inflate_vectors();
    test_inflate_roundtrip();
    test_inflate_errors();
    test_inflate_bombs();
    test_json();
    test_oci_layout();
    test_docker_archive();
    test_zstd_layers();
    test_platforms();
    test_users();
    test_added_layers();
    test_hostile_images();
    test_caps();
    printf("%d checks, %d failures\n", checks, failures);
    return failures != 0;
}
