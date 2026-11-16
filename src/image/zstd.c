// SPDX-License-Identifier: MIT
// Zstandard decompression (RFC 8878): see zstd.h. The input is untrusted:
// every field is checked before it is used, and every table index, copy
// and back-reference is bounded by the buffers it touches.
#include "zstd.h"

#include <stdlib.h>
#include <string.h>

enum {
    BLOCK_MAX = 128 << 10, // Block_Maximum_Size can't exceed this
    IN_CAP = BLOCK_MAX + 64,
    WILD = 32, // slack after every buffer a copy writes to or reads from, for wild_copy
    HUF_MAX_BITS = 11,
    LL_MAX = 35, ML_MAX = 52, OF_MAX = 31,
    LL_AL = 9, ML_AL = 9, OF_AL = 8, HUF_W_AL = 6,
    MAGIC = 0xFD2FB528u, SKIP_MAGIC = 0x184D2A50u, // skippable: 0x184D2A50..5F
};

typedef struct {
    uint8_t sym, nb;
    uint16_t base;
} fse_e;

typedef struct {
    fse_e t[1 << LL_AL];
    unsigned al;
    bool ok;
} fse_t;

typedef struct {
    uint8_t sym[1 << HUF_MAX_BITS], nb[1 << HUF_MAX_BITS];
    uint16_t e[1 << HUF_MAX_BITS]; // sym | nb << 8, for huf_fast
    unsigned max_bits;
    bool ok;
} huf_t;

typedef struct {
    uint64_t v[4], total;
    uint8_t buf[32];
    unsigned n;
} xxh64;

typedef enum { S_FRAME, S_BLOCK, S_TRAILER, S_END } state;

struct zstd_stream {
    inflate_limits lim;
    inflate_pull pull;
    void *ctx;
    state st;
    const char *err;
    bool any_frame;
    // input
    uint8_t in[IN_CAP + WILD];
    size_t in_pos, in_len;
    bool in_eof;
    uint64_t total_in, total_out, builds;
    // output: this frame's last Window_Size bytes and the current block
    uint8_t *win;
    size_t win_cap, win_want, w_end, w_rd;
    // the frame
    uint64_t W, fcs, frame_out;
    bool has_fcs, has_sum, last;
    uint32_t block_max;
    xxh64 h;
    uint64_t rep[3];
    huf_t huf;
    fse_t ll, of, ml;
    uint8_t lit[BLOCK_MAX + WILD];
};

static int fail(zstd_stream *s, const char *why)
{
    if (!s->err)
        s->err = why;
    return -1;
}

static unsigned highbit(uint64_t v) { return 63u - (unsigned)__builtin_clzll(v); } // v != 0

// ---- XXH64 ---------------------------------------------------------------------------
static const uint64_t P1 = 11400714785074694791ull, P2 = 14029467366897019727ull,
                      P3 = 1609587929392839161ull, P4 = 9650029242287828579ull,
                      P5 = 2870177450012600261ull;

static uint64_t rotl(uint64_t x, unsigned r) { return x << r | x >> (64 - r); }
static uint64_t xround(uint64_t acc, uint64_t in) { return rotl(acc + in * P2, 31) * P1; }
static uint64_t xmerge(uint64_t acc, uint64_t v) { return (acc ^ xround(0, v)) * P1 + P4; }

static void xxh_init(xxh64 *h, uint64_t seed)
{
    *h = (xxh64){.v = {seed + P1 + P2, seed + P2, seed, seed - P1}};
}

static void xxh_update(xxh64 *h, const uint8_t *p, size_t n)
{
    h->total += n;
    if (h->n) {
        const size_t k = 32 - h->n < n ? 32 - h->n : n;
        memcpy(h->buf + h->n, p, k);
        h->n += (unsigned)k, p += k, n -= k;
        if (h->n < 32)
            return;
        for (int i = 0; i < 4; i++)
            h->v[i] = xround(h->v[i], get_le64(h->buf + 8 * i));
        h->n = 0;
    }
    for (; n >= 32; p += 32, n -= 32)
        for (int i = 0; i < 4; i++)
            h->v[i] = xround(h->v[i], get_le64(p + 8 * i));
    memcpy(h->buf, p, n);
    h->n = (unsigned)n;
}

static uint64_t xxh_digest(const xxh64 *h)
{
    uint64_t r;
    if (h->total >= 32) {
        r = rotl(h->v[0], 1) + rotl(h->v[1], 7) + rotl(h->v[2], 12) + rotl(h->v[3], 18);
        for (int i = 0; i < 4; i++)
            r = xmerge(r, h->v[i]);
    } else {
        r = h->v[2] + P5; // the seed + P5
    }
    r += h->total;
    const uint8_t *p = h->buf;
    unsigned n = h->n;
    for (; n >= 8; p += 8, n -= 8)
        r = rotl(r ^ xround(0, get_le64(p)), 27) * P1 + P4;
    if (n >= 4) {
        r = rotl(r ^ (uint64_t)get_le32(p) * P1, 23) * P2 + P3;
        p += 4, n -= 4;
    }
    for (; n; p++, n--)
        r = rotl(r ^ *p * P5, 11) * P1;
    r ^= r >> 33;
    r *= P2;
    r ^= r >> 29;
    r *= P3;
    return r ^ r >> 32;
}

uint64_t zstd_xxh64(const void *p, size_t n, uint64_t seed)
{
    xxh64 h;
    xxh_init(&h, seed);
    xxh_update(&h, p, n);
    return xxh_digest(&h);
}

// ---- bit readers ------------------------------------------------------------------------
// Backward (Huffman streams, FSE bitstreams): the last byte's highest set
// bit marks the end; bits are read from there towards the first byte. Bits
// "before" the first byte read as zero, and pos goes negative: callers
// check where pos ends.
typedef struct {
    const uint8_t *p;
    size_t len;
    int64_t pos;
} bbits;

static bool bb_init(bbits *b, const uint8_t *p, size_t len)
{
    if (!len || !p[len - 1])
        return false;
    *b = (bbits){p, len, (int64_t)(len - 1) * 8 + highbit(p[len - 1])};
    return true;
}

// Up to 8 bytes from byte i on, zero past the end.
static uint64_t load(const uint8_t *p, size_t len, size_t i)
{
    if (i + 8 <= len)
        return get_le64(p + i);
    uint64_t v = 0;
    for (size_t k = 0; i + k < len && k < 8; k++)
        v |= (uint64_t)p[i + k] << (8 * k);
    return v;
}

static inline uint64_t bb_read(bbits *b, unsigned n) // n <= 32
{
    if (!n)
        return 0;
    b->pos -= n;
    const int64_t pos = b->pos;
    if (pos >= 0)
        return load(b->p, b->len, (size_t)pos >> 3) >> (pos & 7) & ((1ull << n) - 1);
    const int64_t have = pos + n; // bits that exist, from bit 0
    if (have <= 0)
        return 0;
    return (load(b->p, b->len, 0) & ((1ull << have) - 1)) << -pos;
}

// The next n (<= 56) bits of a 64-bit load of a backward stream, *used of
// its top bits already taken. n = 0 gives 0.
static inline uint64_t take(uint64_t c, unsigned *used, unsigned n)
{
    const uint64_t v = ((c << *used) >> 1) >> (63 - n);
    *used += n;
    return v;
}

// Forward (FSE table descriptions): bit 0 of byte 0 first.
typedef struct {
    const uint8_t *p;
    size_t len;
    uint64_t pos;
} fbits;

static uint32_t fb_peek(const fbits *b, unsigned n) // n <= 16
{
    return (uint32_t)(load(b->p, b->len, b->pos >> 3) >> (b->pos & 7) & ((1u << n) - 1));
}

// ---- FSE -----------------------------------------------------------------------------
// A table description: normalized counts. *used: its bytes.
static bool fse_ncount(const uint8_t *src, size_t len, int16_t *norm, unsigned max_sym, unsigned max_al,
                       unsigned *al, unsigned *nsym, size_t *used)
{
    fbits b = {src, len, 0};
    if (!len)
        return false;
    *al = fb_peek(&b, 4) + 5;
    b.pos += 4;
    if (*al > max_al)
        return false;
    int remaining = (1 << *al) + 1, threshold = 1 << *al;
    unsigned nbits = *al + 1, sym = 0;
    bool prev0 = false;
    while (remaining > 1) {
        if (prev0) { // runs of zero counts: 2-bit repeat flags, 3 = "and more"
            unsigned rep;
            do {
                rep = fb_peek(&b, 2);
                b.pos += 2;
                if (sym + rep > max_sym + 1)
                    return false;
                for (unsigned i = 0; i < rep; i++)
                    norm[sym++] = 0;
            } while (rep == 3 && b.pos <= 8 * len);
        }
        if (sym > max_sym || b.pos > 8 * len)
            return false;
        const int max = (2 * threshold - 1) - remaining;
        const uint32_t v = fb_peek(&b, nbits);
        int count;
        if ((int)(v & (uint32_t)(threshold - 1)) < max) {
            count = (int)(v & (uint32_t)(threshold - 1));
            b.pos += nbits - 1;
        } else {
            count = (int)(v & (uint32_t)(2 * threshold - 1));
            if (count >= threshold)
                count -= max;
            b.pos += nbits;
        }
        count--; // -1: a "less than 1" probability, which takes one cell
        remaining -= count < 0 ? -count : count;
        norm[sym++] = (int16_t)count;
        prev0 = count == 0;
        if (remaining < threshold) {
            if (remaining <= 1)
                break;
            nbits = highbit((unsigned)remaining) + 1;
            threshold = 1 << (nbits - 1);
        }
    }
    if (remaining != 1 || b.pos > 8 * len)
        return false;
    *nsym = sym;
    *used = (size_t)((b.pos + 7) / 8);
    return true;
}

static bool fse_build(fse_t *t, const int16_t *norm, unsigned nsym, unsigned al)
{
    const unsigned size = 1u << al, mask = size - 1;
    unsigned high = size - 1;
    uint16_t next[256];
    t->ok = false;
    for (unsigned s = 0; s < nsym; s++) {
        if (norm[s] == -1) {
            t->t[high--].sym = (uint8_t)s;
            next[s] = 1;
        } else {
            next[s] = (uint16_t)norm[s];
        }
    }
    unsigned pos = 0;
    const unsigned step = (size >> 1) + (size >> 3) + 3;
    for (unsigned s = 0; s < nsym; s++)
        for (int i = 0; i < norm[s]; i++) {
            t->t[pos].sym = (uint8_t)s;
            do
                pos = (pos + step) & mask;
            while (pos > high);
        }
    if (pos != 0) // the counts don't fill the table exactly
        return false;
    for (unsigned u = 0; u < size; u++) {
        const unsigned s = t->t[u].sym, ns = next[s]++;
        const unsigned nb = al - highbit(ns);
        t->t[u].nb = (uint8_t)nb;
        t->t[u].base = (uint16_t)((ns << nb) - size);
    }
    t->al = al;
    t->ok = true;
    return true;
}

static void fse_rle(fse_t *t, uint8_t sym)
{
    t->t[0] = (fse_e){sym, 0, 0};
    t->al = 0;
    t->ok = true;
}

// The predefined distributions (RFC 8878 3.1.1.3.2.2).
static const int16_t LL_DEF[36] = {4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2,
                                   2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1};
static const int16_t ML_DEF[53] = {1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1};
static const int16_t OF_DEF[29] = {1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1,
                                   1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1};
static fse_t ll_def, ml_def, of_def;
static bool defs_ready;

static void defs_init(void)
{
    if (defs_ready)
        return;
    (void)fse_build(&ll_def, LL_DEF, 36, 6);
    (void)fse_build(&ml_def, ML_DEF, 53, 6);
    (void)fse_build(&of_def, OF_DEF, 29, 5);
    defs_ready = true;
}

static const uint32_t LL_BASE[36] = {0,  1,  2,  3,  4,  5,  6,   7,   8,   9,   10,  11,
                                     12, 13, 14, 15, 16, 18, 20,  22,  24,  28,  32,  40,
                                     48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536};
static const uint8_t LL_BITS[36] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
                                    1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
static const uint32_t ML_BASE[53] = {3,  4,  5,  6,  7,  8,  9,  10,  11,   12,   13,   14,   15,   16,
                                     17, 18, 19, 20, 21, 22, 23, 24,  25,   26,   27,   28,   29,   30,
                                     31, 32, 33, 34, 35, 37, 39, 41,  43,   47,   51,   59,   67,   83,
                                     99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539};
static const uint8_t ML_BITS[53] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1,
                                    2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

// ---- Huffman ----------------------------------------------------------------------------
static bool huf_build(huf_t *h, const uint8_t *w, unsigned nw)
{
    // The last symbol's weight is implied: it brings the sum to a power of 2.
    uint32_t sum = 0;
    for (unsigned i = 0; i < nw; i++) {
        if (w[i] > HUF_MAX_BITS)
            return false;
        if (w[i])
            sum += 1u << (w[i] - 1);
    }
    if (!sum)
        return false;
    const unsigned max_bits = highbit(sum) + 1;
    if (max_bits > HUF_MAX_BITS)
        return false;
    const uint32_t left = (1u << max_bits) - sum;
    if (!left || (left & (left - 1)))
        return false;
    uint8_t bits[256];
    for (unsigned i = 0; i < nw; i++)
        bits[i] = w[i] ? (uint8_t)(max_bits + 1 - w[i]) : 0;
    bits[nw] = (uint8_t)(max_bits + 1 - (highbit(left) + 1));
    const unsigned nsym = nw + 1;
    // Canonical codes, longest first, as the reference decoder builds them.
    unsigned count[HUF_MAX_BITS + 2] = {0}, idx[HUF_MAX_BITS + 2] = {0};
    for (unsigned i = 0; i < nsym; i++)
        count[bits[i]]++;
    const unsigned size = 1u << max_bits;
    idx[max_bits] = 0;
    for (unsigned b = max_bits; b >= 1; b--) {
        idx[b - 1] = idx[b] + count[b] * (1u << (max_bits - b));
        if (idx[b - 1] > size)
            return false;
        memset(h->nb + idx[b], (int)b, idx[b - 1] - idx[b]);
    }
    if (idx[0] != size)
        return false;
    for (unsigned i = 0; i < nsym; i++)
        if (bits[i]) {
            const unsigned n = 1u << (max_bits - bits[i]);
            memset(h->sym + idx[bits[i]], (int)i, n);
            idx[bits[i]] += n;
        }
    for (unsigned i = 0; i < size; i++)
        h->e[i] = (uint16_t)(h->sym[i] | h->nb[i] << 8);
    h->max_bits = max_bits;
    h->ok = true;
    return true;
}

// The tree description at p: *used is its size.
static bool huf_read(zstd_stream *s, const uint8_t *p, size_t len, size_t *used)
{
    uint8_t w[256];
    unsigned nw = 0;
    s->huf.ok = false;
    if (!len)
        return false;
    const unsigned hb = p[0];
    if (hb < 128) { // FSE-compressed weights, hb bytes
        if (!hb || 1 + (size_t)hb > len)
            return false;
        int16_t norm[256];
        unsigned al, nsym;
        size_t hl;
        fse_t t;
        if (!fse_ncount(p + 1, hb, norm, 255, HUF_W_AL, &al, &nsym, &hl) || hl >= hb ||
            !fse_build(&t, norm, nsym, al))
            return false;
        bbits b;
        if (!bb_init(&b, p + 1 + hl, hb - hl))
            return false;
        unsigned s1 = (unsigned)bb_read(&b, al), s2 = (unsigned)bb_read(&b, al);
        // Two interleaved states; when the bits run out, the other state's
        // symbol is the last weight.
        for (;;) {
            if (nw >= 255)
                return false;
            w[nw++] = t.t[s1].sym;
            s1 = t.t[s1].base + (unsigned)bb_read(&b, t.t[s1].nb);
            if (b.pos < 0) {
                w[nw++] = t.t[s2].sym;
                break;
            }
            if (nw >= 255)
                return false;
            w[nw++] = t.t[s2].sym;
            s2 = t.t[s2].base + (unsigned)bb_read(&b, t.t[s2].nb);
            if (b.pos < 0) {
                if (nw >= 255)
                    return false;
                w[nw++] = t.t[s1].sym;
                break;
            }
        }
        *used = 1 + hb;
    } else { // 4-bit weights, two per byte
        nw = hb - 127;
        const size_t nb = (nw + 1) / 2;
        if (1 + nb > len)
            return false;
        for (unsigned i = 0; i < nw; i++)
            w[i] = (uint8_t)(i & 1 ? p[1 + i / 2] & 15 : p[1 + i / 2] >> 4);
        *used = 1 + nb;
    }
    if (nw > 255)
        return false;
    s->builds++;
    return huf_build(&s->huf, w, nw);
}

// The rest of a Huffman stream from bit position pos (the bits below it
// unread): one bit read at a time, with the exact end check.
static bool huf_tail(const huf_t *h, const uint8_t *src, size_t len, int64_t pos, uint8_t *dst, size_t n)
{
    bbits b = {src, len, pos};
    const unsigned mb = h->max_bits, mask = (1u << mb) - 1;
    unsigned st = (unsigned)bb_read(&b, mb);
    for (size_t i = 0; i < n; i++) {
        dst[i] = h->sym[st];
        const unsigned nb = h->nb[st];
        st = ((st << nb) | (unsigned)bb_read(&b, nb)) & mask;
        if (b.pos < -(int64_t)mb)
            return false;
    }
    return b.pos == -(int64_t)mb; // every bit used, none made up
}

// HUF_FAST symbols from bit position *pos > 56, from one 64-bit load: at
// most 7 of its bits are past *pos, and four codes and a fifth peek take
// at most 5 * 11 more. Every bit it reads exists, so it decodes exactly
// what huf_tail would.
enum { HUF_FAST = 5 };
static inline void huf_fast(const huf_t *h, const uint8_t *src, int64_t *pos, uint8_t *dst)
{
    const int64_t q = ((*pos + 7) >> 3) - 8; // the load ends at the byte holding bit *pos - 1
    const uint64_t c = get_le64(src + q);
    unsigned used = (unsigned)(8 * q + 64 - *pos);
    const unsigned shift = 64 - h->max_bits;
    for (int k = 0; k < HUF_FAST; k++) {
        const unsigned e = h->e[(c << used) >> shift];
        dst[k] = (uint8_t)e;
        used += e >> 8;
    }
    *pos = 8 * q + 64 - used;
}

static bool huf_stream(const huf_t *h, const uint8_t *src, size_t len, uint8_t *dst, size_t n)
{
    bbits b;
    if (!bb_init(&b, src, len))
        return false;
    size_t i = 0;
    for (; n - i >= HUF_FAST && b.pos > 56; i += HUF_FAST)
        huf_fast(h, src, &b.pos, dst + i);
    return huf_tail(h, src, len, b.pos, dst + i, n - i);
}

// Four streams, interleaved while they all have bits and symbols for it.
static bool huf_streams4(const huf_t *h, const uint8_t *const src[4], const size_t len[4], uint8_t *const dst[4],
                         const size_t n[4])
{
    int64_t pos[4];
    for (int k = 0; k < 4; k++) {
        bbits b;
        if (!bb_init(&b, src[k], len[k]))
            return false;
        pos[k] = b.pos;
    }
    size_t i = 0; // n[3] is the smallest
    for (; n[3] - i >= HUF_FAST && pos[0] > 56 && pos[1] > 56 && pos[2] > 56 && pos[3] > 56; i += HUF_FAST)
        for (int k = 0; k < 4; k++)
            huf_fast(h, src[k], &pos[k], dst[k] + i);
    for (int k = 0; k < 4; k++)
        if (!huf_tail(h, src[k], len[k], pos[k], dst[k] + i, n[k] - i))
            return false;
    return true;
}

// ---- input ---------------------------------------------------------------------------
// At least n bytes (n <= IN_CAP) at s->in + s->in_pos, or *short_input if
// the input ends first. -1 only on a read error.
static int need(zstd_stream *s, size_t n, bool *short_input)
{
    *short_input = false;
    if (s->in_len - s->in_pos >= n)
        return 0;
    memmove(s->in, s->in + s->in_pos, s->in_len - s->in_pos);
    s->in_len -= s->in_pos;
    s->in_pos = 0;
    while (s->in_len < n && !s->in_eof) {
        size_t got = 0;
        if (s->pull(s->ctx, s->in + s->in_len, IN_CAP - s->in_len, &got))
            return fail(s, "cannot read the compressed data");
        if (!got)
            s->in_eof = true;
        s->in_len += got;
        s->total_in += got;
    }
    if (s->in_len < n)
        *short_input = true;
    return 0;
}

// ---- blocks ----------------------------------------------------------------------------
// n bytes, 16 at a time: it may write (and read) up to 15 bytes past n,
// which WILD leaves room for after every buffer it is used on. Those bytes
// are past what the block has produced, and later output overwrites them.
static inline void wild_copy(uint8_t *d, const uint8_t *s, size_t n)
{
    for (size_t i = 0; i < n; i += 16)
        memcpy(d + i, s + i, 16);
}

// The literals section at src: the literals in *lit (*nlit of them), *used bytes.
static int literals(zstd_stream *s, const uint8_t *src, size_t len, const uint8_t **lit, size_t *nlit,
                    size_t *used)
{
    if (!len)
        return fail(s, "zstd: a block without a literals section");
    const unsigned type = src[0] & 3, sf = src[0] >> 2 & 3;
    if (type < 2) { // raw or RLE
        size_t hs, n;
        if (sf == 0 || sf == 2)
            hs = 1, n = src[0] >> 3;
        else if (sf == 1)
            hs = 2, n = len >= 2 ? (size_t)(src[0] >> 4) + ((size_t)src[1] << 4) : 0;
        else
            hs = 3, n = len >= 3 ? (size_t)(src[0] >> 4) + ((size_t)src[1] << 4) + ((size_t)src[2] << 12) : 0;
        if (hs > len || n > s->block_max)
            return fail(s, "zstd: bad literals header");
        if (type == 0) {
            if (n > len - hs)
                return fail(s, "zstd: raw literals run past the block");
            *lit = src + hs;
            *used = hs + n;
        } else {
            if (hs + 1 > len)
                return fail(s, "zstd: RLE literals run past the block");
            memset(s->lit, src[hs], n);
            *lit = s->lit;
            *used = hs + 1;
        }
        *nlit = n;
        return 0;
    }
    // Huffman-coded, with a new tree (2) or the last one (3)
    static const uint8_t HS[4] = {3, 3, 4, 5}, BITS[4] = {10, 10, 14, 18};
    const size_t hs = HS[sf];
    if (hs > len)
        return fail(s, "zstd: bad literals header");
    uint64_t hv = 0;
    for (size_t i = 0; i < hs; i++)
        hv |= (uint64_t)src[i] << (8 * i);
    const unsigned nbits = BITS[sf];
    const size_t n = (size_t)(hv >> 4 & ((1u << nbits) - 1));
    const size_t csize = (size_t)(hv >> (4 + nbits) & ((1u << nbits) - 1));
    const unsigned streams = sf == 0 ? 1 : 4;
    if (n > s->block_max || csize > len - hs || !n)
        return fail(s, "zstd: bad literals sizes");
    const uint8_t *p = src + hs, *end = p + csize;
    if (type == 2) {
        size_t tl;
        if (!huf_read(s, p, csize, &tl))
            return fail(s, "zstd: bad Huffman tree");
        p += tl;
    } else if (!s->huf.ok) {
        return fail(s, "zstd: literals reuse a Huffman tree there isn't");
    }
    if (streams == 1) {
        if (!huf_stream(&s->huf, p, (size_t)(end - p), s->lit, n))
            return fail(s, "zstd: corrupt Huffman literals");
    } else {
        if (end - p < 6 || n < 6)
            return fail(s, "zstd: bad 4-stream literals");
        const size_t l1 = get_le16(p), l2 = get_le16(p + 2), l3 = get_le16(p + 4);
        p += 6;
        const size_t avail = (size_t)(end - p);
        if (l1 + l2 + l3 >= avail)
            return fail(s, "zstd: bad 4-stream literals jump table");
        const size_t l4 = avail - l1 - l2 - l3, seg = (n + 3) / 4;
        const size_t ls[4] = {l1, l2, l3, l4}, ns[4] = {seg, seg, seg, n - 3 * seg};
        const uint8_t *const ss[4] = {p, p + l1, p + l1 + l2, p + l1 + l2 + l3};
        uint8_t *const ds[4] = {s->lit, s->lit + seg, s->lit + 2 * seg, s->lit + 3 * seg};
        if (!huf_streams4(&s->huf, ss, ls, ds, ns))
            return fail(s, "zstd: corrupt Huffman literals");
    }
    *lit = s->lit;
    *nlit = n;
    *used = hs + csize;
    return 0;
}

static int seq_table(zstd_stream *s, unsigned mode, fse_t *t, const fse_t *def, unsigned max_sym,
                     unsigned max_al, const uint8_t **p, const uint8_t *end)
{
    switch (mode) {
    case 0:
        *t = *def;
        return 0;
    case 1:
        if (*p >= end || **p > max_sym)
            return fail(s, "zstd: bad RLE sequence table");
        fse_rle(t, *(*p)++);
        return 0;
    case 2: {
        int16_t norm[64];
        unsigned al, nsym;
        size_t used;
        s->builds++;
        if (!fse_ncount(*p, (size_t)(end - *p), norm, max_sym, max_al, &al, &nsym, &used) ||
            !fse_build(t, norm, nsym, al))
            return fail(s, "zstd: bad FSE sequence table");
        *p += used;
        return 0;
    }
    default:
        if (!t->ok)
            return fail(s, "zstd: a sequence table repeats one there isn't");
        return 0;
    }
}

// A compressed block's content: its output goes to dst (s->win + s->w_end).
static int block(zstd_stream *s, const uint8_t *src, size_t len, size_t *out)
{
    const uint8_t *lit;
    size_t nlit, lit_bytes;
    if (literals(s, src, len, &lit, &nlit, &lit_bytes))
        return -1;
    const uint8_t *p = src + lit_bytes, *end = src + len;
    uint8_t *dst = s->win + s->w_end;
    const size_t cap = s->block_max;
    if (p >= end)
        return fail(s, "zstd: a block without a sequences section");
    size_t nseq = *p++;
    if (nseq >= 128) {
        if (nseq == 255) {
            if (end - p < 2)
                return fail(s, "zstd: bad sequence count");
            nseq = p[0] + ((size_t)p[1] << 8) + 0x7f00;
            p += 2;
        } else {
            if (p >= end)
                return fail(s, "zstd: bad sequence count");
            nseq = ((nseq - 128) << 8) + *p++;
        }
    }
    if (!nseq) {
        if (p != end)
            return fail(s, "zstd: bytes after an empty sequences section");
        memcpy(dst, lit, nlit);
        *out = nlit;
        return 0;
    }
    if (p >= end)
        return fail(s, "zstd: no sequence compression modes");
    const unsigned modes = *p++;
    if (modes & 3)
        return fail(s, "zstd: reserved bits set in the sequence modes");
    if (seq_table(s, modes >> 6, &s->ll, &ll_def, LL_MAX, LL_AL, &p, end) ||
        seq_table(s, modes >> 4 & 3, &s->of, &of_def, OF_MAX, OF_AL, &p, end) ||
        seq_table(s, modes >> 2 & 3, &s->ml, &ml_def, ML_MAX, ML_AL, &p, end))
        return -1;
    bbits b;
    if (!bb_init(&b, p, (size_t)(end - p)))
        return fail(s, "zstd: bad sequences bitstream");
    unsigned sll = (unsigned)bb_read(&b, s->ll.al), sof = (unsigned)bb_read(&b, s->of.al),
             sml = (unsigned)bb_read(&b, s->ml.al);
    size_t op = 0, li = 0;
    for (size_t i = 0; i < nseq; i++) {
        const fse_e el = s->ll.t[sll], eo = s->of.t[sof], em = s->ml.t[sml];
        const unsigned llc = el.sym, ofc = eo.sym, mlc = em.sym;
        if (llc > LL_MAX || mlc > ML_MAX || ofc > OF_MAX)
            return fail(s, "zstd: bad sequence code");
        // The sequence's bits: offset, match and literal length extras,
        // then the next LL, ML and OF states. Their sizes are all known
        // now, so when they fit, one 64-bit load serves them (every bit it
        // reads exists, so this decodes exactly what bb_read would).
        const bool more = i + 1 < nseq;
        const unsigned mlb = ML_BITS[mlc], llb = LL_BITS[llc];
        const unsigned nbits = ofc + mlb + llb + (more ? (unsigned)el.nb + em.nb + eo.nb : 0u);
        uint64_t ofx, mlx, llx, ux = 0, mx = 0, ox = 0;
        if (nbits <= 56 && b.pos > 56) {
            const int64_t q = ((b.pos + 7) >> 3) - 8;
            const uint64_t c = get_le64(b.p + q);
            unsigned used = (unsigned)(8 * q + 64 - b.pos);
            ofx = take(c, &used, ofc);
            mlx = take(c, &used, mlb);
            llx = take(c, &used, llb);
            if (more) {
                ux = take(c, &used, el.nb);
                mx = take(c, &used, em.nb);
                ox = take(c, &used, eo.nb);
            }
            b.pos = 8 * q + 64 - used;
        } else {
            ofx = bb_read(&b, ofc);
            mlx = bb_read(&b, mlb);
            llx = bb_read(&b, llb);
            if (more) {
                ux = bb_read(&b, el.nb);
                mx = bb_read(&b, em.nb);
                ox = bb_read(&b, eo.nb);
            }
        }
        if (more) {
            sll = el.base + (unsigned)ux;
            sml = em.base + (unsigned)mx;
            sof = eo.base + (unsigned)ox;
        }
        uint64_t off = (1ull << ofc) + ofx;
        const size_t ml = ML_BASE[mlc] + (size_t)mlx;
        const size_t ll = LL_BASE[llc] + (size_t)llx;
        // Repeat offsets (RFC 8878 3.1.1.5).
        if (off > 3) {
            off -= 3;
            s->rep[2] = s->rep[1], s->rep[1] = s->rep[0], s->rep[0] = off;
        } else {
            const unsigned k = (unsigned)off - 1 + (ll == 0);
            if (k == 0) {
                off = s->rep[0];
            } else {
                off = k == 3 ? s->rep[0] - 1 : s->rep[k];
                if (k != 1)
                    s->rep[2] = s->rep[1];
                s->rep[1] = s->rep[0];
                s->rep[0] = off;
            }
        }
        if (ll > nlit - li || ll > cap - op || ml > cap - op - ll)
            return fail(s, "zstd: a sequence runs past its block");
        wild_copy(dst + op, lit + li, ll); // the literals and the window are apart
        op += ll, li += ll;
        const uint64_t have = s->w_end + op; // this frame's output still in the window
        if (!off || off > have || off > s->W)
            return fail(s, "zstd: a match reaches back past the window");
        uint8_t *o = dst + op;
        const uint8_t *m = o - off;
        if (off >= 16) { // each 16 bytes read are final before they are read
            wild_copy(o, m, ml);
        } else {
            for (size_t k = 0; k < ml; k++)
                o[k] = m[k];
        }
        op += ml;
    }
    if (b.pos != 0)
        return fail(s, "zstd: corrupt sequences bitstream");
    if (nlit - li > cap - op)
        return fail(s, "zstd: a block decompresses past its maximum size");
    memcpy(dst + op, lit + li, nlit - li);
    *out = op + nlit - li;
    return 0;
}

// ---- frames ----------------------------------------------------------------------------
static int frame_header(zstd_stream *s)
{
    bool short_in;
    if (need(s, 2, &short_in))
        return -1;
    if (short_in)
        return fail(s, "zstd: truncated frame header");
    const uint8_t fhd = s->in[s->in_pos];
    const unsigned fcs_flag = fhd >> 6, single = fhd >> 5 & 1, sum = fhd >> 2 & 1, did = fhd & 3;
    if (fhd & 8)
        return fail(s, "zstd: reserved bit set in a frame header");
    static const uint8_t DID[4] = {0, 1, 2, 4}, FCS[4] = {0, 2, 4, 8};
    const size_t fcs_len = fcs_flag == 0 ? single : FCS[fcs_flag];
    const size_t hl = (size_t)(1 + !single + DID[did]) + fcs_len;
    if (need(s, hl, &short_in))
        return -1;
    if (short_in)
        return fail(s, "zstd: truncated frame header");
    const uint8_t *p = s->in + s->in_pos + 1;
    uint64_t W = 0;
    if (!single) {
        const unsigned e = *p >> 3, m = *p & 7; // window log 10..41; capped below
        const uint64_t base = 1ull << (10 + e);
        W = base + (base / 8) * m;
        p++;
    }
    uint64_t dict = 0;
    for (size_t i = 0; i < DID[did]; i++)
        dict |= (uint64_t)p[i] << (8 * i);
    p += DID[did];
    if (dict)
        return fail(s, "zstd: the frame needs a dictionary, which isn't supported");
    uint64_t fcs = 0;
    for (size_t i = 0; i < fcs_len; i++)
        fcs |= (uint64_t)p[i] << (8 * i);
    if (fcs_len == 2)
        fcs += 256;
    s->has_fcs = fcs_len > 0;
    s->fcs = fcs;
    if (single)
        W = fcs;
    if (W > ZSTD_MAX_WINDOW)
        return fail(s, "zstd: the frame's window is larger than 128 MiB (zstd --long=31?)");
    if (s->lim.max_out && s->has_fcs && fcs > s->lim.max_out)
        return fail(s, "zstd: the frame says it decompresses past the size cap");
    s->in_pos += hl;
    s->W = W;
    s->block_max = (uint32_t)(W < BLOCK_MAX ? W : BLOCK_MAX);
    s->has_sum = sum;
    // The window buffer, grown as the frame outputs: Window_Size of history,
    // then at least as much again (and a block) before it slides, so sliding
    // copies at most as many bytes as the frame outputs. A frame that says
    // how long it is never needs more than that (and never slides).
    const size_t slack = W > BLOCK_MAX ? (size_t)W : BLOCK_MAX;
    s->win_want = (size_t)W + slack + BLOCK_MAX;
    if (s->has_fcs && fcs < s->win_want - BLOCK_MAX)
        s->win_want = (size_t)fcs + BLOCK_MAX;
    s->w_end = s->w_rd = 0;
    s->frame_out = 0;
    s->rep[0] = 1, s->rep[1] = 4, s->rep[2] = 8;
    s->huf.ok = s->ll.ok = s->of.ok = s->ml.ok = false;
    xxh_init(&s->h, 0);
    s->last = false;
    s->any_frame = true;
    s->st = S_BLOCK;
    return 0;
}

static int next_frame(zstd_stream *s)
{
    bool short_in;
    if (need(s, 4, &short_in))
        return -1;
    const size_t have = s->in_len - s->in_pos;
    if (short_in && !have) {
        if (!s->any_frame)
            return fail(s, "zstd: no frame in the data");
        s->st = S_END;
        return 0;
    }
    if (short_in)
        return fail(s, "zstd: trailing bytes after the last frame");
    const uint32_t magic = get_le32(s->in + s->in_pos);
    if ((magic & ~0xfu) == SKIP_MAGIC) {
        if (need(s, 8, &short_in))
            return -1;
        if (short_in)
            return fail(s, "zstd: truncated skippable frame");
        uint64_t skip = get_le32(s->in + s->in_pos + 4);
        s->in_pos += 8;
        while (skip) {
            if (need(s, 1, &short_in))
                return -1;
            if (short_in)
                return fail(s, "zstd: truncated skippable frame");
            const size_t k = s->in_len - s->in_pos < skip ? s->in_len - s->in_pos : (size_t)skip;
            s->in_pos += k;
            skip -= k;
        }
        return 0;
    }
    if (magic != MAGIC)
        return fail(s, s->any_frame ? "zstd: trailing bytes after the last frame" : "not zstd data");
    s->in_pos += 4;
    return frame_header(s);
}

static int check_limits(zstd_stream *s)
{
    const inflate_limits *l = &s->lim;
    if (l->max_out && s->total_out > l->max_out)
        return fail(s, "zstd: decompresses past the size cap");
    if (l->max_ratio && s->total_out > (uint64_t)l->max_ratio * s->total_in + l->ratio_slack)
        return fail(s, "zstd: decompresses past the ratio cap (a bomb?)");
    if (s->builds > 4096 + s->total_out / 1024)
        return fail(s, "zstd: too many table builds for its output");
    return 0;
}

static int next_block(zstd_stream *s)
{
    bool short_in;
    if (need(s, 3, &short_in))
        return -1;
    if (short_in)
        return fail(s, "zstd: truncated block header");
    const uint32_t bh = s->in[s->in_pos] | (uint32_t)s->in[s->in_pos + 1] << 8 | (uint32_t)s->in[s->in_pos + 2] << 16;
    const unsigned type = bh >> 1 & 3;
    const size_t size = bh >> 3;
    s->in_pos += 3;
    s->last = bh & 1;
    if (type == 3)
        return fail(s, "zstd: reserved block type");
    if (size > s->block_max)
        return fail(s, "zstd: a block is larger than the maximum");
    // Room for the block after the window's history: grow the buffer, or
    // once it is as big as the frame needs, slide the history to the front.
    if (s->w_end + BLOCK_MAX > s->win_cap && s->win_cap < s->win_want) {
        size_t cap = 2 * s->win_cap;
        if (cap < s->w_end + BLOCK_MAX)
            cap = s->w_end + BLOCK_MAX;
        if (cap > s->win_want)
            cap = s->win_want;
        uint8_t *w = realloc(s->win, cap + WILD);
        if (!w)
            return fail(s, "out of memory");
        s->win = w;
        s->win_cap = cap;
    }
    if (s->w_end + BLOCK_MAX > s->win_cap) { // win_cap >= W + BLOCK_MAX
        const size_t keep = s->w_end < s->W ? s->w_end : (size_t)s->W;
        memmove(s->win, s->win + s->w_end - keep, keep);
        s->w_end = s->w_rd = keep;
    }
    uint8_t *dst = s->win + s->w_end;
    size_t out = 0;
    const size_t content = type == 1 ? 1 : size;
    if (need(s, content, &short_in))
        return -1;
    if (short_in)
        return fail(s, "zstd: truncated block");
    const uint8_t *src = s->in + s->in_pos;
    if (type == 0) {
        memcpy(dst, src, size);
        out = size;
    } else if (type == 1) {
        memset(dst, src[0], size);
        out = size;
    } else if (block(s, src, size, &out)) {
        return -1;
    }
    s->in_pos += content;
    xxh_update(&s->h, dst, out);
    s->w_end += out;
    s->frame_out += out;
    s->total_out += out;
    if (s->has_fcs && s->frame_out > s->fcs)
        return fail(s, "zstd: the frame is longer than its header says");
    if (s->last)
        s->st = S_TRAILER;
    return check_limits(s);
}

static int trailer(zstd_stream *s)
{
    if (s->has_fcs && s->frame_out != s->fcs)
        return fail(s, "zstd: the frame is shorter than its header says");
    if (s->has_sum) {
        bool short_in;
        if (need(s, 4, &short_in))
            return -1;
        if (short_in)
            return fail(s, "zstd: truncated checksum");
        if (get_le32(s->in + s->in_pos) != (uint32_t)xxh_digest(&s->h))
            return fail(s, "zstd: checksum mismatch");
        s->in_pos += 4;
    }
    s->st = S_FRAME;
    return 0;
}

// ---- the interface ------------------------------------------------------------------------
zstd_stream *zstd_new(const inflate_limits *lim)
{
    defs_init();
    zstd_stream *s = calloc(1, sizeof *s);
    if (s)
        s->lim = *lim;
    return s;
}

void zstd_free(zstd_stream *s)
{
    if (s)
        free(s->win);
    free(s);
}

void zstd_start(zstd_stream *s, inflate_pull pull, void *ctx)
{
    s->pull = pull, s->ctx = ctx;
    s->st = S_FRAME;
    s->err = nullptr;
    s->any_frame = false;
    s->in_pos = s->in_len = 0;
    s->in_eof = false;
    s->total_in = s->total_out = s->builds = 0;
    s->w_end = s->w_rd = 0;
}

int zstd_peek(zstd_stream *s, const uint8_t **p, size_t *n)
{
    if (s->err)
        return -1;
    while (s->w_rd == s->w_end) {
        int r = 0;
        switch (s->st) {
        case S_END:
            *p = s->win, *n = 0;
            return 0;
        case S_FRAME:
            r = next_frame(s);
            break;
        case S_BLOCK:
            r = next_block(s);
            break;
        case S_TRAILER:
            r = trailer(s);
            break;
        }
        if (r)
            return -1;
    }
    *p = s->win + s->w_rd;
    *n = s->w_end - s->w_rd;
    return 0;
}

void zstd_consume(zstd_stream *s, size_t n) { s->w_rd += n; }

int zstd_read(zstd_stream *s, void *dst, size_t len, size_t *got)
{
    *got = 0;
    while (*got < len) {
        const uint8_t *p;
        size_t n;
        if (zstd_peek(s, &p, &n))
            return -1;
        if (!n)
            break;
        if (n > len - *got)
            n = len - *got;
        memcpy((uint8_t *)dst + *got, p, n);
        zstd_consume(s, n);
        *got += n;
    }
    return 0;
}

const char *zstd_error(const zstd_stream *s) { return s->err ? s->err : "no error"; }
uint64_t zstd_total_in(const zstd_stream *s) { return s->total_in; }
uint64_t zstd_total_out(const zstd_stream *s) { return s->total_out; }

typedef struct {
    const uint8_t *p;
    size_t n;
} mem_src;

static int mem_pull(void *ctx, uint8_t *buf, size_t cap, size_t *got)
{
    mem_src *m = ctx;
    const size_t k = m->n < cap ? m->n : cap;
    memcpy(buf, m->p, k);
    m->p += k, m->n -= k;
    *got = k;
    return 0;
}

int zstd_mem(const void *in, size_t inlen, const inflate_limits *lim, uint8_t **out, size_t *outlen,
             const char **err)
{
    *out = nullptr, *outlen = 0;
    zstd_stream *s = zstd_new(lim);
    if (!s) {
        *err = "out of memory";
        return -1;
    }
    mem_src m = {in, inlen};
    zstd_start(s, mem_pull, &m);
    size_t cap = 0, len = 0;
    uint8_t *b = malloc(1);
    int rc = b ? 0 : -1;
    *err = "out of memory";
    while (!rc) {
        const uint8_t *p;
        size_t n;
        if (zstd_peek(s, &p, &n)) {
            *err = zstd_error(s);
            rc = -1;
            break;
        }
        if (!n)
            break;
        if (len + n > cap) {
            cap = (len + n) * 2;
            uint8_t *nb = realloc(b, cap);
            if (!nb) {
                rc = -1;
                break;
            }
            b = nb;
        }
        memcpy(b + len, p, n);
        len += n;
        zstd_consume(s, n);
    }
    zstd_free(s);
    if (rc) {
        free(b);
        return -1;
    }
    *out = b, *outlen = len;
    return 0;
}
