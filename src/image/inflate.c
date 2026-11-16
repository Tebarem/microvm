// SPDX-License-Identifier: MIT
// DEFLATE / gzip decompression (see inflate.h).
//
// Output goes to one linear buffer: 32 KiB of history, then up to 256 KiB
// of new output, which the reader consumes before more is decoded. When the
// buffer is full, the last 32 KiB slide to the front. Huffman codes decode
// with two-level tables (10 + up to 5 bits for literals/lengths, 8 + up to 7
// for distances); a 64-bit bit buffer holds enough bits for a whole
// length/distance pair after one refill.
#include "inflate.h"

#include <stdlib.h>

enum {
    WIN = 32768,
    CAP = 256 * 1024,
    LIM = WIN + CAP,  // decode while wr < LIM; one symbol adds at most 258 (+15 copy overrun)
    SLACK = 512,
    IN_CAP = 64 * 1024,
    LBITS = 10,
    DBITS = 8,
    CBITS = 7,
    LSIZE = (1 << LBITS) + 288 * 32,  // every long code's prefix with a 5-bit subtable
    DSIZE = (1 << DBITS) + 32 * 128,  // ... with a 7-bit subtable
    CSIZE = 1 << CBITS,
    NAME_MAX_LEN = 64 * 1024,         // gzip FNAME / FCOMMENT
};

typedef enum { S_HEADER, S_BLOCK, S_STORED, S_HUFF, S_TRAILER, S_DONE, S_ERROR } state;

struct inflate_stream {
    inflate_format fmt;
    inflate_limits lim;
    inflate_pull pull;
    void *ctx;
    state st;
    const char *err;
    bool final;
    uint64_t bitbuf; // bits above bitcnt are the next input bytes, or zero
    unsigned bitcnt;
    uint8_t *in;
    size_t in_pos, in_len;
    bool in_eof;
    uint64_t total_in, total_out, ndyn, members;
    uint8_t *buf;
    size_t rd, wr, mstart, crc_pos, fill_start; // mstart: where this member's output starts (or 0)
    uint32_t crc;
    uint64_t msize;
    uint64_t stored_left;
    const uint32_t *lt, *dt;
    uint32_t dyn_l[LSIZE], dyn_d[DSIZE], cl[CSIZE];
};

static uint32_t fixed_l[LSIZE], fixed_d[DSIZE];
static bool fixed_ready;

static const uint16_t lbase[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
                                   31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
static const uint8_t lext[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
static const uint16_t dbase[30] = {1,    2,    3,    4,    5,    7,     9,     13,    17,  25,
                                   33,   49,   65,   97,   129,  193,   257,   385,   513, 769,
                                   1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
static const uint8_t dext[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
                                 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
static const uint8_t cl_order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

// ---- CRC-32 (slicing by 8) ----------------------------------------------------
static uint32_t crc_tab[8][256];
static bool crc_ready;

static void crc_init(void)
{
    for (uint32_t n = 0; n < 256; n++) {
        uint32_t c = n;
        for (int k = 0; k < 8; k++)
            c = c & 1 ? 0xedb88320u ^ (c >> 1) : c >> 1;
        crc_tab[0][n] = c;
    }
    for (uint32_t n = 0; n < 256; n++)
        for (int k = 1; k < 8; k++)
            crc_tab[k][n] = crc_tab[0][crc_tab[k - 1][n] & 0xff] ^ (crc_tab[k - 1][n] >> 8);
    crc_ready = true;
}

uint32_t crc32_update(uint32_t crc, const void *data, size_t len)
{
    if (!crc_ready)
        crc_init();
    const uint8_t *p = data;
    crc = ~crc;
    while (len >= 8) {
        uint32_t a, b;
        memcpy(&a, p, 4);
        memcpy(&b, p + 4, 4);
        a ^= crc;
        crc = crc_tab[7][a & 0xff] ^ crc_tab[6][(a >> 8) & 0xff] ^ crc_tab[5][(a >> 16) & 0xff] ^
              crc_tab[4][a >> 24] ^ crc_tab[3][b & 0xff] ^ crc_tab[2][(b >> 8) & 0xff] ^
              crc_tab[1][(b >> 16) & 0xff] ^ crc_tab[0][b >> 24];
        p += 8;
        len -= 8;
    }
    while (len--)
        crc = crc_tab[0][(crc ^ *p++) & 0xff] ^ (crc >> 8);
    return ~crc;
}

// ---- Huffman tables -------------------------------------------------------------
// Entries: a code: sym << 16 | its length (1..15); a link to a subtable:
// offset << 16 | 0x8000 | the subtable's index bits; 0: no such code.
// Fails on over-subscribed lengths, and on incomplete ones unless the code
// has a single 1-bit code (as zlib: allowed for literal/length and
// distance codes, never for the code-length code). No codes at all is
// allowed; using one is then an error.
static int build(uint32_t *t, unsigned pbits, const uint8_t *len, unsigned n, bool cl_code)
{
    unsigned count[16] = {0};
    for (unsigned i = 0; i < n; i++)
        count[len[i]]++;
    count[0] = 0;
    int left = 1;
    unsigned max = 0;
    for (unsigned l = 1; l <= 15; l++) {
        left = left * 2 - (int)count[l];
        if (left < 0)
            return -1;
        if (count[l])
            max = l;
    }
    memset(t, 0, sizeof *t << pbits);
    if (max == 0)
        return 0;
    if (left > 0 && (cl_code || max != 1))
        return -1;

    unsigned next[16];
    unsigned code = 0;
    for (unsigned l = 1; l <= 15; l++) {
        code = (code + count[l - 1]) << 1;
        next[l] = code;
    }
    uint16_t rev[288];
    uint8_t sub[1 << LBITS] = {0};
    const unsigned pmask = (1u << pbits) - 1;
    for (unsigned i = 0; i < n; i++) {
        if (!len[i])
            continue;
        unsigned c = next[len[i]]++, r = 0;
        for (unsigned b = 0; b < len[i]; b++, c >>= 1)
            r = r << 1 | (c & 1);
        rev[i] = (uint16_t)r;
        if (len[i] > pbits && len[i] - pbits > sub[r & pmask])
            sub[r & pmask] = (uint8_t)(len[i] - pbits);
    }
    size_t used = (size_t)1 << pbits;
    for (unsigned p = 0; p <= pmask; p++) {
        if (!sub[p])
            continue;
        t[p] = (uint32_t)used << 16 | 0x8000 | sub[p];
        memset(t + used, 0, sizeof *t << sub[p]);
        used += (size_t)1 << sub[p];
    }
    for (unsigned i = 0; i < n; i++) {
        const unsigned l = len[i];
        if (!l)
            continue;
        const uint32_t e = (uint32_t)i << 16 | l;
        if (l <= pbits) {
            for (unsigned j = rev[i]; j <= pmask; j += 1u << l)
                t[j] = e;
        } else {
            const uint32_t link = t[rev[i] & pmask];
            const unsigned base = link >> 16, sb = link & 15;
            for (unsigned j = rev[i] >> pbits; j < 1u << sb; j += 1u << (l - pbits))
                t[base + j] = e;
        }
    }
    return 0;
}

static void fixed_init(void)
{
    uint8_t l[288];
    memset(l, 8, 144);
    memset(l + 144, 9, 112);
    memset(l + 256, 7, 24);
    memset(l + 280, 8, 8);
    (void)build(fixed_l, LBITS, l, 288, false);
    memset(l, 5, 32);
    (void)build(fixed_d, DBITS, l, 32, false);
    fixed_ready = true;
}

// ---- bits -------------------------------------------------------------------------
static void fail(inflate_stream *s, const char *why)
{
    if (s->st != S_ERROR)
        s->err = why;
    s->st = S_ERROR;
}

static bool pull_more(inflate_stream *s)
{
    if (s->in_eof)
        return false;
    size_t got = 0;
    if (s->pull(s->ctx, s->in, IN_CAP, &got) || got > IN_CAP) {
        fail(s, "cannot read the compressed data");
        s->in_eof = true;
        return false;
    }
    if (!got) {
        s->in_eof = true;
        return false;
    }
    s->in_pos = 0;
    s->in_len = got;
    s->total_in += got;
    return true;
}

static inline void refill(inflate_stream *s)
{
    if (MVM_LIKELY(s->in_len - s->in_pos >= 8)) {
        uint64_t v;
        memcpy(&v, s->in + s->in_pos, 8); // little-endian hosts only (x86-64)
        s->bitbuf |= v << s->bitcnt;
        s->in_pos += (63 - s->bitcnt) >> 3;
        s->bitcnt |= 56;
        return;
    }
    while (s->bitcnt <= 56) {
        if (s->in_pos == s->in_len && !pull_more(s))
            return;
        s->bitbuf |= (uint64_t)s->in[s->in_pos++] << s->bitcnt;
        s->bitcnt += 8;
    }
}

// The next n (<= 32) bits; false if the input ends first.
static bool bits(inflate_stream *s, unsigned n, uint32_t *v)
{
    if (s->bitcnt < n)
        refill(s);
    if (s->bitcnt < n) {
        fail(s, "the compressed data ends early");
        return false;
    }
    *v = (uint32_t)(s->bitbuf & ((1ull << n) - 1));
    s->bitbuf >>= n;
    s->bitcnt -= n;
    return true;
}

static inline bool decode(inflate_stream *s, const uint32_t *t, unsigned pbits, unsigned *sym)
{
    uint32_t e = t[s->bitbuf & ((1u << pbits) - 1)];
    if (e & 0x8000)
        e = t[(e >> 16) + ((s->bitbuf >> pbits) & ((1u << (e & 15)) - 1))];
    const unsigned l = e & 15;
    if (MVM_UNLIKELY(!l || l > s->bitcnt)) {
        fail(s, l ? "the compressed data ends early" : "an invalid Huffman code");
        return false;
    }
    s->bitbuf >>= l;
    s->bitcnt -= l;
    *sym = e >> 16;
    return true;
}

static bool byte(inflate_stream *s, uint32_t *hcrc, uint32_t *v)
{
    if (!bits(s, 8, v))
        return false;
    const uint8_t b = (uint8_t)*v;
    *hcrc = crc32_update(*hcrc, &b, 1);
    return true;
}

// ---- blocks ----------------------------------------------------------------------
static void gzip_header(inflate_stream *s)
{
    uint32_t h = 0, v[10];
    for (int i = 0; i < 10; i++) {
        if (!byte(s, &h, &v[i])) {
            if (s->members && i < 2) // not the start of another member
                s->err = "data after the end of the gzip stream";
            return;
        }
        if (i == 1 && (v[0] != 0x1f || v[1] != 0x8b))
            return fail(s, s->members ? "data after the end of the gzip stream" : "not gzip data");
    }
    if (v[2] != 8)
        return fail(s, "a gzip compression method other than deflate");
    const uint32_t flg = v[3];
    if (flg & 0xe0)
        return fail(s, "reserved gzip header flags are set");
    uint32_t x;
    if (flg & 4) { // FEXTRA
        uint32_t lo, hi;
        if (!byte(s, &h, &lo) || !byte(s, &h, &hi))
            return;
        for (uint32_t i = 0; i < (lo | hi << 8); i++)
            if (!byte(s, &h, &x))
                return;
    }
    for (uint32_t f = 8; f <= 16; f <<= 1) { // FNAME, FCOMMENT: zero-terminated
        if (!(flg & f))
            continue;
        size_t n = 0;
        do {
            if (!byte(s, &h, &x))
                return;
            if (++n > NAME_MAX_LEN)
                return fail(s, "an over-long gzip file name or comment");
        } while (x);
    }
    if (flg & 2) { // FHCRC: the low 16 bits of the header's CRC-32
        uint32_t want;
        if (!bits(s, 16, &want))
            return;
        if (want != (h & 0xffff))
            return fail(s, "the gzip header CRC is wrong");
    }
    s->final = false;
    s->crc = 0;
    s->msize = 0;
    s->crc_pos = s->mstart = s->wr;
    s->st = S_BLOCK;
}

static void crc_update(inflate_stream *s)
{
    if (s->fmt == INFLATE_GZIP && s->wr > s->crc_pos) {
        s->crc = crc32_update(s->crc, s->buf + s->crc_pos, s->wr - s->crc_pos);
        s->msize += s->wr - s->crc_pos;
    }
    s->crc_pos = s->wr;
}

static void gzip_trailer(inflate_stream *s)
{
    crc_update(s);
    s->bitbuf >>= s->bitcnt & 7;
    s->bitcnt &= ~7u;
    uint32_t crc, size;
    if (!bits(s, 32, &crc) || !bits(s, 32, &size))
        return;
    if (crc != s->crc)
        return fail(s, "the gzip CRC-32 is wrong");
    if (size != (uint32_t)s->msize)
        return fail(s, "the gzip size is wrong");
    s->members++;
    refill(s);
    s->st = s->bitcnt ? S_HEADER : S_DONE; // another member, or the end
}

static void dynamic(inflate_stream *s)
{
    uint32_t hlit, hdist, hclen;
    if (!bits(s, 5, &hlit) || !bits(s, 5, &hdist) || !bits(s, 4, &hclen))
        return;
    hlit += 257, hdist += 1, hclen += 4;
    if (hlit > 286 || hdist > 30)
        return fail(s, "too many literal/length or distance codes");
    uint8_t lens[286 + 30] = {0}, cl[19] = {0};
    for (uint32_t i = 0; i < hclen; i++) {
        uint32_t v;
        if (!bits(s, 3, &v))
            return;
        cl[cl_order[i]] = (uint8_t)v;
    }
    if (build(s->cl, CBITS, cl, 19, true))
        return fail(s, "an invalid code-length code");
    const uint32_t n = hlit + hdist;
    for (uint32_t i = 0; i < n;) {
        refill(s);
        unsigned sym;
        if (!decode(s, s->cl, CBITS, &sym))
            return;
        if (sym < 16) {
            lens[i++] = (uint8_t)sym;
            continue;
        }
        uint32_t rep, val = 0;
        if (sym == 16) {
            if (!i)
                return fail(s, "a length repeat with nothing to repeat");
            val = lens[i - 1];
            if (!bits(s, 2, &rep))
                return;
            rep += 3;
        } else if (sym == 17) {
            if (!bits(s, 3, &rep))
                return;
            rep += 3;
        } else {
            if (!bits(s, 7, &rep))
                return;
            rep += 11;
        }
        if (rep > n - i)
            return fail(s, "code length repeats run past the end");
        memset(lens + i, (int)val, rep);
        i += rep;
    }
    if (!lens[256])
        return fail(s, "no end-of-block code");
    if (build(s->dyn_l, LBITS, lens, hlit, false))
        return fail(s, "an invalid literal/length code");
    if (build(s->dyn_d, DBITS, lens + hlit, hdist, false))
        return fail(s, "an invalid distance code");
    // A Huffman block costs a table build; real streams have few, big ones.
    s->ndyn++;
    if (s->ndyn > 256 && s->ndyn > (s->total_out + (s->wr - s->fill_start)) / 256)
        return fail(s, "too many tiny Huffman blocks");
    s->lt = s->dyn_l;
    s->dt = s->dyn_d;
    s->st = S_HUFF;
}

static void block_header(inflate_stream *s)
{
    if (s->final) {
        s->st = s->fmt == INFLATE_GZIP ? S_TRAILER : S_DONE;
        return;
    }
    uint32_t v;
    if (!bits(s, 3, &v))
        return;
    s->final = v & 1;
    switch (v >> 1) {
    case 0: {
        s->bitbuf >>= s->bitcnt & 7;
        s->bitcnt &= ~7u;
        uint32_t len, nlen;
        if (!bits(s, 16, &len) || !bits(s, 16, &nlen))
            return;
        if (len != (~nlen & 0xffff))
            return fail(s, "a stored block's length check is wrong");
        s->stored_left = len;
        s->st = S_STORED;
        return;
    }
    case 1:
        s->lt = fixed_l;
        s->dt = fixed_d;
        s->st = S_HUFF;
        return;
    case 2:
        return dynamic(s);
    default:
        return fail(s, "an invalid block type");
    }
}

static void stored(inflate_stream *s)
{
    size_t k = LIM - s->wr;
    if (k > s->stored_left)
        k = (size_t)s->stored_left;
    s->stored_left -= k;
    while (k && s->bitcnt >= 8) { // bytes already in the bit buffer
        s->buf[s->wr++] = (uint8_t)s->bitbuf;
        s->bitbuf >>= 8;
        s->bitcnt -= 8;
        k--;
    }
    if (k)
        s->bitbuf = 0; // empty: what was above it is copied directly now
    while (k) {
        if (s->in_pos == s->in_len && !pull_more(s))
            return fail(s, "the compressed data ends early");
        size_t c = s->in_len - s->in_pos;
        if (c > k)
            c = k;
        memcpy(s->buf + s->wr, s->in + s->in_pos, c);
        s->wr += c;
        s->in_pos += c;
        k -= c;
    }
    if (!s->stored_left)
        s->st = S_BLOCK;
}

// The hot loop. The bit buffer, input position and tables live in locals:
// through `s` every output byte stored (a uint8_t, which may alias
// anything) would make the compiler reload them.
static void huffman(inflate_stream *s)
{
    uint8_t *const out = s->buf;
    const uint8_t *const in = s->in;
    const uint32_t *const lt = s->lt, *const dt = s->dt;
    const size_t mstart = s->mstart;
    size_t wr = s->wr, ip = s->in_pos, il = s->in_len;
    uint64_t bb = s->bitbuf;
    unsigned bc = s->bitcnt;
    const char *why = nullptr;
    while (wr < LIM) {
        if (bc < 48) { // enough for a whole length/distance pair
            if (MVM_LIKELY(il - ip >= 8)) {
                uint64_t v;
                memcpy(&v, in + ip, 8);
                bb |= v << bc;
                ip += (63 - bc) >> 3;
                bc |= 56;
            } else {
                s->bitbuf = bb, s->bitcnt = bc, s->in_pos = ip;
                refill(s);
                if (s->st == S_ERROR)
                    break;
                bb = s->bitbuf, bc = s->bitcnt, ip = s->in_pos, il = s->in_len;
            }
        }
        uint32_t e = lt[bb & ((1u << LBITS) - 1)];
        if (e & 0x8000)
            e = lt[(e >> 16) + ((bb >> LBITS) & ((1u << (e & 15)) - 1))];
        unsigned l = e & 15;
        if (MVM_UNLIKELY(!l || l > bc)) {
            why = l ? "the compressed data ends early" : "an invalid Huffman code";
            break;
        }
        bb >>= l;
        bc -= l;
        unsigned sym = e >> 16;
        if (sym < 256) {
            out[wr++] = (uint8_t)sym;
            continue;
        }
        if (sym == 256) {
            s->st = S_BLOCK;
            break;
        }
        sym -= 257;
        if (MVM_UNLIKELY(sym >= 29)) {
            why = "an invalid length symbol";
            break;
        }
        unsigned x = lext[sym];
        if (MVM_UNLIKELY(bc < x)) {
            why = "the compressed data ends early";
            break;
        }
        const size_t len = lbase[sym] + (size_t)(bb & ((1u << x) - 1));
        bb >>= x;
        bc -= x;
        e = dt[bb & ((1u << DBITS) - 1)];
        if (e & 0x8000)
            e = dt[(e >> 16) + ((bb >> DBITS) & ((1u << (e & 15)) - 1))];
        l = e & 15;
        if (MVM_UNLIKELY(!l || l > bc)) {
            why = l ? "the compressed data ends early" : "an invalid Huffman code";
            break;
        }
        bb >>= l;
        bc -= l;
        const unsigned dsym = e >> 16;
        if (MVM_UNLIKELY(dsym >= 30)) {
            why = "an invalid distance symbol";
            break;
        }
        x = dext[dsym];
        if (MVM_UNLIKELY(bc < x)) {
            why = "the compressed data ends early";
            break;
        }
        const size_t dist = dbase[dsym] + (size_t)(bb & ((1u << x) - 1));
        bb >>= x;
        bc -= x;
        if (MVM_UNLIKELY(dist > wr - mstart)) {
            why = "a distance too far back";
            break;
        }
        uint8_t *d = out + wr;
        const uint8_t *src = d - dist;
        if (dist >= 16) {
            for (size_t i = 0; i < len; i += 16)
                memcpy(d + i, src + i, 16);
        } else if (dist >= 8) {
            for (size_t i = 0; i < len; i += 8)
                memcpy(d + i, src + i, 8);
        } else if (dist == 1) {
            memset(d, *src, len);
        } else {
            for (size_t i = 0; i < len; i++)
                d[i] = src[i];
        }
        wr += len;
    }
    if (s->st != S_ERROR) {
        s->bitbuf = bb, s->bitcnt = bc, s->in_pos = ip;
        if (why)
            fail(s, why);
    }
    s->wr = wr;
}

static void fill(inflate_stream *s)
{
    if (s->wr >= LIM) { // everything was consumed: keep the last 32 KiB
        const size_t from = s->wr - WIN;
        memmove(s->buf, s->buf + from, WIN);
        s->mstart = s->mstart > from ? s->mstart - from : 0;
        s->rd = s->wr = s->crc_pos = WIN;
    }
    s->fill_start = s->wr;
    while (s->wr < LIM) {
        switch (s->st) {
        case S_HEADER: gzip_header(s); continue;
        case S_BLOCK: block_header(s); continue;
        case S_STORED: stored(s); continue;
        case S_HUFF: huffman(s); continue;
        case S_TRAILER: gzip_trailer(s); continue;
        case S_DONE:
        case S_ERROR: break;
        }
        break;
    }
    crc_update(s);
    s->total_out += s->wr - s->fill_start;
    if (s->lim.max_out && s->total_out > s->lim.max_out)
        fail(s, "the decompressed data exceeds the size cap");
    else if (s->lim.max_ratio &&
             s->total_out / s->lim.max_ratio > s->total_in + s->lim.ratio_slack / s->lim.max_ratio)
        fail(s, "the compression ratio exceeds the cap (a decompression bomb?)");
}

// ---- API ----------------------------------------------------------------------------
inflate_stream *inflate_new(inflate_format fmt, const inflate_limits *lim)
{
    if (!fixed_ready)
        fixed_init();
    if (!crc_ready)
        crc_init();
    inflate_stream *s = calloc(1, sizeof *s);
    if (!s)
        return nullptr;
    s->buf = malloc(LIM + SLACK);
    s->in = malloc(IN_CAP);
    if (!s->buf || !s->in) {
        inflate_free(s);
        return nullptr;
    }
    s->fmt = fmt;
    if (lim)
        s->lim = *lim;
    s->st = S_ERROR;
    s->err = "not started";
    return s;
}

void inflate_free(inflate_stream *s)
{
    if (!s)
        return;
    free(s->buf);
    free(s->in);
    free(s);
}

void inflate_start(inflate_stream *s, inflate_pull pull, void *ctx)
{
    s->pull = pull;
    s->ctx = ctx;
    s->st = s->fmt == INFLATE_GZIP ? S_HEADER : S_BLOCK;
    s->err = nullptr;
    s->final = s->in_eof = false;
    s->bitbuf = 0;
    s->bitcnt = 0;
    s->in_pos = s->in_len = 0;
    s->total_in = s->total_out = s->ndyn = s->members = 0;
    s->rd = s->wr = s->mstart = s->crc_pos = s->fill_start = 0;
    s->crc = 0;
    s->msize = s->stored_left = 0;
}

int inflate_peek(inflate_stream *s, const uint8_t **p, size_t *n)
{
    while (s->rd == s->wr && s->st != S_DONE && s->st != S_ERROR)
        fill(s);
    if (s->st == S_ERROR)
        return -1;
    *p = s->buf + s->rd;
    *n = s->wr - s->rd;
    return 0;
}

void inflate_consume(inflate_stream *s, size_t n)
{
    s->rd += n <= s->wr - s->rd ? n : s->wr - s->rd;
}

int inflate_read(inflate_stream *s, void *dst, size_t len, size_t *got)
{
    uint8_t *d = dst;
    *got = 0;
    while (*got < len) {
        const uint8_t *p;
        size_t n;
        if (inflate_peek(s, &p, &n))
            return -1;
        if (!n)
            break;
        if (n > len - *got)
            n = len - *got;
        memcpy(d + *got, p, n);
        inflate_consume(s, n);
        *got += n;
    }
    return 0;
}

const char *inflate_error(const inflate_stream *s) { return s->err ? s->err : "no error"; }
uint64_t inflate_total_in(const inflate_stream *s) { return s->total_in; }
uint64_t inflate_total_out(const inflate_stream *s) { return s->total_out; }

typedef struct {
    const uint8_t *p;
    size_t n;
} mem_in;

static int mem_pull(void *ctx, uint8_t *buf, size_t cap, size_t *got)
{
    mem_in *m = ctx;
    const size_t k = m->n < cap ? m->n : cap;
    memcpy(buf, m->p, k);
    m->p += k;
    m->n -= k;
    *got = k;
    return 0;
}

int inflate_mem(inflate_format fmt, const void *in, size_t inlen, const inflate_limits *lim,
                uint8_t **out, size_t *outlen, const char **err)
{
    *out = nullptr;
    *outlen = 0;
    inflate_stream *s = inflate_new(fmt, lim);
    uint8_t *o = malloc(1);
    if (!s || !o) {
        inflate_free(s);
        free(o);
        *err = "out of memory";
        return -1;
    }
    mem_in m = {in, inlen};
    inflate_start(s, mem_pull, &m);
    size_t n = 0, cap = 1;
    for (;;) {
        const uint8_t *p;
        size_t k;
        if (inflate_peek(s, &p, &k)) {
            *err = inflate_error(s);
            free(o);
            inflate_free(s);
            return -1;
        }
        if (!k)
            break;
        if (n + k > cap) {
            while (n + k > cap)
                cap *= 2;
            uint8_t *no = realloc(o, cap);
            if (!no) {
                *err = "out of memory";
                free(o);
                inflate_free(s);
                return -1;
            }
            o = no;
        }
        memcpy(o + n, p, k);
        n += k;
        inflate_consume(s, k);
    }
    inflate_free(s);
    *out = o;
    *outlen = n;
    return 0;
}
