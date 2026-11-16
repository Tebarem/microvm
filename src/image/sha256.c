// SPDX-License-Identifier: MIT
// SHA-256: portable C, plus the x86 SHA extensions when the CPU has them
// (checked once with CPUID; the portable code is the reference both are
// tested against).
#include "sha256.h"

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline uint32_t ror(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void blocks_portable(uint32_t h[8], const uint8_t *p, size_t nblk)
{
    while (nblk--) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = be32(p + 4 * i);
        for (int i = 16; i < 64; i++) {
            const uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
        for (int i = 0; i < 64; i++) {
            const uint32_t t1 = k + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
            const uint32_t t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            k = g, g = f, f = e, e = d + t1, d = c, c = b, b = a, a = t1 + t2;
        }
        h[0] += a, h[1] += b, h[2] += c, h[3] += d, h[4] += e, h[5] += f, h[6] += g, h[7] += k;
        p += 64;
    }
}

#if defined(__x86_64__)
#  include <cpuid.h>
#  include <immintrin.h>

[[gnu::target("sha,sse4.1,ssse3")]]
static void blocks_shani(uint32_t h[8], const uint8_t *p, size_t nblk)
{
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bull, 0x0405060700010203ull);
    __m128i tmp = _mm_loadu_si128((const __m128i *)&h[0]);
    __m128i s1 = _mm_loadu_si128((const __m128i *)&h[4]);
    tmp = _mm_shuffle_epi32(tmp, 0xB1);       // CDAB
    s1 = _mm_shuffle_epi32(s1, 0x1B);         // EFGH
    __m128i s0 = _mm_alignr_epi8(tmp, s1, 8); // ABEF
    s1 = _mm_blend_epi16(s1, tmp, 0xF0);      // CDGH
    while (nblk--) {
        const __m128i abef = s0, cdgh = s1;
        __m128i m[4];
#  pragma GCC unroll 16
        for (int i = 0; i < 16; i++) {
            if (i < 4)
                m[i] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(p + 16 * i)), MASK);
            __m128i msg = _mm_add_epi32(m[i % 4], _mm_loadu_si128((const __m128i *)&K[4 * i]));
            s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
            if (i >= 3 && i < 15) {
                const __m128i t = _mm_alignr_epi8(m[i % 4], m[(i + 3) % 4], 4);
                m[(i + 1) % 4] = _mm_sha256msg2_epu32(_mm_add_epi32(m[(i + 1) % 4], t), m[i % 4]);
            }
            msg = _mm_shuffle_epi32(msg, 0x0E);
            s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
            if (i >= 1 && i < 13)
                m[(i + 3) % 4] = _mm_sha256msg1_epu32(m[(i + 3) % 4], m[i % 4]);
        }
        s0 = _mm_add_epi32(s0, abef);
        s1 = _mm_add_epi32(s1, cdgh);
        p += 64;
    }
    tmp = _mm_shuffle_epi32(s0, 0x1B);  // FEBA
    s1 = _mm_shuffle_epi32(s1, 0xB1);   // DCHG
    s0 = _mm_blend_epi16(tmp, s1, 0xF0); // DCBA
    s1 = _mm_alignr_epi8(s1, tmp, 8);   // HGFE
    _mm_storeu_si128((__m128i *)&h[0], s0);
    _mm_storeu_si128((__m128i *)&h[4], s1);
}

static bool have_shani(void)
{
    unsigned a, b, c, d;
    if (!__get_cpuid(1, &a, &b, &c, &d) || !(c & (1u << 19)) || !(c & (1u << 9)))
        return false; // SSE4.1, SSSE3
    if (!__get_cpuid_count(7, 0, &a, &b, &c, &d))
        return false;
    return b & (1u << 29);
}
#endif

static void (*blocks)(uint32_t h[8], const uint8_t *p, size_t nblk);

static void pick(void)
{
    blocks = blocks_portable;
#if defined(__x86_64__)
    if (have_shani())
        blocks = blocks_shani;
#endif
}

void sha256_force_portable(bool on)
{
    pick();
    if (on)
        blocks = blocks_portable;
}

const char *sha256_impl(void)
{
    if (!blocks)
        pick();
    return blocks == blocks_portable ? "portable" : "sha-ni";
}

void sha256_init(sha256_ctx *c)
{
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    if (!blocks)
        pick();
    memcpy(c->h, iv, sizeof iv);
    c->len = 0;
    c->n = 0;
}

void sha256_update(sha256_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = data;
    if (!len)
        return;
    c->len += len;
    if (c->n) {
        const size_t k = len < 64 - c->n ? len : 64 - c->n;
        memcpy(c->buf + c->n, p, k);
        c->n += k, p += k, len -= k;
        if (c->n < 64)
            return;
        blocks(c->h, c->buf, 1);
        c->n = 0;
    }
    if (len >= 64) {
        blocks(c->h, p, len / 64);
        p += len & ~(size_t)63;
        len &= 63;
    }
    memcpy(c->buf, p, len);
    c->n = len;
}

void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    const uint64_t bits = c->len * 8;
    uint8_t pad[72] = {0x80};
    const size_t padlen = (c->n < 56 ? 56 : 120) - c->n;
    for (int i = 0; i < 8; i++)
        pad[padlen + (size_t)i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_update(c, pad, padlen + 8);
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(c->h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(c->h[i] >> 8);
        out[4 * i + 3] = (uint8_t)c->h[i];
    }
}

void sha256(const void *data, size_t len, uint8_t out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

void sha256_hex(const uint8_t d[32], char out[65])
{
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i] = hx[d[i] >> 4];
        out[2 * i + 1] = hx[d[i] & 15];
    }
    out[64] = 0;
}
