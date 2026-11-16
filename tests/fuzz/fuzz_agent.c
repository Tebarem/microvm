// SPDX-License-Identifier: MIT
// Fuzz the host's parser for the guest agent's stream (src/agent/parse.c):
// everything the guest sends after the vsock handshake is hostile.
//
// Input: byte 0 picks the result cap, byte 1 the output cap, bytes 2-3
// seed how the stream is split into reads; the rest is the guest's stream.
// The host has sent INVOKE 1 before reading anything, and after each DONE
// sends the next one (id + 1) if the guest has sent more.
//
// Invariants: no buffer ever holds more than its cap; DONE fields are
// within the protocol's ranges; an error is sticky (nothing more is
// consumed); and the outcome is the same however the stream is split.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent/agent.h"
#include "common.h"
#include "fuzz.h"

enum { MAX_INV = 16 };

typedef struct {
    size_t n;
    struct {
        uint64_t h[3];
        size_t len[3];
        uint32_t kind, flags, duration;
        int32_t status;
    } inv[MAX_INV];
    const char *error;
    size_t consumed;
    bool hello;
    uint32_t served;
} outcome;

static uint64_t fnv(const mva_buf *b)
{
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < b->len; i++)
        h = (h ^ b->data[i]) * 0x100000001b3ull;
    return h;
}

static const uint32_t caps[] = {1, 7, 100, 4096, 65536, 65537, 1u << 20, MVA_MAX_RESULT};

static void check_buf(const mva_buf *b, uint32_t cap)
{
    FUZZ_ASSERT(b->len <= cap && b->len <= b->cap);
    FUZZ_ASSERT(!b->cap || b->data);
}

static void run(const uint8_t *s, size_t n, uint32_t max_result, uint32_t max_output, uint32_t split,
                outcome *o)
{
    memset(o, 0, sizeof *o); // padding too: outcomes are compared with memcmp
    mva_parser p;
    mva_parser_init(&p);
    uint32_t id = 1;
    mva_parser_expect(&p, id, max_result, max_output);
    mva_response rs = {0};
    size_t at = 0;
    uint64_t rng = split * 2654435761u + 1;
    while (at < n && o->n < MAX_INV) {
        size_t chunk = n - at;
        if (split) {
            rng ^= rng << 13, rng ^= rng >> 7, rng ^= rng << 17;
            const size_t c = 1 + (size_t)(rng % (rng & 0x100 ? 23 : 4000));
            chunk = c < chunk ? c : chunk;
        }
        const size_t k = mva_parse(&p, s + at, chunk, &rs);
        FUZZ_ASSERT(k <= chunk);
        at += k;
        check_buf(&rs.result, max_result);
        check_buf(&rs.out, max_output);
        check_buf(&rs.err, max_output);
        if (p.error) {
            FUZZ_ASSERT(mva_parse(&p, s + at, n - at, &rs) == 0); // sticky
            break;
        }
        if (rs.done) {
            FUZZ_ASSERT(rs.kind <= MVA_KIND_MAX && !(rs.flags & ~(uint32_t)MVA_DONE_FLAGS));
            FUZZ_ASSERT(!p.inflight && p.hello);
            const mva_buf *b[3] = {&rs.result, &rs.out, &rs.err};
            for (int i = 0; i < 3; i++) {
                o->inv[o->n].h[i] = fnv(b[i]);
                o->inv[o->n].len[i] = b[i]->len;
            }
            o->inv[o->n].kind = rs.kind;
            o->inv[o->n].status = rs.status;
            o->inv[o->n].flags = rs.flags;
            o->inv[o->n].duration = rs.duration_us;
            o->n++;
            mva_response_free(&rs);
            mva_parser_expect(&p, ++id, max_result, max_output);
        } else {
            FUZZ_ASSERT(k == chunk); // only DONE or an error stop early
        }
    }
    mva_response_free(&rs);
    o->error = p.error;
    o->consumed = at;
    o->hello = p.hello;
    o->served = p.served;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4)
        return 0;
    const uint32_t max_result = caps[data[0] % MVM_ARRAY_LEN(caps)];
    const uint32_t max_output = caps[data[1] % MVM_ARRAY_LEN(caps)];
    const uint32_t split = (uint32_t)data[2] | (uint32_t)data[3] << 8;
    static outcome whole, pieces;
    run(data + 4, size - 4, max_result, max_output, 0, &whole);
    run(data + 4, size - 4, max_result, max_output, split | 1, &pieces);
    FUZZ_ASSERT(whole.n == pieces.n && whole.error == pieces.error && whole.consumed == pieces.consumed &&
                whole.hello == pieces.hello && whole.served == pieces.served);
    FUZZ_ASSERT(!memcmp(whole.inv, pieces.inv, sizeof whole.inv));
    return 0;
}

// ---- seeds: well-formed streams -------------------------------------------------

static size_t frame(uint8_t *p, uint8_t type, uint32_t id, const void *body, uint32_t len)
{
    put_le32(p, MVA_MAGIC);
    p[4] = MVA_VERSION;
    p[5] = type;
    put_le16(p + 6, 0);
    put_le32(p + 8, id);
    put_le32(p + 12, len);
    if (len)
        memcpy(p + MVA_HDR, body, len);
    return MVA_HDR + len;
}

static size_t hello(uint8_t *p, uint32_t served)
{
    uint8_t b[16] = {0};
    put_le32(b, MVA_VERSION);
    put_le32(b + 4, served);
    return frame(p, MVA_HELLO, 0, b, 16);
}

static size_t done(uint8_t *p, uint32_t id, uint32_t kind, int32_t status, uint32_t flags)
{
    uint8_t b[16] = {0};
    put_le32(b, kind);
    put_le32(b + 4, (uint32_t)status);
    put_le32(b + 8, flags);
    put_le32(b + 12, 1234);
    return frame(p, MVA_DONE, id, b, 16);
}

static uint8_t seed_buf[4][8192];

const fuzz_seed *fuzz_seeds(size_t *n)
{
    static fuzz_seed s[4];
    // 1. One invocation: output, error output, result, DONE.
    uint8_t *p = seed_buf[0];
    size_t k = 4;
    p[0] = 3, p[1] = 3, p[2] = 5, p[3] = 0;
    k += hello(p + k, 0);
    k += frame(p + k, MVA_STDOUT, 1, "hello\n", 6);
    k += frame(p + k, MVA_STDERR, 1, "warn\n", 5);
    k += frame(p + k, MVA_RESULT, 1, "{\"ok\":true}", 11);
    k += done(p + k, 1, MVA_RETURNED, 0, 0);
    s[0] = (fuzz_seed){p, k};
    // 2. Three invocations in a row, the last one ends the VM.
    p = seed_buf[1];
    k = 4;
    p[0] = 6, p[1] = 4, p[2] = 77, p[3] = 1;
    k += hello(p + k, 2);
    for (uint32_t id = 1; id <= 3; id++) {
        k += frame(p + k, MVA_RESULT, id, "abcdefgh", 8);
        k += frame(p + k, MVA_STDOUT, id, "x", 1);
        k += done(p + k, id, id == 3 ? MVA_TIMEOUT : MVA_RETURNED, id == 3 ? 0 : (int32_t)id,
                  id == 3 ? MVA_DONE_VM_ENDS | MVA_DONE_TRUNC_STDOUT : 0);
    }
    s[1] = (fuzz_seed){p, k};
    // 3. A cap hit: 100-byte output cap, 2 x 64 bytes.
    p = seed_buf[2];
    k = 4;
    p[0] = 2, p[1] = 2, p[2] = 1, p[3] = 2;
    static uint8_t junk[64];
    memset(junk, 'j', sizeof junk);
    k += hello(p + k, 0);
    k += frame(p + k, MVA_STDOUT, 1, junk, 64);
    k += frame(p + k, MVA_STDERR, 1, junk, 64);
    k += frame(p + k, MVA_STDOUT, 1, junk, 64);
    k += done(p + k, 1, MVA_RETURNED, 0, 0);
    s[2] = (fuzz_seed){p, k};
    // 4. A dead runtime after big result chunks.
    p = seed_buf[3];
    k = 4;
    p[0] = 7, p[1] = 7, p[2] = 9, p[3] = 9;
    k += hello(p + k, 0);
    static uint8_t big[3000];
    memset(big, 'r', sizeof big);
    k += frame(p + k, MVA_RESULT, 1, big, sizeof big);
    k += frame(p + k, MVA_RESULT, 1, big, sizeof big);
    k += done(p + k, 1, MVA_SIGNALED, 9, MVA_DONE_VM_ENDS);
    s[3] = (fuzz_seed){p, k};
    *n = 4;
    return s;
}
