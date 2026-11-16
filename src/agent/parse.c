// SPDX-License-Identifier: MIT
// INVOKE encoding and the parser for what the guest agent sends back
// (src/agent/proto.h). The guest is hostile: every field is checked, every
// size is bounded before anything is allocated, and the first violation
// stops the parser for good.
#include <stdlib.h>
#include <string.h>

#include "../common.h"
#include "agent.h"

static void hdr_put(uint8_t *p, uint8_t type, uint32_t id, uint32_t len)
{
    put_le32(p, MVA_MAGIC);
    p[4] = MVA_VERSION;
    p[5] = type;
    put_le16(p + 6, 0);
    put_le32(p + 8, id);
    put_le32(p + 12, len);
}

uint8_t *mva_encode_invoke(const mva_request *rq, uint32_t id, size_t *len)
{
    const uint32_t max_result = rq->max_result ? rq->max_result : MVA_MAX_RESULT;
    const uint32_t max_output = rq->max_output ? rq->max_output : MVA_MAX_OUTPUT;
    if (rq->deadline_ms < 1 || rq->deadline_ms > MVA_MAX_DEADLINE_MS || max_result > MVA_MAX_RESULT ||
        max_output > MVA_MAX_OUTPUT || rq->nargs > MVA_MAX_STRINGS || rq->nenv > MVA_MAX_STRINGS ||
        rq->payload_len > MVA_MAX_PAYLOAD || (rq->payload_len && !rq->payload))
        return nullptr;
    size_t strings = 0;
    for (size_t i = 0; i < rq->nargs + rq->nenv; i++) {
        const char *s = i < rq->nargs ? rq->argv[i] : rq->envp[i - rq->nargs];
        const size_t n = s ? strlen(s) : MVA_MAX_STRING + 1;
        if (n > MVA_MAX_STRING)
            return nullptr;
        strings += n;
    }
    if (strings > MVA_MAX_STRING_BYTES)
        return nullptr;
    const size_t body = MVA_INVOKE_FIXED + 4 * (rq->nargs + rq->nenv) + strings + rq->payload_len;
    uint8_t *f = malloc(MVA_HDR + body), *p = f;
    if (!f)
        return nullptr;
    hdr_put(p, MVA_INVOKE, id, (uint32_t)body);
    p += MVA_HDR;
    put_le32(p, rq->deadline_ms);
    put_le32(p + 4, max_result);
    put_le32(p + 8, max_output);
    put_le16(p + 12, (uint16_t)rq->nargs);
    put_le16(p + 14, (uint16_t)rq->nenv);
    put_le32(p + 16, (uint32_t)rq->payload_len);
    p += MVA_INVOKE_FIXED;
    for (size_t i = 0; i < rq->nargs + rq->nenv; i++) {
        const char *s = i < rq->nargs ? rq->argv[i] : rq->envp[i - rq->nargs];
        const size_t n = strlen(s);
        put_le32(p, (uint32_t)n);
        memcpy(p + 4, s, n);
        p += 4 + n;
    }
    if (rq->payload_len)
        memcpy(p, rq->payload, rq->payload_len);
    *len = MVA_HDR + body;
    return f;
}

void mva_parser_init(mva_parser *p) { *p = (mva_parser){0}; }

void mva_parser_expect(mva_parser *p, uint32_t id, uint32_t max_result, uint32_t max_output)
{
    p->inflight = true;
    p->id = id;
    p->max_result = max_result ? max_result : MVA_MAX_RESULT;
    p->max_output = max_output ? max_output : MVA_MAX_OUTPUT;
}

void mva_response_free(mva_response *rs)
{
    free(rs->result.data);
    free(rs->out.data);
    free(rs->err.data);
    *rs = (mva_response){0};
}

static size_t fail(mva_parser *p, const char *why, size_t consumed)
{
    p->error = why;
    return consumed;
}

static mva_buf *data_buf(mva_response *rs, uint8_t type)
{
    return type == MVA_STDOUT ? &rs->out : type == MVA_STDERR ? &rs->err : &rs->result;
}

// Room for `more` bytes in b, which may never hold more than `cap`.
static bool reserve(mva_buf *b, size_t more, size_t cap)
{
    if (more > cap || b->len > cap - more)
        return false;
    const size_t need = b->len + more;
    if (need <= b->cap)
        return true;
    size_t c = b->cap < 4096 ? 4096 : b->cap;
    while (c < need)
        c = c > cap / 2 ? cap : 2 * c;
    if (c < need) // cap < 4096 and need <= cap
        c = need;
    uint8_t *d = realloc(b->data, c);
    if (!d)
        return false;
    b->data = d;
    b->cap = c;
    return true;
}

// A complete header in p->hdr: check it and start the body.
static const char *header(mva_parser *p, mva_response *rs)
{
    const uint8_t *h = p->hdr;
    if (get_le32(h) != MVA_MAGIC)
        return "bad magic";
    if (h[4] != MVA_VERSION)
        return "unknown protocol version";
    if (get_le16(h + 6))
        return "nonzero header flags";
    p->type = h[5];
    const uint32_t id = get_le32(h + 8);
    p->body = get_le32(h + 12);
    p->got = 0;
    switch (p->type) {
    case MVA_HELLO:
        if (p->hello)
            return "a second HELLO";
        if (id || p->body != 16)
            return "malformed HELLO";
        return nullptr;
    case MVA_STDOUT:
    case MVA_STDERR:
    case MVA_RESULT: {
        if (!p->hello)
            return "data before HELLO";
        if (!p->inflight || id != p->id)
            return "data for no current invocation";
        if (p->body == 0 || p->body > MVA_MAX_CHUNK)
            return "data frame size out of range";
        const uint32_t cap = p->type == MVA_RESULT ? p->max_result : p->max_output;
        if (!reserve(data_buf(rs, p->type), p->body, cap))
            return p->type == MVA_RESULT ? "result past its cap" : "output past its cap";
        return nullptr;
    }
    case MVA_DONE:
        if (!p->hello)
            return "DONE before HELLO";
        if (!p->inflight || id != p->id)
            return "DONE for no current invocation";
        if (p->body != 16)
            return "malformed DONE";
        return nullptr;
    default:
        return "unknown frame type";
    }
}

// A complete HELLO or DONE body in p->small.
static const char *small_body(mva_parser *p, mva_response *rs)
{
    const uint8_t *b = p->small;
    if (p->type == MVA_HELLO) {
        if (get_le32(b) != MVA_VERSION || get_le32(b + 8) || get_le32(b + 12))
            return "malformed HELLO";
        p->hello = true;
        p->served = get_le32(b + 4);
        return nullptr;
    }
    const uint32_t kind = get_le32(b), flags = get_le32(b + 8);
    if (kind > MVA_KIND_MAX || (flags & ~(uint32_t)MVA_DONE_FLAGS))
        return "malformed DONE";
    // These mean the runtime is gone: the VM must say it ends.
    if ((kind == MVA_EXITED || kind == MVA_SIGNALED || kind == MVA_TIMEOUT || kind == MVA_FAULT) &&
        !(flags & MVA_DONE_VM_ENDS))
        return "DONE without VM_ENDS for a dead runtime";
    rs->kind = kind;
    rs->status = (int32_t)get_le32(b + 4);
    rs->flags = flags;
    rs->duration_us = get_le32(b + 12);
    rs->done = true;
    p->inflight = false;
    return nullptr;
}

size_t mva_parse(mva_parser *p, const uint8_t *buf, size_t n, mva_response *rs)
{
    size_t i = 0;
    while (i < n && !p->error) {
        if (!p->in_body) {
            if (!p->inflight && p->hello)
                return fail(p, "data while no invocation is running", i);
            const size_t k = MVA_HDR - p->have < n - i ? MVA_HDR - p->have : n - i;
            memcpy(p->hdr + p->have, buf + i, k);
            p->have += (uint32_t)k;
            i += k;
            if (p->have < MVA_HDR)
                break;
            p->have = 0;
            const char *e = header(p, rs);
            if (e)
                return fail(p, e, i);
            p->in_body = true;
            continue;
        }
        const size_t k = p->body - p->got < n - i ? p->body - p->got : n - i;
        if (p->type == MVA_HELLO || p->type == MVA_DONE) {
            memcpy(p->small + p->got, buf + i, k);
        } else {
            mva_buf *b = data_buf(rs, p->type);
            memcpy(b->data + b->len, buf + i, k); // reserved in header()
            b->len += k;
        }
        p->got += (uint32_t)k;
        i += k;
        if (p->got < p->body)
            break;
        p->in_body = false;
        if (p->type == MVA_HELLO || p->type == MVA_DONE) {
            const char *e = small_body(p, rs);
            if (e)
                return fail(p, e, i);
            if (rs->done)
                return i;
        }
    }
    return i;
}
