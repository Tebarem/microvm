// SPDX-License-Identifier: MIT
// Fuzz microvm-sbxd's HTTP pieces (src/sbxd/http.c): what API clients send
// is untrusted. The first byte picks the target, the second how the input
// is split into reads.
//
// Invariants:
//   head       accepted heads hold a method, an origin-form path and only
//              clean header values; a head is never accepted past its end.
//   chunked    decoding gives the same bytes and verdict however the input
//              is split.
//   multipart  the same events and part bytes however the input is split.
//   base64     what jw_b64 writes decodes back to the input.
//   json       jw_str always writes one valid JSON string (checked by the
//              strict parser), and valid UTF-8 survives unchanged.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"
#include "image/json.h"
#include "sbxd/http.h"

static void head(const uint8_t *d, size_t n)
{
    http_req r;
    size_t used = 0;
    const int rc = http_parse_head(d, n, &r, &used);
    if (rc != 1)
        return;
    FUZZ_ASSERT(used <= n && used >= 4);
    FUZZ_ASSERT(!memcmp(d + used - 4, "\r\n\r\n", 4));
    FUZZ_ASSERT(r.method && r.method[0] && r.path && r.path[0] == '/' && r.query);
    FUZZ_ASSERT(r.nh >= 0 && r.nh <= HTTP_MAX_HEADERS);
    FUZZ_ASSERT(!(r.chunked && r.length >= 0));
    for (int i = 0; i < r.nh; i++) {
        FUZZ_ASSERT(r.h[i].name[0]);
        for (const char *c = r.h[i].value; *c; c++)
            FUZZ_ASSERT(*c != '\r' && *c != '\n');
    }
    char q[64];
    (void)http_query(&r, "path", q, sizeof q);
    (void)http_header(&r, "host");
    http_req_free(&r);
}

// Decodes d in pieces of `step` bytes (0: whole).
static int chunked_run(const uint8_t *d, size_t n, size_t step, uint8_t *out, size_t *outlen)
{
    http_chunked c = {0};
    size_t o = 0, off = 0;
    uint8_t *buf = malloc(n ? n : 1);
    if (!buf)
        abort();
    int rc = 0;
    while (off < n) {
        size_t k = step ? (n - off < step ? n - off : step) : n - off;
        memcpy(buf, d + off, k);
        size_t used, got;
        rc = http_chunked_feed(&c, buf, k, &used, buf, &got);
        FUZZ_ASSERT(used <= k && got <= used);
        memcpy(out + o, buf, got);
        o += got;
        off += used;
        if (rc != 0)
            break;
        FUZZ_ASSERT(used == k); // takes everything until the end
    }
    free(buf);
    *outlen = o;
    return rc;
}

static void chunked(const uint8_t *d, size_t n, size_t step)
{
    uint8_t *a = malloc(n + 1), *b = malloc(n + 1);
    if (!a || !b)
        abort();
    size_t na, nb;
    const int ra = chunked_run(d, n, 0, a, &na), rb = chunked_run(d, n, step ? step : 1, b, &nb);
    FUZZ_ASSERT(ra == rb);
    // A valid body decodes the same however it arrives (a malformed one is
    // refused either way; how much came out before is irrelevant).
    if (ra >= 0)
        FUZZ_ASSERT(na == nb && !memcmp(a, b, na));
    free(a);
    free(b);
}

typedef struct {
    uint8_t *p;
    size_t n, cap;
} acc;

static void acc_put(acc *a, const void *p, size_t n)
{
    if (a->n + n > a->cap) {
        size_t c = a->cap ? a->cap * 2 : 1024;
        while (c < a->n + n)
            c *= 2;
        if (!(a->p = realloc(a->p, c)))
            abort();
        a->cap = c;
    }
    memcpy(a->p + a->n, p, n);
    a->n += n;
}

// Every event (with its data) as one byte string.
static void multipart_run(const char *ct, const uint8_t *d, size_t n, size_t step, acc *log)
{
    mp_reader m;
    if (!mp_init(&m, ct))
        return;
    size_t off = 0;
    for (;;) {
        const bool end = off == n;
        mp_event ev;
        while ((ev = mp_next(&m, end)) != MP_NONE) {
            const uint8_t e = (uint8_t)ev;
            if (ev == MP_DATA)
                acc_put(log, m.data, m.ndata); // data may come in any split
            else
                acc_put(log, &e, 1);
            if (ev == MP_PART) {
                acc_put(log, m.name, strlen(m.name) + 1);
                acc_put(log, m.filename, strlen(m.filename) + 1);
            }
            if (ev == MP_DONE || ev == MP_ERROR)
                goto out;
        }
        if (end)
            break;
        const size_t k = step && n - off > step ? step : n - off;
        if (!mp_feed(&m, d + off, k)) {
            acc_put(log, "OOM", 3);
            break;
        }
        off += k;
    }
out:
    mp_free(&m);
}

static void multipart(const uint8_t *d, size_t n, size_t step)
{
    const char *ct = "multipart/form-data; boundary=XyZ";
    acc a = {0}, b = {0};
    multipart_run(ct, d, n, 0, &a);
    multipart_run(ct, d, n, step ? step : 1, &b);
    // Data runs may be split differently, but the bytes and events agree.
    FUZZ_ASSERT(a.n == b.n && (!a.n || !memcmp(a.p, b.p, a.n)));
    free(a.p);
    free(b.p);
}

static void base64(const uint8_t *d, size_t n)
{
    sbuf s = {0};
    jw_b64(&s, d, n);
    FUZZ_ASSERT(!s.oom && s.len >= 2 && s.p[0] == '"' && s.p[s.len - 1] == '"');
    uint8_t *out = malloc(n + 3);
    size_t got;
    FUZZ_ASSERT(out && b64_decode(s.p + 1, s.len - 2, out, n + 3, &got));
    FUZZ_ASSERT(got == n && (!n || !memcmp(out, d, n)));
    free(out);
    sb_free(&s);
    // And decoding junk never writes past the end.
    uint8_t small[8];
    (void)b64_decode((const char *)d, n, small, sizeof small, &got);
}

static void json_string(const uint8_t *d, size_t n)
{
    sbuf s = {0};
    jw_str(&s, (const char *)d, n);
    FUZZ_ASSERT(!s.oom);
    const char *err;
    json_doc *doc = json_parse(s.p, s.len, &JSON_DEFAULT_LIMITS, &err);
    FUZZ_ASSERT(doc);
    const json_value *v = json_root(doc);
    FUZZ_ASSERT(v->type == JSON_STRING);
    // Valid UTF-8 in, the same text out.
    json_doc *in = nullptr;
    sbuf q = {0};
    sb_puts(&q, "\"");
    bool plain = true;
    for (size_t i = 0; i < n; i++)
        plain &= d[i] >= 0x20 && d[i] != '"' && d[i] != '\\';
    if (plain) {
        sb_put(&q, d, n);
        sb_puts(&q, "\"");
        in = json_parse(q.p, q.len, &JSON_DEFAULT_LIMITS, &err);
        if (in)
            FUZZ_ASSERT(v->len == n && !memcmp(v->str, d, n));
    }
    json_free(in);
    sb_free(&q);
    json_free(doc);
    sb_free(&s);
    char out[64];
    (void)http_pct_decode((const char *)d, n, out, sizeof out, true);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
        return 0;
    const uint8_t which = data[0] % 5;
    const size_t step = data[1] % 17;
    data += 2, size -= 2;
    switch (which) {
    case 0: head(data, size); break;
    case 1: chunked(data, size, step); break;
    case 2: multipart(data, size, step); break;
    case 3: base64(data, size); break;
    default: json_string(data, size); break;
    }
    return 0;
}

const fuzz_seed *fuzz_seeds(size_t *n)
{
    static const char h[] = "\0\0POST /process.Process/Start?a=b%20c HTTP/1.1\r\nHost: 8000-abc.sbx.test\r\n"
                            "Transfer-Encoding: chunked\r\nE2b-Sandbox-Id: abc\r\nConnection: keep-alive\r\n\r\n";
    static const char c[] = "\1\3" "5\r\nhello\r\n3;ext=1\r\n wo\r\nA\r\n0123456789\r\n0\r\nTrailer: x\r\n\r\n";
    static const char m[] = "\2\5preamble\r\n--XyZ\r\nContent-Disposition: form-data; name=\"file\"; "
                            "filename=\"/tmp/a.txt\"\r\nContent-Type: text/plain\r\n\r\nalpha\r\n--XyZ\r\n"
                            "Content-Disposition: form-data; name=\"file\"; filename=\"b\"\r\n\r\n"
                            "-XyZ not a boundary\r\n--XyZ--\r\nepilogue";
    static const char b[] = "\3\0any bytes \xff\x00\x01";
    static const char j[] = "\4\0text \xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80 \xff\xfe \x01 \"q\" \\";
    static fuzz_seed s[5];
    s[0] = (fuzz_seed){(const uint8_t *)h, sizeof h - 1};
    s[1] = (fuzz_seed){(const uint8_t *)c, sizeof c - 1};
    s[2] = (fuzz_seed){(const uint8_t *)m, sizeof m - 1};
    s[3] = (fuzz_seed){(const uint8_t *)b, sizeof b - 1};
    s[4] = (fuzz_seed){(const uint8_t *)j, sizeof j - 1};
    *n = 5;
    return s;
}
