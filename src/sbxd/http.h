// SPDX-License-Identifier: MIT
// HTTP/1.1 for microvm-sbxd: an incremental request-head parser, the
// chunked transfer coding, a streaming multipart/form-data reader, and a
// JSON writer with base64. Requests come from the network: every limit is
// checked before anything is copied, and anything unusual is refused
// rather than guessed at (no obsolete line folding, no bare LF, no
// Content-Length together with chunked, no duplicate Content-Length).
#pragma once

#include <stddef.h>
#include <stdint.h>

enum {
    HTTP_MAX_HEAD = 32 * 1024, // request line + headers
    HTTP_MAX_HEADERS = 64,
};

typedef struct {
    const char *name, *value; // NUL-terminated, inside the request's copy
} http_hdr;

typedef struct {
    char *raw; // the head, copied (free it with http_req_free)
    const char *method, *target, *path, *query; // path: target before '?', query after (or "")
    http_hdr h[HTTP_MAX_HEADERS];
    int nh;
    int64_t length;  // Content-Length, or -1
    bool chunked;    // Transfer-Encoding: chunked
    bool close;      // Connection: close (or HTTP/1.0 without keep-alive)
    bool expect_100; // Expect: 100-continue
} http_req;

// Parses a complete head out of buf[0..len): 1 (r filled, *used bytes
// taken), 0 (need more), or an HTTP status to refuse with (400, 413, 431,
// 501, 505).
int http_parse_head(const uint8_t *buf, size_t len, http_req *r, size_t *used);
void http_req_free(http_req *r);
// A header's value (case-insensitive name), or nullptr.
const char *http_header(const http_req *r, const char *name);
// A query parameter, percent-decoded into out (cap bytes, NUL-terminated):
// true if present and it fits and holds no NUL.
bool http_query(const http_req *r, const char *name, char *out, size_t cap);
// Percent-decode s[0..n) (with '+' as space when form); false if malformed.
bool http_pct_decode(const char *s, size_t n, char *out, size_t cap, bool form);

// The chunked coding, decoded in place as it arrives.
typedef struct {
    int st;
    uint64_t left;
    unsigned ext; // bytes of chunk extensions / trailers seen (capped)
    bool digits;  // the size line has a digit
} http_chunked;

// Takes in[0..n): body bytes are copied to out (at most n of them; out
// may be in), *outn says how many, *used how much input was taken. 1 at
// the end of the body (after the trailers), 0 more to come, -1 malformed.
int http_chunked_feed(http_chunked *c, const uint8_t *in, size_t n, size_t *used, uint8_t *out, size_t *outn);

// multipart/form-data, streamed: feed the body, take events.
typedef enum { MP_NONE, MP_PART, MP_DATA, MP_END_PART, MP_DONE, MP_ERROR } mp_event;

typedef struct {
    char boundary[80]; // "\r\n--" + the boundary
    size_t blen;
    int st;
    uint8_t *buf;
    size_t len, cap, off;
    char name[256], filename[4096]; // the current part's Content-Disposition
    const uint8_t *data;            // MP_DATA: data[0..ndata)
    size_t ndata;
} mp_reader;

// From a Content-Type value: false if it isn't multipart/form-data with a
// usable boundary.
bool mp_init(mp_reader *m, const char *content_type);
bool mp_feed(mp_reader *m, const void *p, size_t n); // false: out of memory (or too much buffered)
// The next event; MP_NONE: feed more. After MP_DONE or MP_ERROR, stays.
mp_event mp_next(mp_reader *m, bool body_ended);
void mp_free(mp_reader *m);

// --- output ----------------------------------------------------------------

// A growable byte buffer. After every append p[len] is 0, so a buffer built
// only by appends is also a C string.
typedef struct {
    char *p;
    size_t len, cap;
    bool oom;
} sbuf;

void sb_put(sbuf *b, const void *p, size_t n);
void sb_puts(sbuf *b, const char *s);
void sb_printf(sbuf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void sb_free(sbuf *b);

// JSON values (the caller writes the punctuation between them).
void jw_str(sbuf *b, const char *s, size_t n); // a string: invalid UTF-8 becomes U+FFFD
void jw_cstr(sbuf *b, const char *s);
void jw_key(sbuf *b, bool *first, const char *key); // ,"key":
void jw_b64(sbuf *b, const void *p, size_t n);      // a string holding base64 (standard, padded)
// base64 (standard or URL-safe, padding optional): false if malformed.
bool b64_decode(const char *s, size_t n, uint8_t *out, size_t cap, size_t *outn);
// RFC 3339 UTC with nanoseconds, as ProtoJSON writes Timestamps.
void jw_time(sbuf *b, int64_t sec, uint32_t nsec);
