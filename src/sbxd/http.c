// SPDX-License-Identifier: MIT
// HTTP/1.1 pieces for microvm-sbxd (http.h). Network input: strict.
#include "sbxd/http.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static char lower(char c) { return c >= 'A' && c <= 'Z' ? (char)(c + 32) : c; }

static bool ieq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++)
        if (lower(*a) != lower(*b))
            return false;
    return !*a && !*b;
}

static bool tchar(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           (c && strchr("!#$%&'*+-.^_`|~", c));
}

// Does a comma-separated header value list hold token (case-insensitive)?
static bool has_token(const char *v, const char *token)
{
    const size_t tl = strlen(token);
    while (*v) {
        while (*v == ' ' || *v == '\t' || *v == ',')
            v++;
        const char *s = v;
        while (*v && *v != ',')
            v++;
        const char *e = v;
        while (e > s && (e[-1] == ' ' || e[-1] == '\t'))
            e--;
        if ((size_t)(e - s) == tl) {
            bool same = true;
            for (size_t i = 0; i < tl; i++)
                same &= lower(s[i]) == lower(token[i]);
            if (same)
                return true;
        }
    }
    return false;
}

void http_req_free(http_req *r)
{
    free(r->raw);
    *r = (http_req){0};
}

int http_parse_head(const uint8_t *buf, size_t len, http_req *r, size_t *used)
{
    *r = (http_req){.length = -1};
    // Leading empty lines are allowed before a request (RFC 9112 2.2).
    size_t start = 0;
    while (start + 1 < len && buf[start] == '\r' && buf[start + 1] == '\n')
        start += 2;
    const uint8_t *end = nullptr;
    for (size_t i = start; i + 3 < len; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            end = buf + i;
            break;
        }
    if (!end)
        return len - start > HTTP_MAX_HEAD ? 431 : 0;
    const size_t hl = (size_t)(end - buf) - start;
    if (hl > HTTP_MAX_HEAD)
        return 431;
    // One block: the head (with its CRLF), then a copy of the target that
    // is split into path and query.
    char *h = malloc(2 * hl + 8);
    if (!h)
        return 503;
    memcpy(h, buf + start, hl);
    h[hl] = '\r', h[hl + 1] = '\n', h[hl + 2] = 0;
    r->raw = h;
    for (size_t i = 0; i < hl; i++) // no NULs, no bare CR or LF
        if (!h[i] || (h[i] == '\r' && h[i + 1] != '\n') || (h[i] == '\n' && (i == 0 || h[i - 1] != '\r')))
            goto bad;
    // Request line: METHOD SP target SP HTTP/1.1
    char *line_end = strstr(h, "\r\n");
    *line_end = 0;
    char *sp1 = strchr(h, ' ');
    char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : nullptr;
    if (!sp1 || !sp2 || strchr(sp2 + 1, ' ') || sp1 == h || sp2 == sp1 + 1)
        goto bad;
    *sp1 = *sp2 = 0;
    r->method = h;
    r->target = sp1 + 1;
    for (const char *c = r->method; *c; c++)
        if (!tchar(*c))
            goto bad;
    // HTTP/1.1 only: the responses are chunked, and nothing that talks to
    // this daemon (the SDKs, curl) speaks 1.0.
    if (strcmp(sp2 + 1, "HTTP/1.1")) {
        http_req_free(r);
        return 505;
    }
    if (r->target[0] != '/') // origin-form only
        goto bad;
    for (const char *c = r->target; *c; c++)
        if ((unsigned char)*c <= 0x20 || *c == 0x7f)
            goto bad;
    const size_t tl = strlen(r->target);
    char *pq = h + hl + 3;
    memcpy(pq, r->target, tl + 1);
    char *q = strchr(pq, '?');
    if (q)
        *q = 0;
    r->path = pq;
    r->query = q ? q + 1 : pq + tl;
    // Headers.
    bool have_len = false;
    for (char *p = line_end + 2; *p;) {
        char *e = strstr(p, "\r\n");
        *e = 0;
        if (*p == ' ' || *p == '\t') // obsolete line folding
            goto bad;
        char *colon = strchr(p, ':');
        if (!colon || colon == p)
            goto bad;
        *colon = 0;
        for (char *c = p; *c; c++)
            if (!tchar(*c))
                goto bad;
        char *v = colon + 1;
        while (*v == ' ' || *v == '\t')
            v++;
        char *ve = v + strlen(v);
        while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t'))
            *--ve = 0;
        for (char *c = v; *c; c++)
            if ((unsigned char)*c < 0x20 && *c != '\t')
                goto bad;
        if (r->nh == HTTP_MAX_HEADERS) {
            http_req_free(r);
            return 431;
        }
        r->h[r->nh++] = (http_hdr){p, v};
        if (ieq(p, "content-length")) {
            if (have_len || !*v || strlen(v) > 18)
                goto bad;
            int64_t n = 0;
            for (char *c = v; *c; c++) {
                if (*c < '0' || *c > '9')
                    goto bad;
                n = n * 10 + (*c - '0');
            }
            r->length = n;
            have_len = true;
        } else if (ieq(p, "transfer-encoding")) {
            if (!ieq(v, "chunked")) { // only chunked, alone
                http_req_free(r);
                return 501;
            }
            r->chunked = true;
        } else if (ieq(p, "connection")) {
            r->close |= has_token(v, "close");
        } else if (ieq(p, "expect")) {
            if (!ieq(v, "100-continue"))
                goto bad;
            r->expect_100 = true;
        }
        p = e + 2;
    }
    if (r->chunked && have_len) // request smuggling: refuse
        goto bad;
    *used = (size_t)(end - buf) + 4;
    return 1;
bad:
    http_req_free(r);
    return 400;
}

const char *http_header(const http_req *r, const char *name)
{
    for (int i = 0; i < r->nh; i++)
        if (ieq(r->h[i].name, name))
            return r->h[i].value;
    return nullptr;
}

static int hexv(char c)
{
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

bool http_pct_decode(const char *s, size_t n, char *out, size_t cap, bool form)
{
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == '%') {
            if (i + 2 >= n || hexv(s[i + 1]) < 0 || hexv(s[i + 2]) < 0)
                return false;
            c = (char)(hexv(s[i + 1]) << 4 | hexv(s[i + 2]));
            i += 2;
            if (!c)
                return false;
        } else if (c == '+' && form) {
            c = ' ';
        }
        if (k + 1 >= cap)
            return false;
        out[k++] = c;
    }
    out[k] = 0;
    return true;
}

bool http_query(const http_req *r, const char *name, char *out, size_t cap)
{
    const size_t nl = strlen(name);
    for (const char *p = r->query; *p;) {
        const char *e = strchr(p, '&');
        if (!e)
            e = p + strlen(p);
        const char *eq = memchr(p, '=', (size_t)(e - p));
        const char *ke = eq ? eq : e;
        char key[128];
        if (http_pct_decode(p, (size_t)(ke - p), key, sizeof key, true) && strlen(key) == nl && !memcmp(key, name, nl))
            return http_pct_decode(eq ? eq + 1 : e, eq ? (size_t)(e - eq - 1) : 0, out, cap, true);
        p = *e ? e + 1 : e;
    }
    return false;
}

// --- chunked -------------------------------------------------------------------

enum { CK_SIZE, CK_EXT, CK_SIZE_LF, CK_DATA, CK_DATA_CR, CK_DATA_LF, CK_TRAILER, CK_TRAILER_LF, CK_TLINE, CK_TLINE_LF, CK_DONE, CK_ERROR };

int http_chunked_feed(http_chunked *c, const uint8_t *in, size_t n, size_t *used, uint8_t *out, size_t *outn)
{
    size_t i = 0, o = 0;
    if (c->st == CK_ERROR)
        goto bad;
    while (i < n && c->st != CK_DONE) {
        const uint8_t b = in[i];
        switch (c->st) {
        case CK_SIZE:
            if (hexv((char)b) >= 0) {
                if (c->left >> 56) // more than 2^60
                    goto bad;
                c->left = c->left << 4 | (uint64_t)hexv((char)b);
                c->digits = true;
                i++;
            } else if (c->digits && (b == ';' || b == ' ' || b == '\t')) {
                c->st = CK_EXT, i++;
            } else if (c->digits && b == '\r') {
                c->st = CK_SIZE_LF, i++;
            } else {
                goto bad;
            }
            break;
        case CK_EXT:
            if (++c->ext > 4096)
                goto bad;
            if (b == '\r')
                c->st = CK_SIZE_LF;
            else if (b < 0x20 && b != '\t')
                goto bad;
            i++;
            break;
        case CK_SIZE_LF:
            if (b != '\n')
                goto bad;
            i++;
            c->st = c->left ? CK_DATA : CK_TRAILER;
            break;
        case CK_DATA: {
            size_t k = n - i < c->left ? n - i : (size_t)c->left;
            memmove(out + o, in + i, k);
            o += k, i += k;
            c->left -= k;
            if (!c->left)
                c->st = CK_DATA_CR;
            break;
        }
        case CK_DATA_CR:
            if (b != '\r')
                goto bad;
            c->st = CK_DATA_LF, i++;
            break;
        case CK_DATA_LF:
            if (b != '\n')
                goto bad;
            c->st = CK_SIZE, i++;
            c->digits = false;
            break;
        case CK_TRAILER: // after the last chunk: CRLF, or trailer lines
            if (b == '\r')
                c->st = CK_TRAILER_LF;
            else
                c->st = CK_TLINE;
            i++;
            break;
        case CK_TRAILER_LF:
            if (b != '\n')
                goto bad;
            c->st = CK_DONE, i++;
            break;
        case CK_TLINE:
            if (++c->ext > 8192)
                goto bad;
            if (b == '\r')
                c->st = CK_TLINE_LF;
            i++;
            break;
        case CK_TLINE_LF:
            if (b != '\n')
                goto bad;
            c->st = CK_TRAILER, i++;
            break;
        }
    }
    *used = i;
    *outn = o;
    return c->st == CK_DONE ? 1 : 0;
bad:
    c->st = CK_ERROR; // and it stays an error
    *used = i;
    *outn = o;
    return -1;
}

// --- multipart --------------------------------------------------------------

enum { MPS_PREAMBLE, MPS_HEADERS, MPS_BODY, MPS_DONE, MPS_ERROR };
enum { MP_MAX_BUFFER = 256 * 1024 };

bool mp_init(mp_reader *m, const char *ct)
{
    *m = (mp_reader){0};
    if (!ct)
        return false;
    const char *semi = strchr(ct, ';');
    if (!semi)
        return false;
    char type[32];
    size_t tl = (size_t)(semi - ct);
    while (tl && (ct[tl - 1] == ' ' || ct[tl - 1] == '\t'))
        tl--;
    if (tl >= sizeof type)
        return false;
    memcpy(type, ct, tl);
    type[tl] = 0;
    if (!ieq(type, "multipart/form-data"))
        return false;
    const char *b = nullptr;
    for (const char *p = semi; p && *p;) {
        p++;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!strncmp(p, "boundary=", 9) || !strncmp(p, "BOUNDARY=", 9)) {
            b = p + 9;
            break;
        }
        p = strchr(p, ';');
    }
    if (!b)
        return false;
    char bd[72];
    size_t n = 0;
    if (*b == '"') {
        b++;
        while (*b && *b != '"' && n < 71)
            bd[n++] = *b++;
        if (*b != '"')
            return false;
    } else {
        while (*b && *b != ';' && *b != ' ' && n < 71)
            bd[n++] = *b++;
    }
    if (!n || n > 70)
        return false;
    memcpy(m->boundary, "\r\n--", 4);
    memcpy(m->boundary + 4, bd, n);
    m->blen = n + 4;
    m->boundary[m->blen] = 0;
    // The first boundary has no CRLF before it: start with one in the
    // buffer, so every boundary looks the same.
    return mp_feed(m, "\r\n", 2);
}

bool mp_feed(mp_reader *m, const void *p, size_t n)
{
    if (m->off && m->off == m->len)
        m->off = m->len = 0;
    if (m->off && n > m->cap - m->len) {
        memmove(m->buf, m->buf + m->off, m->len - m->off);
        m->len -= m->off, m->off = 0;
    }
    if (m->len + n > MP_MAX_BUFFER + 65536)
        return false;
    if (n > m->cap - m->len) {
        size_t cap = m->cap ? m->cap : 8192;
        while (cap - m->len < n)
            cap *= 2;
        uint8_t *q = realloc(m->buf, cap);
        if (!q)
            return false;
        m->buf = q, m->cap = cap;
    }
    memcpy(m->buf + m->len, p, n);
    m->len += n;
    return true;
}

static const uint8_t *find(const uint8_t *h, size_t hn, const char *needle, size_t nn)
{
    if (hn < nn)
        return nullptr;
    for (size_t i = 0; i + nn <= hn; i++)
        if (h[i] == (uint8_t)needle[0] && !memcmp(h + i, needle, nn))
            return h + i;
    return nullptr;
}

// A parameter of Content-Disposition (name="..." / filename="...").
static bool disp_param(const char *v, const char *key, char *out, size_t cap)
{
    const size_t kl = strlen(key);
    for (const char *p = v; (p = strchr(p, ';'));) {
        p++;
        while (*p == ' ' || *p == '\t')
            p++;
        if (strncmp(p, key, kl) || p[kl] != '=')
            continue;
        p += kl + 1;
        size_t n = 0;
        if (*p == '"') {
            for (p++; *p && *p != '"'; p++) {
                char c = *p;
                if (c == '\\' && p[1])
                    c = *++p;
                if (n + 1 >= cap)
                    return false;
                out[n++] = c;
            }
            if (*p != '"')
                return false;
        } else {
            for (; *p && *p != ';' && *p != ' '; p++) {
                if (n + 1 >= cap)
                    return false;
                out[n++] = *p;
            }
        }
        out[n] = 0;
        return true;
    }
    return false;
}

mp_event mp_next(mp_reader *m, bool body_ended)
{
    for (;;) {
        const uint8_t *b = m->buf + m->off;
        const size_t n = m->len - m->off;
        switch (m->st) {
        case MPS_PREAMBLE:
        case MPS_BODY: {
            const uint8_t *hit = find(b, n, m->boundary, m->blen);
            if (m->st == MPS_BODY) {
                // Data up to the boundary, or all but what could be its start.
                const size_t safe = hit ? (size_t)(hit - b) : n > m->blen ? n - m->blen : 0;
                if (safe) {
                    m->data = b, m->ndata = safe;
                    m->off += safe;
                    return MP_DATA;
                }
            }
            if (!hit) {
                if (m->st == MPS_PREAMBLE && n > m->blen) // drop the preamble as it comes
                    m->off += n - m->blen;
                if (body_ended)
                    return m->st = MPS_ERROR, MP_ERROR;
                return MP_NONE;
            }
            // After the boundary: "--" (the end) or CRLF (a part).
            const size_t after = (size_t)(hit - b) + m->blen;
            if (n < after + 2)
                return body_ended ? (m->st = MPS_ERROR, MP_ERROR) : MP_NONE;
            const bool was_body = m->st == MPS_BODY;
            if (b[after] == '-' && b[after + 1] == '-') {
                m->off += after + 2;
                m->st = MPS_DONE;
                return was_body ? MP_END_PART : MP_DONE;
            }
            // Transport padding (spaces/tabs) may follow the boundary.
            size_t k = after;
            while (k < n && (b[k] == ' ' || b[k] == '\t'))
                k++;
            if (n < k + 2)
                return body_ended ? (m->st = MPS_ERROR, MP_ERROR) : MP_NONE;
            if (b[k] != '\r' || b[k + 1] != '\n')
                return m->st = MPS_ERROR, MP_ERROR;
            m->off += k + 2;
            m->st = MPS_HEADERS;
            if (was_body)
                return MP_END_PART;
            break;
        }
        case MPS_HEADERS: {
            if (n < 2)
                return body_ended ? (m->st = MPS_ERROR, MP_ERROR) : MP_NONE;
            size_t hl, skip;
            if (b[0] == '\r' && b[1] == '\n') { // no headers at all
                hl = 0, skip = 2;
            } else {
                const uint8_t *e = find(b, n, "\r\n\r\n", 4);
                if (!e) {
                    if (n > 16384 || body_ended)
                        return m->st = MPS_ERROR, MP_ERROR;
                    return MP_NONE;
                }
                hl = (size_t)(e - b), skip = hl + 4;
            }
            if (hl > 16384 || memchr(b, 0, hl)) // no NULs in a part's headers
                return m->st = MPS_ERROR, MP_ERROR;
            char *h = malloc(hl + 3);
            if (!h)
                return m->st = MPS_ERROR, MP_ERROR;
            memcpy(h, b, hl);
            memcpy(h + hl, "\r\n", 3);
            m->name[0] = m->filename[0] = 0;
            for (char *p = h; *p;) {
                char *le = strstr(p, "\r\n"); // the block ends with one
                if (!le)
                    break;
                *le = 0;
                char *colon = strchr(p, ':');
                if (colon) {
                    *colon = 0;
                    if (ieq(p, "content-disposition")) {
                        disp_param(colon + 1, "name", m->name, sizeof m->name);
                        disp_param(colon + 1, "filename", m->filename, sizeof m->filename);
                    }
                }
                p = le + 2;
            }
            free(h);
            m->off += skip;
            m->st = MPS_BODY;
            return MP_PART;
        }
        case MPS_DONE:
            return MP_DONE;
        default:
            return MP_ERROR;
        }
    }
}

void mp_free(mp_reader *m)
{
    free(m->buf);
    *m = (mp_reader){0};
}

// --- output --------------------------------------------------------------------

void sb_put(sbuf *b, const void *p, size_t n)
{
    if (b->oom || !n)
        return;
    if (n >= b->cap - b->len) { // and one more for the NUL
        size_t cap = b->cap ? b->cap : 512;
        while (cap - b->len <= n)
            cap *= 2;
        char *q = realloc(b->p, cap);
        if (!q) {
            b->oom = true;
            return;
        }
        b->p = q, b->cap = cap;
    }
    memcpy(b->p + b->len, p, n);
    b->len += n;
    b->p[b->len] = 0;
}

void sb_puts(sbuf *b, const char *s) { sb_put(b, s, strlen(s)); }

void sb_printf(sbuf *b, const char *fmt, ...)
{
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof tmp) {
        b->oom = true;
        return;
    }
    sb_put(b, tmp, (size_t)n);
}

void sb_free(sbuf *b)
{
    free(b->p);
    *b = (sbuf){0};
}

// The length of a valid UTF-8 sequence at s (n bytes left), or 0.
static size_t utf8_len(const uint8_t *s, size_t n)
{
    const uint8_t c = s[0];
    size_t k;
    uint32_t cp;
    if (c < 0x80)
        return 1;
    if (c >= 0xc2 && c <= 0xdf)
        k = 2, cp = c & 0x1f;
    else if (c >= 0xe0 && c <= 0xef)
        k = 3, cp = c & 0x0f;
    else if (c >= 0xf0 && c <= 0xf4)
        k = 4, cp = c & 0x07;
    else
        return 0;
    if (n < k)
        return 0;
    for (size_t i = 1; i < k; i++) {
        if ((s[i] & 0xc0) != 0x80)
            return 0;
        cp = cp << 6 | (s[i] & 0x3f);
    }
    if ((k == 3 && (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff))) || (k == 4 && (cp < 0x10000 || cp > 0x10ffff)))
        return 0;
    return k;
}

void jw_str(sbuf *b, const char *s, size_t n)
{
    sb_put(b, "\"", 1);
    const uint8_t *p = (const uint8_t *)s;
    size_t run = 0; // bytes copied as they are, pending
    for (size_t i = 0; i < n;) {
        const uint8_t c = p[i];
        const char *esc = nullptr;
        char u[8];
        size_t k = 1;
        if (c == '"')
            esc = "\\\"";
        else if (c == '\\')
            esc = "\\\\";
        else if (c < 0x20) {
            snprintf(u, sizeof u, "\\u%04x", c);
            esc = u;
        } else if (c >= 0x80 && !(k = utf8_len(p + i, n - i))) {
            esc = "\xef\xbf\xbd"; // U+FFFD
            k = 1;
        }
        if (esc) {
            sb_put(b, p + i - run, run);
            run = 0;
            sb_puts(b, esc);
        } else {
            run += k;
        }
        i += k;
    }
    sb_put(b, p + n - run, run);
    sb_put(b, "\"", 1);
}

void jw_cstr(sbuf *b, const char *s) { jw_str(b, s, strlen(s)); }

void jw_key(sbuf *b, bool *first, const char *key)
{
    if (!*first)
        sb_put(b, ",", 1);
    *first = false;
    jw_cstr(b, key);
    sb_put(b, ":", 1);
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void jw_b64(sbuf *b, const void *data, size_t n)
{
    const uint8_t *p = data;
    sb_put(b, "\"", 1);
    char q[4];
    for (size_t i = 0; i < n; i += 3) {
        const uint32_t v = (uint32_t)p[i] << 16 | (i + 1 < n ? (uint32_t)p[i + 1] << 8 : 0) | (i + 2 < n ? p[i + 2] : 0);
        q[0] = B64[v >> 18 & 63];
        q[1] = B64[v >> 12 & 63];
        q[2] = i + 1 < n ? B64[v >> 6 & 63] : '=';
        q[3] = i + 2 < n ? B64[v & 63] : '=';
        sb_put(b, q, 4);
    }
    sb_put(b, "\"", 1);
}

static int b64v(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+' || c == '-')
        return 62;
    if (c == '/' || c == '_')
        return 63;
    return -1;
}

bool b64_decode(const char *s, size_t n, uint8_t *out, size_t cap, size_t *outn)
{
    while (n && s[n - 1] == '=')
        n--;
    if (n % 4 == 1)
        return false;
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        const int v = b64v(s[i]);
        if (v < 0)
            return false;
        acc = acc << 6 | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap)
                return false;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    *outn = o;
    return true;
}

void jw_time(sbuf *b, int64_t sec, uint32_t nsec)
{
    const time_t t = (time_t)sec;
    struct tm tm;
    if (!gmtime_r(&t, &tm)) {
        jw_cstr(b, "1970-01-01T00:00:00Z");
        return;
    }
    char s[64];
    if (nsec)
        snprintf(s, sizeof s, "%04d-%02d-%02dT%02d:%02d:%02d.%09uZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec, nsec);
    else
        snprintf(s, sizeof s, "%04d-%02d-%02dT%02d:%02d:%02dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec);
    jw_cstr(b, s);
}
