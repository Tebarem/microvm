// SPDX-License-Identifier: MIT
// The sandbox protocol's host side (sbx.h): request encoders, and the
// reader of what the guest sends, which is hostile input.
#include "sbx/sbx.h"

#include <stdlib.h>
#include <string.h>

void mvs_buf_put(mvs_buf *b, const void *p, size_t n)
{
    if (b->oom || !n)
        return;
    if (n > b->cap - b->len) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap - b->len < n) {
            if (cap > SIZE_MAX / 2) {
                b->oom = true;
                return;
            }
            cap *= 2;
        }
        uint8_t *q = realloc(b->p, cap);
        if (!q) {
            b->oom = true;
            return;
        }
        b->p = q, b->cap = cap;
    }
    memcpy(b->p + b->len, p, n);
    b->len += n;
}

void mvs_buf_free(mvs_buf *b)
{
    free(b->p);
    *b = (mvs_buf){0};
}

static void put32(mvs_buf *b, uint32_t v)
{
    const uint8_t x[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
    mvs_buf_put(b, x, 4);
}

static void put16(mvs_buf *b, uint16_t v)
{
    const uint8_t x[2] = {(uint8_t)v, (uint8_t)(v >> 8)};
    mvs_buf_put(b, x, 2);
}

static void put_bytes(mvs_buf *b, const void *p, size_t n)
{
    put32(b, (uint32_t)n);
    mvs_buf_put(b, p, n);
}

static void put_str(mvs_buf *b, const char *s) { put_bytes(b, s ? s : "", s ? strlen(s) : 0); }

// A frame: header now, its length patched by end().
static size_t begin(mvs_buf *b, uint8_t type)
{
    const size_t at = b->len;
    put32(b, MVS_MAGIC);
    const uint8_t v[4] = {MVS_VERSION, type, 0, 0};
    mvs_buf_put(b, v, 4);
    put32(b, 0);
    return at;
}

static void end(mvs_buf *b, size_t at)
{
    if (b->oom)
        return;
    const size_t n = b->len - at - MVS_HDR;
    if (n > MVS_MAX_BODY) { // the guest would refuse it: drop it here
        b->len = at;
        b->oom = true;
        return;
    }
    for (int i = 0; i < 4; i++)
        b->p[at + 8 + i] = (uint8_t)(n >> (8 * i));
}

static void put_sel(mvs_buf *b, const mvs_sel *s)
{
    put32(b, s->kind);
    put32(b, s->pid);
    put_str(b, s->kind == MVS_SEL_TAG ? s->tag : "");
}

void mvs_req_start(mvs_buf *b, const mvs_start *s)
{
    const size_t at = begin(b, MVS_START);
    put32(b, s->flags | (s->tag ? MVS_S_TAG : 0));
    put16(b, s->cols);
    put16(b, s->rows);
    put16(b, (uint16_t)s->nargs);
    put16(b, (uint16_t)s->nenv);
    put_str(b, s->user);
    put_str(b, s->cwd);
    if (s->tag)
        put_str(b, s->tag);
    for (size_t i = 0; i < s->nargs; i++)
        put_str(b, s->argv[i]);
    for (size_t i = 0; i < s->nenv; i++)
        put_str(b, s->envs[i]);
    if (s->nargs > MVS_MAX_STRINGS || s->nenv > MVS_MAX_STRINGS)
        b->oom = true;
    end(b, at);
}

void mvs_req_sel(mvs_buf *b, uint8_t type, const mvs_sel *sel)
{
    const size_t at = begin(b, type);
    put_sel(b, sel);
    end(b, at);
}

void mvs_req_input(mvs_buf *b, const mvs_sel *sel, uint32_t flags, const void *data, size_t n)
{
    const size_t at = begin(b, MVS_INPUT);
    put_sel(b, sel);
    put32(b, flags);
    put_bytes(b, data, n);
    end(b, at);
}

void mvs_req_signal(mvs_buf *b, const mvs_sel *sel, uint32_t sig)
{
    const size_t at = begin(b, MVS_SIGNAL);
    put_sel(b, sel);
    put32(b, sig);
    end(b, at);
}

void mvs_req_resize(mvs_buf *b, const mvs_sel *sel, uint16_t cols, uint16_t rows)
{
    const size_t at = begin(b, MVS_RESIZE);
    put_sel(b, sel);
    put16(b, cols);
    put16(b, rows);
    end(b, at);
}

void mvs_req_path(mvs_buf *b, uint8_t type, const char *user, const char *path)
{
    const size_t at = begin(b, type);
    put_str(b, user);
    put_str(b, path);
    end(b, at);
}

void mvs_req_move(mvs_buf *b, const char *user, const char *from, const char *to)
{
    const size_t at = begin(b, MVS_MOVE);
    put_str(b, user);
    put_str(b, from);
    put_str(b, to);
    end(b, at);
}

void mvs_req_list(mvs_buf *b, const char *user, const char *path, uint32_t depth)
{
    const size_t at = begin(b, MVS_LIST);
    put32(b, depth);
    put_str(b, user);
    put_str(b, path);
    end(b, at);
}

void mvs_req_watch(mvs_buf *b, const char *user, const char *path, uint32_t flags)
{
    const size_t at = begin(b, MVS_WATCH);
    put32(b, flags);
    put_str(b, user);
    put_str(b, path);
    end(b, at);
}

void mvs_req_port(mvs_buf *b, uint32_t port)
{
    const size_t at = begin(b, MVS_PORT_CONNECT);
    put32(b, port);
    end(b, at);
}

void mvs_req_set_env(mvs_buf *b, const char *const *envs, size_t n)
{
    const size_t at = begin(b, MVS_SET_ENV);
    put16(b, (uint16_t)n);
    for (size_t i = 0; i < n; i++)
        put_str(b, envs[i]);
    if (n > 0xffff)
        b->oom = true;
    end(b, at);
}

void mvs_req_empty(mvs_buf *b, uint8_t type) { end(b, begin(b, type)); }

void mvs_req_data(mvs_buf *b, const void *p, size_t n)
{
    const size_t at = begin(b, MVS_DATA);
    mvs_buf_put(b, p, n);
    end(b, at);
}

// --- the reader -------------------------------------------------------------

bool mvs_feed(mvs_reader *r, const void *p, size_t n)
{
    if (r->off && r->off == r->len)
        r->off = r->len = 0;
    if (n > r->cap - r->len && r->off) {
        memmove(r->buf, r->buf + r->off, r->len - r->off);
        r->len -= r->off;
        r->off = 0;
    }
    if (n > r->cap - r->len) {
        size_t cap = r->cap ? r->cap : 4096;
        while (cap - r->len < n)
            cap *= 2;
        uint8_t *q = realloc(r->buf, cap);
        if (!q)
            return false;
        r->buf = q, r->cap = cap;
    }
    memcpy(r->buf + r->len, p, n);
    r->len += n;
    return true;
}

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t le64(const uint8_t *p) { return le32(p) | (uint64_t)le32(p + 4) << 32; }

static bool guest_type(uint8_t t)
{
    return (t >= MVS_HELLO && t <= MVS_W_EVENT) || t == MVS_DATA || t == MVS_DONE;
}

int mvs_next(mvs_reader *r, mvs_frame *f)
{
    if (r->error[0])
        return -1;
    const size_t have = r->len - r->off;
    if (have < MVS_HDR)
        return 0;
    const uint8_t *h = r->buf + r->off;
    const uint32_t len = le32(h + 8);
    const char *bad = le32(h) != MVS_MAGIC  ? "bad magic"
                      : h[4] != MVS_VERSION ? "unknown version"
                      : h[6] || h[7]        ? "flags set"
                      : !guest_type(h[5])   ? "unknown frame type"
                      : len > MVS_MAX_BODY  ? "frame too long"
                                            : nullptr;
    if (bad) {
        strcpy(r->error, bad);
        return -1;
    }
    if (have - MVS_HDR < len)
        return 0;
    *f = (mvs_frame){.type = h[5], .len = len, .body = h + MVS_HDR};
    r->off += MVS_HDR + len;
    return 1;
}

void mvs_reader_free(mvs_reader *r)
{
    free(r->buf);
    *r = (mvs_reader){0};
}

// --- bodies -------------------------------------------------------------------

typedef struct {
    const uint8_t *p;
    size_t n;
    bool bad;
} rd;

static uint32_t rd32(rd *r)
{
    if (r->n < 4) {
        r->bad = true;
        return 0;
    }
    const uint32_t v = le32(r->p);
    r->p += 4, r->n -= 4;
    return v;
}

static uint64_t rd64(rd *r)
{
    if (r->n < 8) {
        r->bad = true;
        return 0;
    }
    const uint64_t v = le64(r->p);
    r->p += 8, r->n -= 8;
    return v;
}

static mvs_str rdstr(rd *r, size_t max)
{
    const uint32_t n = rd32(r);
    if (r->bad || n > r->n || n > max) {
        r->bad = true;
        return (mvs_str){"", 0};
    }
    const mvs_str s = {(const char *)r->p, n};
    if (memchr(s.p, 0, n)) // strings never hold NUL bytes
        r->bad = true;
    r->p += n, r->n -= n;
    return s;
}

bool mvs_dec_hello(const mvs_frame *f, uint32_t *version, uint32_t *resumes)
{
    if (f->type != MVS_HELLO || f->len != 8)
        return false;
    *version = le32(f->body);
    *resumes = le32(f->body + 4);
    return *version == MVS_VERSION;
}

bool mvs_dec_u32(const mvs_frame *f, uint32_t *v)
{
    if (f->len != 4)
        return false;
    *v = le32(f->body);
    return true;
}

bool mvs_dec_u64(const mvs_frame *f, uint64_t *v)
{
    if (f->len != 8)
        return false;
    *v = le64(f->body);
    return true;
}

bool mvs_dec_end(const mvs_frame *f, uint32_t *wait_status)
{
    if (f->type != MVS_P_END || f->len != 8 || le32(f->body + 4))
        return false;
    *wait_status = le32(f->body);
    return true;
}

bool mvs_dec_error(const mvs_frame *f, mvs_error *e)
{
    rd r = {f->body, f->len, false};
    if (f->type != MVS_ERROR)
        return false;
    e->kind = rd32(&r);
    e->err = rd32(&r);
    e->msg = rdstr(&r, 512);
    return !r.bad && !r.n && e->kind >= MVS_E_INVALID && e->kind <= MVS_E_LIMIT && e->err < 4096;
}

enum { PATH_MAX_ = 4096 };

static bool entry(rd *r, mvs_entry *e)
{
    e->mode = rd32(r);
    e->uid = rd32(r);
    e->gid = rd32(r);
    e->flags = rd32(r);
    e->size = rd64(r);
    e->mtime_sec = (int64_t)rd64(r);
    e->mtime_nsec = rd32(r);
    e->path = rdstr(r, PATH_MAX_);
    e->owner = rdstr(r, 255);
    e->group = rdstr(r, 255);
    e->target = rdstr(r, PATH_MAX_);
    return !r->bad && !(e->flags & ~MVS_E_SYMLINK) && e->mtime_nsec < 1000000000u && e->path.n &&
           e->path.p[0] == '/' && (e->target.n == 0 || e->flags & MVS_E_SYMLINK);
}

bool mvs_dec_entry(const uint8_t *b, size_t n, mvs_entry *e)
{
    rd r = {b, n, false};
    return entry(&r, e) && !r.n;
}

bool mvs_dec_proc(const mvs_frame *f, mvs_proc *p)
{
    rd r = {f->body, f->len, false};
    if (f->type != MVS_PROC)
        return false;
    p->pid = rd32(&r);
    p->flags = rd32(&r);
    const uint32_t counts = rd32(&r);
    p->nargs = (uint16_t)counts;
    p->nenv = (uint16_t)(counts >> 16);
    p->tag = rdstr(&r, 4096);
    p->cwd = rdstr(&r, PATH_MAX_);
    p->strs = r.p;
    for (uint32_t i = 0; i < (uint32_t)p->nargs + p->nenv && !r.bad; i++)
        rdstr(&r, MVS_MAX_STRING);
    p->strs_len = (size_t)(r.p - p->strs);
    return !r.bad && !r.n && p->nargs && (uint32_t)p->nargs + p->nenv <= MVS_MAX_STRINGS &&
           !(p->flags & ~MVS_S_FLAGS) && p->pid;
}

bool mvs_dec_wevent(const mvs_frame *f, mvs_wevent *w)
{
    rd r = {f->body, f->len, false};
    if (f->type != MVS_W_EVENT)
        return false;
    w->event = rd32(&r);
    w->flags = rd32(&r);
    w->name = rdstr(&r, PATH_MAX_);
    w->has_entry = !(w->flags & MVS_W_NOENTRY);
    if (w->has_entry && !entry(&r, &w->entry))
        return false;
    return !r.bad && !r.n && w->event >= MVS_EV_CREATE && w->event <= MVS_EV_CHMOD &&
           !(w->flags & ~MVS_W_NOENTRY) && w->name.n;
}

mvs_str mvs_next_str(const uint8_t **p)
{
    const uint32_t n = le32(*p);
    const mvs_str s = {(const char *)*p + 4, n};
    *p += 4 + n;
    return s;
}
