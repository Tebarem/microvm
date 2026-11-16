// SPDX-License-Identifier: MIT
// Test helpers shared by the image tests: CHECK, a growing byte buffer, an
// in-memory tar builder, and a small EROFS reader written from the on-disk
// format (fs/erofs/erofs_fs.h), not from the writer, so the two can't share
// a misunderstanding silently.
#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "image/fstree.h"

[[maybe_unused]] static int failures, checks;
#define CHECK(cond)                                                                      \
    do {                                                                                 \
        checks++;                                                                        \
        if (!(cond)) {                                                                   \
            failures++;                                                                  \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);    \
        }                                                                                \
    } while (0)

// ---- growing byte buffer: a tar layer being built, or an image ---------------
typedef struct {
    uint8_t *p;
    size_t n, cap;
} buf;

static inline void buf_put(buf *b, const void *data, size_t len)
{
    if (b->n + len > b->cap) {
        size_t c = b->cap ? b->cap : 4096;
        while (c < b->n + len)
            c *= 2;
        if (!(b->p = realloc(b->p, c)))
            abort();
        b->cap = c;
    }
    if (len)
        memcpy(b->p + b->n, data, len);
    b->n += len;
}

static inline void buf_zero(buf *b, size_t len)
{
    static const uint8_t z[512];
    while (len) {
        const size_t k = len < sizeof z ? len : sizeof z;
        buf_put(b, z, k);
        len -= k;
    }
}

static inline int buf_read(void *ctx, void *dst, size_t len, uint64_t off)
{
    const buf *b = ctx;
    if (off > b->n || len > b->n - off)
        return -1;
    if (!len)
        return 0;
    memcpy(dst, b->p + off, len);
    return 0;
}

static inline int buf_write(void *ctx, const void *data, size_t len)
{
    buf_put(ctx, data, len);
    return 0;
}

// ---- tar builder ----------------------------------------------------------------
static inline void oct(uint8_t *f, size_t w, uint64_t v)
{
    char tmp[32];
    snprintf(tmp, sizeof tmp, "%0*llo", (int)(w - 1), (unsigned long long)v);
    memcpy(f, tmp, w - 1);
    f[w - 1] = 0;
}

static inline void fix_sum(uint8_t *h)
{
    memset(h + 148, ' ', 8);
    unsigned s = 0;
    for (size_t i = 0; i < 512; i++)
        s += h[i];
    char tmp[16];
    snprintf(tmp, sizeof tmp, "%06o", s);
    memcpy(h + 148, tmp, 6);
    h[154] = 0;
    h[155] = ' ';
}

// Append one entry; returns the header's offset (to corrupt it in tests).
// `size` is the header's size field, `data`/`len` what follows it.
static inline size_t tar_raw(buf *b, const char *name, char type, unsigned mode, uint64_t size,
                      const void *data, size_t len, const char *link, unsigned major, unsigned minor)
{
    uint8_t h[512] = {0};
    memcpy(h, name, strnlen(name, 100));
    oct(h + 100, 8, mode);
    oct(h + 108, 8, 1000); // uid
    oct(h + 116, 8, 2000); // gid
    oct(h + 124, 12, size);
    oct(h + 136, 12, 1700000000);
    h[156] = (uint8_t)type;
    if (link)
        memcpy(h + 157, link, strnlen(link, 100));
    memcpy(h + 257, "ustar", 6);
    memcpy(h + 263, "00", 2);
    oct(h + 329, 8, major);
    oct(h + 337, 8, minor);
    fix_sum(h);
    const size_t at = b->n;
    buf_put(b, h, 512);
    buf_put(b, data, len);
    buf_zero(b, (512 - len % 512) % 512);
    return at;
}

static inline size_t tar_file(buf *b, const char *name, const char *content)
{
    const size_t l = strlen(content);
    return tar_raw(b, name, '0', 0644, l, content, l, nullptr, 0, 0);
}

static inline void tar_dir(buf *b, const char *name, unsigned mode)
{
    tar_raw(b, name, '5', mode, 0, nullptr, 0, nullptr, 0, 0);
}

static inline void tar_link(buf *b, const char *name, char type, const char *target)
{
    tar_raw(b, name, type, 0777, 0, nullptr, 0, target, 0, 0);
}

// A pax extended header with one "key=value" record.
static inline void tar_pax(buf *b, const char *key, const char *value)
{
    char rec[8192];
    const size_t body = strlen(key) + strlen(value) + 3; // ' ' '=' '\n'
    size_t len = body + 1;
    while ((size_t)snprintf(nullptr, 0, "%zu", len) + body != len)
        len++;
    snprintf(rec, sizeof rec, "%zu %s=%s\n", len, key, value);
    tar_raw(b, "././@PaxHeader", 'x', 0644, len, rec, len, nullptr, 0, 0);
}

static inline void tar_end(buf *b) { buf_zero(b, 1024); }

// ---- EROFS reader ---------------------------------------------------------------
typedef struct {
    const uint8_t *p;
    size_t n;
    uint64_t meta, root;
} img;

static inline uint64_t rd16(const uint8_t *p) { return p[0] | (uint64_t)p[1] << 8; }
static inline uint64_t rd32(const uint8_t *p) { return rd16(p) | rd16(p + 2) << 16; }
static inline uint64_t rd64(const uint8_t *p) { return rd32(p) | rd32(p + 4) << 32; }

typedef struct {
    uint32_t mode, uid, gid, nlink, u, ino;
    uint64_t size;
} inode;

static inline bool img_open(img *m, const buf *b)
{
    *m = (img){b->p, b->n, 0, 0};
    if (b->n < 4096 || b->n % 4096 || rd32(b->p + 1024) != 0xE0F5E1E2 || b->p[1024 + 12] != 12)
        return false;
    m->root = rd16(b->p + 1024 + 14);
    m->meta = rd32(b->p + 1024 + 40);
    return rd32(b->p + 1024 + 36) * 4096 == b->n; // blocks: the whole image
}

static inline bool get_inode(const img *m, uint64_t nid, inode *o)
{
    const uint64_t off = m->meta * 4096 + nid * 32;
    if (off + 64 > m->n)
        return false;
    const uint8_t *p = m->p + off;
    if (rd16(p) != 1) // extended inode, flat plain: all the writer makes
        return false;
    *o = (inode){.mode = (uint32_t)rd16(p + 4), .size = rd64(p + 8), .u = (uint32_t)rd32(p + 16),
                 .ino = (uint32_t)rd32(p + 20), .uid = (uint32_t)rd32(p + 24),
                 .gid = (uint32_t)rd32(p + 28), .nlink = (uint32_t)rd32(p + 44)};
    return true;
}

static inline const uint8_t *data_of(const img *m, const inode *in)
{
    const uint64_t off = (uint64_t)in->u * 4096;
    return off <= m->n && in->size <= m->n - off ? m->p + off : nullptr;
}

// Calls fn(name, len, nid) for every entry, in on-disk order; checks the
// order is strictly increasing (the driver binary-searches it).
static inline int dir_walk(const img *m, uint64_t nid, void (*fn)(void *, const char *, size_t, uint64_t),
                    void *ctx)
{
    inode d;
    if (!get_inode(m, nid, &d) || (d.mode & FS_IFMT) != FS_IFDIR)
        return -1;
    const uint8_t *base = data_of(m, &d);
    if (!base)
        return -1;
    char prev[256] = "";
    size_t prevl = 0;
    bool first = true;
    int count = 0;
    for (uint64_t at = 0; at < d.size; at += 4096) {
        const uint8_t *blk = base + at;
        const size_t blen = d.size - at < 4096 ? (size_t)(d.size - at) : 4096;
        const size_t n0 = (size_t)rd16(blk + 8);
        if (n0 % 12 || n0 == 0 || n0 > blen)
            return -1;
        for (size_t i = 0; i < n0 / 12; i++) {
            const size_t no = (size_t)rd16(blk + i * 12 + 8);
            size_t end = i + 1 < n0 / 12 ? (size_t)rd16(blk + (i + 1) * 12 + 8) : blen;
            if (no > end || end > blen)
                return -1;
            size_t l = end - no;
            if (i + 1 == n0 / 12)
                l = strnlen((const char *)blk + no, l);
            if (l == 0 || l > 255)
                return -1;
            const char *name = (const char *)blk + no;
            const size_t c = l < prevl ? l : prevl;
            int cmp = memcmp(prev, name, c);
            if (!first && (cmp > 0 || (cmp == 0 && prevl >= l)))
                return -1; // not sorted
            memcpy(prev, name, l);
            prevl = l;
            first = false;
            fn(ctx, name, l, rd64(blk + i * 12));
            count++;
        }
    }
    return count;
}

typedef struct {
    const char *want;
    uint64_t nid;
    bool found;
} lookup_ctx;

static inline void lookup_fn(void *ctx, const char *name, size_t l, uint64_t nid)
{
    lookup_ctx *c = ctx;
    if (strlen(c->want) == l && !memcmp(c->want, name, l))
        c->nid = nid, c->found = true;
}

// Resolve a path ("a/b/c", no symlinks followed) to a nid.
static inline bool lookup(const img *m, const char *path, uint64_t *nid)
{
    uint64_t cur = m->root;
    char comp[256];
    for (const char *p = path; *p;) {
        size_t l = strcspn(p, "/");
        if (l >= sizeof comp)
            return false;
        memcpy(comp, p, l);
        comp[l] = 0;
        lookup_ctx c = {comp, 0, false};
        if (dir_walk(m, cur, lookup_fn, &c) < 0 || !c.found)
            return false;
        cur = c.nid;
        p += l;
        p += *p == '/';
    }
    *nid = cur;
    return true;
}

static inline bool stat_path(const img *m, const char *path, inode *o)
{
    uint64_t nid;
    return lookup(m, path, &nid) && get_inode(m, nid, o);
}

static inline bool file_is(const img *m, const char *path, const char *content)
{
    inode in;
    if (!stat_path(m, path, &in) || (in.mode & FS_IFMT) != FS_IFREG || in.size != strlen(content))
        return false;
    const uint8_t *d = data_of(m, &in);
    return d && !memcmp(d, content, in.size);
}

static inline bool exists(const img *m, const char *path)
{
    uint64_t nid;
    return lookup(m, path, &nid);
}
