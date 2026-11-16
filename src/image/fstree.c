// SPDX-License-Identifier: MIT
// The in-memory tree and the tar reader (see fstree.h).
#include <stdio.h>
#include "fstree.h"

#include <stdlib.h>

static void *grow(void *p, size_t *cap, size_t need, size_t elem)
{
    if (need <= *cap)
        return p;
    size_t c = *cap ? *cap : 8;
    while (c < need)
        if (ckd_mul(&c, c, 2))
            return nullptr;
    size_t bytes;
    if (ckd_mul(&bytes, c, elem))
        return nullptr;
    void *np = realloc(p, bytes);
    if (np)
        *cap = c;
    return np;
}

static char *dupn(const char *s, size_t n)
{
    char *d = malloc(n + 1);
    if (d) {
        memcpy(d, s, n);
        d[n] = 0;
    }
    return d;
}

static fs_inode *new_inode(fs_tree *t, uint32_t mode)
{
    if (t->n >= FS_MAX_INODES)
        return nullptr;
    fs_inode **all = grow(t->all, &t->cap, t->n + 1, sizeof *all);
    if (!all)
        return nullptr;
    t->all = all;
    fs_inode *ino = calloc(1, sizeof *ino);
    if (!ino)
        return nullptr;
    ino->mode = mode;
    ino->id = (uint32_t)t->n;
    t->all[t->n++] = ino;
    return ino;
}

int fs_tree_init(fs_tree *t)
{
    *t = (fs_tree){0};
    t->root = new_inode(t, FS_IFDIR | 0755);
    return t->root ? 0 : -1;
}

void fs_tree_free(fs_tree *t)
{
    for (size_t i = 0; i < t->n; i++) {
        fs_inode *ino = t->all[i];
        for (size_t j = 0; j < ino->nents; j++)
            free(ino->ents[j].name);
        free(ino->ents);
        free(ino->target);
        free(ino);
    }
    free(t->all);
    free(t->src);
    *t = (fs_tree){0};
}

static bool is_dir(const fs_inode *ino) { return (ino->mode & FS_IFMT) == FS_IFDIR; }

// Binary search for `name` (n bytes) in a directory: its index, or where
// it would go (*found false).
static size_t find(const fs_inode *dir, const char *name, size_t n, bool *found)
{
    size_t lo = 0, hi = dir->nents;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        const char *e = dir->ents[mid].name;
        int c = strncmp(e, name, n);
        if (c == 0)
            c = e[n] ? 1 : 0;
        if (c == 0) {
            *found = true;
            return mid;
        }
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    *found = false;
    return lo;
}

static int insert(fs_inode *dir, size_t at, const char *name, size_t n, fs_inode *ino, uint32_t layer)
{
    fs_dirent *e = grow(dir->ents, &dir->cap, dir->nents + 1, sizeof *e);
    if (!e)
        return -1;
    dir->ents = e;
    char *nm = dupn(name, n);
    if (!nm)
        return -1;
    memmove(&e[at + 1], &e[at], (dir->nents - at) * sizeof *e);
    e[at] = (fs_dirent){nm, ino, layer};
    dir->nents++;
    return 0;
}

static void erase(fs_inode *dir, size_t at)
{
    free(dir->ents[at].name);
    memmove(&dir->ents[at], &dir->ents[at + 1], (dir->nents - at - 1) * sizeof dir->ents[0]);
    dir->nents--;
}

// Split a tar path into components: no empty or "." ones; ".." is an error.
// Returns the number of components, or -1. comp[i] points into `path`.
static int split(const char *path, const char *comp[], size_t clen[], int max)
{
    int n = 0;
    for (const char *p = path; *p;) {
        while (*p == '/')
            p++;
        const char *s = p;
        while (*p && *p != '/')
            p++;
        const size_t l = (size_t)(p - s);
        if (l == 0 || (l == 1 && s[0] == '.'))
            continue;
        if ((l == 2 && s[0] == '.' && s[1] == '.') || l > FS_MAX_NAME || n == max)
            return -1;
        comp[n] = s;
        clen[n++] = l;
    }
    return n;
}

// The directory that holds the last component of `path`, creating missing
// parents (as 0755 root-owned directories). Never goes through anything
// but a directory: a symlink or file on the way is an error.
static fs_inode *parent_dir(fs_tree *t, const char *comp[], const size_t clen[], int n,
                            bool create, uint32_t layer, int64_t mtime)
{
    fs_inode *dir = t->root;
    for (int i = 0; i + 1 < n; i++) {
        bool found;
        const size_t at = find(dir, comp[i], clen[i], &found);
        if (found) {
            dir = dir->ents[at].ino;
            if (!is_dir(dir))
                return nullptr;
            continue;
        }
        if (!create)
            return nullptr;
        fs_inode *d = new_inode(t, FS_IFDIR | 0755);
        if (!d || insert(dir, at, comp[i], clen[i], d, layer))
            return nullptr;
        d->mtime = mtime;
        dir = d;
    }
    return dir;
}

// ---- tar --------------------------------------------------------------------
typedef struct {
    char path[FS_MAX_PATH + 1];
    char link[FS_MAX_PATH + 1];
    bool has_path, has_link, has_size, has_uid, has_gid, has_mtime;
    uint64_t size, uid, gid;
    int64_t mtime;
} tar_ext; // what pax / GNU long-name records say about the next entry

// A numeric header field: octal digits (space/NUL padded), or GNU base-256.
static bool tar_num(const uint8_t *f, size_t len, uint64_t *out)
{
    uint64_t v = 0;
    if (f[0] & 0x80) {
        if (f[0] != 0x80) // negative or too wide
            return false;
        for (size_t i = 1; i < len; i++)
            if (ckd_mul(&v, v, 256) || ckd_add(&v, v, f[i]))
                return false;
        *out = v;
        return true;
    }
    size_t i = 0;
    while (i < len && f[i] == ' ')
        i++;
    bool any = false;
    for (; i < len && f[i] >= '0' && f[i] <= '7'; i++, any = true)
        if (ckd_mul(&v, v, 8) || ckd_add(&v, v, (uint64_t)(f[i] - '0')))
            return false;
    for (; i < len; i++)
        if (f[i] != ' ' && f[i] != 0)
            return false;
    *out = any ? v : 0;
    return true;
}

static bool tar_checksum_ok(const uint8_t *h)
{
    uint64_t want;
    if (!tar_num(h + 148, 8, &want))
        return false;
    uint64_t u = 0;
    int64_t s = 0;
    for (size_t i = 0; i < 512; i++) {
        const uint8_t b = (i >= 148 && i < 156) ? ' ' : h[i];
        u += b;
        s += (int8_t)b;
    }
    return u == want || (uint64_t)s == want; // some old tars sum signed bytes
}

static bool dec(const char *s, size_t n, uint64_t *out)
{
    uint64_t v = 0;
    if (!n)
        return false;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9' || ckd_mul(&v, v, 10) || ckd_add(&v, v, (uint64_t)(s[i] - '0')))
            return false;
    }
    *out = v;
    return true;
}

// pax records: "LEN KEY=VALUE\n" ...
static bool pax_parse(const char *p, size_t n, tar_ext *x)
{
    while (n) {
        size_t i = 0;
        while (i < n && p[i] >= '0' && p[i] <= '9')
            i++;
        uint64_t len;
        if (i == 0 || i >= n || p[i] != ' ' || !dec(p, i, &len) || len > n || len < i + 3 ||
            p[len - 1] != '\n')
            return false;
        const char *kv = p + i + 1, *end = p + len - 1;
        const char *eq = memchr(kv, '=', (size_t)(end - kv));
        if (!eq)
            return false;
        const size_t kl = (size_t)(eq - kv), vl = (size_t)(end - eq - 1);
        const char *v = eq + 1;
        uint64_t num;
        if (kl == 4 && !memcmp(kv, "path", 4)) {
            if (vl > FS_MAX_PATH || memchr(v, 0, vl))
                return false;
            memcpy(x->path, v, vl);
            x->path[vl] = 0;
            x->has_path = true;
        } else if (kl == 8 && !memcmp(kv, "linkpath", 8)) {
            if (vl > FS_MAX_PATH || memchr(v, 0, vl))
                return false;
            memcpy(x->link, v, vl);
            x->link[vl] = 0;
            x->has_link = true;
        } else if (kl == 4 && !memcmp(kv, "size", 4)) {
            if (!dec(v, vl, &x->size))
                return false;
            x->has_size = true;
        } else if (kl == 3 && !memcmp(kv, "uid", 3)) {
            if (!dec(v, vl, &x->uid) || x->uid > UINT32_MAX)
                return false;
            x->has_uid = true;
        } else if (kl == 3 && !memcmp(kv, "gid", 3)) {
            if (!dec(v, vl, &x->gid) || x->gid > UINT32_MAX)
                return false;
            x->has_gid = true;
        } else if (kl == 5 && !memcmp(kv, "mtime", 5)) {
            const char *dot = memchr(v, '.', vl); // fractional seconds: dropped
            if (dec(v, dot ? (size_t)(dot - v) : vl, &num) && num <= INT64_MAX) {
                x->mtime = (int64_t)num;
                x->has_mtime = true;
            }
        }
        p += len;
        n -= len;
    }
    return true;
}

// Linux new_encode_dev().
static uint32_t encode_dev(uint64_t major, uint64_t minor)
{
    return (uint32_t)((minor & 0xff) | ((major & 0xfff) << 8) | ((minor & ~0xffull) << 12));
}

// Apply one tar entry to the tree.
static int tar_entry(fs_tree *t, const char *path, char type, uint64_t mode,
                     uint64_t uid, uint64_t gid, int64_t mtime, uint64_t size, uint64_t data_off,
                     const char *link, uint64_t major, uint64_t minor, const char **err)
{
    const char *comp[FS_MAX_PATH / 2 + 1];
    size_t clen[FS_MAX_PATH / 2 + 1];
    const int n = split(path, comp, clen, (int)MVM_ARRAY_LEN(comp));
    if (n < 0) {
        *err = "a path has a \"..\" component or an over-long name";
        return -1;
    }
    const uint32_t layer = t->layer;
    if (n == 0) { // the root itself: only its metadata can change
        if (type != '5') {
            *err = "a layer replaces the root directory with a non-directory";
            return -1;
        }
        t->root->mode = FS_IFDIR | (uint32_t)(mode & 07777);
        t->root->uid = (uint32_t)uid;
        t->root->gid = (uint32_t)gid;
        t->root->mtime = mtime;
        return 0;
    }
    const char *name = comp[n - 1];
    const size_t nl = clen[n - 1];

    // OCI whiteouts: hide what lower layers put here.
    if (nl >= 4 && !memcmp(name, ".wh.", 4)) {
        fs_inode *dir = parent_dir(t, comp, clen, n, true, layer, mtime);
        if (!dir) {
            *err = "a whiteout's path goes through a non-directory";
            return -1;
        }
        if (nl == 12 && !memcmp(name, ".wh..wh..opq", 12)) {
            for (size_t i = dir->nents; i-- > 0;)
                if (dir->ents[i].layer < layer)
                    erase(dir, i);
            return 0;
        }
        bool found;
        const size_t at = find(dir, name + 4, nl - 4, &found);
        if (found && dir->ents[at].layer < layer)
            erase(dir, at);
        return 0;
    }

    fs_inode *dir = parent_dir(t, comp, clen, n, true, layer, mtime);
    if (!dir) {
        *err = "a path goes through a non-directory";
        return -1;
    }
    bool found;
    const size_t at = find(dir, name, nl, &found);
    fs_inode *old = found ? dir->ents[at].ino : nullptr;

    if (type == '5' && old && is_dir(old)) { // existing directory: new metadata
        old->mode = FS_IFDIR | (uint32_t)(mode & 07777);
        old->uid = (uint32_t)uid;
        old->gid = (uint32_t)gid;
        old->mtime = mtime;
        dir->ents[at].layer = layer;
        return 0;
    }

    fs_inode *ino = nullptr;
    if (type == '1') { // hard link: another entry for an inode already here
        const char *lc[FS_MAX_PATH / 2 + 1];
        size_t ll[FS_MAX_PATH / 2 + 1];
        const int ln = split(link, lc, ll, (int)MVM_ARRAY_LEN(lc));
        fs_inode *ld = ln > 0 ? parent_dir(t, lc, ll, ln, false, layer, mtime) : nullptr;
        bool lf = false;
        const size_t li = ld ? find(ld, lc[ln - 1], ll[ln - 1], &lf) : 0;
        if (!lf || is_dir(ld->ents[li].ino)) {
            *err = "a hard link's target is missing or a directory";
            return -1;
        }
        ino = ld->ents[li].ino;
    } else {
        uint32_t fmt;
        switch (type) {
        case '0': case '\0': case '7': fmt = FS_IFREG; break;
        case '2': fmt = FS_IFLNK; break;
        case '3': fmt = FS_IFCHR; break;
        case '4': fmt = FS_IFBLK; break;
        case '5': fmt = FS_IFDIR; break;
        case '6': fmt = FS_IFIFO; break;
        default: return 0; // other entry types carry nothing we keep
        }
        ino = new_inode(t, fmt | (uint32_t)(mode & 07777));
        if (!ino) {
            *err = "too many files, or out of memory";
            return -1;
        }
        ino->uid = (uint32_t)uid;
        ino->gid = (uint32_t)gid;
        ino->mtime = mtime;
        if (fmt == FS_IFREG) {
            ino->size = size;
            ino->src = (uint32_t)(t->nsrc - 1);
            ino->off = data_off;
        } else if (fmt == FS_IFLNK) {
            const size_t l = strlen(link);
            if (!l || !(ino->target = dupn(link, l))) {
                *err = "an empty symlink target, or out of memory";
                return -1;
            }
            ino->size = l;
        } else if (fmt == FS_IFCHR || fmt == FS_IFBLK) {
            ino->rdev = encode_dev(major, minor);
        }
    }
    if (found) { // replace what was there (a directory's subtree goes too)
        dir->ents[at].ino = ino;
        dir->ents[at].layer = layer;
        return 0;
    }
    if (insert(dir, at, name, nl, ino, layer)) {
        *err = "out of memory";
        return -1;
    }
    return 0;
}

int fs_import_tar(fs_tree *t, const fs_source *in, const char **err)
{
    const uint64_t fsize = in->size;
    fs_source *src = realloc(t->src, (t->nsrc + 1) * sizeof *src);
    if (!src || t->layer == UINT32_MAX) {
        *err = "out of memory";
        return -1;
    }
    t->src = src;
    t->src[t->nsrc++] = *in;
    t->layer++;

    static tar_ext x;
    memset(&x, 0, sizeof x);
    static char longname[FS_MAX_PATH + 1], longlink[FS_MAX_PATH + 1];
    bool has_longname = false, has_longlink = false;
    uint64_t off = 0;
    for (;;) {
        uint8_t h[512];
        if (off + 512 > fsize) {
            if (off == fsize)
                return 0; // no end-of-archive blocks: fine
            *err = "the layer ends inside a header";
            return -1;
        }
        if (in->read(in->ctx, h, 512, off)) {
            *err = "cannot read the layer";
            return -1;
        }
        bool zero = true;
        for (size_t i = 0; i < 512 && zero; i++)
            zero = h[i] == 0;
        if (zero)
            return 0; // end of archive
        if (!tar_checksum_ok(h)) {
            *err = "a tar header's checksum is wrong";
            return -1;
        }
        uint64_t mode, uid, gid, mtime, size, major = 0, minor = 0;
        if (!tar_num(h + 100, 8, &mode) || !tar_num(h + 108, 8, &uid) || !tar_num(h + 116, 8, &gid) ||
            !tar_num(h + 124, 12, &size) || !tar_num(h + 136, 12, &mtime)) {
            *err = "a tar header has a bad number";
            return -1;
        }
        const bool ustar = !memcmp(h + 257, "ustar", 5);
        if (ustar && (!tar_num(h + 329, 8, &major) || !tar_num(h + 337, 8, &minor))) {
            *err = "a tar header has a bad device number";
            return -1;
        }
        const char type = (char)h[156];
        const bool meta = type == 'x' || type == 'L' || type == 'K' || type == 'g';
        if (x.has_size && !meta) // a pax size is the next real entry's
            size = x.size;
        uint64_t data = off + 512, padded, next, end;
        if (ckd_add(&padded, size, 511) || ckd_add(&next, data, padded & ~511ull) ||
            ckd_add(&end, data, size) || end > fsize) {
            *err = "a tar entry's data runs past the end of the layer";
            return -1;
        }
        if (meta && type != 'g') {
            if (size > 1u << 20) {
                *err = "an over-long pax or GNU long-name record";
                return -1;
            }
            char *buf = malloc((size_t)size + 1);
            if (!buf || in->read(in->ctx, buf, (size_t)size, data)) {
                free(buf);
                *err = "cannot read a pax or GNU long-name record";
                return -1;
            }
            buf[size] = 0;
            bool ok = true;
            if (type == 'x') {
                ok = pax_parse(buf, (size_t)size, &x);
            } else {
                const size_t l = strnlen(buf, (size_t)size);
                ok = l <= FS_MAX_PATH;
                if (ok) {
                    memcpy(type == 'L' ? longname : longlink, buf, l + 1);
                    *(type == 'L' ? &has_longname : &has_longlink) = true;
                }
            }
            free(buf);
            if (!ok) {
                *err = "a bad pax or GNU long-name record";
                return -1;
            }
            off = next;
            continue;
        }
        if (type == 'g') { // global pax header: nothing we use
            off = next;
            continue;
        }

        char path[FS_MAX_PATH + 1], link[FS_MAX_PATH + 1];
        if (x.has_path) {
            memcpy(path, x.path, sizeof path);
        } else if (has_longname) {
            memcpy(path, longname, sizeof path);
        } else {
            const size_t nl = strnlen((const char *)h, 100);
            const size_t pl = ustar ? strnlen((const char *)h + 345, 155) : 0;
            size_t k = 0;
            if (pl) {
                memcpy(path, h + 345, pl);
                path[pl] = '/';
                k = pl + 1;
            }
            memcpy(path + k, h, nl);
            path[k + nl] = 0;
        }
        if (x.has_link) {
            memcpy(link, x.link, sizeof link);
        } else if (has_longlink) {
            memcpy(link, longlink, sizeof link);
        } else {
            const size_t ll = strnlen((const char *)h + 157, 100);
            memcpy(link, h + 157, ll);
            link[ll] = 0;
        }
        if (x.has_uid)
            uid = x.uid;
        if (x.has_gid)
            gid = x.gid;
        int64_t mt = mtime > INT64_MAX ? 0 : (int64_t)mtime;
        if (x.has_mtime)
            mt = x.mtime;
        if (uid > UINT32_MAX || gid > UINT32_MAX) {
            *err = "a uid or gid doesn't fit in 32 bits";
            return -1;
        }
        if (type != '0' && type != '\0' && type != '7')
            size = 0; // only regular files have contents in the image
        if (tar_entry(t, path, type, mode, uid, gid, mt, size, data, link, major, minor, err))
            return -1;
        memset(&x, 0, sizeof x);
        has_longname = has_longlink = false;
        off = next;
    }
}

fs_inode *fs_lookup(const fs_tree *t, const char *path, bool follow)
{
    enum { MAXD = FS_MAX_PATH / 2 + 1, WORK = 2 * FS_MAX_PATH + 2 };
    if (strlen(path) > FS_MAX_PATH)
        return nullptr;
    fs_inode **stack = malloc(MAXD * sizeof *stack);
    char *work = malloc(WORK), *next = malloc(WORK);
    fs_inode *r = nullptr;
    if (!stack || !work || !next)
        goto out;
    strcpy(work, path);
    size_t sp = 0;
    stack[sp++] = t->root;
    int hops = 0;
    const char *p = work;
    for (;;) {
        while (*p == '/')
            p++;
        if (!*p) {
            r = stack[sp - 1];
            break;
        }
        const char *s = p;
        while (*p && *p != '/')
            p++;
        const size_t l = (size_t)(p - s);
        const char *rest = p;
        while (*rest == '/')
            rest++;
        const bool last = !*rest;
        if (l == 1 && s[0] == '.')
            continue;
        if (l == 2 && s[0] == '.' && s[1] == '.') {
            if (sp > 1)
                sp--;
            continue;
        }
        bool found;
        const fs_inode *dir = stack[sp - 1];
        const size_t at = l <= FS_MAX_NAME ? find(dir, s, l, &found) : (found = false, 0);
        if (!found)
            break;
        fs_inode *c = dir->ents[at].ino;
        if ((c->mode & FS_IFMT) == FS_IFLNK && (!last || follow)) {
            const size_t tl = strlen(c->target), rl = strlen(rest);
            if (++hops > 16 || tl + 1 + rl + 1 > WORK)
                break;
            memcpy(next, c->target, tl);
            next[tl] = '/';
            memcpy(next + tl + 1, rest, rl + 1);
            char *tmp = work;
            work = next, next = tmp;
            p = work;
            if (c->target[0] == '/')
                sp = 1;
            continue;
        }
        if (last) {
            r = c;
            break;
        }
        if (!is_dir(c) || sp == MAXD)
            break;
        stack[sp++] = c;
    }
out:
    free(stack);
    free(work);
    free(next);
    return r;
}

// ---- COPY -------------------------------------------------------------------

// One pattern element (not '*') against c: how many pattern bytes it took.
static bool glob_one(const char *p, size_t n, char c, size_t *adv)
{
    if (p[0] == '?') {
        *adv = 1;
        return true;
    }
    if (p[0] == '\\' && n > 1) {
        *adv = 2;
        return p[1] == c;
    }
    if (p[0] == '[') {
        size_t i = 1;
        const bool neg = i < n && (p[i] == '!' || p[i] == '^');
        i += neg;
        const size_t first = i;
        bool hit = false;
        for (; i < n && (p[i] != ']' || i == first); i++) {
            char lo = p[i];
            if (lo == '\\' && i + 1 < n)
                lo = p[++i];
            if (i + 2 < n && p[i + 1] == '-' && p[i + 2] != ']') {
                char hi = p[i + 2];
                i += 2;
                if (hi == '\\' && i + 1 < n)
                    hi = p[++i];
                hit |= c >= lo && c <= hi;
            } else {
                hit |= c == lo;
            }
        }
        if (i >= n) { // no closing ']': a literal '['
            *adv = 1;
            return c == '[';
        }
        *adv = i + 1;
        return hit != neg;
    }
    *adv = 1;
    return p[0] == c;
}

// Go's filepath.Match for one path component (what Docker's COPY uses):
// * ? [set] [!set] [a-z] and \ escapes; '*' matches dot files too.
static bool glob_match(const char *p, size_t pn, const char *s, size_t sn)
{
    size_t pi = 0, si = 0, star = SIZE_MAX, star_s = 0;
    while (si < sn) {
        if (pi < pn && p[pi] == '*') {
            star = ++pi;
            star_s = si;
            continue;
        }
        size_t adv;
        if (pi < pn && glob_one(p + pi, pn - pi, s[si], &adv)) {
            pi += adv;
            si++;
            continue;
        }
        if (star == SIZE_MAX)
            return false;
        pi = star;
        si = ++star_s;
    }
    while (pi < pn && p[pi] == '*')
        pi++;
    return pi == pn;
}

static bool has_glob(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (s[i] == '*' || s[i] == '?' || s[i] == '[' || s[i] == '\\')
            return true;
    return false;
}

typedef struct {
    struct cmatch {
        fs_inode *ino;
        char *name; // its last component ("" for the context's root)
    } *v;
    size_t n, cap;
} cmatches;

enum { MAX_COPY_MATCHES = 1u << 16 };

static int collect(fs_inode *node, const char *name, size_t nl, const char *comp[], const size_t clen[],
                   int i, int n, cmatches *m)
{
    if (i == n) {
        if (m->n >= MAX_COPY_MATCHES)
            return -1;
        struct cmatch *v = grow(m->v, &m->cap, m->n + 1, sizeof *v);
        char *nm = v ? dupn(name, nl) : nullptr;
        if (!nm)
            return -1;
        m->v = v;
        v[m->n++] = (struct cmatch){node, nm};
        return 0;
    }
    if (!is_dir(node))
        return 0;
    if (!has_glob(comp[i], clen[i])) {
        bool found;
        const size_t at = find(node, comp[i], clen[i], &found);
        return found ? collect(node->ents[at].ino, node->ents[at].name, clen[i], comp, clen, i + 1, n, m) : 0;
    }
    for (size_t k = 0; k < node->nents; k++) {
        const char *e = node->ents[k].name;
        const size_t el = strlen(e);
        if (glob_match(comp[i], clen[i], e, el) && collect(node->ents[k].ino, e, el, comp, clen, i + 1, n, m))
            return -1;
    }
    return 0;
}

static void apply_owner(fs_inode *ino, const fs_copy *c)
{
    ino->uid = c->chown ? c->uid : 0; // as in Docker: root's, unless --chown
    ino->gid = c->chown ? c->gid : 0;
    if (c->mode >= 0 && (ino->mode & FS_IFMT) != FS_IFLNK)
        ino->mode = (ino->mode & FS_IFMT) | ((uint32_t)c->mode & 07777);
}

// The directory at `path` in t, made if missing (with mtime, the time of
// what is copied: not 1970): symlinks on the way are followed inside the
// tree, as COPY follows them in the image.
static fs_inode *copy_dir(fs_tree *t, const char *path, const fs_copy *c, int64_t mtime, const char **err)
{
    const char *comp[FS_MAX_PATH / 2 + 1];
    size_t clen[FS_MAX_PATH / 2 + 1];
    const int n = split(path, comp, clen, (int)MVM_ARRAY_LEN(comp));
    if (n < 0) {
        *err = "COPY: the destination has a \"..\" component or an over-long name";
        return nullptr;
    }
    char pre[FS_MAX_PATH + 2];
    size_t pl = 0;
    fs_inode *dir = t->root;
    for (int i = 0; i < n; i++) {
        pre[pl++] = '/';
        memcpy(pre + pl, comp[i], clen[i]);
        pl += clen[i];
        pre[pl] = 0;
        bool found;
        const size_t at = find(dir, comp[i], clen[i], &found);
        if (found) {
            fs_inode *e = dir->ents[at].ino;
            if ((e->mode & FS_IFMT) == FS_IFLNK)
                e = fs_lookup(t, pre, true);
            if (!e || !is_dir(e)) {
                *err = "COPY: the destination goes through something that isn't a directory";
                return nullptr;
            }
            dir = e;
            continue;
        }
        fs_inode *d = new_inode(t, FS_IFDIR | 0755);
        if (!d || insert(dir, at, comp[i], clen[i], d, t->layer)) {
            *err = "out of memory";
            return nullptr;
        }
        apply_owner(d, &(fs_copy){.chown = c->chown, .uid = c->uid, .gid = c->gid, .mode = -1});
        d->mtime = mtime;
        dir = d;
    }
    return dir;
}

// sn (from the context) and what is under it, as `name` in dir. A
// directory merges into one already there; anything else replaces what
// is there. Hard links within the context stay links (sn->parent marks
// what was copied, and to where: the context's tree is never written).
static int graft(fs_tree *t, fs_inode *dir, const char *name, size_t nl, fs_inode *sn, uint32_t si,
                 const fs_copy *c, const char **err)
{
    bool found;
    const size_t at = find(dir, name, nl, &found);
    fs_inode *old = found ? dir->ents[at].ino : nullptr;
    fs_inode *ino = is_dir(sn) ? (old && is_dir(old) ? old : nullptr) : sn->parent;
    if (!ino) {
        if (!(ino = new_inode(t, sn->mode))) {
            *err = "too many files, or out of memory";
            return -1;
        }
        ino->uid = sn->uid, ino->gid = sn->gid, ino->mtime = sn->mtime;
        ino->size = sn->size, ino->rdev = sn->rdev, ino->off = sn->off, ino->src = si;
        if (sn->target && !(ino->target = dupn(sn->target, strlen(sn->target)))) {
            *err = "out of memory";
            return -1;
        }
        apply_owner(ino, c);
        if (!is_dir(sn))
            sn->parent = ino;
    }
    if (ino != old) {
        if (found) {
            dir->ents[at].ino = ino;
            dir->ents[at].layer = t->layer;
        } else if (insert(dir, at, name, nl, ino, t->layer)) {
            *err = "out of memory";
            return -1;
        }
    }
    if (is_dir(sn))
        for (size_t k = 0; k < sn->nents; k++)
            if (graft(t, ino, sn->ents[k].name, strlen(sn->ents[k].name), sn->ents[k].ino, si, c, err))
                return -1;
    return 0;
}

int fs_import_copy(fs_tree *t, const fs_source *in, const fs_copy *c, const char **err)
{
    if (!c->dest || c->dest[0] != '/' || strlen(c->dest) > FS_MAX_PATH) {
        *err = "COPY: the destination must be an absolute path";
        return -1;
    }
    const char *comp[FS_MAX_PATH / 2 + 1];
    size_t clen[FS_MAX_PATH / 2 + 1];
    const int n = split(c->src, comp, clen, (int)MVM_ARRAY_LEN(comp));
    if (n < 0) {
        *err = "COPY: the source has a \"..\" component or an over-long name";
        return -1;
    }
    fs_tree s;
    cmatches m = {0};
    int rc = -1;
    if (fs_tree_init(&s)) {
        *err = "out of memory";
        return -1;
    }
    if (fs_import_tar(&s, in, err))
        goto out;
    if (collect(s.root, "", 0, comp, clen, 0, n, &m)) {
        *err = "COPY: too many files match the source, or out of memory";
        goto out;
    }
    if (!m.n) {
        *err = "COPY: nothing in the build context matches the source";
        goto out;
    }
    fs_source *src = realloc(t->src, (t->nsrc + 1) * sizeof *src);
    if (!src || t->layer == UINT32_MAX) {
        *err = "out of memory";
        goto out;
    }
    t->src = src;
    t->src[t->nsrc++] = *in;
    t->layer++;
    const uint32_t si = (uint32_t)(t->nsrc - 1);
    // Docker's rules: a directory's contents go into dest; a file goes to
    // dest, or into it when dest ends in '/', is a directory already, or
    // more than one thing matched.
    const size_t dl = strlen(c->dest);
    const fs_inode *dd = fs_lookup(t, c->dest, true);
    const bool into = c->dest[dl - 1] == '/' || m.n > 1 || (dd && is_dir(dd));
    for (size_t i = 0; i < m.n; i++) {
        fs_inode *sn = m.v[i].ino;
        if (is_dir(sn)) {
            fs_inode *d = copy_dir(t, c->dest, c, sn->mtime, err);
            if (!d)
                goto out;
            for (size_t k = 0; k < sn->nents; k++)
                if (graft(t, d, sn->ents[k].name, strlen(sn->ents[k].name), sn->ents[k].ino, si, c, err))
                    goto out;
            continue;
        }
        char path[FS_MAX_PATH + FS_MAX_NAME + 2];
        snprintf(path, sizeof path, "%s%s%s", c->dest, into && c->dest[dl - 1] != '/' ? "/" : "",
                 into ? m.v[i].name : "");
        const size_t pl = strlen(path);
        size_t b = pl;
        while (b && path[b - 1] != '/')
            b--;
        if (b == pl || pl > FS_MAX_PATH) {
            *err = "COPY: a file can't be copied to a directory's name";
            goto out;
        }
        char parent[FS_MAX_PATH + 1];
        memcpy(parent, path, b);
        parent[b] = 0;
        fs_inode *d = copy_dir(t, parent, c, sn->mtime, err);
        if (!d || graft(t, d, path + b, pl - b, sn, si, c, err))
            goto out;
    }
    rc = 0;
out:
    for (size_t i = 0; i < m.n; i++)
        free(m.v[i].name);
    free(m.v);
    fs_tree_free(&s);
    return rc;
}

// ---- EROFS images as lower layers ----------------------------------------------
// Only what erofs_write() makes is read: 4 KiB blocks, 64-byte extended
// inodes, flat data, no xattrs. Everything is checked against the image's
// size before use; a directory reached twice (a loop) is refused.
enum { E_BLK = 4096, E_INODE = 64, E_DIRENT = 12, E_MAX_DEPTH = FS_MAX_PATH / 2 };
constexpr uint32_t E_MAGIC = 0xE0F5E1E2;

static uint16_t g16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t g32(const uint8_t *p) { return (uint32_t)g16(p) | (uint32_t)g16(p + 2) << 16; }
static uint64_t g64(const uint8_t *p) { return (uint64_t)g32(p) | (uint64_t)g32(p + 4) << 32; }

typedef struct {
    uint32_t mode, uid, gid, rdev;
    uint64_t size, blk;
    int64_t mtime;
} e_inode;

typedef struct {
    uint64_t nid, size, blk;
    fs_inode *dir;
    int depth;
} e_dir;

typedef struct {
    const fs_source *in;
    uint64_t meta, blocks;
    uint32_t src, layer;
    // nid -> the inode made from it (hard links share it); open addressing
    uint64_t *key; // nid + 1; 0: empty
    fs_inode **val;
    size_t cap, used;
    e_dir *stack;
    size_t sp, scap;
} erd;

static size_t e_find(const erd *r, uint64_t nid)
{
    size_t h = (size_t)((nid + 1) * 0x9E3779B97F4A7C15ull) & (r->cap - 1);
    while (r->key[h] && r->key[h] != nid + 1)
        h = (h + 1) & (r->cap - 1);
    return h;
}

static int e_put(erd *r, uint64_t nid, fs_inode *ino)
{
    if ((r->used + 1) * 2 > r->cap) {
        const size_t oc = r->cap, nc = oc ? oc * 2 : 1024;
        uint64_t *ok = r->key;
        fs_inode **ov = r->val;
        r->key = calloc(nc, sizeof *r->key);
        r->val = calloc(nc, sizeof *r->val);
        if (!r->key || !r->val) {
            free(r->key);
            free(r->val);
            r->key = ok, r->val = ov;
            return -1;
        }
        r->cap = nc;
        for (size_t i = 0; i < oc; i++)
            if (ok[i]) {
                const size_t h = e_find(r, ok[i] - 1);
                r->key[h] = ok[i], r->val[h] = ov[i];
            }
        free(ok);
        free(ov);
    }
    const size_t h = e_find(r, nid);
    if (!r->key[h])
        r->used++;
    r->key[h] = nid + 1, r->val[h] = ino;
    return 0;
}

static fs_inode *e_get(const erd *r, uint64_t nid)
{
    if (!r->cap)
        return nullptr;
    const size_t h = e_find(r, nid);
    return r->key[h] ? r->val[h] : nullptr;
}

static int e_inode_read(const erd *r, uint64_t nid, e_inode *o, const char **err)
{
    uint8_t p[E_INODE];
    uint64_t off;
    if (ckd_mul(&off, nid, 32) || ckd_add(&off, off, r->meta) || off > r->in->size ||
        r->in->size - off < E_INODE) {
        *err = "an inode is outside the image";
        return -1;
    }
    if (r->in->read(r->in->ctx, p, E_INODE, off)) {
        *err = "cannot read the image";
        return -1;
    }
    // Extended (bit 0), flat (layout 0 in bits 1-3), no xattrs.
    if (g16(p) != 1 || g16(p + 2) != 0) {
        *err = "an inode isn't one microvm-mkrootfs writes (extended, flat, without xattrs)";
        return -1;
    }
    *o = (e_inode){.mode = g16(p + 4), .size = g64(p + 8), .uid = g32(p + 24), .gid = g32(p + 28),
                   .mtime = (int64_t)g64(p + 32)};
    const uint32_t fmt = o->mode & FS_IFMT;
    switch (fmt) {
    case FS_IFREG:
    case FS_IFDIR:
    case FS_IFLNK: {
        o->blk = g32(p + 16);
        const uint64_t nblk = o->size / E_BLK + (o->size % E_BLK != 0);
        uint64_t end;
        if ((fmt == FS_IFDIR && !o->size) || (fmt == FS_IFLNK && (!o->size || o->size > FS_MAX_PATH)) ||
            ckd_add(&end, o->blk, nblk) || (nblk && (o->blk == 0 || end > r->blocks))) {
            *err = "an inode's data is outside the image";
            return -1;
        }
        break;
    }
    case FS_IFCHR:
    case FS_IFBLK:
        o->rdev = g32(p + 16);
        break;
    case FS_IFIFO:
    case FS_IFSOCK:
        break;
    default:
        *err = "an inode has an unknown file type";
        return -1;
    }
    return 0;
}

static uint8_t e_ftype(uint32_t mode)
{
    static const uint8_t t[16] = {[FS_IFREG >> 12] = 1, [FS_IFDIR >> 12] = 2, [FS_IFCHR >> 12] = 3,
                                  [FS_IFBLK >> 12] = 4, [FS_IFIFO >> 12] = 5, [FS_IFSOCK >> 12] = 6,
                                  [FS_IFLNK >> 12] = 7};
    return t[(mode & FS_IFMT) >> 12];
}

static void e_meta(fs_inode *x, const e_inode *c)
{
    x->mode = c->mode & (FS_IFMT | 07777);
    x->uid = c->uid;
    x->gid = c->gid;
    x->mtime = c->mtime;
}

// One directory entry of the image, applied to `dir` in the tree.
static int e_entry(fs_tree *t, erd *r, fs_inode *dir, const char *name, size_t nl, uint64_t nid,
                   uint8_t ftype, int depth, const char **err)
{
    e_inode c;
    if (e_inode_read(r, nid, &c, err))
        return -1;
    if (ftype != e_ftype(c.mode)) {
        *err = "a directory entry's type isn't its inode's";
        return -1;
    }
    bool found;
    const size_t at = find(dir, name, nl, &found);
    if (found && dir->ents[at].layer == r->layer) {
        *err = "a directory holds a name twice";
        return -1;
    }
    const uint32_t fmt = c.mode & FS_IFMT;
    if (fmt == FS_IFCHR && c.rdev == 0) { // a whiteout: hide the lower layers' entry
        if (found)
            erase(dir, at);
        return 0;
    }
    fs_inode *x;
    if (fmt == FS_IFDIR) {
        if (e_get(r, nid)) {
            *err = "a directory is linked twice";
            return -1;
        }
        if (depth >= E_MAX_DEPTH) {
            *err = "directories are nested too deeply";
            return -1;
        }
        const bool merge = found && is_dir(dir->ents[at].ino);
        if (!(x = merge ? dir->ents[at].ino : new_inode(t, FS_IFDIR)))
            goto oom;
        e_meta(x, &c);
        e_dir *s = grow(r->stack, &r->scap, r->sp + 1, sizeof *s);
        if (!s)
            goto oom;
        r->stack = s;
        r->stack[r->sp++] = (e_dir){nid, c.size, c.blk, x, depth + 1};
    } else if ((x = e_get(r, nid))) { // a hard link
        if (is_dir(x)) {
            *err = "a directory is linked twice";
            return -1;
        }
    } else {
        if (!(x = new_inode(t, fmt)))
            goto oom;
        e_meta(x, &c);
        if (fmt == FS_IFREG) {
            x->size = c.size;
            x->src = r->src;
            x->off = c.blk * E_BLK;
        } else if (fmt == FS_IFLNK) {
            char *s = malloc((size_t)c.size + 1);
            if (!s)
                goto oom;
            if (r->in->read(r->in->ctx, s, (size_t)c.size, c.blk * E_BLK)) {
                free(s);
                *err = "cannot read the image";
                return -1;
            }
            s[c.size] = 0;
            x->target = s;
            x->size = c.size;
            if (strlen(s) != c.size) {
                *err = "a symlink's target holds a NUL byte";
                return -1;
            }
        } else if (fmt == FS_IFCHR || fmt == FS_IFBLK) {
            x->rdev = c.rdev;
        }
    }
    if (e_put(r, nid, x))
        goto oom;
    if (found) {
        dir->ents[at].ino = x;
        dir->ents[at].layer = r->layer;
    } else if (insert(dir, at, name, nl, x, r->layer)) {
        goto oom;
    }
    return 0;
oom:
    *err = "too many files, or out of memory";
    return -1;
}

int fs_import_erofs(fs_tree *t, const fs_source *in, const char **err)
{
    fs_source *src = realloc(t->src, (t->nsrc + 1) * sizeof *src);
    if (!src || t->layer == UINT32_MAX) {
        *err = "out of memory";
        return -1;
    }
    t->src = src;
    t->src[t->nsrc++] = *in;
    t->layer++;
    erd r = {.in = in, .src = (uint32_t)(t->nsrc - 1), .layer = t->layer};
    uint8_t *blk = malloc(E_BLK);
    int rc = -1;
    if (!blk) {
        *err = "out of memory";
        return -1;
    }
    if (in->size < E_BLK || in->read(in->ctx, blk, E_BLK, 0)) {
        *err = "not an EROFS image (too small, or unreadable)";
        goto out;
    }
    const uint8_t *sb = blk + 1024;
    r.blocks = g32(sb + 36);
    const uint32_t meta = g32(sb + 40);
    if (g32(sb) != E_MAGIC || sb[12] != 12 || g32(sb + 80) != 0 || !meta || meta >= r.blocks ||
        r.blocks > in->size / E_BLK) {
        *err = "not an EROFS image as microvm-mkrootfs writes them (4 KiB blocks, no features)";
        goto out;
    }
    r.meta = (uint64_t)meta * E_BLK;
    const uint64_t root_nid = g16(sb + 14);
    e_inode root;
    if (e_inode_read(&r, root_nid, &root, err))
        goto out;
    if ((root.mode & FS_IFMT) != FS_IFDIR) {
        *err = "the image's root isn't a directory";
        goto out;
    }
    e_meta(t->root, &root);
    if (e_put(&r, root_nid, t->root) || !(r.stack = grow(nullptr, &r.scap, 1, sizeof *r.stack))) {
        *err = "out of memory";
        goto out;
    }
    r.stack[r.sp++] = (e_dir){root_nid, root.size, root.blk, t->root, 0};
    while (r.sp) {
        const e_dir d = r.stack[--r.sp];
        for (uint64_t b = 0; b * E_BLK < d.size; b++) {
            const size_t blen = d.size - b * E_BLK < E_BLK ? (size_t)(d.size - b * E_BLK) : E_BLK;
            if (in->read(in->ctx, blk, blen, (d.blk + b) * E_BLK)) {
                *err = "cannot read the image";
                goto out;
            }
            // Entries, then their names: the first name starts where the
            // entries end; each runs to the next, the last to the block's
            // end (or a NUL).
            const size_t first = blen >= E_DIRENT ? g16(blk + 8) : 0;
            const size_t n = first / E_DIRENT;
            if (!n || first % E_DIRENT || first > blen) {
                *err = "a directory block is malformed";
                goto out;
            }
            for (size_t i = 0; i < n; i++) {
                const uint8_t *e = blk + i * E_DIRENT;
                const size_t no = g16(e + 8), end = i + 1 < n ? g16(e + E_DIRENT + 8) : blen;
                if (no < first || end > blen || end <= no) {
                    *err = "a directory block is malformed";
                    goto out;
                }
                const char *name = (const char *)blk + no;
                size_t nl = 0;
                while (no + nl < end && name[nl])
                    nl++;
                if ((nl == 1 && name[0] == '.') || (nl == 2 && name[0] == '.' && name[1] == '.'))
                    continue;
                if (!nl || nl > FS_MAX_NAME || memchr(name, '/', nl)) {
                    *err = "a directory entry has a bad name";
                    goto out;
                }
                if (e_entry(t, &r, d.dir, name, nl, g64(e), e[10], d.depth, err))
                    goto out;
            }
        }
    }
    rc = 0;
out:
    free(blk);
    free(r.key);
    free(r.val);
    free(r.stack);
    return rc;
}

// ---- what changed since a mark --------------------------------------------------
int fs_tree_mark(const fs_tree *t, fs_mark *m)
{
    *m = (fs_mark){.n = t->n, .saved = calloc(t->n ? t->n : 1, sizeof *m->saved)};
    if (!m->saved)
        return -1;
    for (size_t i = 0; i < t->n; i++) {
        const fs_inode *s = t->all[i];
        fs_inode *c = &m->saved[i];
        *c = *s;
        c->ents = nullptr, c->nents = c->cap = 0, c->target = nullptr;
        if (s->target && !(c->target = dupn(s->target, strlen(s->target))))
            goto oom;
        if (s->nents && !(c->ents = malloc(s->nents * sizeof *c->ents)))
            goto oom;
        for (size_t j = 0; j < s->nents; j++) {
            c->ents[j] = s->ents[j];
            if (!(c->ents[j].name = dupn(s->ents[j].name, strlen(s->ents[j].name))))
                goto oom;
            c->nents = c->cap = j + 1;
        }
    }
    return 0;
oom:
    fs_mark_free(m);
    return -1;
}

void fs_mark_free(fs_mark *m)
{
    for (size_t i = 0; m->saved && i < m->n; i++) {
        for (size_t j = 0; j < m->saved[i].nents; j++)
            free(m->saved[i].ents[j].name);
        free(m->saved[i].ents);
        free(m->saved[i].target);
    }
    free(m->saved);
    *m = (fs_mark){0};
}

typedef struct {
    const fs_mark *m;
    fs_tree *d;
    fs_inode **dof; // t's inode id -> its copy in d (non-directories: hard links stay links)
} dctx;

static bool same_meta(const fs_inode *a, const fs_inode *b)
{
    return a->mode == b->mode && a->uid == b->uid && a->gid == b->gid && a->mtime == b->mtime &&
           a->size == b->size && a->rdev == b->rdev && a->src == b->src && a->off == b->off &&
           !a->target == !b->target && (!a->target || !strcmp(a->target, b->target));
}

static fs_inode *d_copy(dctx *c, const fs_inode *x)
{
    if (!is_dir(x) && c->dof[x->id])
        return c->dof[x->id];
    fs_inode *y = new_inode(c->d, x->mode);
    if (!y)
        return nullptr;
    y->uid = x->uid, y->gid = x->gid, y->mtime = x->mtime, y->size = x->size, y->rdev = x->rdev;
    y->src = x->src, y->off = x->off;
    if (x->target && !(y->target = dupn(x->target, strlen(x->target))))
        return nullptr;
    if (!is_dir(x))
        c->dof[x->id] = y;
    return y;
}

// All of directory x's entries into its copy y.
static int d_whole(dctx *c, const fs_inode *x, fs_inode *y)
{
    for (size_t i = 0; i < x->nents; i++) {
        const fs_dirent *e = &x->ents[i];
        fs_inode *z = d_copy(c, e->ino);
        if (!z || insert(y, y->nents, e->name, strlen(e->name), z, 0) ||
            (is_dir(e->ino) && d_whole(c, e->ino, z)))
            return -1;
    }
    return 0;
}

// Directory x (in t now) against o (the directory at its path at the mark,
// as saved), into y (x's copy in d): 1 if y got entries, 0 if not, -1 on
// error. Both entry lists are sorted the same way: one pass merges them.
static int d_dir(dctx *c, const fs_inode *x, const fs_inode *o, fs_inode *y)
{
    int any = 0;
    size_t i = 0, j = 0;
    while (i < x->nents || j < o->nents) {
        const int cmp = i == x->nents ? 1 : j == o->nents ? -1 : strcmp(x->ents[i].name, o->ents[j].name);
        if (cmp > 0) { // gone: a whiteout
            const char *nm = o->ents[j++].name;
            fs_inode *w = new_inode(c->d, FS_IFCHR);
            if (!w || insert(y, y->nents, nm, strlen(nm), w, 0))
                return -1;
            any = 1;
            continue;
        }
        const fs_dirent *e = &x->ents[i++];
        const fs_inode *now = e->ino, *was = cmp == 0 ? o->ents[j++].ino : nullptr;
        // Entries saved at the mark are inodes that existed then.
        const fs_inode *ws = was ? &c->m->saved[was->id] : nullptr;
        fs_inode *z;
        if (is_dir(now)) {
            if (!(z = d_copy(c, now)))
                return -1;
            if (ws && is_dir(ws)) {
                const int r = d_dir(c, now, ws, z);
                if (r < 0)
                    return -1;
                if (!r && same_meta(now, ws))
                    continue; // unchanged (z stays out of the tree)
            } else if (d_whole(c, now, z)) {
                return -1;
            }
        } else {
            if (now == was && same_meta(now, ws))
                continue;
            if (!(z = d_copy(c, now)))
                return -1;
        }
        if (insert(y, y->nents, e->name, strlen(e->name), z, 0))
            return -1;
        any = 1;
    }
    return any;
}

int fs_tree_diff(const fs_tree *t, const fs_mark *m, fs_tree *d, const char **err)
{
    if (!m->n || fs_tree_init(d)) {
        *err = "out of memory";
        return -1;
    }
    dctx c = {m, d, calloc(t->n ? t->n : 1, sizeof *c.dof)};
    d->src = t->nsrc ? malloc(t->nsrc * sizeof *d->src) : nullptr;
    if (!c.dof || (t->nsrc && !d->src)) {
        free(c.dof);
        fs_tree_free(d);
        *err = "out of memory";
        return -1;
    }
    if (t->nsrc)
        memcpy(d->src, t->src, t->nsrc * sizeof *d->src);
    d->nsrc = t->nsrc;
    d->layer = 1;
    d->root->mode = t->root->mode, d->root->uid = t->root->uid, d->root->gid = t->root->gid;
    d->root->mtime = t->root->mtime;
    // The root is the first inode a tree makes: saved[0].
    const int r = d_dir(&c, t->root, &m->saved[0], d->root);
    free(c.dof);
    if (r < 0) {
        fs_tree_free(d);
        *err = "too many files, or out of memory";
        return -1;
    }
    return 0;
}
