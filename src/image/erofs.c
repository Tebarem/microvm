// SPDX-License-Identifier: MIT
// EROFS writer: the simplest layout the Linux driver reads (fs/erofs).
//   block 0          superblock at byte 1024
//   blocks 1..       inode table: one 64-byte extended inode per file, so
//                    nid (the inode's offset / 32) = 2 * index, root first
//   then             every inode's data, whole blocks each
//                    (EROFS_INODE_FLAT_PLAIN): directory blocks (sorted
//                    dirents, names after them) and symlink targets in inode
//                    order, then file bytes in layer order
// No compression, no xattrs, no tail packing: files are block-aligned in
// the image, which is what lets the guest read them straight from memory.
#include "fstree.h"

#include <stdlib.h>

enum {
    BLK = 4096,
    SB_OFF = 1024,
    INODE_SIZE = 64,
    DIRENT_SIZE = 12,
    META_BLK = 1,
};
constexpr uint32_t EROFS_MAGIC = 0xE0F5E1E2;

static uint8_t file_type(uint32_t mode)
{
    switch (mode & FS_IFMT) {
    case FS_IFREG: return 1;
    case FS_IFDIR: return 2;
    case FS_IFCHR: return 3;
    case FS_IFBLK: return 4;
    case FS_IFIFO: return 5;
    case FS_IFSOCK: return 6;
    case FS_IFLNK: return 7;
    default: return 0;
    }
}

typedef struct {
    const char *name;
    size_t len;
    const fs_inode *ino;
} dent;

static int dent_cmp(const void *a, const void *b)
{
    const dent *x = a, *y = b;
    const size_t n = x->len < y->len ? x->len : y->len;
    const int c = memcmp(x->name, y->name, n);
    return c ? c : (x->len > y->len) - (x->len < y->len);
}

// A directory's entries including "." and "..", sorted as the driver's
// binary search expects (bytewise, a prefix first).
static dent *dir_entries(const fs_inode *d, size_t *n)
{
    dent *e = malloc((d->nents + 2) * sizeof *e);
    if (!e)
        return nullptr;
    e[0] = (dent){".", 1, d};
    e[1] = (dent){"..", 2, d->parent};
    for (size_t i = 0; i < d->nents; i++)
        e[i + 2] = (dent){d->ents[i].name, strlen(d->ents[i].name), d->ents[i].ino};
    *n = d->nents + 2;
    qsort(e, *n, sizeof *e, dent_cmp);
    return e;
}

// How many of e[0..n) fit in one directory block.
static size_t fit(const dent *e, size_t n)
{
    size_t k = 0, used = 0;
    while (k < n && used + DIRENT_SIZE + e[k].len <= BLK) {
        used += DIRENT_SIZE + e[k].len;
        k++;
    }
    return k;
}

static void le16(uint8_t *p, uint64_t v) { p[0] = (uint8_t)v, p[1] = (uint8_t)(v >> 8); }
static void le32(uint8_t *p, uint64_t v) { le16(p, v), le16(p + 2, v >> 16); }
static void le64(uint8_t *p, uint64_t v) { le32(p, v), le32(p + 4, v >> 32); }

// Regular files by where their data is: layer, then offset.
static int by_source(const void *a, const void *b)
{
    const fs_inode *x = *(fs_inode *const *)a, *y = *(fs_inode *const *)b;
    if (x->src != y->src)
        return x->src < y->src ? -1 : 1;
    if (x->off != y->off)
        return x->off < y->off ? -1 : 1;
    return (x->index > y->index) - (x->index < y->index);
}

static uint64_t nid_of(const fs_inode *ino) { return (ino->index - 1) * (INODE_SIZE / 32); }

int erofs_write(fs_tree *t, const fs_sink *out, const char **err)
{
    int rc = -1;
    fs_inode **order = malloc((t->n ? t->n : 1) * sizeof *order);
    fs_inode **stack = malloc((t->n ? t->n : 1) * sizeof *stack);
    uint8_t *buf = calloc(1, 64 * 1024);
    if (!order || !stack || !buf) {
        *err = "out of memory";
        goto out;
    }
    for (size_t i = 0; i < t->n; i++)
        t->all[i]->index = 0, t->all[i]->nlink = 0;

    // 1. number every reachable inode, depth first from the root; count links
    size_t n = 0, sp = 0;
    t->root->parent = t->root;
    t->root->index = ++n;
    order[0] = t->root;
    stack[sp++] = t->root;
    while (sp) {
        fs_inode *d = stack[--sp];
        d->nlink = 2;
        for (size_t i = 0; i < d->nents; i++) {
            fs_inode *c = d->ents[i].ino;
            if ((c->mode & FS_IFMT) == FS_IFDIR) {
                d->nlink++;
                if (c->index) { // can't happen: directories have no hard links
                    *err = "a directory is linked twice";
                    goto out;
                }
                c->parent = d;
                stack[sp++] = c;
            } else {
                c->nlink++;
            }
            if (!c->index) {
                c->index = ++n;
                order[n - 1] = c;
            }
        }
    }

    // 2. lay out the data: blocks after the inode table
    uint64_t meta_bytes;
    if (ckd_mul(&meta_bytes, (uint64_t)n, INODE_SIZE)) {
        *err = "too many files";
        goto out;
    }
    uint64_t blk = META_BLK + (meta_bytes + BLK - 1) / BLK;
    for (size_t i = 0; i < n; i++) {
        fs_inode *ino = order[i];
        ino->nblk = 0;
        if ((ino->mode & FS_IFMT) == FS_IFDIR) {
            size_t ne;
            dent *e = dir_entries(ino, &ne);
            if (!e) {
                *err = "out of memory";
                goto out;
            }
            uint64_t last = 0;
            for (size_t j = 0; j < ne;) {
                const size_t k = fit(e + j, ne - j);
                last = 0;
                for (size_t q = j; q < j + k; q++)
                    last += DIRENT_SIZE + e[q].len;
                j += k;
                ino->nblk++;
            }
            free(e);
            ino->dsize = (ino->nblk - 1) * BLK + last;
        } else if ((ino->mode & FS_IFMT) == FS_IFREG || (ino->mode & FS_IFMT) == FS_IFLNK) {
            ino->nblk = ino->size / BLK + (ino->size % BLK != 0);
        }
        ino->blk = 0;
    }
    // Directories and symlinks first, in inode order; then regular files in
    // the order their bytes sit in the layers, so that a layer that can only
    // be read front to back (a compressed one) is read once, in one pass.
    size_t nd = 0;
    for (size_t i = 0; i < n; i++)
        if (order[i]->nblk && (order[i]->mode & FS_IFMT) != FS_IFREG)
            stack[nd++] = order[i];
    const size_t nmeta = nd;
    for (size_t i = 0; i < n; i++)
        if (order[i]->nblk && (order[i]->mode & FS_IFMT) == FS_IFREG)
            stack[nd++] = order[i];
    qsort(stack + nmeta, nd - nmeta, sizeof *stack, by_source);
    for (size_t i = 0; i < nd; i++) {
        stack[i]->blk = blk;
        if (ckd_add(&blk, blk, stack[i]->nblk) || blk > UINT32_MAX) {
            *err = "the image would exceed 16 TiB";
            goto out;
        }
    }

    // 3. superblock
    memset(buf, 0, BLK);
    uint8_t *sb = buf + SB_OFF;
    le32(sb + 0, EROFS_MAGIC);
    sb[12] = 12; // blkszbits: 4 KiB blocks
    le16(sb + 14, nid_of(t->root));
    le64(sb + 16, n);
    le32(sb + 36, blk); // blocks
    le32(sb + 40, META_BLK);
    memcpy(sb + 64, "microvm", 7); // volume name
    if (out->write(out->ctx, buf, BLK))
        goto io;

    // 4. inode table
    for (size_t i = 0; i < n;) {
        memset(buf, 0, BLK);
        for (size_t s = 0; s < BLK / INODE_SIZE && i < n; s++, i++) {
            const fs_inode *ino = order[i];
            uint8_t *p = buf + s * INODE_SIZE;
            const uint32_t fmt = ino->mode & FS_IFMT;
            le16(p + 0, 1);               // extended inode, EROFS_INODE_FLAT_PLAIN
            le16(p + 4, ino->mode & 0xffff);
            le64(p + 8, fmt == FS_IFDIR ? ino->dsize : ino->size);
            le32(p + 16, (fmt == FS_IFCHR || fmt == FS_IFBLK) ? ino->rdev : ino->blk);
            le32(p + 20, ino->index);     // 32-bit inode number
            le32(p + 24, ino->uid);
            le32(p + 28, ino->gid);
            le64(p + 32, (uint64_t)ino->mtime);
            le32(p + 44, ino->nlink);
        }
        if (out->write(out->ctx, buf, BLK))
            goto io;
    }

    // 5. data, in the order laid out above
    for (size_t i = 0; i < nd; i++) {
        const fs_inode *ino = stack[i];
        const uint32_t fmt = ino->mode & FS_IFMT;
        if (fmt == FS_IFDIR) {
            size_t ne;
            dent *e = dir_entries(ino, &ne);
            if (!e) {
                *err = "out of memory";
                goto out;
            }
            for (size_t j = 0; j < ne;) {
                const size_t k = fit(e + j, ne - j);
                memset(buf, 0, BLK);
                size_t nameoff = k * DIRENT_SIZE;
                for (size_t q = 0; q < k; q++) {
                    uint8_t *d = buf + q * DIRENT_SIZE;
                    le64(d, nid_of(e[j + q].ino));
                    le16(d + 8, nameoff);
                    d[10] = file_type(e[j + q].ino->mode);
                    memcpy(buf + nameoff, e[j + q].name, e[j + q].len);
                    nameoff += e[j + q].len;
                }
                j += k;
                if (out->write(out->ctx, buf, BLK)) {
                    free(e);
                    goto io;
                }
            }
            free(e);
        } else if (fmt == FS_IFLNK) {
            memset(buf, 0, ino->nblk * BLK);
            memcpy(buf, ino->target, ino->size); // targets are at most FS_MAX_PATH
            if (out->write(out->ctx, buf, ino->nblk * BLK))
                goto io;
        } else if (fmt == FS_IFREG) {
            uint64_t left = ino->size, off = ino->off;
            while (left) {
                const size_t chunk = left > 64 * 1024 ? 64 * 1024 : (size_t)left;
                const fs_source *s = &t->src[ino->src];
                if (s->read(s->ctx, buf, chunk, off)) {
                    *err = "cannot read a file's data from its layer";
                    goto out;
                }
                const size_t pad = chunk % BLK ? BLK - chunk % BLK : 0;
                memset(buf + chunk, 0, pad);
                if (out->write(out->ctx, buf, chunk + pad))
                    goto io;
                left -= chunk;
                off += chunk;
            }
        }
    }
    rc = 0;
    goto out;
io:
    *err = "cannot write the image";
out:
    free(order);
    free(stack);
    free(buf);
    return rc;
}
