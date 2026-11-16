// SPDX-License-Identifier: MIT
// Tests for the root-filesystem image builder (src/image): tar layers in,
// EROFS out. Layers are built in memory; the image is read back with a small
// EROFS reader written from the on-disk format (fs/erofs/erofs_fs.h), not
// from the writer, so the two can't share a misunderstanding silently.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "image/fstree.h"
#include "image_util.h"

// ---- driving the builder ------------------------------------------------------
// Import the layers (bottom first) and write the image into *out. Returns
// the import or write error, nullptr on success.
static const char *build(buf *layers, size_t n, buf *out)
{
    fs_tree t;
    if (fs_tree_init(&t))
        return "init";
    const char *err = nullptr;
    for (size_t i = 0; i < n && !err; i++) {
        const fs_source s = {buf_read, &layers[i], layers[i].n};
        const char *e = "";
        if (fs_import_tar(&t, &s, &e))
            err = e;
    }
    if (!err) {
        const char *e = "";
        if (erofs_write(&t, &(fs_sink){buf_write, out}, &e))
            err = e[0] ? e : "write";
    }
    fs_tree_free(&t);
    return err;
}

// One layer that must be rejected.
static bool rejected(buf *layer)
{
    buf out = {0};
    const char *err = build(layer, 1, &out);
    free(out.p);
    free(layer->p);
    *layer = (buf){0};
    return err != nullptr;
}

static void test_basic(void)
{
    buf l = {0};
    tar_dir(&l, "./", 0700);
    tar_dir(&l, "bin/", 0755);
    tar_file(&l, "bin/sh", "#!shell\n");
    tar_link(&l, "bin/ash", '2', "sh");
    tar_link(&l, "bin/sh2", '1', "bin/sh");
    tar_file(&l, "etc/deep/missing/parents", "made\n");
    tar_raw(&l, "dev/null", '3', 0666, 0, nullptr, 0, nullptr, 1, 3);
    tar_raw(&l, "dev/pmem0", '4', 0600, 0, nullptr, 0, nullptr, 259, 0);
    tar_raw(&l, "run/fifo", '6', 0600, 0, nullptr, 0, nullptr, 0, 0);
    // a big file: crosses the writer's 64 KiB copy chunks, ends mid-block
    const size_t big = 70000;
    char *bd = malloc(big);
    for (size_t i = 0; i < big; i++)
        bd[i] = (char)(i * 7 + 3);
    tar_raw(&l, "big", '0', 0600, big, bd, big, nullptr, 0, 0);
    tar_end(&l);

    buf out = {0};
    CHECK(build(&l, 1, &out) == nullptr);
    img m;
    CHECK(img_open(&m, &out));
    inode in;
    CHECK(get_inode(&m, m.root, &in) && in.mode == (FS_IFDIR | 0700));
    CHECK(file_is(&m, "bin/sh", "#!shell\n"));
    CHECK(stat_path(&m, "bin/sh", &in) && in.mode == (FS_IFREG | 0644) && in.uid == 1000 &&
          in.gid == 2000 && in.nlink == 2);
    uint64_t a, b;
    CHECK(lookup(&m, "bin/sh", &a) && lookup(&m, "bin/sh2", &b) && a == b); // hard link
    CHECK(stat_path(&m, "bin/ash", &in) && (in.mode & FS_IFMT) == FS_IFLNK && in.size == 2 &&
          data_of(&m, &in) && !memcmp(data_of(&m, &in), "sh", 2));
    CHECK(file_is(&m, "etc/deep/missing/parents", "made\n"));
    CHECK(stat_path(&m, "etc/deep", &in) && in.mode == (FS_IFDIR | 0755) && in.uid == 0);
    CHECK(stat_path(&m, "dev/null", &in) && in.mode == (FS_IFCHR | 0666) && in.u == 0x103);
    CHECK(stat_path(&m, "dev/pmem0", &in) && (in.mode & FS_IFMT) == FS_IFBLK &&
          in.u == ((259u & 0xfff) << 8));
    CHECK(stat_path(&m, "run/fifo", &in) && (in.mode & FS_IFMT) == FS_IFIFO);
    CHECK(stat_path(&m, "big", &in) && in.size == big && data_of(&m, &in) &&
          !memcmp(data_of(&m, &in), bd, big));
    // "." and ".." of a subdirectory, and the root's ".." (itself)
    uint64_t bin, dot, dotdot, rdd;
    CHECK(lookup(&m, "bin", &bin) && lookup(&m, "bin/.", &dot) && lookup(&m, "bin/..", &dotdot));
    CHECK(dot == bin && dotdot == m.root);
    CHECK(lookup(&m, "..", &rdd) && rdd == m.root);
    // directory link counts: 2 + subdirectories
    CHECK(get_inode(&m, m.root, &in) && in.nlink == 2 + 4); // bin etc dev run
    // same input, same image
    buf out2 = {0};
    CHECK(build(&l, 1, &out2) == nullptr);
    CHECK(out2.n == out.n && !memcmp(out.p, out2.p, out.n));
    free(bd);
    free(out.p);
    free(out2.p);
    free(l.p);
}

static void test_layers(void)
{
    buf l[3] = {0};
    tar_file(&l[0], "d/a", "a1");
    tar_file(&l[0], "d/b", "b1");
    tar_file(&l[0], "d/sub/c", "c1");
    tar_file(&l[0], "e", "e1");
    tar_file(&l[0], "keep", "k1");
    tar_end(&l[0]);
    tar_file(&l[1], "d/.wh.a", "");
    tar_file(&l[1], ".wh.e", "");
    tar_file(&l[1], "keep", "k2");      // replaced by a later layer
    tar_file(&l[1], "same", "s2");
    tar_file(&l[1], ".wh.same", "");    // a whiteout doesn't hide its own layer
    tar_file(&l[1], "d/sub", "now a file"); // a directory replaced by a file
    tar_end(&l[1]);
    tar_file(&l[2], "f/x", "x3");
    tar_file(&l[2], "d/.wh..wh..opq", ""); // opaque: drop everything below in d
    tar_file(&l[2], "d/new", "n3");
    tar_end(&l[2]);

    buf out = {0};
    CHECK(build(l, 2, &out) == nullptr);
    img m;
    CHECK(img_open(&m, &out));
    CHECK(!exists(&m, "d/a") && file_is(&m, "d/b", "b1") && !exists(&m, "e"));
    CHECK(file_is(&m, "keep", "k2") && file_is(&m, "same", "s2"));
    CHECK(file_is(&m, "d/sub", "now a file") && !exists(&m, "d/sub/c"));
    CHECK(!exists(&m, ".wh.e") && !exists(&m, "d/.wh.a"));
    free(out.p);

    out = (buf){0};
    CHECK(build(l, 3, &out) == nullptr);
    CHECK(img_open(&m, &out));
    CHECK(!exists(&m, "d/b") && !exists(&m, "d/sub") && file_is(&m, "d/new", "n3"));
    CHECK(file_is(&m, "f/x", "x3") && file_is(&m, "keep", "k2"));
    free(out.p);
    for (int i = 0; i < 3; i++)
        free(l[i].p);
}

static void count_fn(void *ctx, const char *name, size_t l, uint64_t nid)
{
    (void)name, (void)l, (void)nid;
    ++*(int *)ctx;
}

static void test_big_dir(void)
{
    buf l = {0};
    char name[64];
    for (int i = 0; i < 600; i++) { // ~600 * (12 + 24) bytes: several blocks
        snprintf(name, sizeof name, "many/entry-number-%05d", (i * 7919) % 600);
        tar_file(&l, name, "");
    }
    tar_end(&l);
    buf out = {0};
    CHECK(build(&l, 1, &out) == nullptr);
    img m;
    CHECK(img_open(&m, &out));
    uint64_t nid;
    int n = 0;
    CHECK(lookup(&m, "many", &nid) && dir_walk(&m, nid, count_fn, &n) == 602 && n == 602);
    CHECK(exists(&m, "many/entry-number-00000") && exists(&m, "many/entry-number-00599"));
    free(out.p);
    free(l.p);
}

static void test_pax_and_long_names(void)
{
    char longpath[400];
    size_t k = 0;
    for (int i = 0; i < 60; i++)
        k += (size_t)snprintf(longpath + k, sizeof longpath - k, "d%d/", i % 10);
    snprintf(longpath + k, sizeof longpath - k, "leaf");

    buf l = {0};
    tar_pax(&l, "path", longpath);
    tar_file(&l, "ignored-short-name", "via pax");
    // GNU long name
    const size_t gl = strlen("gnu/") + 150;
    char gname[200] = "gnu/";
    memset(gname + 4, 'n', 150);
    gname[gl] = 0;
    tar_raw(&l, "././@LongLink", 'L', 0644, gl + 1, gname, gl + 1, nullptr, 0, 0);
    tar_file(&l, "short", "via gnu");
    // a pax size for the next real entry, with a GNU long-name record in
    // between: the long-name record keeps its own size
    tar_pax(&l, "size", "3");
    tar_raw(&l, "././@LongLink", 'L', 0644, 9, "pax-size", 9, nullptr, 0, 0);
    tar_raw(&l, "x", '0', 0644, 0, "abc", 3, nullptr, 0, 0);
    tar_pax(&l, "uid", "4000000000");
    tar_file(&l, "bigid", "u");
    tar_end(&l);

    buf out = {0};
    CHECK(build(&l, 1, &out) == nullptr);
    img m;
    CHECK(img_open(&m, &out));
    CHECK(file_is(&m, longpath, "via pax") && !exists(&m, "ignored-short-name"));
    CHECK(file_is(&m, gname, "via gnu"));
    CHECK(file_is(&m, "pax-size", "abc"));
    inode in;
    CHECK(stat_path(&m, "bigid", &in) && in.uid == 4000000000u);
    free(out.p);
    free(l.p);
}

static void test_hostile(void)
{
    buf l = {0};
    // ".." anywhere
    tar_file(&l, "../escape", "x");
    tar_end(&l);
    CHECK(rejected(&l));
    tar_file(&l, "a/../../escape", "x");
    tar_end(&l);
    CHECK(rejected(&l));
    tar_pax(&l, "path", "ok/../../escape");
    tar_file(&l, "f", "x");
    tar_end(&l);
    CHECK(rejected(&l));
    // through a symlink: nothing is ever resolved through one
    tar_link(&l, "etc", '2', "/host/etc");
    tar_file(&l, "etc/passwd", "x");
    tar_end(&l);
    CHECK(rejected(&l));
    tar_link(&l, "lnk", '2', "/");
    tar_file(&l, "lnk/.wh.x", "");
    tar_end(&l);
    CHECK(rejected(&l));
    // through a regular file
    tar_file(&l, "f", "x");
    tar_file(&l, "f/g", "x");
    tar_end(&l);
    CHECK(rejected(&l));
    // hard links: missing target, a directory, "..", through a symlink
    tar_link(&l, "h", '1', "nothing-here");
    tar_end(&l);
    CHECK(rejected(&l));
    tar_dir(&l, "d/", 0755);
    tar_link(&l, "h", '1', "d");
    tar_end(&l);
    CHECK(rejected(&l));
    tar_file(&l, "f", "x");
    tar_link(&l, "h", '1', "../f");
    tar_end(&l);
    CHECK(rejected(&l));
    tar_link(&l, "s", '2', ".");
    tar_file(&l, "f", "x");
    tar_link(&l, "h", '1', "s/f");
    tar_end(&l);
    CHECK(rejected(&l));
    // the root replaced by a file
    tar_file(&l, "./", "x");
    tar_end(&l);
    CHECK(rejected(&l));
    // a name over 255 bytes
    char name[300];
    memset(name, 'a', 256);
    name[256] = 0;
    tar_pax(&l, "path", name);
    tar_file(&l, "f", "x");
    tar_end(&l);
    CHECK(rejected(&l));
    // a bad checksum
    size_t h = tar_file(&l, "f", "x");
    l.p[h + 148] ^= 1;
    tar_end(&l);
    CHECK(rejected(&l));
    // a size past the end of the layer
    tar_raw(&l, "f", '0', 0644, 1 << 20, "short", 5, nullptr, 0, 0);
    tar_end(&l);
    CHECK(rejected(&l));
    // a base-256 size that wraps the offset arithmetic
    h = tar_file(&l, "f", "x");
    l.p[h + 124] = 0x80;
    memset(l.p + h + 125, 0xff, 11);
    fix_sum(l.p + h);
    tar_end(&l);
    CHECK(rejected(&l));
    // a negative base-256 number
    h = tar_file(&l, "f", "x");
    l.p[h + 124] = 0xff;
    fix_sum(l.p + h);
    tar_end(&l);
    CHECK(rejected(&l));
    // garbage in a number field
    h = tar_file(&l, "f", "x");
    memcpy(l.p + h + 100, "07x4", 4);
    fix_sum(l.p + h);
    tar_end(&l);
    CHECK(rejected(&l));
    // pax: a record length past the record, a NUL in the path, a too-big uid
    tar_raw(&l, "p", 'x', 0644, 12, "99 path=xx\n", 12, nullptr, 0, 0);
    tar_file(&l, "f", "x");
    tar_end(&l);
    CHECK(rejected(&l));
    tar_raw(&l, "p", 'x', 0644, 12, "12 path=x\0x\n", 12, nullptr, 0, 0);
    tar_file(&l, "f", "x");
    tar_end(&l);
    CHECK(rejected(&l));
    tar_pax(&l, "uid", "4294967296");
    tar_file(&l, "f", "x");
    tar_end(&l);
    CHECK(rejected(&l));
    // a header cut short
    tar_file(&l, "f", "x");
    l.n -= 300;
    CHECK(rejected(&l));

    // Accepted, but kept inside: absolute paths are relative to the image.
    tar_file(&l, "/etc/abs", "inside");
    tar_link(&l, "up", '2', "../../../../etc/shadow"); // a symlink's target is just data
    tar_end(&l);
    buf out = {0};
    CHECK(build(&l, 1, &out) == nullptr);
    img m;
    CHECK(img_open(&m, &out) && file_is(&m, "etc/abs", "inside") && exists(&m, "up"));
    free(out.p);
    free(l.p);
}

// ---- layers: EROFS images as lower layers, deltas on them ----------------------
typedef struct {
    char name[256];
    uint64_t nid;
} ent;

typedef struct {
    ent *v;
    size_t n;
} ents;

static void collect_fn(void *ctx, const char *name, size_t l, uint64_t nid)
{
    ents *e = ctx;
    if ((l == 1 && name[0] == '.') || (l == 2 && name[0] == '.' && name[1] == '.'))
        return;
    if (!(e->v = realloc(e->v, (e->n + 1) * sizeof *e->v)))
        abort();
    memcpy(e->v[e->n].name, name, l);
    e->v[e->n].name[l] = 0;
    e->v[e->n++].nid = nid;
}

// The same tree under a and b: names, types, permissions, owners, sizes,
// contents, link targets and device numbers (not inode numbers or links).
static bool same_tree(const img *a, uint64_t na, const img *b, uint64_t nb, const char *path)
{
    inode x, y;
    if (!get_inode(a, na, &x) || !get_inode(b, nb, &y))
        return false;
    if (x.mode != y.mode || x.uid != y.uid || x.gid != y.gid) {
        fprintf(stderr, "%s: mode/owner %o %u %u vs %o %u %u\n", path, x.mode, x.uid, x.gid, y.mode, y.uid, y.gid);
        return false;
    }
    const uint32_t fmt = x.mode & FS_IFMT;
    if (fmt == FS_IFREG || fmt == FS_IFLNK) {
        const uint8_t *dx = data_of(a, &x), *dy = data_of(b, &y);
        if (x.size != y.size || (x.size && (!dx || !dy || memcmp(dx, dy, x.size)))) {
            fprintf(stderr, "%s: contents differ\n", path);
            return false;
        }
    } else if ((fmt == FS_IFCHR || fmt == FS_IFBLK) && x.u != y.u) {
        return false;
    }
    if (fmt != FS_IFDIR)
        return true;
    ents ea = {0}, eb = {0};
    bool ok = dir_walk(a, na, collect_fn, &ea) >= 0 && dir_walk(b, nb, collect_fn, &eb) >= 0 && ea.n == eb.n;
    if (!ok)
        fprintf(stderr, "%s: %zu entries vs %zu\n", path, ea.n, eb.n);
    for (size_t i = 0; ok && i < ea.n; i++) {
        char p[4096];
        snprintf(p, sizeof p, "%s/%s", path, ea.v[i].name);
        ok = !strcmp(ea.v[i].name, eb.v[i].name) && same_tree(a, ea.v[i].nid, b, eb.v[i].nid, p);
        if (!ok && strcmp(ea.v[i].name, eb.v[i].name))
            fprintf(stderr, "%s: %s vs %s\n", path, ea.v[i].name, eb.v[i].name);
    }
    free(ea.v);
    free(eb.v);
    return ok;
}

// Images (bottom first) into a tree, then tar layers on top; written out.
static const char *build_on(buf *lower, size_t nlo, buf *tars, size_t nt, buf *out, bool diff)
{
    fs_tree t, d = {0};
    fs_mark mk = {0};
    if (fs_tree_init(&t))
        return "init";
    const char *e = nullptr;
    for (size_t i = 0; i < nlo && !e; i++) {
        const fs_source s = {buf_read, &lower[i], lower[i].n};
        const char *x = "";
        if (fs_import_erofs(&t, &s, &x))
            e = x;
    }
    if (!e && diff && fs_tree_mark(&t, &mk))
        e = "mark";
    for (size_t i = 0; i < nt && !e; i++) {
        const fs_source s = {buf_read, &tars[i], tars[i].n};
        const char *x = "";
        if (fs_import_tar(&t, &s, &x))
            e = x;
    }
    const char *x = "";
    if (!e && diff && fs_tree_diff(&t, &mk, &d, &x))
        e = x;
    if (!e && erofs_write(diff ? &d : &t, &(fs_sink){buf_write, out}, &x))
        e = x[0] ? x : "write";
    fs_mark_free(&mk);
    fs_tree_free(&d);
    fs_tree_free(&t);
    return e;
}

static bool is_whiteout(const img *m, const char *path)
{
    inode in;
    return stat_path(m, path, &in) && (in.mode & FS_IFMT) == FS_IFCHR && in.u == 0;
}

static void test_lower(void)
{
    buf base = {0}, up = {0}, up2 = {0};
    tar_dir(&base, "./", 0755);
    tar_file(&base, "bin/sh", "#!shell\n");
    tar_link(&base, "bin/sh2", '1', "bin/sh");
    tar_link(&base, "bin/ash", '2', "sh");
    tar_file(&base, "etc/passwd", "root:x:0:0::/root:/bin/sh\napp:x:1000:1000::/home/app:/bin/sh\n");
    tar_file(&base, "etc/issue", "base\n");
    tar_file(&base, "etc/keep", "keep\n");
    tar_file(&base, "usr/share/a", "a\n");
    tar_file(&base, "usr/share/sub/b", "b\n");
    tar_file(&base, "gone/dir/f", "f\n");
    tar_file(&base, "todir", "a file, then a directory\n");
    tar_file(&base, "tofile/x", "a directory, then a file\n");
    tar_raw(&base, "dev/null", '3', 0666, 0, nullptr, 0, nullptr, 1, 3);
    const size_t big = 70000;
    char *bd = malloc(big);
    for (size_t i = 0; i < big; i++)
        bd[i] = (char)(i * 13 + 1);
    tar_raw(&base, "big", '0', 0600, big, bd, big, nullptr, 0, 0);
    tar_end(&base);

    tar_file(&up, "etc/.wh.issue", "");           // removed
    tar_file(&up, "etc/motd", "new\n");           // added
    tar_file(&up, "etc/keep", "changed\n");       // replaced
    tar_file(&up, "usr/share/.wh..wh..opq", "");  // emptied ...
    tar_file(&up, "usr/share/only", "only\n");    // ... but for this
    tar_file(&up, ".wh.gone", "");                // a whole directory removed
    tar_file(&up, "todir/inside", "now a dir\n"); // a file replaced by a directory? no: through a file
    tar_end(&up);

    // The base as an image; read back and written again, byte for byte.
    buf bimg = {0}, again = {0};
    CHECK(build(&base, 1, &bimg) == nullptr);
    CHECK(build_on(&bimg, 1, nullptr, 0, &again, false) == nullptr);
    CHECK(again.n == bimg.n && !memcmp(again.p, bimg.p, bimg.n));
    free(again.p);

    // "todir/inside" goes through a file: refused, as in a tar layer.
    buf delta = {0};
    CHECK(build_on(&bimg, 1, &up, 1, &delta, true) != nullptr);
    free(delta.p);
    free(up.p);
    up = (buf){0};
    tar_file(&up, "etc/.wh.issue", "");
    tar_file(&up, "etc/motd", "new\n");
    tar_file(&up, "etc/keep", "changed\n");
    tar_file(&up, "usr/share/.wh..wh..opq", "");
    tar_file(&up, "usr/share/only", "only\n");
    tar_file(&up, ".wh.gone", "");
    tar_file(&up, ".wh.todir", "");
    tar_file(&up, "todir/inside", "now a dir\n");  // a file replaced by a directory
    tar_file(&up, "tofile", "now a file\n");       // a directory replaced by a file
    tar_link(&up, "bin/sh3", '1', "bin/sh");       // a hard link to a lower file
    tar_raw(&up, "bin/", '5', 0700, 0, nullptr, 0, nullptr, 0, 0); // new metadata only
    tar_end(&up);

    delta = (buf){0};
    CHECK(build_on(&bimg, 1, &up, 1, &delta, true) == nullptr);
    img m;
    CHECK(img_open(&m, &delta));
    // Only what changed: whiteouts for what went; untouched files aren't there.
    CHECK(is_whiteout(&m, "etc/issue") && is_whiteout(&m, "gone"));
    CHECK(is_whiteout(&m, "usr/share/a") && is_whiteout(&m, "usr/share/sub"));
    CHECK(file_is(&m, "etc/motd", "new\n") && file_is(&m, "etc/keep", "changed\n"));
    CHECK(file_is(&m, "usr/share/only", "only\n") && file_is(&m, "todir/inside", "now a dir\n"));
    CHECK(file_is(&m, "tofile", "now a file\n") && file_is(&m, "bin/sh3", "#!shell\n"));
    CHECK(!exists(&m, "etc/passwd") && !exists(&m, "big") && !exists(&m, "dev") && !exists(&m, "bin/sh") &&
          !exists(&m, "bin/ash"));
    inode in;
    CHECK(stat_path(&m, "bin", &in) && in.mode == (FS_IFDIR | 0700));

    // The base and the delta stacked are the base and the tar layer.
    buf merged = {0}, whole = {0}, both[2] = {base, up};
    buf lowers[2] = {bimg, delta};
    CHECK(build_on(lowers, 2, nullptr, 0, &merged, false) == nullptr);
    CHECK(build(both, 2, &whole) == nullptr);
    img a, b;
    CHECK(img_open(&a, &merged) && img_open(&b, &whole) && same_tree(&a, a.root, &b, b.root, ""));

    // A delta on the delta: a third layer.
    tar_file(&up2, "etc/.wh.motd", "");
    tar_file(&up2, "third", "3\n");
    tar_end(&up2);
    buf delta2 = {0}, merged2 = {0}, whole2 = {0}, three[3] = {base, up, up2};
    CHECK(build_on(lowers, 2, &up2, 1, &delta2, true) == nullptr);
    CHECK(img_open(&m, &delta2) && is_whiteout(&m, "etc/motd") && file_is(&m, "third", "3\n") &&
          !exists(&m, "etc/keep"));
    buf lowers3[3] = {bimg, delta, delta2};
    CHECK(build_on(lowers3, 3, nullptr, 0, &merged2, false) == nullptr);
    CHECK(build(three, 3, &whole2) == nullptr);
    CHECK(img_open(&a, &merged2) && img_open(&b, &whole2) && same_tree(&a, a.root, &b, b.root, ""));
    // No changes: a delta with nothing in it but the root.
    buf empty = {0};
    CHECK(build_on(&bimg, 1, nullptr, 0, &empty, true) == nullptr);
    CHECK(img_open(&m, &empty) && dir_walk(&m, m.root, count_fn, &(int){0}) == 2);

    // Hostile lower images: each refused.
    buf bad = {0};
    img bmi;
    const img *bm = &bmi;
    CHECK(img_open(&bmi, &bimg));
    uint64_t bin;
    CHECK(lookup(bm, "bin", &bin));
    const size_t ioff = (size_t)(bm->meta * 4096 + bin * 32);
    struct {
        size_t off;
        uint8_t val;
    } patches[] = {
        {1024, 0},            // magic
        {1024 + 12, 9},       // block size
        {1024 + 80, 1},       // an incompatible feature
        {1024 + 39, 0x10},    // more blocks than the image
        {ioff, 0},            // a compact inode
        {ioff + 2, 1},        // xattrs
        {ioff + 5, 0xf0},     // an unknown file type
        {ioff + 19, 0x7f},    // data past the end
    };
    for (size_t i = 0; i < MVM_ARRAY_LEN(patches); i++) {
        bad = (buf){0};
        buf_put(&bad, bimg.p, bimg.n);
        bad.p[patches[i].off] = patches[i].val;
        buf o = {0};
        if (build_on(&bad, 1, nullptr, 0, &o, false) == nullptr)
            fprintf(stderr, "hostile image %zu accepted\n", i);
        CHECK(build_on(&bad, 1, nullptr, 0, &o, false) != nullptr);
        free(o.p);
        free(bad.p);
    }
    // A directory that contains its parent: a loop.
    inode root = {0};
    CHECK(get_inode(bm, bm->root, &root));
    bad = (buf){0};
    buf_put(&bad, bimg.p, bimg.n);
    uint8_t *blk = bad.p + (size_t)root.u * 4096;
    const size_t n0 = (size_t)rd16(blk + 8) / 12;
    for (size_t i = 0; i < n0; i++) {
        const size_t no = (size_t)rd16(blk + i * 12 + 8);
        if (!memcmp(blk + no, "bin", 3) && rd64(blk + i * 12) == bin)
            for (int k = 0; k < 8; k++)
                blk[i * 12 + k] = (uint8_t)(bm->root >> (8 * k));
    }
    buf o = {0};
    CHECK(build_on(&bad, 1, nullptr, 0, &o, false) != nullptr);
    free(o.p);
    free(bad.p);
    // Truncated: refused, never read past the end.
    for (size_t cut = 0; cut < bimg.n; cut += 4096) {
        bad = (buf){0};
        buf_put(&bad, bimg.p, cut);
        o = (buf){0};
        CHECK(build_on(&bad, 1, nullptr, 0, &o, false) != nullptr);
        free(o.p);
        free(bad.p);
    }

    free(bd);
    free(bimg.p);
    free(delta.p);
    free(delta2.p);
    free(merged.p);
    free(merged2.p);
    free(whole.p);
    free(whole2.p);
    free(empty.p);
    free(base.p);
    free(up.p);
    free(up2.p);
}

int main(void)
{
    test_basic();
    test_layers();
    test_big_dir();
    test_pax_and_long_names();
    test_hostile();
    test_lower();
    if (failures) {
        fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    printf("all %d checks passed\n", checks);
    return 0;
}
