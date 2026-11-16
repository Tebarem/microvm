// SPDX-License-Identifier: MIT
// Fuzz the EROFS reader (fs_import_erofs): lower layers are images we made,
// but they come back from storage, so they are read as untrusted input.
// The input is split at its first 0xA5 0x5A pair into two images, a lower
// and an upper one, so merges and whiteouts across layers get exercised.
//
// Invariants on every accepted input: the merged tree writes out; that
// image reads back and writes out the same bytes again; and a diff of the
// upper layer against the lower one writes out too.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"
#include "image/fstree.h"

typedef struct {
    const uint8_t *p;
    size_t n;
} src;

static int rd(void *ctx, void *dst, size_t len, uint64_t off)
{
    const src *s = ctx;
    if (off > s->n || len > s->n - off)
        return -1;
    if (len)
        memcpy(dst, s->p + off, len);
    return 0;
}

typedef struct {
    uint8_t *p;
    size_t n, cap;
} sink;

static int wr(void *ctx, const void *data, size_t len)
{
    sink *s = ctx;
    if (len > (64u << 20) - s->n)
        return -1;
    if (s->n + len > s->cap) {
        size_t c = s->cap ? s->cap : 65536;
        while (c < s->n + len)
            c *= 2;
        uint8_t *np = realloc(s->p, c);
        if (!np)
            abort();
        s->p = np;
        s->cap = c;
    }
    memcpy(s->p + s->n, data, len);
    s->n += len;
    return 0;
}

static unsigned long long n_inputs, n_accepted;

static void stats(void)
{
    fprintf(stderr, "fuzz_erofs: %llu inputs, %llu accepted\n", n_inputs, n_accepted);
}

// Images into a tree (bottom first) and written out; with `diff`, only
// what the last one changed.
static int build(const src *imgs, size_t n, bool diff, sink *out)
{
    fs_tree t, d = {0};
    fs_mark mk = {0};
    if (fs_tree_init(&t))
        abort();
    const char *err = "";
    int rc = 0;
    for (size_t i = 0; i < n && !rc; i++) {
        if (diff && i + 1 == n && fs_tree_mark(&t, &mk))
            abort();
        const fs_source s = {rd, (void *)&imgs[i], imgs[i].n};
        rc = fs_import_erofs(&t, &s, &err);
    }
    if (!rc && diff)
        rc = fs_tree_diff(&t, &mk, &d, &err);
    if (!rc)
        rc = erofs_write(diff ? &d : &t, &(fs_sink){wr, out}, &err);
    FUZZ_ASSERT(!rc || err != nullptr);
    fs_mark_free(&mk);
    fs_tree_free(&d);
    fs_tree_free(&t);
    return rc;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static bool init;
    if (!init) {
        init = true;
        if (getenv("MVM_FUZZ_STATS"))
            atexit(stats);
    }
    n_inputs++;
    src imgs[2] = {{data, size}, {nullptr, 0}};
    size_t n = 1;
    for (size_t i = 0; i + 1 < size; i++) {
        if (data[i] == 0xA5 && data[i + 1] == 0x5A) {
            imgs[0].n = i;
            imgs[1] = (src){data + i + 2, size - i - 2};
            n = 2;
            break;
        }
    }
    sink a = {0}, b = {0}, c = {0};
    if (build(imgs, n, false, &a) == 0) {
        n_accepted++;
        // What we write, we read: and it writes out the same.
        const src again = {a.p, a.n};
        FUZZ_ASSERT(build(&again, 1, false, &b) == 0);
        FUZZ_ASSERT(a.n == b.n && !memcmp(a.p, b.p, a.n));
        if (n == 2)
            FUZZ_ASSERT(build(imgs, n, true, &c) == 0);
    }
    free(a.p);
    free(b.p);
    free(c.p);
    return 0;
}

// Seeds: images written by erofs_write() from small tar layers.
static fuzz_seed seeds[2];
static sink seed_img[2];

static size_t hdr(uint8_t *p, const char *name, char type, size_t size, const char *link)
{
    memset(p, 0, 512);
    memcpy(p, name, strlen(name));
    memcpy(p + 100, "0000644", 7);
    memcpy(p + 108, "0000000", 7);
    memcpy(p + 116, "0000000", 7);
    snprintf((char *)p + 124, 12, "%011zo", size);
    memcpy(p + 136, "00000000000", 11);
    p[156] = (uint8_t)type;
    if (link)
        memcpy(p + 157, link, strlen(link));
    memcpy(p + 257, "ustar\0" "00", 8);
    memset(p + 148, ' ', 8);
    unsigned s = 0;
    for (int i = 0; i < 512; i++)
        s += p[i];
    snprintf((char *)p + 148, 8, "%06o", s);
    return 512;
}

static void seed_from_tar(sink *out, const uint8_t *tar, size_t n)
{
    fs_tree t;
    const src s = {tar, n};
    const char *err = "";
    if (fs_tree_init(&t) || fs_import_tar(&t, &(fs_source){rd, (void *)&s, n}, &err) ||
        erofs_write(&t, &(fs_sink){wr, out}, &err))
        abort();
    fs_tree_free(&t);
}

const fuzz_seed *fuzz_seeds(size_t *n)
{
    static uint8_t tar[8192];
    size_t k = 0;
    k += hdr(tar + k, "bin/", '5', 0, nullptr);
    k += hdr(tar + k, "bin/sh", '0', 5, nullptr);
    memcpy(tar + k, "hello", 5);
    k += 512;
    k += hdr(tar + k, "bin/ash", '2', 0, "sh");
    k += hdr(tar + k, "bin/sh2", '1', 0, "bin/sh");
    k += hdr(tar + k, "dev/null", '3', 0, nullptr);
    memset(tar + k, 0, 1024);
    seed_from_tar(&seed_img[0], tar, k + 1024);
    seeds[0] = (fuzz_seed){seed_img[0].p, seed_img[0].n};

    // Two images: the second replaces, adds and whites out (a 0/0 device).
    sink both = {0};
    wr(&both, seed_img[0].p, seed_img[0].n);
    wr(&both, "\xA5\x5A", 2);
    k = 0;
    k += hdr(tar + k, "bin/sh", '0', 3, nullptr);
    memcpy(tar + k, "new", 3);
    k += 512;
    k += hdr(tar + k, "bin/ash", '3', 0, nullptr); // major/minor 0: a whiteout
    k += hdr(tar + k, "etc/new", '0', 0, nullptr);
    memset(tar + k, 0, 1024);
    seed_from_tar(&seed_img[1], tar, k + 1024);
    wr(&both, seed_img[1].p, seed_img[1].n);
    seeds[1] = (fuzz_seed){both.p, both.n};
    *n = 2;
    return seeds;
}
