// SPDX-License-Identifier: MIT
// Fuzz the image reader: index, manifest and config parsing, platform
// selection, digest/size/diff_id checks, gzip, zstd and tar layers on top of each
// other, the image config and User lookup, and the EROFS writer.
//
// Mutated digests would stop almost every input at the first digest check,
// so the input is a template. It is split at 0xA5 0x5A pairs into chunks:
//   0: index.json   1: a manifest   2: the image config   3...: layer blobs
// and before use "@N" in a chunk becomes "sha256:<digest of chunk N>",
// "%N" the digest of chunk N decompressed (a diff_id), "#N" chunk N's size.
// Chunks are resolved from the last to the first, so references point at
// final bytes. Chunks 1.. are stored as blobs/sha256/<digest>.
//
// An input starting with "TAR" is instead a whole archive (a docker-archive
// or a layout in a tar), digests as they are.
//
// Invariants on every accepted image: a well-formed EROFS superblock that
// covers the image, the same bytes on a second run, and an image config
// that parses (and is in the image).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"
#include "gzwrite.h"
#include "image/inflate.h"
#include "image/oci.h"
#include "image/sha256.h"
#include "image/zstd.h"

enum { MAXC = 8 };

typedef struct {
    buf c[MAXC];
    char hex[MAXC][65];
    size_t n;
} chunks;

static int store_open(void *ctx, const char *path, fs_source *out)
{
    chunks *ch = ctx;
    static buf layout = {(uint8_t *)"{\"imageLayoutVersion\":\"1.0.0\"}", 30, 30};
    if (!strcmp(path, "oci-layout")) {
        *out = (fs_source){buf_read, &layout, layout.n};
        return 0;
    }
    if (!strcmp(path, "index.json") && ch->n) {
        *out = (fs_source){buf_read, &ch->c[0], ch->c[0].n};
        return 0;
    }
    if (!strncmp(path, "blobs/sha256/", 13))
        for (size_t i = 1; i < ch->n; i++)
            if (!strcmp(path + 13, ch->hex[i])) {
                *out = (fs_source){buf_read, &ch->c[i], ch->c[i].n};
                return 0;
            }
    return -1;
}

static void diff_of(const buf *b, char hex[65])
{
    uint8_t *o = nullptr;
    size_t on = 0;
    const char *err;
    const inflate_limits lim = {.max_out = 1 << 22};
    uint8_t d[32];
    if (b->n >= 2 && b->p[0] == 0x1f && b->p[1] == 0x8b && !inflate_mem(INFLATE_GZIP, b->p, b->n, &lim, &o, &on, &err))
        sha256(o, on, d);
    else if (b->n >= 4 && !memcmp(b->p, "\x28\xb5\x2f\xfd", 4) && !zstd_mem(b->p, b->n, &lim, &o, &on, &err))
        sha256(o, on, d);
    else
        sha256(b->p, b->n, d);
    free(o);
    sha256_hex(d, hex);
}

static void resolve(chunks *ch, size_t i)
{
    buf o = {0};
    const buf *in = &ch->c[i];
    for (size_t k = 0; k < in->n; k++) {
        const uint8_t c = in->p[k];
        if ((c == '@' || c == '%' || c == '#') && k + 1 < in->n && in->p[k + 1] >= '0' &&
            in->p[k + 1] < '0' + MAXC) {
            const size_t j = in->p[k + 1] - '0';
            if (j > i && j < ch->n) {
                char s[80];
                if (c == '@')
                    snprintf(s, sizeof s, "sha256:%s", ch->hex[j]);
                else if (c == '#')
                    snprintf(s, sizeof s, "%zu", ch->c[j].n);
                else {
                    char h[65];
                    diff_of(&ch->c[j], h);
                    snprintf(s, sizeof s, "sha256:%s", h);
                }
                buf_put(&o, s, strlen(s));
                k++;
                continue;
            }
        }
        buf_put(&o, &c, 1);
    }
    free(ch->c[i].p);
    ch->c[i] = o;
    uint8_t d[32];
    sha256(o.p, o.n, d);
    sha256_hex(d, ch->hex[i]);
}

static int build(const oci_store *st, buf *image, buf *cfg)
{
    fs_tree t;
    if (fs_tree_init(&t))
        abort();
    oci_image *im = oci_new(&(oci_opts){.max_bytes = 8 << 20, .max_ratio = 100});
    const char *err = "";
    int rc = oci_build(im, st, &t, &err);
    if (!rc)
        rc = erofs_write(&t, &(fs_sink){buf_write, image}, &err);
    FUZZ_ASSERT(!rc || err != nullptr);
    if (!rc) {
        size_t n;
        const uint8_t *c = oci_config(im, &n);
        buf_put(cfg, c, n);
    }
    oci_free(im);
    fs_tree_free(&t);
    return rc;
}

static void count(void *ctx, const char *k, const char *v)
{
    (void)k, (void)v;
    ++*(int *)ctx;
}

static void check(const oci_store *st)
{
    buf i1 = {0}, i2 = {0}, c1 = {0}, c2 = {0};
    if (build(st, &i1, &c1) == 0) {
        FUZZ_ASSERT(i1.n >= 4096 && i1.n % 4096 == 0);
        const uint8_t *sb = i1.p + 1024;
        FUZZ_ASSERT((sb[0] | sb[1] << 8 | sb[2] << 16 | (uint32_t)sb[3] << 24) == 0xE0F5E1E2u);
        FUZZ_ASSERT((uint64_t)(sb[36] | sb[37] << 8 | sb[38] << 16 | (uint32_t)sb[39] << 24) * 4096 == i1.n);
        int recs = 0;
        FUZZ_ASSERT(!oci_config_walk(c1.p, c1.n, count, &recs) && recs >= 3);
        FUZZ_ASSERT(build(st, &i2, &c2) == 0);
        FUZZ_ASSERT(i1.n == i2.n && !memcmp(i1.p, i2.p, i1.n));
        FUZZ_ASSERT(c1.n == c2.n && !memcmp(c1.p, c2.p, c1.n));
    }
    free(i1.p), free(i2.p), free(c1.p), free(c2.p);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size >= 3 && !memcmp(data, "TAR", 3)) {
        buf tar = {(uint8_t *)data + 3, size - 3, size - 3};
        const fs_source s = {buf_read, &tar, tar.n};
        oci_archive *a;
        const char *err;
        if (oci_archive_open(&a, &s, &err) == 0) {
            oci_store st = oci_archive_store(a);
            check(&st);
            oci_archive_free(a);
        }
        return 0;
    }
    chunks ch = {0};
    size_t start = 0;
    for (size_t i = 0; i <= size && ch.n < MAXC; i++) {
        if (i == size || (i + 1 < size && data[i] == 0xA5 && data[i + 1] == 0x5A)) {
            buf_put(&ch.c[ch.n], data + start, i - start);
            buf_put(&ch.c[ch.n], "", 0);
            ch.n++;
            start = i + 2;
            i++;
        }
    }
    for (size_t i = ch.n; i-- > 0;)
        resolve(&ch, i);
    oci_store st = {store_open, &ch};
    check(&st);
    for (size_t i = 0; i < ch.n; i++)
        free(ch.c[i].p);
    return 0;
}

// Seeds: a two-layer image (a gzip layer and a tar layer with a whiteout),
// templates as described above; the same with a zstd layer; a
// docker-archive.
static buf seed_buf[3];
static fuzz_seed seeds[3];

static void put_le(buf *b, uint64_t v, int n)
{
    for (int i = 0; i < n; i++)
        buf_put(b, &(uint8_t){(uint8_t)(v >> (8 * i))}, 1);
}

// A zstd frame of one raw block, with its size and checksum.
static void zstd_raw(buf *b, const uint8_t *p, size_t n)
{
    buf_put(b, "\x28\xb5\x2f\xfd\x44\x00", 6); // 2-byte size, checksum; a 1 KiB window
    put_le(b, n - 256, 2);
    size_t i = 0;
    do {
        const size_t k = n - i < 1024 ? n - i : 1024;
        put_le(b, (uint64_t)(i + k == n) | (uint64_t)k << 3, 3);
        buf_put(b, p + i, k);
        i += k;
    } while (i < n);
    put_le(b, (uint32_t)zstd_xxh64(p, n, 0), 4);
}

static void hdr(buf *b, const char *name, char type, const char *data)
{
    const size_t n = data ? strlen(data) : 0;
    tar_raw(b, name, type, 0644, n, data, n, nullptr, 0, 0);
}

const fuzz_seed *fuzz_seeds(size_t *n)
{
    buf *s = &seed_buf[0];
    static const uint8_t SEP[2] = {0xA5, 0x5A};
    const char *idx = "{\"schemaVersion\":2,\"manifests\":[{\"mediaType\":\"application/vnd.oci.image."
                      "manifest.v1+json\",\"digest\":\"@1\",\"size\":#1,\"platform\":{\"os\":\"linux\","
                      "\"architecture\":\"amd64\"}}]}";
    const char *man = "{\"schemaVersion\":2,\"config\":{\"mediaType\":\"application/vnd.oci.image.config."
                      "v1+json\",\"digest\":\"@2\",\"size\":#2},\"layers\":[{\"mediaType\":\"application/"
                      "vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"@3\",\"size\":#3},{\"mediaType\":"
                      "\"application/vnd.oci.image.layer.v1.tar\",\"digest\":\"@4\",\"size\":#4}]}";
    const char *cfg = "{\"architecture\":\"amd64\",\"os\":\"linux\",\"config\":{\"User\":\"app:1\","
                      "\"Env\":[\"A=1\"],\"Cmd\":[\"/bin/x\"]},\"rootfs\":{\"type\":\"layers\","
                      "\"diff_ids\":[\"%3\",\"%4\"]}}";
    buf_put(s, idx, strlen(idx));
    buf_put(s, SEP, 2);
    buf_put(s, man, strlen(man));
    buf_put(s, SEP, 2);
    buf_put(s, cfg, strlen(cfg));
    buf_put(s, SEP, 2);
    buf l1 = {0}, g = {0};
    hdr(&l1, "etc/", '5', nullptr);
    hdr(&l1, "etc/passwd", '0', "app:x:7:8::/:/bin/x\n");
    hdr(&l1, "bin/x", '0', "#!x");
    hdr(&l1, "d/f", '0', "f");
    buf_zero(&l1, 1024);
    gz_gzip(&g, l1.p, l1.n, GZ_FIXED);
    buf_put(s, g.p, g.n);
    buf_put(s, SEP, 2);
    buf l2 = {0};
    hdr(&l2, "d/.wh.f", '0', nullptr);
    hdr(&l2, "x", '2', nullptr);
    buf_zero(&l2, 1024);
    buf_put(s, l2.p, l2.n);
    seeds[0] = (fuzz_seed){s->p, s->n};

    // the same with the first layer zstd'ed
    buf *z = &seed_buf[2];
    char man_z[512];
    snprintf(man_z, sizeof man_z, "%s", man);
    char *gzt = strstr(man_z, "tar+gzip");
    memcpy(gzt, "tar+zstd", 8);
    buf_put(z, idx, strlen(idx));
    buf_put(z, SEP, 2);
    buf_put(z, man_z, strlen(man_z));
    buf_put(z, SEP, 2);
    buf_put(z, cfg, strlen(cfg));
    buf_put(z, SEP, 2);
    zstd_raw(z, l1.p, l1.n);
    buf_put(z, SEP, 2);
    buf_put(z, l2.p, l2.n);
    seeds[2] = (fuzz_seed){z->p, z->n};

    // a docker-archive with one uncompressed layer, as an archive
    buf *t = &seed_buf[1];
    buf_put(t, "TAR", 3);
    char cfgtxt[512], hex[65], lhex[65], mf[400];
    uint8_t d[32];
    sha256(l1.p, l1.n, d);
    sha256_hex(d, lhex);
    snprintf(cfgtxt, sizeof cfgtxt, "{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{\"type\":"
                                    "\"layers\",\"diff_ids\":[\"sha256:%s\"]}}", lhex);
    sha256(cfgtxt, strlen(cfgtxt), d);
    sha256_hex(d, hex);
    char name[80];
    snprintf(name, sizeof name, "%s.json", hex);
    hdr(t, name, '0', cfgtxt);
    tar_raw(t, "l/layer.tar", '0', 0644, l1.n, l1.p, l1.n, nullptr, 0, 0);
    snprintf(mf, sizeof mf, "[{\"Config\":\"%s\",\"RepoTags\":[\"x:1\"],\"Layers\":[\"l/layer.tar\"]}]", name);
    hdr(t, "manifest.json", '0', mf);
    buf_zero(t, 1024);
    seeds[1] = (fuzz_seed){t->p, t->n};
    free(l1.p), free(g.p), free(l2.p);
    *n = 3;
    return seeds;
}
