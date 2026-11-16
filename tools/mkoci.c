// SPDX-License-Identifier: MIT
// mvm-mkoci: assemble a container image from layer tarballs, for tests and
// benchmarks (no docker, no registry):
//
//   mvm-mkoci [--docker-archive] [--gzip] [--config JSON] OUT LAYER...
//
// OUT is an OCI image layout directory, or with --docker-archive a tar
// file as `docker save` writes (legacy layout). Each LAYER is a tar, stored
// as is (or gzip'ed by tests/gzwrite.h with --gzip), or an already gzip'ed
// or zstd'ed tar, stored as is. --config gives the image config's "config"
// object, e.g. '{"Entrypoint":["/bin/probe"],"User":"1000"}'.
//
//   mvm-mkoci --bench FILE      gzip or zstd decompression and SHA-256
//                               throughput on FILE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <direct.h>
#  define mkdir_one(p) _mkdir(p)
#else
#  include <sys/stat.h>
#  define mkdir_one(p) mkdir((p), 0755)
#endif

#include "clock.h"
#include "image/zstd.h"
#include "ociwrite.h"

static int read_file(const char *path, buf *b)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    uint8_t *tmp = malloc(1 << 20);
    size_t n;
    while ((n = fread(tmp, 1, 1 << 20, f)) > 0)
        buf_put(b, tmp, n);
    free(tmp);
    fclose(f);
    return 0;
}

static void mkdirs(const char *path)
{
    char p[4096];
    snprintf(p, sizeof p, "%s", path);
    for (char *c = p + 1; *c; c++) {
        if (*c == '/') {
            *c = 0;
            mkdir_one(p);
            *c = '/';
        }
    }
    mkdir_one(p);
}

static void disk_put(void *ctx, const char *path, const uint8_t *data, size_t n)
{
    char full[4096];
    snprintf(full, sizeof full, "%s/%s", (const char *)ctx, path);
    char *slash = strrchr(full, '/');
    *slash = 0;
    mkdirs(full);
    *slash = '/';
    FILE *f = fopen(full, "wb");
    if (!f || fwrite(data, 1, n, f) != n || fclose(f)) {
        fprintf(stderr, "mvm-mkoci: cannot write %s\n", full);
        exit(1);
    }
}

static bool is_zstd(const buf *b) { return b->n >= 4 && !memcmp(b->p, "\x28\xb5\x2f\xfd", 4); }

// sha256 of a gzip'ed or zstd'ed tar's contents.
static int unpack_hex(const buf *z, char hex[65])
{
    uint8_t *o;
    size_t on;
    const char *err;
    if (is_zstd(z) ? zstd_mem(z->p, z->n, &(inflate_limits){0}, &o, &on, &err)
                   : inflate_mem(INFLATE_GZIP, z->p, z->n, nullptr, &o, &on, &err)) {
        fprintf(stderr, "mvm-mkoci: %s\n", err);
        return -1;
    }
    ow_hex(o, on, hex);
    free(o);
    return 0;
}

typedef struct {
    const uint8_t *p;
    size_t n;
} mem_src;

static int mem_pull(void *ctx, uint8_t *b, size_t cap, size_t *got)
{
    mem_src *m = ctx;
    const size_t k = m->n < cap ? m->n : cap;
    memcpy(b, m->p, k);
    m->p += k, m->n -= k;
    *got = k;
    return 0;
}

// Decompress streamed (as the converter does: peek, consume), best of 5;
// then SHA-256 of the output.
static int bench(const char *path)
{
    buf gz = {0}, all = {0};
    if (read_file(path, &gz))
        return 1;
    const bool zst = is_zstd(&gz);
    const inflate_limits nolim = {0};
    inflate_stream *z = zst ? nullptr : inflate_new(INFLATE_GZIP, &nolim);
    zstd_stream *zs = zst ? zstd_new(&nolim) : nullptr;
    uint64_t best = UINT64_MAX, out = 0;
    for (int r = 0; r < 5; r++) {
        mem_src m = {gz.p, gz.n};
        if (zst)
            zstd_start(zs, mem_pull, &m);
        else
            inflate_start(z, mem_pull, &m);
        out = 0;
        const uint64_t t0 = mvm_now_ns();
        for (;;) {
            const uint8_t *p;
            size_t k;
            if (zst ? zstd_peek(zs, &p, &k) : inflate_peek(z, &p, &k)) {
                fprintf(stderr, "mvm-mkoci: %s\n", zst ? zstd_error(zs) : inflate_error(z));
                return 1;
            }
            if (!k)
                break;
            if (r == 0)
                buf_put(&all, p, k);
            out += k;
            if (zst)
                zstd_consume(zs, k);
            else
                inflate_consume(z, k);
        }
        const uint64_t t = mvm_now_ns() - t0;
        if (r > 0) // the first run also keeps the output
            best = t < best ? t : best;
    }
    inflate_free(z);
    zstd_free(zs);
    printf("%s: %.1f MB -> %.1f MB in %.1f ms: %.0f MB/s out, %.0f MB/s in\n", zst ? "zstd" : "inflate",
           (double)gz.n / 1e6,
           (double)out / 1e6, (double)best / 1e6, (double)out / ((double)best / 1e3),
           (double)gz.n / ((double)best / 1e3));
    uint64_t sbest = UINT64_MAX;
    for (int k = 0; k < 3; k++) {
        const uint64_t s0 = mvm_now_ns();
        uint8_t d[32];
        sha256(all.p, all.n, d);
        const uint64_t st = mvm_now_ns() - s0;
        sbest = st < sbest ? st : sbest;
    }
    printf("sha256 (%s): %.0f MB/s\n", sha256_impl(), (double)all.n / ((double)sbest / 1e3));
    sha256_force_portable(true);
    const uint64_t s0 = mvm_now_ns();
    uint8_t d[32];
    sha256(all.p, all.n, d);
    printf("sha256 (portable): %.0f MB/s\n", (double)all.n / ((double)(mvm_now_ns() - s0) / 1e3));
    free(gz.p);
    free(all.p);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--bench"))
        return bench(argv[2]);
    bool docker = false, gzip = false;
    const char *config = nullptr;
    int i = 1;
    for (; i < argc && !strncmp(argv[i], "--", 2); i++) {
        if (!strcmp(argv[i], "--docker-archive"))
            docker = true;
        else if (!strcmp(argv[i], "--gzip"))
            gzip = true;
        else if (!strcmp(argv[i], "--config") && i + 1 < argc)
            config = argv[++i];
        else
            break;
    }
    if (argc - i < 2) {
        fprintf(stderr, "usage: mvm-mkoci [--docker-archive] [--gzip] [--config JSON] OUT LAYER...\n");
        return 2;
    }
    const char *out = argv[i++];
    const size_t n = (size_t)(argc - i);
    ow_layer *ls = calloc(n, sizeof *ls);
    buf *raw = calloc(n, sizeof *raw), *gz = calloc(n, sizeof *gz);
    for (size_t k = 0; k < n; k++) {
        if (read_file(argv[i + (int)k], &raw[k])) {
            fprintf(stderr, "mvm-mkoci: cannot read %s\n", argv[i + (int)k]);
            return 1;
        }
        const bool is_gz = raw[k].n >= 2 && raw[k].p[0] == 0x1f && raw[k].p[1] == 0x8b;
        if (is_gz || is_zstd(&raw[k])) {
            ls[k] = (ow_layer){.data = raw[k].p, .n = raw[k].n};
            if (unpack_hex(&raw[k], ls[k].diff))
                return 1;
        } else {
            ow_layer_set(&ls[k], &gz[k], &raw[k], gzip ? GZ_FIXED : -1);
        }
    }
    const ow_image im = {.config = config};
    if (docker) {
        buf tar = {0};
        ow_docker(&(ow_out){ow_tar_put, &tar}, ls, n, &im, "mvm-mkoci:latest", &tar);
        buf_zero(&tar, 1024);
        FILE *f = fopen(out, "wb");
        if (!f || fwrite(tar.p, 1, tar.n, f) != tar.n || fclose(f)) {
            fprintf(stderr, "mvm-mkoci: cannot write %s\n", out);
            return 1;
        }
        free(tar.p);
    } else {
        mkdirs(out);
        ow_out o = {disk_put, (void *)out};
        char *d = ow_image_blobs(&o, ls, n, &(ow_image){.config = config, .platform = "linux/amd64"});
        ow_index(&o, &d, 1);
        free(d);
    }
    for (size_t k = 0; k < n; k++)
        free(raw[k].p), free(gz[k].p);
    free(raw), free(gz), free(ls);
    return 0;
}
