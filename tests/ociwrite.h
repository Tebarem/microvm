// SPDX-License-Identifier: MIT
// Writing container images for tests and test tools: the blobs, manifest,
// config and index.json of an OCI image layout, or the files of a
// docker-archive (`docker save`, legacy layout). Output goes through a
// callback that stores a file by path, so the same code writes to memory,
// to a directory or into a tar.
#pragma once

#include <stdarg.h>
#include <stdio.h>

#include "gzwrite.h"
#include "image/sha256.h"
#include "image_util.h"

typedef struct {
    void (*put)(void *ctx, const char *path, const uint8_t *data, size_t n);
    void *ctx;
} ow_out;

typedef struct {
    const uint8_t *data; // the blob as stored (compressed or not)
    size_t n;
    const char *media;   // nullptr: by its first bytes (tar, tar+gzip or tar+zstd)
    char diff[65];       // hex sha256 of the uncompressed tar (ow_layer_set fills it in)
} ow_layer;

typedef struct {
    const char *arch, *os; // nullptr: amd64, linux
    const char *config;    // the config's "config" object (JSON text), or nullptr
    const char *platform;  // descriptor platform for an index entry, e.g. "linux/amd64"; nullptr: none
    const char *ref;       // org.opencontainers.image.ref.name annotation; nullptr: none
} ow_image;

[[gnu::format(gnu_printf, 2, 3)]] static inline void ow_printf(buf *b, const char *fmt, ...)
{
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    const int n = vsnprintf(nullptr, 0, fmt, ap);
    va_end(ap);
    if (n < 0)
        abort();
    char *s = malloc((size_t)n + 1);
    if (!s)
        abort();
    vsnprintf(s, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    buf_put(b, s, (size_t)n);
    free(s);
}

static inline void ow_hex(const void *p, size_t n, char hex[65])
{
    uint8_t d[32];
    sha256(p, n, d);
    sha256_hex(d, hex);
}

// A layer from an uncompressed tar: gzip'ed (mode) or not (stored == nullptr
// mode < 0). The caller frees *store.
static inline void ow_layer_set(ow_layer *l, buf *store, const buf *tar, int mode)
{
    ow_hex(tar->p, tar->n, l->diff);
    if (mode < 0) {
        l->data = tar->p;
        l->n = tar->n;
    } else {
        *store = (buf){0};
        gz_gzip(store, tar->p, tar->n, (gz_mode)mode);
        l->data = store->p;
        l->n = store->n;
    }
    l->media = nullptr;
}

static inline void ow_blob(const ow_out *o, const void *p, size_t n, char hex[65])
{
    ow_hex(p, n, hex);
    char path[96];
    snprintf(path, sizeof path, "blobs/sha256/%s", hex);
    o->put(o->ctx, path, p, n);
}

static inline const char *ow_media(const ow_layer *l)
{
    if (l->media)
        return l->media;
    if (l->n >= 4 && !memcmp(l->data, "\x28\xb5\x2f\xfd", 4))
        return "application/vnd.oci.image.layer.v1.tar+zstd";
    return l->n >= 2 && l->data[0] == 0x1f && l->data[1] == 0x8b
               ? "application/vnd.oci.image.layer.v1.tar+gzip"
               : "application/vnd.oci.image.layer.v1.tar";
}

// The config JSON (malloc'ed, NUL-terminated).
static inline char *ow_config_json(const ow_layer *ls, size_t n, const ow_image *im)
{
    buf c = {0};
    ow_printf(&c, "{\"architecture\":\"%s\",\"os\":\"%s\"", im->arch ? im->arch : "amd64",
              im->os ? im->os : "linux");
    if (im->config)
        ow_printf(&c, ",\"config\":%s", im->config);
    ow_printf(&c, ",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[");
    for (size_t i = 0; i < n; i++)
        ow_printf(&c, "%s\"sha256:%s\"", i ? "," : "", ls[i].diff);
    ow_printf(&c, "]}}");
    buf_put(&c, "", 1);
    return (char *)c.p;
}

// Layer, config and manifest blobs; returns the manifest's descriptor (for
// index.json; malloc'ed).
static inline char *ow_image_blobs(const ow_out *o, const ow_layer *ls, size_t n, const ow_image *im)
{
    char hex[65];
    buf m = {0};
    char *cfg = ow_config_json(ls, n, im);
    ow_blob(o, cfg, strlen(cfg), hex);
    ow_printf(&m, "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
                  "\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
                  "\"digest\":\"sha256:%s\",\"size\":%zu},\"layers\":[", hex, strlen(cfg));
    free(cfg);
    for (size_t i = 0; i < n; i++) {
        ow_blob(o, ls[i].data, ls[i].n, hex);
        ow_printf(&m, "%s{\"mediaType\":\"%s\",\"digest\":\"sha256:%s\",\"size\":%zu}", i ? "," : "",
                  ow_media(&ls[i]), hex, ls[i].n);
    }
    ow_printf(&m, "]}");
    ow_blob(o, m.p, m.n, hex);
    buf d = {0};
    ow_printf(&d, "{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:%s\","
                  "\"size\":%zu", hex, m.n);
    free(m.p);
    if (im->platform) {
        const char *slash = strchr(im->platform, '/');
        ow_printf(&d, ",\"platform\":{\"os\":\"%.*s\",\"architecture\":\"%s\"}",
                  (int)(slash - im->platform), im->platform, slash + 1);
    }
    if (im->ref)
        ow_printf(&d, ",\"annotations\":{\"org.opencontainers.image.ref.name\":\"%s\"}", im->ref);
    ow_printf(&d, "}");
    buf_put(&d, "", 1);
    return (char *)d.p;
}

// index.json (an index of the given descriptors) and oci-layout.
static inline void ow_index(const ow_out *o, char *const *descs, size_t n)
{
    buf x = {0};
    ow_printf(&x, "{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\","
                  "\"manifests\":[");
    for (size_t i = 0; i < n; i++)
        ow_printf(&x, "%s%s", i ? "," : "", descs[i]);
    ow_printf(&x, "]}");
    o->put(o->ctx, "index.json", x.p, x.n);
    free(x.p);
    static const char lay[] = "{\"imageLayoutVersion\":\"1.0.0\"}";
    o->put(o->ctx, "oci-layout", (const uint8_t *)lay, sizeof lay - 1);
}

// A docker-archive's files (the legacy layout of `docker save`): <id>/layer.tar
// per layer, <config hex>.json, manifest.json. With dup_last, one more layer
// entry repeats the first layer through a symlink, as docker does.
static inline void ow_docker(const ow_out *o, const ow_layer *ls, size_t n, const ow_image *im,
                             const char *tag, buf *tar_symlinks)
{
    char *cfg = ow_config_json(ls, n, im);
    char hex[65], path[160];
    ow_hex(cfg, strlen(cfg), hex);
    snprintf(path, sizeof path, "%s.json", hex);
    o->put(o->ctx, path, (const uint8_t *)cfg, strlen(cfg));
    free(cfg);
    buf m = {0};
    ow_printf(&m, "[{\"Config\":\"%s.json\",\"RepoTags\":[\"%s\"],\"Layers\":[", hex, tag);
    for (size_t i = 0; i < n; i++) {
        char id[65];
        snprintf(path, sizeof path, "layer %zu", i);
        ow_hex(path, strlen(path), id);
        snprintf(path, sizeof path, "%s/layer.tar", id);
        if (tar_symlinks && i > 0 && !strcmp(ls[i].diff, ls[0].diff)) {
            // the same bytes as layer 0: a symlink, as docker writes it
            char id0[65], target[160];
            ow_hex("layer 0", 7, id0);
            snprintf(target, sizeof target, "../%s/layer.tar", id0);
            tar_link(tar_symlinks, path, '2', target);
        } else {
            o->put(o->ctx, path, ls[i].data, ls[i].n);
        }
        ow_printf(&m, "%s\"%s\"", i ? "," : "", path);
    }
    ow_printf(&m, "]}]");
    o->put(o->ctx, "manifest.json", m.p, m.n);
    free(m.p);
}

// ow_out that appends files to a tar (the docker-archive itself).
static inline void ow_tar_put(void *ctx, const char *path, const uint8_t *data, size_t n)
{
    tar_raw(ctx, path, '0', 0644, n, data, n, nullptr, 0, 0);
}
