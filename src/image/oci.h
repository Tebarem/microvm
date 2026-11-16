// SPDX-License-Identifier: MIT
// Container images to root filesystems: an OCI image layout or a
// docker-archive (`docker save`) flattened into an fs_tree, which
// erofs_write() then writes out. Images are untrusted input.
//
// - The linux/amd64 image is picked from an index or manifest list (or the
//   one tagged opts.ref).
// - Every blob is checked against its descriptor before it is used: its
//   size, then its sha256 digest. Each layer's uncompressed bytes must also
//   match the config's diff_id, which is checked before the layer is parsed
//   too (a docker-archive has no other digests). Layers are tar, or tar
//   compressed with gzip or zstd (by media type, checked against the bytes).
// - Layers stream into the tree from the blob files: nothing is extracted.
//   A compressed layer is decompressed once to check it, once to read it into
//   the tree, and once more by erofs_write() for the file data, which it
//   lays out in layer order so each pass reads front to back.
// - The image config's Entrypoint, Cmd, Env, WorkingDir and User become a
//   small file in the image, at OCI_CONFIG_PATH (format: IMAGES.md).
#pragma once

#include "fstree.h"

#define OCI_CONFIG_PATH "/.microvm/image-config"

typedef struct {
    uint64_t max_bytes;   // all layers' decompressed bytes together; 0: 16 GiB
    uint32_t max_ratio;   // a compressed layer's decompressed : compressed bytes; 0: 200
    const char *ref;      // the image to take when there are several (a tag or ref name)
    // Layers to put on top of the image's, as a Dockerfile's COPY would
    // (tar, gzip or zstd; no digests to check). They go in before the
    // config is resolved, so a User they add to /etc/passwd counts, and the
    // config file records each one's sha256. Must stay readable until
    // erofs_write() is done.
    const fs_source *add;
    size_t nadd;
    // nullptr, or one per add: copy[i].src non-null makes add[i] a tar of
    // a build context's files for a Dockerfile COPY (fs_import_copy()),
    // not a layer. owner: "" or COPY --chown's user[:group], resolved in
    // the image as it is at that point.
    const struct oci_copy {
        const char *src, *dest, *owner;
        int32_t mode; // -1, or --chmod's bits
    } *copy;
    // Changes to the image's config, as a build's ENV, WORKDIR and USER
    // make them: each NAME=VALUE in env replaces the image's NAME, in its
    // place, or comes after the image's; workdir and user (when not
    // nullptr) replace the image's.
    const char *const *env;
    size_t nenv;
    const char *workdir, *user;
} oci_opts;

// The image's files, by path from its root: "oci-layout", "index.json",
// "blobs/sha256/<hex>", or for a docker-archive "manifest.json" and any
// member. open() returns 0 and fills in *out, or -1 if there is no such file.
typedef struct {
    int (*open)(void *ctx, const char *path, fs_source *out);
    void *ctx;
} oci_store;

typedef struct oci_image oci_image;

[[nodiscard]] oci_image *oci_new(const oci_opts *o);
// After erofs_write(): the layers' sources belong to the image.
void oci_free(oci_image *im);

// Read the image in `st` into t (empty so far), config file included.
// On error *err says why.
[[nodiscard]] int oci_build(oci_image *im, const oci_store *st, fs_tree *t, const char **err);
// Or on an image already in t (lower layers: fs_import_erofs()): the
// caller's layers (opts.add) on top of it, then its config, which starts
// from the one at OCI_CONFIG_PATH in t (if any) with opts' env, workdir and
// user applied, and the user resolved again in the image as it is now.
[[nodiscard]] int oci_build_on(oci_image *im, fs_tree *t, const char **err);
// Or just layers: tar or gzip'ed tar (told apart by their first bytes), no
// digests. `raw` must stay readable until erofs_write() is done.
[[nodiscard]] int oci_add_layer(oci_image *im, fs_tree *t, const fs_source *raw, const char **err);
// The image config file's bytes (after oci_build), or nullptr.
const uint8_t *oci_config(const oci_image *im, size_t *len);
// Decompressed bytes of all layers so far.
uint64_t oci_layer_bytes(const oci_image *im);

// A docker-archive (or any tar of an image's files) as a store: the tar's
// member table is read (headers only) with the layer reader's path rules.
// Symlinks between members are followed inside the archive.
typedef struct oci_archive oci_archive;
[[nodiscard]] int oci_archive_open(oci_archive **a, const fs_source *tar, const char **err);
oci_store oci_archive_store(oci_archive *a);
void oci_archive_free(oci_archive *a);

// Parse a serialized image config (format: IMAGES.md); for tests and tools.
// Calls fn(key, value) for each record; returns 0, or -1 if malformed.
[[nodiscard]] int oci_config_walk(const uint8_t *p, size_t n,
                                  void (*fn)(void *ctx, const char *key, const char *value),
                                  void *ctx);
