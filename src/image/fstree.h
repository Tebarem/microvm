// SPDX-License-Identifier: MIT
// Root filesystem images: untrusted tar layers (OCI image layers) are read
// into an in-memory file tree, which is written out as one read-only EROFS
// image for --rootfs.
//
// Nothing here creates, opens or resolves a path on the host: the only host
// files involved are the layer files the caller opened and the output image.
// Tar paths are resolved inside the tree, never through a symlink, and a
// "../" component is refused, so a hostile layer can't name anything outside
// the image (the classic tar-extraction escapes have nothing to act on).
#pragma once

#include "../common.h"
#include "../os.h"

// File types, as in Linux's mode_t (independent of the host's <sys/stat.h>).
enum : uint32_t {
    FS_IFMT = 0170000,
    FS_IFSOCK = 0140000,
    FS_IFLNK = 0120000,
    FS_IFREG = 0100000,
    FS_IFBLK = 0060000,
    FS_IFDIR = 0040000,
    FS_IFCHR = 0020000,
    FS_IFIFO = 0010000,
};

typedef struct fs_inode fs_inode;

// Where a layer's bytes come from: a file (microvm-mkrootfs) or memory
// (tests, fuzzing). read() returns 0 when all `len` bytes were read.
typedef struct {
    int (*read)(void *ctx, void *buf, size_t len, uint64_t off);
    void *ctx;
    uint64_t size;
} fs_source;

// Where the image goes. write() returns 0 when all `len` bytes were taken.
typedef struct {
    int (*write)(void *ctx, const void *buf, size_t len);
    void *ctx;
} fs_sink;

typedef struct {
    char *name;
    fs_inode *ino;
    uint32_t layer; // the layer that put it here (OCI whiteouts hide lower ones)
} fs_dirent;

struct fs_inode {
    uint32_t mode; // file type | permission bits
    uint32_t uid, gid;
    int64_t mtime;
    uint64_t size;   // regular files: bytes; symlinks: target length
    uint32_t rdev;   // device nodes: Linux new_encode_dev(major, minor)
    char *target;    // symlinks
    uint32_t src;    // regular files: data at offset `off` of sources[src]
    uint64_t off;
    fs_dirent *ents; // directories: entries, sorted by name (bytewise)
    size_t nents, cap;
    uint32_t id;     // its place in fs_tree.all
    // filled in by erofs_write()
    uint64_t index;  // position in the inode table, + 1 (0: not reached)
    fs_inode *parent;
    uint32_t nlink;
    uint64_t blk, nblk, dsize;
};

typedef struct {
    fs_inode *root;
    fs_inode **all; // every inode ever made, for fs_tree_free()
    size_t n, cap;
    fs_source *src; // data sources: the layers, in import order
    size_t nsrc;
    uint32_t layer; // layers imported so far
} fs_tree;

// Limits on what an image may hold (beyond them, import fails).
constexpr size_t FS_MAX_INODES = 1u << 24;
constexpr size_t FS_MAX_PATH = 4096;
constexpr size_t FS_MAX_NAME = 255;

[[nodiscard]] int fs_tree_init(fs_tree *t);
void fs_tree_free(fs_tree *t);

// Read one tar layer (ustar, GNU or pax; uncompressed) on top of what's in
// the tree. OCI whiteouts (".wh.NAME", ".wh..wh..opq") remove what lower
// layers put there. `src` must stay readable until erofs_write() is done:
// file contents are copied from it then. On error *err says why.
[[nodiscard]] int fs_import_tar(fs_tree *t, const fs_source *src, const char **err);

// A Dockerfile COPY from a tar of the build context's files.
typedef struct {
    const char *src;  // a path in the context, or a glob (* ? [...] in its components); "." is all of it
    const char *dest; // absolute; a trailing '/' makes it a directory
    bool chown;       // owned by uid and gid; else by root (as in Docker)
    uint32_t uid, gid;
    int32_t mode;     // -1, or the permission bits of everything copied (not symlinks)
} fs_copy;

// COPY from the tar `src` (as fs_import_tar() reads it) into the tree,
// with Docker's rules: a directory's contents go into dest; a file goes to
// dest, or into it when dest ends in '/', is a directory already, or more
// than one thing matched. Directories merge into those already there;
// anything else replaces what is there. Everything copied, and missing
// directories on the way to dest (0755), are owned by root or as chown
// says; symlinks on the way are
// followed inside the tree. `src` must stay readable until erofs_write().
[[nodiscard]] int fs_import_copy(fs_tree *t, const fs_source *src, const fs_copy *c, const char **err);

// Read one EROFS image as microvm-mkrootfs writes it (erofs_write():
// extended, flat inodes, no xattrs; anything else is refused) on top of
// what's in the tree, as one more layer: its directories merge into those
// already there (their metadata replaces the old), anything else replaces
// what is there, and a 0/0 character device (an overlayfs whiteout) removes
// what a lower layer put at its name. File data stays in the image: `src`
// must stay readable until erofs_write() is done.
[[nodiscard]] int fs_import_erofs(fs_tree *t, const fs_source *src, const char **err);

// The tree as it is now, to diff against later (fs_tree_diff).
typedef struct {
    size_t n;         // inodes then: t->all[0 .. n)
    fs_inode *saved;  // each one's metadata and entries then (names copied)
} fs_mark;
[[nodiscard]] int fs_tree_mark(const fs_tree *t, fs_mark *m);
void fs_mark_free(fs_mark *m);

// What changed in t since the mark, as a tree of its own (d, initialized
// here) that goes on top of the marked tree as an overlayfs layer: new and
// changed entries; every directory on the way to them (with its metadata
// now); and for each name that went away, a whiteout (a 0/0 character
// device). File data comes from t's sources, so they must stay readable
// until erofs_write(d) is done. Free d with fs_tree_free().
[[nodiscard]] int fs_tree_diff(const fs_tree *t, const fs_mark *m, fs_tree *d, const char **err);

// The inode at `path` in the tree, or nullptr. Symlinks are followed
// inside the tree only (at most 16; ".." stops at the root, as in a
// chroot); the last component's only if `follow`.
fs_inode *fs_lookup(const fs_tree *t, const char *path, bool follow);

// Write the tree as an EROFS image (4 KiB blocks, uncompressed). The output
// depends only on the tree: same layers, same image.
[[nodiscard]] int erofs_write(fs_tree *t, const fs_sink *out, const char **err);
