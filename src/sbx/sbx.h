// SPDX-License-Identifier: MIT
// The host side of the sandbox protocol (proto.h): request encoders, and a
// strict reader for what the guest sends. Everything from the guest is
// hostile: every frame and body is checked before anything uses it, and
// the strings it holds are views into the frame (pointer and length; not
// NUL-terminated, and not necessarily UTF-8).
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sbx/proto.h"

// A growable byte buffer. Appending never fails: on out-of-memory it sets
// oom and drops the data (the caller checks oom once, at the end).
typedef struct {
    uint8_t *p;
    size_t len, cap;
    bool oom;
} mvs_buf;

void mvs_buf_put(mvs_buf *b, const void *p, size_t n);
void mvs_buf_free(mvs_buf *b);

typedef struct {
    const char *p;
    size_t n;
} mvs_str;

// --- requests (each appends one whole frame) ---------------------------------

typedef struct {
    uint32_t kind; // MVS_SEL_PID or MVS_SEL_TAG
    uint32_t pid;
    const char *tag;
} mvs_sel;

typedef struct {
    uint32_t flags; // MVS_S_*
    uint16_t cols, rows;
    const char *user, *cwd, *tag;
    const char *const *argv; // argv[0] is the command
    size_t nargs;
    const char *const *envs; // NAME=VALUE
    size_t nenv;
} mvs_start;

void mvs_req_start(mvs_buf *b, const mvs_start *s);
void mvs_req_sel(mvs_buf *b, uint8_t type, const mvs_sel *sel); // CONNECT, CLOSE_STDIN
void mvs_req_input(mvs_buf *b, const mvs_sel *sel, uint32_t flags, const void *data, size_t n);
void mvs_req_signal(mvs_buf *b, const mvs_sel *sel, uint32_t sig);
void mvs_req_resize(mvs_buf *b, const mvs_sel *sel, uint16_t cols, uint16_t rows);
// STAT, MKDIR, REMOVE, READ, WRITE
void mvs_req_path(mvs_buf *b, uint8_t type, const char *user, const char *path);
void mvs_req_move(mvs_buf *b, const char *user, const char *from, const char *to);
void mvs_req_list(mvs_buf *b, const char *user, const char *path, uint32_t depth);
void mvs_req_watch(mvs_buf *b, const char *user, const char *path, uint32_t flags);
void mvs_req_port(mvs_buf *b, uint32_t port);
void mvs_req_set_env(mvs_buf *b, const char *const *envs, size_t n);
void mvs_req_empty(mvs_buf *b, uint8_t type); // PS, SNAPSHOT, DONE
void mvs_req_data(mvs_buf *b, const void *p, size_t n); // one DATA frame (n <= MVS_MAX_CHUNK)

// --- what the guest sends --------------------------------------------------

typedef struct {
    uint8_t type;
    uint32_t len;
    const uint8_t *body;
} mvs_frame;

// Frames out of a byte stream: feed what arrives, take frames out. The
// frames point into the reader's buffer, valid until the next feed.
typedef struct {
    uint8_t *buf;
    size_t len, cap, off;
    char error[96]; // why it failed, once it has
} mvs_reader;

// false: out of memory (the data is lost).
bool mvs_feed(mvs_reader *r, const void *p, size_t n);
// 1 a frame, 0 need more, -1 a malformed frame (r->error says why; final).
int mvs_next(mvs_reader *r, mvs_frame *f);
void mvs_reader_free(mvs_reader *r);

typedef struct {
    uint32_t mode, uid, gid, flags;
    uint64_t size;
    int64_t mtime_sec;
    uint32_t mtime_nsec;
    mvs_str path, owner, group, target;
} mvs_entry;

typedef struct {
    uint32_t kind; // enum mvs_err
    uint32_t err;  // errno, or 0
    mvs_str msg;
} mvs_error;

typedef struct {
    uint32_t pid, flags;
    mvs_str tag, cwd;
    uint16_t nargs, nenv;
    const uint8_t *strs; // nargs then nenv strs, checked: walk with mvs_next_str
    size_t strs_len;
} mvs_proc;

typedef struct {
    uint32_t event, flags;
    mvs_str name;
    bool has_entry;
    mvs_entry entry;
} mvs_wevent;

// Each decoder checks the whole body; false if it is malformed.
bool mvs_dec_hello(const mvs_frame *f, uint32_t *version, uint32_t *resumes);
bool mvs_dec_u32(const mvs_frame *f, uint32_t *v); // P_START
bool mvs_dec_u64(const mvs_frame *f, uint64_t *v); // READ's OK
bool mvs_dec_end(const mvs_frame *f, uint32_t *wait_status);
bool mvs_dec_error(const mvs_frame *f, mvs_error *e);
bool mvs_dec_entry(const uint8_t *b, size_t n, mvs_entry *e);
bool mvs_dec_proc(const mvs_frame *f, mvs_proc *p);
bool mvs_dec_wevent(const mvs_frame *f, mvs_wevent *w);
// The next string of a checked list (mvs_proc's strs).
mvs_str mvs_next_str(const uint8_t **p);
