// SPDX-License-Identifier: MIT
// Fuzz the host's reader for what a sandbox's guest agent sends
// (src/sbx/wire.c): the guest is hostile, and microvm-sbxd hands every
// frame it gets to these decoders. The first byte picks how the stream is
// split into reads; the rest is the stream.
//
// Invariants:
//   - a frame never claims more than MVS_MAX_BODY, and a malformed stream
//     stays refused (the error is sticky);
//   - the frames, their decoded fields and the verdict are the same however
//     the stream is split;
//   - every string a decoder hands out lies inside its frame's body, holds
//     no NUL, and respects its cap; a PROC's string list walks exactly to
//     its end.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"
#include "sbx/sbx.h"

typedef struct {
    uint8_t *p;
    size_t n, cap;
} acc;

static void put(acc *a, const void *p, size_t n)
{
    if (a->n + n > a->cap) {
        size_t c = a->cap ? a->cap * 2 : 4096;
        while (c < a->n + n)
            c *= 2;
        if (!(a->p = realloc(a->p, c)))
            abort();
        a->cap = c;
    }
    if (n)
        memcpy(a->p + a->n, p, n);
    a->n += n;
}

static void put32(acc *a, uint64_t v) { put(a, &v, sizeof v); }

static void check_str(const mvs_frame *f, mvs_str s, acc *log)
{
    const char *lo = (const char *)f->body, *hi = lo + f->len;
    if (s.n) {
        FUZZ_ASSERT(s.p >= lo && s.p <= hi && s.n <= (size_t)(hi - s.p));
        FUZZ_ASSERT(!memchr(s.p, 0, s.n));
    }
    FUZZ_ASSERT(s.n <= MVS_MAX_STRING);
    put32(log, s.n);
    put(log, s.p, s.n);
}

static void check_entry(const mvs_frame *f, const mvs_entry *e, acc *log)
{
    put32(log, e->mode), put32(log, e->uid), put32(log, e->gid), put32(log, e->flags);
    put32(log, e->size), put32(log, (uint64_t)e->mtime_sec), put32(log, e->mtime_nsec);
    check_str(f, e->path, log);
    check_str(f, e->owner, log);
    check_str(f, e->group, log);
    check_str(f, e->target, log);
}

// Every decoder on the frame (each refuses the types it isn't for).
static void decode(const mvs_frame *f, acc *log)
{
    FUZZ_ASSERT(f->len <= MVS_MAX_BODY);
    put(log, &f->type, 1);
    put32(log, f->len);
    put(log, f->body, f->len);

    uint32_t a, b;
    uint64_t q;
    if (mvs_dec_hello(f, &a, &b))
        put(log, "H", 1), put32(log, a), put32(log, b);
    if (mvs_dec_u32(f, &a))
        put(log, "U", 1), put32(log, a);
    if (mvs_dec_u64(f, &q))
        put(log, "Q", 1), put32(log, q);
    if (mvs_dec_end(f, &a))
        put(log, "N", 1), put32(log, a);
    mvs_error e;
    if (mvs_dec_error(f, &e)) {
        put(log, "E", 1), put32(log, e.kind), put32(log, e.err);
        check_str(f, e.msg, log);
    }
    mvs_entry en;
    if (mvs_dec_entry(f->body, f->len, &en))
        put(log, "Y", 1), check_entry(f, &en, log);
    mvs_proc p;
    if (mvs_dec_proc(f, &p)) {
        put(log, "P", 1), put32(log, p.pid), put32(log, p.flags);
        FUZZ_ASSERT(p.nargs >= 1 && (uint32_t)p.nargs + p.nenv <= MVS_MAX_STRINGS);
        check_str(f, p.tag, log);
        check_str(f, p.cwd, log);
        FUZZ_ASSERT(p.strs >= f->body && p.strs_len <= (size_t)(f->body + f->len - p.strs));
        const uint8_t *s = p.strs;
        for (uint32_t i = 0; i < (uint32_t)p.nargs + p.nenv; i++) {
            FUZZ_ASSERT((size_t)(p.strs + p.strs_len - s) >= 4);
            const mvs_str x = mvs_next_str(&s);
            FUZZ_ASSERT(s <= p.strs + p.strs_len);
            check_str(f, x, log);
        }
        FUZZ_ASSERT(s == p.strs + p.strs_len);
    }
    mvs_wevent w;
    if (mvs_dec_wevent(f, &w)) {
        put(log, "W", 1), put32(log, w.event), put32(log, w.flags);
        check_str(f, w.name, log);
        if (w.has_entry)
            check_entry(f, &w.entry, log);
    }
}

// Feeds d in pieces of `step` bytes (0: all at once), taking frames out as
// they complete. Returns the verdict: -1 refused, 0 fine.
static int run(const uint8_t *d, size_t n, size_t step, acc *log)
{
    mvs_reader r = {0};
    size_t off = 0;
    int rc = 0;
    while (off < n && rc >= 0) {
        const size_t k = step && n - off > step ? step : n - off;
        if (!mvs_feed(&r, d + off, k))
            abort(); // inputs are small
        off += k;
        mvs_frame f;
        while ((rc = mvs_next(&r, &f)) == 1)
            decode(&f, log);
    }
    if (rc < 0) {
        FUZZ_ASSERT(r.error[0]);
        mvs_frame f;
        FUZZ_ASSERT(mvs_next(&r, &f) == -1); // sticky
        uint8_t more[MVS_HDR] = {0};
        (void)mvs_feed(&r, more, sizeof more);
        FUZZ_ASSERT(mvs_next(&r, &f) == -1);
    }
    mvs_reader_free(&r);
    return rc < 0 ? -1 : 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;
    const size_t step = data[0] % 33;
    data++, size--;
    acc a = {0}, b = {0};
    const int ra = run(data, size, 0, &a), rb = run(data, size, step ? step : 1, &b);
    FUZZ_ASSERT(ra == rb);
    FUZZ_ASSERT(a.n == b.n && (!a.n || !memcmp(a.p, b.p, a.n)));
    free(a.p);
    free(b.p);
    return 0;
}

// --- seeds: one of every frame the guest sends ----------------------------

static acc seed_buf;

static void w8(uint8_t v) { put(&seed_buf, &v, 1); }
static void w16(uint16_t v) { put(&seed_buf, &v, 2); }
static void w32(uint32_t v) { put(&seed_buf, &v, 4); }
static void w64(uint64_t v) { put(&seed_buf, &v, 8); }
static void wstr(const char *s) { w32((uint32_t)strlen(s)), put(&seed_buf, s, strlen(s)); }

static size_t frame_start;
static void begin(uint8_t type)
{
    w32(MVS_MAGIC), w8(MVS_VERSION), w8(type), w16(0), w32(0);
    frame_start = seed_buf.n;
}
static void end(void)
{
    const uint32_t len = (uint32_t)(seed_buf.n - frame_start);
    memcpy(seed_buf.p + frame_start - 4, &len, 4);
}
static void entry_body(const char *path, const char *target)
{
    w32(0100644), w32(1000), w32(1000), w32(target[0] ? MVS_E_SYMLINK : 0), w64(5), w64(1700000000), w32(7);
    wstr(path), wstr("user"), wstr("user"), wstr(target);
}

const fuzz_seed *fuzz_seeds(size_t *n)
{
    static fuzz_seed s[4];
    static size_t cuts[5];
    seed_buf.n = 0;
    cuts[0] = 0;

    w8(7); // a process: hello, start, output, end
    begin(MVS_HELLO), w32(1), w32(0), end();
    begin(MVS_P_START), w32(17), end();
    begin(MVS_P_STDOUT), put(&seed_buf, "hello\n", 6), end();
    begin(MVS_P_STDERR), put(&seed_buf, "oops\n", 5), end();
    begin(MVS_P_END), w32(3 << 8), w32(0), end();
    cuts[1] = seed_buf.n;

    w8(3); // files: entries, a read, an error
    begin(MVS_HELLO), w32(1), w32(2), end();
    begin(MVS_ENTRY), entry_body("/home/user/a.txt", ""), end();
    begin(MVS_ENTRY), entry_body("/home/user/l", "/etc/passwd"), end();
    begin(MVS_OK), w64(5), end();
    begin(MVS_DATA), put(&seed_buf, "abcde", 5), end();
    begin(MVS_DONE), end();
    begin(MVS_ERROR), w32(MVS_E_NOTFOUND), w32(2), wstr("no such file"), end();
    cuts[2] = seed_buf.n;

    w8(1); // ps and watch
    begin(MVS_PROC), w32(42), w32(MVS_S_TAG | MVS_S_STDIN), w16(3), w16(1), wstr("srv"), wstr("/app");
    wstr("python3"), wstr("-m"), wstr("http.server"), wstr("PORT=8000"), end();
    begin(MVS_OK), end();
    begin(MVS_W_EVENT), w32(MVS_EV_CREATE), w32(0), wstr("dir/new.txt"), entry_body("/w/dir/new.txt", ""), end();
    begin(MVS_W_EVENT), w32(MVS_EV_REMOVE), w32(MVS_W_NOENTRY), wstr("gone"), end();
    cuts[3] = seed_buf.n;

    w8(0); // a terminal stream cut short
    begin(MVS_P_PTY), put(&seed_buf, "\x1b[1m$ \x1b[0m", 11), end();
    begin(MVS_P_START), w32(5);
    cuts[4] = seed_buf.n;

    for (int i = 0; i < 4; i++)
        s[i] = (fuzz_seed){seed_buf.p + cuts[i], cuts[i + 1] - cuts[i]};
    *n = 4;
    return s;
}
