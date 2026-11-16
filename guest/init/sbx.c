// SPDX-License-Identifier: MIT
// The sandbox agent, part of /init (freestanding like init.c):
//
//   init sandbox run      (microvm --rootfs IMAGE --vsock PATH --append sandbox)
//
// enters the root filesystem image, then serves an E2B-style agent sandbox
// over vsock port MVS_PORT, one operation per connection
// (src/sbx/proto.h): start processes (pipes or a terminal) and stream their
// output, take their input and signals; stat, list, move, remove, read,
// write and watch files; export the root filesystem's changes as a
// layer (image builds); forward a connection to a TCP port in the guest;
// and stop everything for a snapshot (pause, or a template), which every
// restored VM continues from. /init stays pid 1 and keeps the control
// ports; processes get none of them.
//
// One thread, one epoll loop, and it never blocks on the host: a host that
// doesn't read gets at most MVS_MAX_BUFFER of output held for it, and then
// the process (or file, or port) feeding it stops being read until it
// catches up. Two exceptions, both bounded by a timeout: LIST and PS write
// their answer as they go, and wait for the host to read; file writes are
// written to the file as they arrive.
//
// File operations run as root, the way E2B's envd does: the user names the
// home directory for relative paths, and owns what is created. The guest
// is not a security boundary: whatever runs in it can be root.
#include "../../src/sbx/proto.h"
#include "init.h"

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

void *memcpy(void *d, const void *s, unsigned long n); // agent.c
void *memset(void *d, int c, unsigned long n);
void *memmove(void *d, const void *s, unsigned long n);

static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
    long r;
    register long r10 __asm__("r10") = d, r8 __asm__("r8") = e, r9 __asm__("r9") = f;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return r;
}
static long sys3(long n, long a, long b, long c) { return sys6(n, a, b, c, 0, 0, 0); }
static long sys4(long n, long a, long b, long c, long d) { return sys6(n, a, b, c, d, 0, 0); }
static long sys5(long n, long a, long b, long c, long d, long e) { return sys6(n, a, b, c, d, e, 0); }

enum {
    SYS_read = 0, SYS_write = 1, SYS_open = 2, SYS_close = 3, SYS_fstat = 5, SYS_poll = 7, SYS_mmap = 9,
    SYS_munmap = 11, SYS_rt_sigprocmask = 14, SYS_ioctl = 16, SYS_dup2 = 33, SYS_socket = 41,
    SYS_connect = 42, SYS_shutdown = 48, SYS_bind = 49, SYS_listen = 50, SYS_getsockopt = 55,
    SYS_fork = 57, SYS_execve = 59, SYS_exit = 60, SYS_wait4 = 61, SYS_kill = 62, SYS_fcntl = 72,
    SYS_chdir = 80, SYS_rename = 82, SYS_mkdir = 83, SYS_rmdir = 84, SYS_unlink = 87,
    SYS_readlink = 89, SYS_chown = 92, SYS_fchown = 93, SYS_lchown = 94, SYS_setsid = 112, SYS_setgroups = 116,
    SYS_setresuid = 117, SYS_setresgid = 119, SYS_ioperm = 173, SYS_getdents64 = 217,
    SYS_epoll_wait = 232, SYS_epoll_ctl = 233, SYS_inotify_add_watch = 254, SYS_inotify_rm_watch = 255,
    SYS_fgetxattr = 193, SYS_newfstatat = 262, SYS_openat = 257, SYS_readlinkat = 267, SYS_accept4 = 288, SYS_signalfd4 = 289, SYS_epoll_create1 = 291,
    SYS_pipe2 = 293, SYS_inotify_init1 = 294, SYS_close_range = 436,
};
enum {
    O_RDONLY = 0, O_WRONLY = 1, O_RDWR = 2, O_CREAT = 0100, O_NOCTTY = 0400, O_TRUNC = 01000,
    O_NONBLOCK = 04000, O_DIRECTORY = 0200000, O_NOFOLLOW = 0400000, O_CLOEXEC = 02000000,
    F_SETFD = 2, F_SETFL = 4, FD_CLOEXEC = 1, AT_FDCWD = -100, AT_SYMLINK_NOFOLLOW = 0x100,
    AF_INET = 2, AF_VSOCK = 40, SOCK_STREAM = 1, SHUT_WR = 1, SOL_SOCKET = 1, SO_ERROR = 4,
    PROT_RW = 3, MAP_PRIVATE_ANON = 0x22, MAP_NORESERVE = 0x4000,
    EPOLLIN = 1, EPOLLOUT = 4, EPOLLERR = 8, EPOLLHUP = 0x10, EPOLL_CTL_ADD = 1, EPOLL_CTL_DEL = 2,
    EPOLL_CTL_MOD = 3, POLLOUT = 4,
    EPERM = 1, ENOENT = 2, EINTR = 4, EIO = 5, EBADF = 9, EAGAIN = 11, ENOMEM = 12, EACCES = 13,
    EEXIST = 17, ENOTDIR = 20, EISDIR = 21, EINVAL = 22, ENOSPC = 28, ENAMETOOLONG = 36,
    ELOOP = 40, EINPROGRESS = 115,
    WNOHANG = 1, SIGKILL = 9, SIGTERM = 15, SIGCHLD = 17, SIGCONT = 18, SIGSTOP = 19,
    TIOCSCTTY = 0x540E, TIOCSWINSZ = 0x5414, TIOCGPTN = (int)0x80045430, TIOCSPTLCK = 0x40045431,
    S_IFMT = 0170000, S_IFDIR = 0040000, S_IFCHR = 0020000, S_IFIFO = 0010000, S_IFREG = 0100000, S_IFLNK = 0120000,
    IN_MODIFY = 2, IN_ATTRIB = 4, IN_MOVED_FROM = 0x40, IN_MOVED_TO = 0x80, IN_CREATE = 0x100,
    IN_DELETE = 0x200, IN_DELETE_SELF = 0x400, IN_MOVE_SELF = 0x800, IN_Q_OVERFLOW = 0x4000,
    IN_IGNORED = 0x8000, IN_ONLYDIR = 0x01000000, IN_ISDIR = 0x40000000,
    PORT_MARK = 0x700, PORT_SNAPSHOT = 0x706, NPORTS = 8,
};

static void outb(u16 port, u8 v) { __asm__ volatile("outb %0, %1" : : "a"(v), "Nd"(port)); }

// --- small helpers -----------------------------------------------------------

struct kstat {
    u64 dev, ino, nlink;
    u32 mode, uid, gid, pad0;
    u64 rdev;
    i64 size, blksize, blocks;
    i64 atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns;
    i64 unused[3];
};

struct epev {
    u32 events;
    u64 data;
} __attribute__((packed));

static u64 slen(const char *s)
{
    u64 n = 0;
    while (s[n])
        n++;
    return n;
}

static bool seqn(const char *a, const char *b, u64 n)
{
    for (u64 i = 0; i < n; i++)
        if (a[i] != b[i])
            return false;
    return true;
}

static bool seq(const char *a, const char *b) { return slen(a) == slen(b) && seqn(a, b, slen(a)); }

static u32 le32(const u8 *p) { return (u32)p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24; }
static u16 le16(const u8 *p) { return (u16)(p[0] | p[1] << 8); }
static void put32(u8 *p, u32 v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (u8)(v >> (8 * i));
}
static void put64(u8 *p, u64 v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (u8)(v >> (8 * i));
}

static void *map(u64 n)
{
    const long p = sys6(SYS_mmap, 0, (long)((n + 4095) & ~4095ul), PROT_RW, MAP_PRIVATE_ANON | MAP_NORESERVE, -1, 0);
    return p < 0 && p > -4096 ? nullptr : (void *)p;
}
static void unmap(void *p, u64 n)
{
    if (p)
        sys3(SYS_munmap, (long)p, (long)((n + 4095) & ~4095ul), 0);
}

static void xclose(int *fd)
{
    if (*fd >= 0)
        sys3(SYS_close, *fd, 0, 0);
    *fd = -1;
}

static bool dec_u32(const char *s, u64 n, u32 *out)
{
    u64 v = 0;
    if (!n || n > 10)
        return false;
    for (u64 i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10 + (u64)(s[i] - '0');
    }
    if (v > 0xffffffffu)
        return false;
    *out = (u32)v;
    return true;
}

// A whole small file, NUL-terminated, into a fresh mapping (nullptr if it
// can't be read). *cap is what to unmap.
static char *slurp(const char *path, u64 max, u64 *len, u64 *cap)
{
    const int fd = (int)sys3(SYS_open, (long)path, O_RDONLY | O_CLOEXEC | O_NONBLOCK, 0);
    if (fd < 0)
        return nullptr;
    *cap = max + 1;
    char *b = map(*cap);
    u64 n = 0;
    long r = 0;
    while (b && n < max && (r = sys3(SYS_read, fd, (long)(b + n), (long)(max - n))) > 0)
        n += (u64)r;
    sys3(SYS_close, fd, 0, 0);
    if (!b || r < 0) {
        unmap(b, *cap);
        return nullptr;
    }
    b[n] = 0;
    *len = n;
    return b;
}

// --- users ---------------------------------------------------------------------

enum { MAX_GROUPS = 32, PATHMAX = 4096 };

struct user {
    u32 uid, gid, groups[MAX_GROUPS];
    int ngroups;
    char name[256], home[PATHMAX];
};

// The next line of a passwd/group file split at ':' into f (up to nf
// fields); returns the number of fields, 0 at the end. Lines are cut in
// place.
static int fields(char **cur, char **f, int nf)
{
    char *line = *cur;
    if (!line || !*line)
        return 0;
    char *eol = line;
    while (*eol && *eol != '\n')
        eol++;
    *cur = *eol ? eol + 1 : eol;
    *eol = 0;
    int n = 1;
    f[0] = line;
    for (char *c = line; *c && n < nf; c++)
        if (*c == ':')
            *c = 0, f[n++] = c + 1;
    for (int i = n; i < nf; i++)
        f[i] = (char *)"";
    return n;
}

static void copy_str(char *dst, u64 cap, const char *src)
{
    u64 n = slen(src);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
}

// The user by name (or a number) from the image's /etc/passwd and
// /etc/group. An empty name is root.
static bool user_find(const char *name, struct user *u)
{
    memset(u, 0, sizeof *u);
    if (!*name)
        name = "root";
    copy_str(u->name, sizeof u->name, name);
    u64 n, cap;
    char *pw = slurp("/etc/passwd", 4u << 20, &n, &cap);
    bool found = false;
    char *cur = pw, *f[7];
    while (!found && fields(&cur, f, 7)) {
        if (!seq(f[0], name))
            continue;
        found = dec_u32(f[2], slen(f[2]), &u->uid) && dec_u32(f[3], slen(f[3]), &u->gid);
        copy_str(u->home, sizeof u->home, f[5][0] ? f[5] : "/");
    }
    unmap(pw, cap);
    if (!found) {
        if (seq(name, "root")) {
            copy_str(u->home, sizeof u->home, "/root");
            found = true;
        } else if (dec_u32(name, slen(name), &u->uid)) {
            u->gid = u->uid;
            copy_str(u->home, sizeof u->home, "/");
            found = true;
        }
    }
    if (!found)
        return false;
    u->groups[u->ngroups++] = u->gid;
    char *gr = slurp("/etc/group", 4u << 20, &n, &cap);
    cur = gr;
    char *g[4];
    while (u->ngroups < MAX_GROUPS && fields(&cur, g, 4)) {
        u32 gid;
        if (!dec_u32(g[2], slen(g[2]), &gid) || gid == u->gid)
            continue;
        for (char *m = g[3]; *m;) {
            char *e = m;
            while (*e && *e != ',')
                e++;
            if ((u64)(e - m) == slen(u->name) && seqn(m, u->name, (u64)(e - m))) {
                u->groups[u->ngroups++] = gid;
                break;
            }
            m = *e ? e + 1 : e;
        }
    }
    unmap(gr, cap);
    return true;
}

// uid/gid -> name, from files read once per operation.
static struct {
    char *pw, *gr;
    u64 pwcap, grcap;
} names;

static void names_load(void)
{
    u64 n;
    unmap(names.pw, names.pwcap);
    unmap(names.gr, names.grcap);
    names.pw = slurp("/etc/passwd", 4u << 20, &n, &names.pwcap);
    names.gr = slurp("/etc/group", 4u << 20, &n, &names.grcap);
}

// Writes the name of id (field 2 of the file's lines) to out; "" if none.
static u64 name_of(const char *file, u32 id, char *out, u64 cap)
{
    for (const char *line = file; line && *line;) {
        const char *c1 = line;
        while (*c1 && *c1 != ':' && *c1 != '\n')
            c1++;
        const char *c2 = *c1 == ':' ? c1 + 1 : c1;
        while (*c2 && *c2 != ':' && *c2 != '\n')
            c2++;
        const char *c3 = *c2 == ':' ? c2 + 1 : c2, *e3 = c3;
        while (*e3 && *e3 != ':' && *e3 != '\n')
            e3++;
        u32 v;
        if (*c1 == ':' && *c2 == ':' && dec_u32(c3, (u64)(e3 - c3), &v) && v == id) {
            u64 n = (u64)(c1 - line);
            if (n >= cap)
                n = cap - 1;
            memcpy(out, line, n);
            return n;
        }
        while (*line && *line != '\n')
            line++;
        if (*line)
            line++;
    }
    return 0;
}

// --- paths -----------------------------------------------------------------------

// An absolute, lexically clean path: relative ones (and ~) start at the
// user's home. false if it doesn't fit.
static bool resolve(const struct user *u, const char *p, char *out)
{
    char tmp[2 * PATHMAX];
    u64 n = 0;
    const u64 pl = slen(p), hl = slen(u->home);
    if (p[0] == '/') {
        if (pl >= sizeof tmp)
            return false;
        memcpy(tmp, p, pl + 1);
    } else {
        const char *rest = p;
        if (p[0] == '~' && (p[1] == 0 || p[1] == '/'))
            rest = p[1] ? p + 2 : p + 1;
        const u64 rl = slen(rest);
        if (hl + rl + 2 >= sizeof tmp)
            return false;
        memcpy(tmp, u->home, hl);
        tmp[hl] = '/';
        memcpy(tmp + hl + 1, rest, rl + 1);
    }
    // Clean: no empty, "." or ".." segments.
    out[n++] = '/';
    for (const char *s = tmp; *s;) {
        while (*s == '/')
            s++;
        const char *e = s;
        while (*e && *e != '/')
            e++;
        const u64 sl = (u64)(e - s);
        if (sl == 0 || (sl == 1 && s[0] == '.')) {
        } else if (sl == 2 && s[0] == '.' && s[1] == '.') {
            while (n > 1 && out[n - 1] != '/')
                n--;
            if (n > 1)
                n--; // the slash before the segment
        } else {
            if (n + sl + 2 > PATHMAX)
                return false;
            if (n > 1)
                out[n++] = '/';
            memcpy(out + n, s, sl);
            n += sl;
        }
        s = e;
    }
    out[n] = 0;
    return true;
}

static long lstat_(const char *p, struct kstat *st) { return sys4(SYS_newfstatat, AT_FDCWD, (long)p, (long)st, AT_SYMLINK_NOFOLLOW); }
static long stat_(const char *p, struct kstat *st) { return sys4(SYS_newfstatat, AT_FDCWD, (long)p, (long)st, 0); }

// mkdir -p, the directories it makes owned by uid:gid. 0 or -errno; *made
// says whether the last one was made here.
static long mkdir_p(const char *path, u32 uid, u32 gid, bool *made)
{
    char p[PATHMAX];
    copy_str(p, sizeof p, path);
    const u64 n = slen(p);
    *made = false;
    for (u64 i = 1; i <= n; i++) {
        if (i < n && p[i] != '/')
            continue;
        p[i] = 0;
        long r = sys3(SYS_mkdir, (long)p, 0755, 0);
        if (r == 0) {
            sys3(SYS_chown, (long)p, uid, gid);
            *made = i == n;
        } else if (r != -EEXIST) {
            return r;
        } else if (i == n) {
            struct kstat st;
            if (stat_(p, &st) == 0 && (st.mode & S_IFMT) != S_IFDIR)
                return -ENOTDIR;
        }
        if (i < n)
            p[i] = '/';
    }
    return 0;
}

static void parent_of(const char *path, char *out)
{
    copy_str(out, PATHMAX, path);
    u64 n = slen(out);
    while (n > 1 && out[n - 1] != '/')
        n--;
    out[n > 1 ? n - 1 : 1] = 0;
}

// --- connections and processes --------------------------------------------------

enum {
    MAX_CONNS = 512,
    NPROCS = (int)MVS_MAX_PROCS,
    MAX_SUBS = 8,
    IN_CAP = MVS_HDR + MVS_MAX_BODY,
    OUT_CAP = 2 * MVS_MAX_BUFFER + 4 * (MVS_HDR + MVS_MAX_CHUNK),
    HOLD = MVS_MAX_BUFFER - (MVS_HDR + MVS_MAX_CHUNK), // pending output past which producers wait
    MAX_WATCHES = 8192,
    WNAMES = 4u << 20,
    INQ_CAP = 1u << 20,
};

enum cstate : u8 {
    C_FREE, C_REQ, C_STREAM, C_WATCH, C_READ, C_WRITE, C_PORT_WAIT, C_PORT, C_CLOSING, C_LINGER,
};

struct wd {
    int wd;
    u32 name; // offset in names: the directory relative to the root ("" for the root)
};

struct conn {
    int fd, peer, file, ino;
    enum cstate state;
    bool in_eof, peer_eof, peer_shut, fd_shut, dead;
    u16 gen;
    int proc; // the process this streams, or -1
    u32 ev, peer_ev, ino_ev;
    u8 *in;
    u32 ilen;
    u8 *out;
    u32 olen, ooff;
    struct wd *wds;
    u32 nwd;
    char *wnames;
    u32 wnlen;
    bool recursive;
    char *root; // WATCH: the watched directory; WRITE: the file
};

struct proc {
    int pid; // 0: a free slot
    int out, err, in; // a terminal: out == in == its master, err == -1
    u32 flags;
    bool out_eof, err_eof, close_in;
    u16 gen;
    u32 ev_out, ev_err, ev_in;
    int subs[MAX_SUBS];
    int nsubs;
    u8 *rec; // its PROC frame body, for PS
    u32 rec_len;
    char *tag; // in rec's copy, NUL-terminated separately
    u8 *inq;
    u32 inq_len;
};

static struct {
    int ep, ls, sigfd;
    struct conn *c;
    struct proc *p;
    u32 resumes;
    char **base_env;
    char *def_env; // SET_ENV: NUL-separated NAME=VALUE strings
    u32 def_env_len, def_env_n;
} s;

enum { K_LISTEN = 1, K_SIG, K_CONN, K_PEER, K_FILE, K_WATCH, K_POUT, K_PERR, K_PIN };

static u64 tag_of(int kind, u16 gen, int idx) { return (u64)kind << 48 | (u64)gen << 32 | (u32)idx; }

static void ep_set(int fd, u32 want, u32 *cur, u64 data)
{
    if (fd < 0 || want == *cur)
        return;
    struct epev e = {want, data};
    sys4(SYS_epoll_ctl, s.ep, EPOLL_CTL_MOD, fd, (long)&e);
    *cur = want;
}
static void ep_add(int fd, u32 want, u32 *cur, u64 data)
{
    struct epev e = {want, data};
    sys4(SYS_epoll_ctl, s.ep, EPOLL_CTL_ADD, fd, (long)&e);
    if (cur)
        *cur = want;
}
static void ep_del(int fd)
{
    if (fd >= 0)
        sys4(SYS_epoll_ctl, s.ep, EPOLL_CTL_DEL, fd, 0);
}

static u32 pending(const struct conn *c) { return c->olen - c->ooff; }

// Room for a frame of up to `max` body bytes: a pointer to its body, or
// nullptr (the connection is then dead: it can't happen within the caps).
static u8 *frame_begin(struct conn *c, u32 max)
{
    if (c->olen + MVS_HDR + max > OUT_CAP && c->ooff) {
        memmove(c->out, c->out + c->ooff, pending(c));
        c->olen -= c->ooff;
        c->ooff = 0;
    }
    if (c->olen + MVS_HDR + max > OUT_CAP) {
        c->dead = true;
        return nullptr;
    }
    return c->out + c->olen + MVS_HDR;
}

static void frame_end(struct conn *c, u8 type, u32 len)
{
    u8 *h = c->out + c->olen;
    put32(h, MVS_MAGIC);
    h[4] = MVS_VERSION;
    h[5] = type;
    h[6] = h[7] = 0;
    put32(h + 8, len);
    c->olen += MVS_HDR + len;
}

static void emit(struct conn *c, u8 type, const void *body, u32 len)
{
    u8 *b = frame_begin(c, len);
    if (!b)
        return;
    if (len)
        memcpy(b, body, len);
    frame_end(c, type, len);
}

static u8 *put_str(u8 *p, const char *str, u64 n)
{
    put32(p, (u32)n);
    memcpy(p + 4, str, n);
    return p + 4 + n;
}

static void conn_events(struct conn *c);
static void proc_events(struct proc *p);
static void conn_close(struct conn *c);
static void read_pump(struct conn *c);

// Write what is pending; then let whatever feeds this connection go on.
static void flush(struct conn *c)
{
    while (pending(c) && !c->dead) {
        long n = sys3(SYS_write, c->fd, (long)(c->out + c->ooff), pending(c));
        if (n > 0)
            c->ooff += (u32)n;
        else if (n == -EINTR)
            continue;
        else {
            if (n != -EAGAIN)
                c->dead = true;
            break;
        }
    }
    if (!pending(c))
        c->olen = c->ooff = 0;
    if (c->dead) {
        conn_close(c);
        return;
    }
    if (c->state == C_CLOSING && !pending(c)) {
        sys3(SYS_shutdown, c->fd, SHUT_WR, 0);
        c->state = C_LINGER; // until the host closes its side
    }
    if (c->proc >= 0)
        proc_events(&s.p[c->proc]);
    if (c->state == C_READ)
        read_pump(c);
    if (c->dead) {
        conn_close(c);
        return;
    }
    conn_events(c);
}

// Waits (up to 30 s) until the host has taken most of what is pending:
// for answers written as they are made (LIST, PS). false: give up.
static bool flush_wait(struct conn *c)
{
    for (int tries = 0; pending(c) > HOLD / 2; tries++) {
        long n = sys3(SYS_write, c->fd, (long)(c->out + c->ooff), pending(c));
        if (n > 0) {
            c->ooff += (u32)n;
            continue;
        }
        if (n != -EAGAIN && n != -EINTR) {
            c->dead = true;
            return false;
        }
        struct {
            int fd;
            short events, revents;
        } p = {c->fd, POLLOUT, 0};
        if (tries > 30 || sys3(SYS_poll, (long)&p, 1, 1000) < 0) {
            c->dead = true;
            return false;
        }
    }
    return true;
}

static void finish(struct conn *c)
{
    c->state = C_CLOSING;
    flush(c);
}

static void reply_ok(struct conn *c, const void *body, u32 len)
{
    emit(c, MVS_OK, body, len);
    finish(c);
}

static u32 err_kind(long e)
{
    switch (-e) {
    case ENOENT: case ENOTDIR: return MVS_E_NOTFOUND;
    case EEXIST: return MVS_E_EXIST;
    case EACCES: case EPERM: return MVS_E_DENIED;
    case EINVAL: case EISDIR: case ENAMETOOLONG: case ELOOP: return MVS_E_INVALID;
    default: return MVS_E_FAILED;
    }
}

static void reply_err(struct conn *c, u32 kind, long err, const char *msg)
{
    u8 *b = frame_begin(c, 12 + 512);
    if (b) {
        u64 n = slen(msg);
        if (n > 512)
            n = 512;
        put32(b, kind);
        put32(b + 4, (u32)(err < 0 ? -err : err));
        put_str(b + 8, msg, n);
        frame_end(c, MVS_ERROR, (u32)(12 + n));
    }
    finish(c);
}

static void reply_errno(struct conn *c, long err, const char *msg) { reply_err(c, err_kind(err), err, msg); }

// --- entries ----------------------------------------------------------------------

// An ENTRY body for path into b (room for MVS_ENTRY_FIXED + 16 + 3 *
// PATHMAX + 512); its length, or -errno.
static long entry_body(const char *path, u8 *b)
{
    struct kstat st, t;
    long r = lstat_(path, &st);
    if (r < 0)
        return r;
    u32 mode = st.mode, flags = 0;
    char target[PATHMAX];
    long tl = 0;
    if ((st.mode & S_IFMT) == S_IFLNK) {
        flags |= MVS_E_SYMLINK;
        tl = sys3(SYS_readlink, (long)path, (long)target, sizeof target - 1);
        if (tl < 0)
            tl = 0;
        mode = stat_(path, &t) == 0 ? t.mode : 0;
    }
    put32(b, mode);
    put32(b + 4, st.uid);
    put32(b + 8, st.gid);
    put32(b + 12, flags);
    put64(b + 16, (u64)st.size);
    put64(b + 24, (u64)st.mtime);
    put32(b + 32, (u32)st.mtime_ns);
    u8 *p = b + MVS_ENTRY_FIXED;
    p = put_str(p, path, slen(path));
    char nm[256];
    u64 n = name_of(names.pw, st.uid, nm, sizeof nm);
    p = put_str(p, nm, n);
    n = name_of(names.gr, st.gid, nm, sizeof nm);
    p = put_str(p, nm, n);
    p = put_str(p, target, (u64)tl);
    return p - b;
}

enum { ENTRY_MAX = MVS_ENTRY_FIXED + 16 + 3 * PATHMAX + 512 };

static long emit_entry(struct conn *c, u8 type, const char *path)
{
    u8 *b = frame_begin(c, ENTRY_MAX);
    if (!b)
        return -ENOMEM;
    long n = entry_body(path, b);
    if (n >= 0)
        frame_end(c, type, (u32)n);
    return n;
}

// --- request parsing -----------------------------------------------------------

struct rd {
    const u8 *p;
    u32 n;
    bool bad;
    char *arena; // NUL-terminated copies of strings
    u64 used, cap;
};

static u32 rd32(struct rd *r)
{
    if (r->n < 4) {
        r->bad = true;
        return 0;
    }
    u32 v = le32(r->p);
    r->p += 4, r->n -= 4;
    return v;
}
static u16 rd16(struct rd *r)
{
    if (r->n < 2) {
        r->bad = true;
        return 0;
    }
    u16 v = le16(r->p);
    r->p += 2, r->n -= 2;
    return v;
}
static char *rdstr(struct rd *r, u32 max)
{
    u32 n = rd32(r);
    if (r->bad || n > r->n || n > max || r->used + n + 1 > r->cap) {
        r->bad = true;
        return (char *)"";
    }
    char *d = r->arena + r->used;
    for (u32 i = 0; i < n; i++)
        if (!(d[i] = (char)r->p[i])) {
            r->bad = true;
            return (char *)"";
        }
    d[n] = 0;
    r->used += n + 1;
    r->p += n, r->n -= n;
    return d;
}
// The raw bytes of a string (data may hold NULs).
static const u8 *rdbytes(struct rd *r, u32 *len)
{
    u32 n = rd32(r);
    if (r->bad || n > r->n) {
        r->bad = true;
        return nullptr;
    }
    const u8 *d = r->p;
    r->p += n, r->n -= n;
    *len = n;
    return d;
}

static struct proc *select_proc(struct rd *r)
{
    const u32 kind = rd32(r), pid = rd32(r);
    const char *tag = rdstr(r, 4096);
    if (r->bad)
        return nullptr;
    for (int i = 0; i < NPROCS; i++) {
        struct proc *p = &s.p[i];
        if (!p->pid)
            continue;
        if (kind == MVS_SEL_PID && (u32)p->pid == pid)
            return p;
        if (kind == MVS_SEL_TAG && p->tag && *tag && seq(p->tag, tag))
            return p;
    }
    return nullptr;
}

// --- processes ----------------------------------------------------------------------

static bool proc_room(const struct proc *p)
{
    for (int i = 0; i < p->nsubs; i++)
        if (pending(&s.c[p->subs[i]]) > HOLD)
            return false;
    return true;
}

static void proc_events(struct proc *p)
{
    if (!p->pid)
        return;
    const int idx = (int)(p - s.p);
    const u32 rd = proc_room(p) ? EPOLLIN : 0;
    if (!p->out_eof)
        ep_set(p->out, rd, &p->ev_out, tag_of(K_POUT, p->gen, idx));
    if (!p->err_eof && p->err >= 0)
        ep_set(p->err, rd, &p->ev_err, tag_of(K_PERR, p->gen, idx));
    if (p->in >= 0 && p->in != p->out)
        ep_set(p->in, p->inq_len ? EPOLLOUT : 0, &p->ev_in, tag_of(K_PIN, p->gen, idx));
    else if (p->in >= 0 && p->in == p->out && !p->out_eof)
        ep_set(p->out, rd | (p->inq_len ? EPOLLOUT : 0), &p->ev_out, tag_of(K_POUT, p->gen, idx));
}

static void broadcast(struct proc *p, u8 type, const void *b, u32 n)
{
    for (int i = 0; i < p->nsubs; i++)
        emit(&s.c[p->subs[i]], type, b, n);
    for (int i = p->nsubs - 1; i >= 0; i--) // a flush may close one: it leaves the list
        flush(&s.c[p->subs[i]]);
}

static u8 iobuf[MVS_MAX_CHUNK];

// One read of an output fd; false at its end.
static bool proc_read(struct proc *p, int fd, u8 type)
{
    long n = sys3(SYS_read, fd, (long)iobuf, sizeof iobuf);
    if (n > 0) {
        broadcast(p, type, iobuf, (u32)n);
        return true;
    }
    return n == -EAGAIN || n == -EINTR;
}

static void unsubscribe(struct conn *c)
{
    if (c->proc < 0)
        return;
    struct proc *p = &s.p[c->proc];
    const int me = (int)(c - s.c);
    for (int i = 0; i < p->nsubs; i++)
        if (p->subs[i] == me) {
            p->subs[i] = p->subs[--p->nsubs];
            break;
        }
    c->proc = -1;
    proc_events(p);
}

static void stdin_pump(struct proc *p)
{
    while (p->inq_len) {
        long n = sys3(SYS_write, p->in, (long)p->inq, p->inq_len);
        if (n > 0) {
            memmove(p->inq, p->inq + n, p->inq_len - (u32)n);
            p->inq_len -= (u32)n;
        } else if (n == -EINTR) {
            continue;
        } else {
            if (n != -EAGAIN)
                p->inq_len = 0; // the reader is gone: drop it
            break;
        }
    }
    if (!p->inq_len && p->close_in && p->in >= 0 && p->in != p->out) {
        ep_del(p->in);
        xclose(&p->in);
        p->ev_in = 0;
    }
    proc_events(p);
}

// The process has exited (wait status st): pass on what it left in its
// pipes, then P_END, and forget it.
static void proc_end(struct proc *p, int st)
{
    u32 budget = MVS_MAX_BUFFER;
    if (!p->out_eof)
        for (bool more = true; more && budget >= MVS_MAX_CHUNK;) {
            long n = sys3(SYS_read, p->out, (long)iobuf, sizeof iobuf);
            if ((more = n > 0)) {
                budget -= (u32)n;
                broadcast(p, p->flags & MVS_S_PTY ? MVS_P_PTY : MVS_P_STDOUT, iobuf, (u32)n);
            }
        }
    if (!p->err_eof && p->err >= 0)
        for (bool more = true; more && budget >= MVS_MAX_CHUNK;) {
            long n = sys3(SYS_read, p->err, (long)iobuf, sizeof iobuf);
            if ((more = n > 0)) {
                budget -= (u32)n;
                broadcast(p, MVS_P_STDERR, iobuf, (u32)n);
            }
        }
    u8 b[8];
    put32(b, (u32)st);
    put32(b + 4, 0);
    while (p->nsubs) {
        struct conn *c = &s.c[p->subs[--p->nsubs]];
        c->proc = -1;
        emit(c, MVS_P_END, b, 8);
        finish(c);
    }
    ep_del(p->out);
    ep_del(p->err);
    if (p->in != p->out)
        ep_del(p->in);
    if (p->in == p->out)
        p->in = -1;
    xclose(&p->out);
    xclose(&p->err);
    xclose(&p->in);
    unmap(p->rec, p->rec_len + 4096);
    unmap(p->inq, INQ_CAP);
    const u16 gen = (u16)(p->gen + 1);
    memset(p, 0, sizeof *p);
    p->gen = gen;
    p->out = p->err = p->in = -1;
}

static void reap(void)
{
    u8 junk[128 * 4];
    while (sys3(SYS_read, s.sigfd, (long)junk, sizeof junk) > 0)
        ;
    for (;;) {
        int st = 0;
        const long pid = sys4(SYS_wait4, -1, (long)&st, WNOHANG, 0);
        if (pid <= 0)
            break;
        for (int i = 0; i < NPROCS; i++)
            if (s.p[i].pid == pid) {
                proc_end(&s.p[i], st);
                break;
            }
    }
}

static long find_exec(char **argv, char **envp)
{
    const char *f = argv[0];
    for (const char *c = f; *c; c++)
        if (*c == '/') {
            long r = sys3(SYS_execve, (long)f, (long)argv, (long)envp);
            // E2B's SDKs run every command as /bin/bash -l -c CMD (and a
            // terminal as /bin/bash -i -l). Images without bash (Alpine,
            // distroless with busybox) get /bin/sh, as argv[0] too: busybox
            // picks its applet by that name.
            if (r == -ENOENT && seq(f, "/bin/bash")) {
                argv[0] = (char *)"/bin/sh";
                r = sys3(SYS_execve, (long)argv[0], (long)argv, (long)envp);
            }
            return r;
        }
    const char *path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    for (char **e = envp; *e; e++)
        if (seqn(*e, "PATH=", 5))
            path = *e + 5;
    const u64 fl = slen(f);
    long err = -ENOENT;
    char buf[PATHMAX];
    for (const char *d = path;;) {
        const char *e = d;
        while (*e && *e != ':')
            e++;
        u64 dl = (u64)(e - d);
        if (dl + fl + 2 <= sizeof buf) {
            if (dl == 0)
                buf[0] = '.', dl = 1;
            else
                memcpy(buf, d, dl);
            buf[dl] = '/';
            memcpy(buf + dl + 1, f, fl + 1);
            long r = sys3(SYS_execve, (long)buf, (long)argv, (long)envp);
            if (r == -EACCES)
                err = r;
            else if (r != -ENOENT && r != -ENOTDIR)
                return r;
        }
        if (!*e)
            break;
        d = e + 1;
    }
    return err;
}

// envp: base, then add (NAME=VALUE each) over it. Writes into v (cap
// entries, the last for nullptr); returns the count.
static int env_put(char **v, int k, int cap, char *e)
{
    u64 nl = 0;
    while (e[nl] && e[nl] != '=')
        nl++;
    for (int i = 0; i < k; i++)
        if (seqn(v[i], e, nl) && (v[i][nl] == '=' || !v[i][nl])) {
            v[i] = e;
            return k;
        }
    if (k < cap - 1)
        v[k++] = e;
    return k;
}

static void op_start(struct conn *c, struct rd *r)
{
    const u32 flags = rd32(r);
    const u16 cols = rd16(r), rows = rd16(r), nargs = rd16(r), nenv = rd16(r);
    const char *uname = rdstr(r, 255);
    const char *cwd = rdstr(r, PATHMAX - 1);
    const char *tag = flags & MVS_S_TAG ? rdstr(r, 4096) : nullptr;
    if (r->bad || flags & ~MVS_S_FLAGS || !nargs || nargs + nenv > MVS_MAX_STRINGS)
        return reply_err(c, MVS_E_INVALID, 0, "bad START");
    char **argv = (char **)(r->arena + ((r->used + 7) & ~7ul));
    r->used = ((r->used + 7) & ~7ul) + (u64)(nargs + 1) * sizeof(char *);
    char **envs = (char **)(r->arena + r->used);
    r->used += (u64)(nenv + 1) * sizeof(char *);
    if (r->used > r->cap)
        return reply_err(c, MVS_E_INVALID, 0, "bad START");
    for (int i = 0; i < nargs; i++)
        argv[i] = rdstr(r, MVS_MAX_STRING);
    argv[nargs] = nullptr;
    for (int i = 0; i < nenv; i++)
        envs[i] = rdstr(r, MVS_MAX_STRING);
    if (r->bad || r->n || !argv[0][0])
        return reply_err(c, MVS_E_INVALID, 0, "bad START");
    if (tag)
        for (int i = 0; i < NPROCS; i++)
            if (s.p[i].pid && s.p[i].tag && seq(s.p[i].tag, tag))
                return reply_err(c, MVS_E_EXIST, 0, "a process with this tag is running");
    struct proc *p = nullptr;
    for (int i = 0; i < NPROCS && !p; i++)
        if (!s.p[i].pid)
            p = &s.p[i];
    if (!p)
        return reply_err(c, MVS_E_LIMIT, 0, "too many processes");
    static struct user u;
    if (!user_find(uname, &u))
        return reply_err(c, MVS_E_NOTFOUND, 0, "no such user");
    static char dir[PATHMAX];
    if (!resolve(&u, *cwd ? cwd : u.home, dir))
        return reply_err(c, MVS_E_INVALID, -ENAMETOOLONG, "cwd too long");
    struct kstat hs;
    if (!*cwd && stat_(dir, &hs) < 0)
        copy_str(dir, sizeof dir, "/"); // a home the image doesn't have

    // The environment: the image's, the defaults (SET_ENV), the user's,
    // then the request's.
    int nbase = 0;
    for (char **e = s.base_env; e && *e; e++)
        nbase++;
    const int cap = nbase + (int)s.def_env_n + nenv + 8;
    char **envp = map((u64)cap * sizeof(char *));
    if (!envp)
        return reply_err(c, MVS_E_FAILED, -ENOMEM, "out of memory");
    int k = 0;
    for (int i = 0; i < nbase; i++)
        k = env_put(envp, k, cap, s.base_env[i]);
    char *d = s.def_env;
    for (u32 i = 0; i < s.def_env_n; i++, d += slen(d) + 1)
        k = env_put(envp, k, cap, d);
    static char home_e[PATHMAX + 8], user_e[300], logname_e[300];
    copy_str(home_e, sizeof home_e, "HOME=");
    copy_str(home_e + 5, sizeof home_e - 5, u.home);
    copy_str(user_e, sizeof user_e, "USER=");
    copy_str(user_e + 5, sizeof user_e - 5, u.name);
    copy_str(logname_e, sizeof logname_e, "LOGNAME=");
    copy_str(logname_e + 8, sizeof logname_e - 8, u.name);
    k = env_put(envp, k, cap, home_e);
    k = env_put(envp, k, cap, user_e);
    k = env_put(envp, k, cap, logname_e);
    if (flags & MVS_S_PTY)
        k = env_put(envp, k, cap, (char *)"TERM=xterm-256color");
    for (int i = 0; i < nenv; i++)
        k = env_put(envp, k, cap, envs[i]);
    envp[k] = nullptr;

    // The fds: a terminal, or pipes.
    int outp[2] = {-1, -1}, errp[2] = {-1, -1}, inp[2] = {-1, -1}, ep2[2] = {-1, -1}, master = -1;
    char slave[32];
    long rr = 0;
    if (flags & MVS_S_PTY) {
        master = (int)sys3(SYS_open, (long)"/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK, 0);
        int unlock = 0;
        u32 ptn = 0;
        if (master < 0 || (rr = sys3(SYS_ioctl, master, TIOCSPTLCK, (long)&unlock)) < 0 ||
            (rr = sys3(SYS_ioctl, master, TIOCGPTN, (long)&ptn)) < 0) {
            rr = master < 0 ? master : rr;
            xclose(&master);
            unmap(envp, (u64)cap * sizeof(char *));
            return reply_errno(c, rr, "cannot make a terminal");
        }
        const u16 ws[4] = {rows ? rows : 24, cols ? cols : 80, 0, 0};
        sys3(SYS_ioctl, master, TIOCSWINSZ, (long)ws);
        copy_str(slave, sizeof slave, "/dev/pts/");
        char num[12];
        int nd = 0;
        do
            num[nd++] = (char)('0' + ptn % 10);
        while (ptn /= 10);
        for (int i = 0; i < nd; i++)
            slave[9 + i] = num[nd - 1 - i];
        slave[9 + nd] = 0;
    } else {
        long ok = sys3(SYS_pipe2, (long)outp, O_CLOEXEC, 0);
        if (ok == 0)
            ok = sys3(SYS_pipe2, (long)errp, O_CLOEXEC, 0);
        if (ok == 0 && flags & MVS_S_STDIN)
            ok = sys3(SYS_pipe2, (long)inp, O_CLOEXEC, 0);
        if (ok < 0) {
            int *all[] = {outp, errp, inp};
            for (int i = 0; i < 3; i++)
                xclose(&all[i][0]), xclose(&all[i][1]);
            unmap(envp, (u64)cap * sizeof(char *));
            return reply_errno(c, ok, "pipe");
        }
    }
    sys3(SYS_pipe2, (long)ep2, O_CLOEXEC, 0);

    const long pid = sys3(SYS_fork, 0, 0, 0);
    if (pid == 0) {
        // The child: its own session, the fds, the user, the directory.
        const u64 none = 0;
        sys4(SYS_rt_sigprocmask, 2 /* SIG_SETMASK */, (long)&none, 0, 8);
        sys3(SYS_ioperm, PORT_MARK, NPORTS, 0);
        sys3(SYS_setsid, 0, 0, 0);
        u32 stage = 1;
        long e = 0;
        if (master >= 0) {
            const int t = (int)sys3(SYS_open, (long)slave, O_RDWR, 0);
            if (t < 0)
                e = t;
            else {
                sys3(SYS_ioctl, t, TIOCSCTTY, 0);
                sys3(SYS_dup2, t, 0, 0);
                sys3(SYS_dup2, t, 1, 0);
                sys3(SYS_dup2, t, 2, 0);
            }
        } else {
            int in = inp[0] >= 0 ? inp[0] : (int)sys3(SYS_open, (long)"/dev/null", O_RDONLY, 0);
            sys3(SYS_dup2, in, 0, 0);
            sys3(SYS_dup2, outp[1], 1, 0);
            sys3(SYS_dup2, errp[1], 2, 0);
        }
        sys3(SYS_dup2, ep2[1], 3, 0);
        sys3(SYS_fcntl, 3, F_SETFD, FD_CLOEXEC);
        sys3(SYS_close_range, 4, ~0u, 0);
        if (!e) {
            stage = 2;
            if ((e = sys3(SYS_setgroups, u.ngroups, (long)u.groups, 0)) == 0 &&
                (e = sys3(SYS_setresgid, u.gid, u.gid, u.gid)) == 0)
                e = sys3(SYS_setresuid, u.uid, u.uid, u.uid);
        }
        if (!e) {
            stage = 3;
            e = sys3(SYS_chdir, (long)dir, 0, 0);
        }
        if (!e) {
            stage = 4;
            e = find_exec(argv, envp);
        }
        u8 rep[8];
        put32(rep, stage);
        put32(rep + 4, (u32)-e);
        sys3(SYS_write, 3, (long)rep, 8);
        for (;;)
            sys3(SYS_exit, 127, 0, 0);
    }
    unmap(envp, (u64)cap * sizeof(char *));
    xclose(&outp[1]);
    xclose(&errp[1]);
    xclose(&inp[0]);
    xclose(&ep2[1]);
    u8 rep[8];
    long got = 0;
    while (pid > 0 && ep2[0] >= 0) {
        long n = sys3(SYS_read, ep2[0], (long)(rep + got), 8 - got);
        if (n == -EINTR)
            continue;
        if (n <= 0)
            break;
        if ((got += n) == 8)
            break;
    }
    xclose(&ep2[0]);
    if (pid < 0 || got == 8) {
        if (pid > 0) {
            int st;
            sys4(SYS_wait4, pid, (long)&st, 0, 0);
        }
        xclose(&master), xclose(&outp[0]), xclose(&errp[0]), xclose(&inp[1]);
        if (pid < 0)
            return reply_errno(c, pid, "fork");
        const u32 stage = le32(rep);
        const long e = -(long)le32(rep + 4);
        return reply_errno(c, e,
                           stage == 1   ? "cannot open the terminal"
                           : stage == 2 ? "cannot switch to the user"
                           : stage == 3 ? "cannot enter the working directory"
                                        : "cannot run the command");
    }

    // The parent: track it, stream it to this connection.
    const u16 gen = p->gen;
    memset(p, 0, sizeof *p);
    p->gen = gen;
    p->pid = (int)pid;
    p->flags = flags;
    p->in = p->err = -1;
    if (master >= 0) {
        p->out = p->in = master;
    } else {
        p->out = outp[0];
        p->err = errp[0];
        p->in = inp[1];
        sys3(SYS_fcntl, p->out, F_SETFL, O_NONBLOCK);
        sys3(SYS_fcntl, p->err, F_SETFL, O_NONBLOCK);
        if (p->in >= 0)
            sys3(SYS_fcntl, p->in, F_SETFL, O_NONBLOCK);
    }
    // PROC record: pid, flags, nargs, nenv, then tag, cwd, args, envs.
    u64 rl = 12 + 4 + (tag ? slen(tag) : 0) + 4 + slen(dir);
    for (int i = 0; i < nargs; i++)
        rl += 4 + slen(argv[i]);
    for (int i = 0; i < nenv; i++)
        rl += 4 + slen(envs[i]);
    if (rl <= MVS_MAX_BODY && (p->rec = map(rl + 4096))) {
        u8 *q = p->rec;
        put32(q, (u32)pid);
        put32(q + 4, flags);
        q[8] = (u8)nargs, q[9] = (u8)(nargs >> 8), q[10] = (u8)nenv, q[11] = (u8)(nenv >> 8);
        q = put_str(q + 12, tag ? tag : "", tag ? slen(tag) : 0);
        q = put_str(q, dir, slen(dir));
        for (int i = 0; i < nargs; i++)
            q = put_str(q, argv[i], slen(argv[i]));
        for (int i = 0; i < nenv; i++)
            q = put_str(q, envs[i], slen(envs[i]));
        p->rec_len = (u32)rl;
        if (tag) {
            p->tag = (char *)p->rec + rl;
            copy_str(p->tag, 4096, tag);
        }
    }
    const int idx = (int)(p - s.p);
    ep_add(p->out, EPOLLIN, &p->ev_out, tag_of(K_POUT, p->gen, idx));
    if (p->err >= 0)
        ep_add(p->err, EPOLLIN, &p->ev_err, tag_of(K_PERR, p->gen, idx));
    if (p->in >= 0 && p->in != p->out)
        ep_add(p->in, 0, &p->ev_in, tag_of(K_PIN, p->gen, idx));
    p->subs[p->nsubs++] = (int)(c - s.c);
    c->proc = idx;
    c->state = C_STREAM;
    u8 b[4];
    put32(b, (u32)pid);
    emit(c, MVS_P_START, b, 4);
    flush(c);
}

static void op_connect(struct conn *c, struct rd *r)
{
    struct proc *p = select_proc(r);
    if (r->bad || r->n)
        return reply_err(c, MVS_E_INVALID, 0, "bad CONNECT");
    if (!p)
        return reply_err(c, MVS_E_NOTFOUND, 0, "no such process");
    if (p->nsubs == MAX_SUBS)
        return reply_err(c, MVS_E_LIMIT, 0, "too many connections to this process");
    p->subs[p->nsubs++] = (int)(c - s.c);
    c->proc = (int)(p - s.p);
    c->state = C_STREAM;
    u8 b[4];
    put32(b, (u32)p->pid);
    emit(c, MVS_P_START, b, 4);
    flush(c);
}

static void op_ps(struct conn *c, struct rd *r)
{
    if (r->n)
        return reply_err(c, MVS_E_INVALID, 0, "bad PS");
    for (int i = 0; i < NPROCS && !c->dead; i++)
        if (s.p[i].pid && s.p[i].rec) {
            emit(c, MVS_PROC, s.p[i].rec, s.p[i].rec_len);
            flush_wait(c);
        }
    if (c->dead)
        return conn_close(c);
    reply_ok(c, nullptr, 0);
}

static void op_input(struct conn *c, struct rd *r)
{
    struct proc *p = select_proc(r);
    const u32 flags = rd32(r);
    u32 n = 0;
    const u8 *data = rdbytes(r, &n);
    if (r->bad || r->n || flags & ~MVS_IN_PTY)
        return reply_err(c, MVS_E_INVALID, 0, "bad INPUT");
    if (!p)
        return reply_err(c, MVS_E_NOTFOUND, 0, "no such process");
    if (!!(flags & MVS_IN_PTY) != !!(p->flags & MVS_S_PTY))
        return reply_err(c, MVS_E_INVALID, 0, flags & MVS_IN_PTY ? "the process has no terminal" : "the process has a terminal: send to it");
    if (p->in < 0 || p->close_in)
        return reply_err(c, MVS_E_INVALID, 0, "the process's stdin is closed");
    if (!p->inq && !(p->inq = map(INQ_CAP)))
        return reply_err(c, MVS_E_FAILED, -ENOMEM, "out of memory");
    if (n > INQ_CAP - p->inq_len)
        return reply_err(c, MVS_E_LIMIT, 0, "the process isn't reading its input");
    memcpy(p->inq + p->inq_len, data, n);
    p->inq_len += n;
    stdin_pump(p);
    reply_ok(c, nullptr, 0);
}

static void op_close_stdin(struct conn *c, struct rd *r)
{
    struct proc *p = select_proc(r);
    if (r->bad || r->n)
        return reply_err(c, MVS_E_INVALID, 0, "bad CLOSE_STDIN");
    if (!p)
        return reply_err(c, MVS_E_NOTFOUND, 0, "no such process");
    if (p->flags & MVS_S_PTY)
        return reply_err(c, MVS_E_INVALID, 0, "the process has a terminal: send it ^D");
    p->close_in = true;
    if (p->in >= 0)
        stdin_pump(p);
    reply_ok(c, nullptr, 0);
}

static void op_signal(struct conn *c, struct rd *r)
{
    struct proc *p = select_proc(r);
    const u32 sig = rd32(r);
    if (r->bad || r->n || (sig != SIGKILL && sig != SIGTERM))
        return reply_err(c, MVS_E_INVALID, 0, "bad SIGNAL");
    if (!p)
        return reply_err(c, MVS_E_NOTFOUND, 0, "no such process");
    // The whole session's process group: what the command started, too.
    if (sys3(SYS_kill, -p->pid, sig, 0) < 0)
        sys3(SYS_kill, p->pid, sig, 0);
    reply_ok(c, nullptr, 0);
}

static void op_resize(struct conn *c, struct rd *r)
{
    struct proc *p = select_proc(r);
    const u16 cols = rd16(r), rows = rd16(r);
    if (r->bad || r->n || !cols || !rows)
        return reply_err(c, MVS_E_INVALID, 0, "bad RESIZE");
    if (!p)
        return reply_err(c, MVS_E_NOTFOUND, 0, "no such process");
    if (!(p->flags & MVS_S_PTY))
        return reply_err(c, MVS_E_INVALID, 0, "the process has no terminal");
    const u16 ws[4] = {rows, cols, 0, 0};
    long e = sys3(SYS_ioctl, p->out, TIOCSWINSZ, (long)ws);
    if (e < 0)
        return reply_errno(c, e, "resize");
    reply_ok(c, nullptr, 0);
}

// --- files ----------------------------------------------------------------------------

static bool path_arg(struct conn *c, struct rd *r, struct user *u, char *path)
{
    const char *uname = rdstr(r, 255);
    const char *p = rdstr(r, PATHMAX - 1);
    if (r->bad || !*p) {
        reply_err(c, MVS_E_INVALID, 0, "bad request");
        return false;
    }
    if (!user_find(uname, u)) {
        reply_err(c, MVS_E_NOTFOUND, 0, "no such user");
        return false;
    }
    if (!resolve(u, p, path)) {
        reply_err(c, MVS_E_INVALID, -ENAMETOOLONG, "path too long");
        return false;
    }
    return true;
}

static void op_stat(struct conn *c, struct rd *r)
{
    static struct user u;
    static char path[PATHMAX];
    if (!path_arg(c, r, &u, path))
        return;
    if (r->n)
        return reply_err(c, MVS_E_INVALID, 0, "bad STAT");
    names_load();
    u8 *b = frame_begin(c, ENTRY_MAX);
    long n = b ? entry_body(path, b) : -ENOMEM;
    if (n < 0)
        return reply_errno(c, n, n == -ENOENT ? "no such file or directory" : "stat");
    frame_end(c, MVS_OK, (u32)n);
    finish(c);
}

static void op_mkdir(struct conn *c, struct rd *r)
{
    static struct user u;
    static char path[PATHMAX];
    if (!path_arg(c, r, &u, path))
        return;
    if (r->n)
        return reply_err(c, MVS_E_INVALID, 0, "bad MKDIR");
    struct kstat st;
    if (lstat_(path, &st) == 0)
        return reply_err(c, MVS_E_EXIST, -EEXIST, (st.mode & S_IFMT) == S_IFDIR ? "the directory exists" : "a file is in the way");
    bool made;
    long e = mkdir_p(path, u.uid, u.gid, &made);
    if (e < 0)
        return reply_errno(c, e, "mkdir");
    names_load();
    u8 *b = frame_begin(c, ENTRY_MAX);
    long n = b ? entry_body(path, b) : -ENOMEM;
    if (n < 0)
        return reply_errno(c, n, "stat");
    frame_end(c, MVS_OK, (u32)n);
    finish(c);
}

static void op_move(struct conn *c, struct rd *r)
{
    static struct user u;
    static char from[PATHMAX], to[PATHMAX], dir[PATHMAX];
    const char *uname = rdstr(r, 255);
    const char *f = rdstr(r, PATHMAX - 1), *t = rdstr(r, PATHMAX - 1);
    if (r->bad || r->n || !*f || !*t)
        return reply_err(c, MVS_E_INVALID, 0, "bad MOVE");
    if (!user_find(uname, &u))
        return reply_err(c, MVS_E_NOTFOUND, 0, "no such user");
    if (!resolve(&u, f, from) || !resolve(&u, t, to))
        return reply_err(c, MVS_E_INVALID, -ENAMETOOLONG, "path too long");
    struct kstat st;
    if (lstat_(from, &st) < 0)
        return reply_err(c, MVS_E_NOTFOUND, -ENOENT, "no such file or directory");
    parent_of(to, dir);
    bool made;
    long e = mkdir_p(dir, u.uid, u.gid, &made);
    if (e == 0)
        e = sys3(SYS_rename, (long)from, (long)to, 0);
    if (e < 0)
        return reply_errno(c, e, "rename");
    names_load();
    u8 *b = frame_begin(c, ENTRY_MAX);
    long n = b ? entry_body(to, b) : -ENOMEM;
    if (n < 0)
        return reply_errno(c, n, "stat");
    frame_end(c, MVS_OK, (u32)n);
    finish(c);
}

struct dirent64 {
    u64 ino;
    i64 off;
    u16 reclen;
    u8 type;
    char name[];
};

// Each entry under path (as an ENTRY frame), down to depth levels.
static void list_dir(struct conn *c, char *path, u32 depth)
{
    const int fd = (int)sys3(SYS_open, (long)path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0)
        return;
    const u64 pl = slen(path);
    u8 buf[2048];
    for (long n; !c->dead && (n = sys3(SYS_getdents64, fd, (long)buf, sizeof buf)) > 0;)
        for (long off = 0; off < n && !c->dead;) {
            struct dirent64 *d = (struct dirent64 *)(buf + off);
            off += d->reclen;
            const u64 nl = slen(d->name);
            if ((nl == 1 && d->name[0] == '.') || (nl == 2 && d->name[0] == '.' && d->name[1] == '.'))
                continue;
            if (pl + nl + 2 > PATHMAX)
                continue;
            u64 at = pl;
            if (pl > 1)
                path[at++] = '/';
            memcpy(path + at, d->name, nl + 1);
            if (emit_entry(c, MVS_ENTRY, path) >= 0)
                flush_wait(c);
            struct kstat st;
            if (depth > 1 && lstat_(path, &st) == 0 && (st.mode & S_IFMT) == S_IFDIR)
                list_dir(c, path, depth - 1);
            path[pl] = 0;
        }
    sys3(SYS_close, fd, 0, 0);
}

static void op_list(struct conn *c, struct rd *r)
{
    static struct user u;
    static char path[PATHMAX];
    const u32 depth = rd32(r);
    if (!path_arg(c, r, &u, path))
        return;
    if (r->n || !depth || depth > MVS_MAX_DEPTH)
        return reply_err(c, MVS_E_INVALID, 0, "bad LIST");
    struct kstat st;
    long e = stat_(path, &st);
    if (e < 0)
        return reply_errno(c, e, "no such directory");
    if ((st.mode & S_IFMT) != S_IFDIR)
        return reply_err(c, MVS_E_INVALID, -ENOTDIR, "not a directory");
    names_load();
    list_dir(c, path, depth);
    if (c->dead)
        return conn_close(c);
    reply_ok(c, nullptr, 0);
}

// rm -rf path (path is a buffer of PATHMAX, restored on return).
static long remove_all(char *path, int level)
{
    struct kstat st;
    long e = lstat_(path, &st);
    if (e < 0)
        return e;
    if ((st.mode & S_IFMT) != S_IFDIR)
        return sys3(SYS_unlink, (long)path, 0, 0);
    if (level > 1024)
        return -ELOOP;
    const int fd = (int)sys3(SYS_open, (long)path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (fd < 0)
        return fd;
    const u64 pl = slen(path);
    u8 buf[1024];
    long first_err = 0;
    for (long n; (n = sys3(SYS_getdents64, fd, (long)buf, sizeof buf)) > 0;)
        for (long off = 0; off < n;) {
            struct dirent64 *d = (struct dirent64 *)(buf + off);
            off += d->reclen;
            const u64 nl = slen(d->name);
            if ((nl == 1 && d->name[0] == '.') || (nl == 2 && d->name[0] == '.' && d->name[1] == '.'))
                continue;
            if (pl + nl + 2 > PATHMAX) {
                first_err = first_err ? first_err : -ENAMETOOLONG;
                continue;
            }
            path[pl] = '/';
            memcpy(path + pl + 1, d->name, nl + 1);
            e = remove_all(path, level + 1);
            if (e < 0 && e != -ENOENT && !first_err)
                first_err = e;
            path[pl] = 0;
        }
    sys3(SYS_close, fd, 0, 0);
    e = sys3(SYS_rmdir, (long)path, 0, 0);
    return first_err ? first_err : e;
}

static void op_remove(struct conn *c, struct rd *r)
{
    static struct user u;
    static char path[PATHMAX];
    if (!path_arg(c, r, &u, path))
        return;
    if (r->n)
        return reply_err(c, MVS_E_INVALID, 0, "bad REMOVE");
    if (path[0] == '/' && !path[1])
        return reply_err(c, MVS_E_INVALID, -EINVAL, "won't remove /");
    long e = remove_all(path, 0);
    if (e < 0)
        return reply_errno(c, e, e == -ENOENT ? "no such file or directory" : "remove");
    reply_ok(c, nullptr, 0);
}

static void read_pump(struct conn *c)
{
    while (c->state == C_READ && pending(c) <= HOLD) {
        u8 *b = frame_begin(c, MVS_MAX_CHUNK);
        if (!b)
            return;
        long n = sys3(SYS_read, c->file, (long)b, MVS_MAX_CHUNK);
        if (n == -EINTR)
            continue;
        if (n > 0) {
            frame_end(c, MVS_DATA, (u32)n);
            continue;
        }
        xclose(&c->file);
        if (n == 0)
            emit(c, MVS_DONE, nullptr, 0);
        else
            c->dead = true; // the host sees the stream end without DONE
        c->state = C_CLOSING;
    }
}

static void op_read(struct conn *c, struct rd *r)
{
    static struct user u;
    static char path[PATHMAX];
    if (!path_arg(c, r, &u, path))
        return;
    if (r->n)
        return reply_err(c, MVS_E_INVALID, 0, "bad READ");
    const int fd = (int)sys3(SYS_open, (long)path, O_RDONLY | O_CLOEXEC | O_NONBLOCK, 0);
    if (fd < 0)
        return reply_errno(c, fd, fd == -ENOENT ? "no such file" : "open");
    struct kstat st;
    long e = sys3(SYS_fstat, fd, (long)&st, 0);
    if (e < 0 || (st.mode & S_IFMT) != S_IFREG) {
        sys3(SYS_close, fd, 0, 0);
        return reply_err(c, MVS_E_INVALID, e < 0 ? e : -EISDIR, "not a regular file");
    }
    c->file = fd;
    u8 b[8];
    put64(b, (u64)st.size);
    emit(c, MVS_OK, b, 8);
    c->state = C_READ;
    flush(c);
}

static void op_write(struct conn *c, struct rd *r)
{
    static struct user u;
    static char path[PATHMAX], dir[PATHMAX];
    if (!path_arg(c, r, &u, path))
        return;
    if (r->n)
        return reply_err(c, MVS_E_INVALID, 0, "bad WRITE");
    parent_of(path, dir);
    bool made;
    long e = mkdir_p(dir, u.uid, u.gid, &made);
    if (e < 0)
        return reply_errno(c, e, "cannot make the directory");
    const int fd = (int)sys3(SYS_open, (long)path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NONBLOCK, 0644);
    if (fd < 0)
        return reply_errno(c, fd, "open");
    struct kstat st;
    if ((e = sys3(SYS_fstat, fd, (long)&st, 0)) < 0 || (st.mode & S_IFMT) != S_IFREG) {
        sys3(SYS_close, fd, 0, 0);
        return reply_err(c, MVS_E_INVALID, e < 0 ? e : -EISDIR, "not a regular file");
    }
    sys3(SYS_fchown, fd, u.uid, u.gid);
    sys3(SYS_fcntl, fd, F_SETFL, 0);
    if (!(c->root = map(PATHMAX))) {
        sys3(SYS_close, fd, 0, 0);
        return reply_errno(c, -ENOMEM, "out of memory");
    }
    copy_str(c->root, PATHMAX, path); // for the answer
    c->file = fd;
    c->state = C_WRITE;
}

static void write_frame(struct conn *c, u8 type, const u8 *b, u32 n)
{
    if (type == MVS_DATA) {
        for (u32 done = 0; done < n;) {
            long w = sys3(SYS_write, c->file, (long)(b + done), n - done);
            if (w == -EINTR)
                continue;
            if (w <= 0) {
                xclose(&c->file);
                c->state = C_REQ;
                return reply_errno(c, w ? w : -EIO, "write");
            }
            done += (u32)w;
        }
        return;
    }
    if (type != MVS_DONE || n) {
        c->dead = true;
        return;
    }
    xclose(&c->file);
    c->state = C_REQ;
    static char path[PATHMAX];
    copy_str(path, sizeof path, c->root);
    names_load();
    u8 *b2 = frame_begin(c, ENTRY_MAX);
    long len = b2 ? entry_body(path, b2) : -ENOMEM;
    if (len < 0)
        return reply_errno(c, len, "stat");
    frame_end(c, MVS_OK, (u32)len);
    finish(c);
}

// --- watching ---------------------------------------------------------------------------

static void watch_add(struct conn *c, const char *rel, u32 depth)
{
    if (c->nwd >= MAX_WATCHES)
        return;
    static char abs[PATHMAX];
    const u64 rl = slen(c->root), ll = slen(rel);
    if (rl + ll + 2 > PATHMAX || c->wnlen + ll + 1 > WNAMES)
        return;
    memcpy(abs, c->root, rl);
    u64 at = rl;
    if (ll) {
        if (rl > 1)
            abs[at++] = '/';
        memcpy(abs + at, rel, ll);
        at += ll;
    }
    abs[at] = 0;
    const long wd = sys3(SYS_inotify_add_watch, c->ino, (long)abs,
                         IN_MODIFY | IN_ATTRIB | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE |
                             IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR);
    if (wd < 0)
        return;
    for (u32 i = 0; i < c->nwd; i++)
        if (c->wds[i].wd == wd)
            return; // already watched (a hard link or a rename)
    c->wds[c->nwd++] = (struct wd){(int)wd, c->wnlen};
    memcpy(c->wnames + c->wnlen, rel, ll + 1);
    c->wnlen += (u32)ll + 1;
    if (!c->recursive || depth >= MVS_MAX_DEPTH)
        return;
    const int fd = (int)sys3(SYS_open, (long)abs, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (fd < 0)
        return;
    u8 buf[1024];
    char sub[PATHMAX];
    for (long n; (n = sys3(SYS_getdents64, fd, (long)buf, sizeof buf)) > 0;)
        for (long off = 0; off < n;) {
            struct dirent64 *d = (struct dirent64 *)(buf + off);
            off += d->reclen;
            const u64 nl = slen(d->name);
            if (d->type != 4 /* DT_DIR */ || (nl == 1 && d->name[0] == '.') ||
                (nl == 2 && d->name[0] == '.' && d->name[1] == '.') || ll + nl + 2 > PATHMAX)
                continue;
            u64 k = 0;
            if (ll) {
                memcpy(sub, rel, ll);
                sub[ll] = '/';
                k = ll + 1;
            }
            memcpy(sub + k, d->name, nl + 1);
            watch_add(c, sub, depth + 1);
        }
    sys3(SYS_close, fd, 0, 0);
}

static void op_watch(struct conn *c, struct rd *r)
{
    static struct user u;
    static char path[PATHMAX];
    const u32 flags = rd32(r);
    if (!path_arg(c, r, &u, path))
        return;
    if (r->n || flags & ~MVS_W_RECURSIVE)
        return reply_err(c, MVS_E_INVALID, 0, "bad WATCH");
    struct kstat st;
    long e = stat_(path, &st);
    if (e < 0)
        return reply_errno(c, e, "no such directory");
    if ((st.mode & S_IFMT) != S_IFDIR)
        return reply_err(c, MVS_E_INVALID, -ENOTDIR, "not a directory");
    c->ino = (int)sys3(SYS_inotify_init1, O_NONBLOCK | O_CLOEXEC, 0, 0);
    c->wds = map(MAX_WATCHES * sizeof(struct wd));
    c->wnames = map(WNAMES);
    c->root = map(PATHMAX);
    if (c->ino < 0 || !c->wds || !c->wnames || !c->root)
        return reply_errno(c, c->ino < 0 ? c->ino : -ENOMEM, "inotify");
    copy_str(c->root, PATHMAX, path);
    c->recursive = flags & MVS_W_RECURSIVE;
    watch_add(c, "", 0);
    if (!c->nwd)
        return reply_errno(c, -EACCES, "cannot watch the directory");
    ep_add(c->ino, EPOLLIN, &c->ino_ev, tag_of(K_WATCH, c->gen, (int)(c - s.c)));
    c->state = C_WATCH;
    emit(c, MVS_OK, nullptr, 0);
    flush(c);
}

struct inev {
    int wd;
    u32 mask, cookie, len;
    char name[];
};

static void watch_read(struct conn *c)
{
    static u8 buf[64 * 1024] __attribute__((aligned(8)));
    if (pending(c) > HOLD)
        return; // inotify queues meanwhile (and drops past its limit)
    long n = sys3(SYS_read, c->ino, (long)buf, sizeof buf);
    if (n <= 0)
        return;
    names_load();
    static char rel[PATHMAX], abs[PATHMAX];
    for (long off = 0; off < n;) {
        struct inev *e = (struct inev *)(buf + off);
        off += (long)sizeof *e + e->len;
        int at = -1;
        for (u32 i = 0; i < c->nwd; i++)
            if (c->wds[i].wd == e->wd)
                at = (int)i;
        if (at < 0)
            continue;
        const char *dir = c->wnames + c->wds[at].name;
        if (e->mask & IN_IGNORED || e->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
            if (at == 0 && e->mask & (IN_IGNORED | IN_DELETE_SELF | IN_MOVE_SELF)) {
                finish(c); // the watched directory is gone
                return;
            }
            if (e->mask & IN_IGNORED)
                c->wds[at].wd = -1;
            continue;
        }
        if (!e->len)
            continue;
        u32 type = e->mask & (IN_CREATE | IN_MOVED_TO) ? MVS_EV_CREATE
                   : e->mask & IN_MODIFY               ? MVS_EV_WRITE
                   : e->mask & IN_DELETE               ? MVS_EV_REMOVE
                   : e->mask & IN_MOVED_FROM           ? MVS_EV_RENAME
                   : e->mask & IN_ATTRIB               ? MVS_EV_CHMOD
                                                       : 0;
        if (!type)
            continue;
        const u64 dl = slen(dir), nl = slen(e->name), rl = slen(c->root);
        if (dl + nl + rl + 3 > PATHMAX)
            continue;
        u64 k = 0;
        if (dl) {
            memcpy(rel, dir, dl);
            rel[dl] = '/';
            k = dl + 1;
        }
        memcpy(rel + k, e->name, nl + 1);
        memcpy(abs, c->root, rl);
        u64 a = rl;
        if (rl > 1)
            abs[a++] = '/';
        memcpy(abs + a, rel, k + nl + 1);
        if (c->recursive && e->mask & IN_ISDIR && type == MVS_EV_CREATE)
            watch_add(c, rel, 1);
        u8 *b = frame_begin(c, 12 + PATHMAX + ENTRY_MAX);
        if (!b)
            return conn_close(c);
        put32(b, type);
        u8 *q = put_str(b + 8, rel, k + nl);
        long el = type == MVS_EV_REMOVE || type == MVS_EV_RENAME ? -1 : entry_body(abs, q);
        put32(b + 4, el < 0 ? MVS_W_NOENTRY : 0);
        frame_end(c, MVS_W_EVENT, (u32)(q - b) + (u32)(el < 0 ? 0 : el));
    }
    flush(c);
}

// --- ports ------------------------------------------------------------------------------

static void op_port(struct conn *c, struct rd *r)
{
    const u32 port = rd32(r);
    if (r->bad || r->n || !port || port > 65535)
        return reply_err(c, MVS_E_INVALID, 0, "bad PORT_CONNECT");
    c->peer = (int)sys3(SYS_socket, AF_INET, SOCK_STREAM | O_NONBLOCK | O_CLOEXEC, 0);
    if (c->peer < 0)
        return reply_errno(c, c->peer, "socket");
    struct {
        u16 family, port;
        u8 addr[4], zero[8];
    } a = {AF_INET, (u16)(port >> 8 | (port & 0xff) << 8), {127, 0, 0, 1}, {0}};
    long e = sys3(SYS_connect, c->peer, (long)&a, sizeof a);
    if (e < 0 && e != -EINPROGRESS) {
        xclose(&c->peer);
        return reply_errno(c, e, "connect");
    }
    c->state = C_PORT_WAIT;
    ep_add(c->peer, EPOLLOUT, &c->peer_ev, tag_of(K_PEER, c->gen, (int)(c - s.c)));
    conn_events(c);
}

static void peer_ready(struct conn *c, u32 events)
{
    if (c->state == C_PORT_WAIT) {
        int err = 0;
        u32 len = sizeof err;
        sys5(SYS_getsockopt, c->peer, SOL_SOCKET, SO_ERROR, (long)&err, (long)&len);
        if (err) {
            ep_del(c->peer);
            xclose(&c->peer);
            c->ilen = 0;
            return reply_errno(c, -err, "connection refused");
        }
        c->state = C_PORT;
        emit(c, MVS_OK, nullptr, 0);
    }
    if (events & EPOLLIN && pending(c) <= HOLD) {
        u8 *b = c->out + c->olen;
        if (c->olen + MVS_MAX_CHUNK > OUT_CAP) {
            memmove(c->out, c->out + c->ooff, pending(c));
            c->olen -= c->ooff, c->ooff = 0;
            b = c->out + c->olen;
        }
        long n = sys3(SYS_read, c->peer, (long)b, MVS_MAX_CHUNK);
        if (n > 0)
            c->olen += (u32)n;
        else if (n == 0 || (n != -EAGAIN && n != -EINTR))
            c->peer_eof = true;
    }
    if (c->ilen) {
        long n = sys3(SYS_write, c->peer, (long)c->in, c->ilen);
        if (n > 0) {
            memmove(c->in, c->in + n, c->ilen - (u32)n);
            c->ilen -= (u32)n;
        } else if (n != -EAGAIN && n != -EINTR) {
            c->dead = true;
        }
    }
    if (c->in_eof && !c->ilen && !c->peer_shut) {
        sys3(SYS_shutdown, c->peer, SHUT_WR, 0);
        c->peer_shut = true;
    }
    if (events & (EPOLLERR | EPOLLHUP) && !(events & EPOLLIN))
        c->peer_eof = true;
    flush(c);
}

// --- EXPORT: the root filesystem's changes as an OCI layer ------------------------
//
// The overlay's upper directory, walked from the fd enter_root() kept, as a
// ustar tar (pax records for long names): what was added or changed, a
// .wh.NAME entry for what was removed (overlayfs's whiteout, a 0/0
// character device) and .wh..wh..opq in a directory that replaced one
// below (overlayfs's opaque xattr). Hard links within the changes stay
// links. Device nodes and sockets are left out, and so are /etc/hostname,
// /etc/hosts and /etc/resolv.conf: every sandbox gets its own. Everything else in the
// sandbox is stopped meanwhile, so the walk sees one moment.
//
// The host treats the tar as untrusted (mkrootfs checks every entry).

enum { XP_DEPTH = 256, XP_LINKS = 1u << 16, XP_LINK_NAMES = 8u << 20 };

struct xp {
    struct conn *c;
    u32 len;     // bytes in xbuf
    u64 total;   // tar bytes sent
    const char *err;
    long errno_;
    struct xlink { u64 ino; u32 off, len; } *links; // nlink > 1: the first path of each inode
    char *lnames;
    u32 nlinks, lnlen;
};

static u8 xbuf[MVS_MAX_CHUNK];
static char xpath[PATHMAX + 16];
static char xpax[2 * PATHMAX + 64];

static void xp_fail(struct xp *x, const char *err, long e)
{
    if (!x->err)
        x->err = err, x->errno_ = e;
}

static void xp_send(struct xp *x)
{
    if (!x->len || x->err)
        return;
    emit(x->c, MVS_DATA, xbuf, x->len);
    x->total += x->len;
    x->len = 0;
    if (x->c->dead || !flush_wait(x->c))
        xp_fail(x, "the host stopped reading", -EIO);
}

static void xp_put(struct xp *x, const void *p, u64 n)
{
    const u8 *b = p;
    while (n && !x->err) {
        u64 k = MVS_MAX_CHUNK - x->len;
        if (k > n)
            k = n;
        if (b)
            memcpy(xbuf + x->len, b, k), b += k;
        else
            memset(xbuf + x->len, 0, k);
        x->len += (u32)k;
        n -= k;
        if (x->len == MVS_MAX_CHUNK)
            xp_send(x);
    }
}

static void xp_pad(struct xp *x, u64 n) { xp_put(x, nullptr, (512 - n % 512) % 512); }

// A numeric field of w bytes: octal and a NUL, or GNU base-256 if too big.
static void tar_num(u8 *f, u32 w, u64 v)
{
    if (w - 1 >= 22 || v < 1ull << (3 * (w - 1))) {
        for (u32 i = w - 1; i-- > 0; v >>= 3)
            f[i] = (u8)('0' + (v & 7));
        f[w - 1] = 0;
        return;
    }
    for (u32 i = w; i-- > 1; v >>= 8)
        f[i] = (u8)v;
    f[0] = 0x80;
}

static u64 pax_rec(char *p, const char *key, const char *v, u64 vl)
{
    const u64 kl = slen(key), base = 1 + kl + 1 + vl + 1; // " key=v\n"
    u64 len = base + 1;
    for (u64 d = 1, lim = 10; len >= lim; d++, lim *= 10)
        len = base + d + 1;
    char num[24];
    int nd = 0;
    for (u64 t = len; t; t /= 10)
        num[nd++] = (char)('0' + t % 10);
    u64 at = 0;
    while (nd)
        p[at++] = num[--nd];
    p[at++] = ' ';
    memcpy(p + at, key, kl), at += kl;
    p[at++] = '=';
    memcpy(p + at, v, vl), at += vl;
    p[at++] = '\n';
    return at;
}

static void tar_head(struct xp *x, const char *name, u64 nl, char type, const struct kstat *st, u64 size,
                     const char *link, u64 ll)
{
    u8 h[512];
    if (nl > 100 || ll > 100) {
        u64 n = 0;
        if (nl > 100)
            n += pax_rec(xpax + n, "path", name, nl);
        if (ll > 100)
            n += pax_rec(xpax + n, "linkpath", link, ll);
        memset(h, 0, sizeof h);
        memcpy(h, "././@PaxHeader", 14);
        tar_num(h + 100, 8, 0644);
        tar_num(h + 108, 8, 0);
        tar_num(h + 116, 8, 0);
        tar_num(h + 124, 12, n);
        tar_num(h + 136, 12, 0);
        h[156] = 'x';
        memcpy(h + 257, "ustar\0" "00", 8);
        memset(h + 148, ' ', 8);
        u32 sum = 0;
        for (int i = 0; i < 512; i++)
            sum += h[i];
        tar_num(h + 148, 7, sum);
        xp_put(x, h, 512);
        xp_put(x, xpax, n);
        xp_pad(x, n);
    }
    memset(h, 0, sizeof h);
    memcpy(h, name, nl > 100 ? 100 : nl);
    tar_num(h + 100, 8, st ? st->mode & 07777 : 0644);
    tar_num(h + 108, 8, st ? st->uid : 0);
    tar_num(h + 116, 8, st ? st->gid : 0);
    tar_num(h + 124, 12, size);
    tar_num(h + 136, 12, st && st->mtime > 0 ? (u64)st->mtime : 0);
    h[156] = (u8)type;
    if (ll)
        memcpy(h + 157, link, ll > 100 ? 100 : ll);
    memcpy(h + 257, "ustar\0" "00", 8);
    memset(h + 148, ' ', 8);
    u32 sum = 0;
    for (int i = 0; i < 512; i++)
        sum += h[i];
    tar_num(h + 148, 7, sum);
    xp_put(x, h, 512);
}

// The first path of a hard-linked inode, or nullptr (and it is remembered).
static const char *xp_link(struct xp *x, u64 ino, const char *path, u64 pl, u64 *len)
{
    if (!x->links)
        return nullptr;
    u32 i = (u32)(ino * 0x9E3779B97F4A7C15ull >> 48) & (XP_LINKS - 1);
    for (u32 k = 0; k < XP_LINKS; k++, i = (i + 1) & (XP_LINKS - 1)) {
        struct xlink *l = &x->links[i];
        if (!l->len) {
            if (x->nlinks + 1 >= XP_LINKS / 2 || x->lnlen + pl > XP_LINK_NAMES)
                return nullptr; // full: later links become copies
            memcpy(x->lnames + x->lnlen, path, pl);
            *l = (struct xlink){ino, x->lnlen, (u32)pl};
            x->lnlen += (u32)pl;
            x->nlinks++;
            return nullptr;
        }
        if (l->ino == ino) {
            *len = l->len;
            return x->lnames + l->off;
        }
    }
    return nullptr;
}

static void xp_file(struct xp *x, int dfd, const char *name, u64 pl, const struct kstat *st)
{
    u64 ll = 0;
    const char *first = st->nlink > 1 ? xp_link(x, st->ino, xpath, pl, &ll) : nullptr;
    if (first)
        return tar_head(x, xpath, pl, '1', st, 0, first, ll);
    const int fd = (int)sys4(SYS_openat, dfd, (long)name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (fd < 0)
        return xp_fail(x, "cannot open a changed file", fd);
    const u64 size = (u64)st->size;
    tar_head(x, xpath, pl, '0', st, size, nullptr, 0);
    u64 left = size;
    while (left && !x->err) {
        u64 k = MVS_MAX_CHUNK - x->len;
        if (k > left)
            k = left;
        const long n = sys3(SYS_read, fd, (long)(xbuf + x->len), (long)k);
        if (n == -EINTR)
            continue;
        if (n <= 0) { // shrunk meanwhile: the tar still says size bytes
            xp_put(x, nullptr, left);
            break;
        }
        x->len += (u32)n;
        left -= (u64)n;
        if (x->len == MVS_MAX_CHUNK)
            xp_send(x);
    }
    sys3(SYS_close, fd, 0, 0);
    xp_pad(x, size);
}

// The entries of directory dfd, whose path in the tar is xpath[0..pl).
static void xp_dir(struct xp *x, int dfd, u64 pl, u32 depth)
{
    if (depth > XP_DEPTH)
        return xp_fail(x, "the changes are nested too deep", -ELOOP);
    u8 buf[2048];
    for (long n; !x->err && (n = sys3(SYS_getdents64, dfd, (long)buf, sizeof buf)) != 0;) {
        if (n < 0)
            return xp_fail(x, "cannot list a changed directory", n);
        for (long off = 0; off < n && !x->err;) {
            struct dirent64 *d = (struct dirent64 *)(buf + off);
            off += d->reclen;
            const u64 nl = slen(d->name);
            if ((nl == 1 && d->name[0] == '.') || (nl == 2 && d->name[0] == '.' && d->name[1] == '.'))
                continue;
            if (pl + 1 + 4 + nl + 1 + 13 > PATHMAX)
                return xp_fail(x, "a changed path is too long", -ENAMETOOLONG);
            if (pl == 3 && seqn(xpath, "etc", 3) && (seq(d->name, "hostname") || seq(d->name, "hosts") ||
                                                    seq(d->name, "resolv.conf")))
                continue; // the sandbox's own (image.c), as in a container
            struct kstat st;
            long e = sys4(SYS_newfstatat, dfd, (long)d->name, (long)&st, AT_SYMLINK_NOFOLLOW);
            if (e == -ENOENT)
                continue; // gone meanwhile
            if (e < 0)
                return xp_fail(x, "cannot stat a change", e);
            u64 at = pl;
            if (pl)
                xpath[at++] = '/';
            const u32 fmt = st.mode & S_IFMT;
            if (fmt == S_IFCHR && st.rdev == 0) { // a whiteout
                memcpy(xpath + at, ".wh.", 4);
                memcpy(xpath + at + 4, d->name, nl);
                tar_head(x, xpath, at + 4 + nl, '0', nullptr, 0, nullptr, 0);
                continue;
            }
            memcpy(xpath + at, d->name, nl);
            const u64 len = at + nl;
            if (fmt == S_IFREG) {
                xp_file(x, dfd, d->name, len, &st);
            } else if (fmt == S_IFLNK) {
                static char target[PATHMAX];
                const long tl = sys4(SYS_readlinkat, dfd, (long)d->name, (long)target, sizeof target);
                if (tl <= 0 || tl >= (long)sizeof target)
                    return xp_fail(x, "cannot read a changed symlink", tl < 0 ? tl : -ENAMETOOLONG);
                tar_head(x, xpath, len, '2', &st, 0, target, (u64)tl);
            } else if (fmt == S_IFIFO) {
                tar_head(x, xpath, len, '6', &st, 0, nullptr, 0);
            } else if (fmt == S_IFDIR) {
                const int fd = (int)sys4(SYS_openat, dfd, (long)d->name,
                                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
                if (fd < 0)
                    return xp_fail(x, "cannot open a changed directory", fd);
                tar_head(x, xpath, len, '5', &st, 0, nullptr, 0);
                char v[4];
                if (sys4(SYS_fgetxattr, fd, (long)"trusted.overlay.opaque", (long)v, sizeof v) == 1 && v[0] == 'y') {
                    memcpy(xpath + len, "/.wh..wh..opq", 13);
                    tar_head(x, xpath, len + 13, '0', nullptr, 0, nullptr, 0);
                }
                xp_dir(x, fd, len, depth + 1);
                sys3(SYS_close, fd, 0, 0);
            } // devices and sockets: left out
            xpath[pl] = 0;
        }
    }
}

static void op_export(struct conn *c, u32 n)
{
    if (n)
        return reply_err(c, MVS_E_INVALID, 0, "bad EXPORT");
    if (upper_dir < 0)
        return reply_err(c, MVS_E_FAILED, -EBADF, "no changes directory");
    static struct xp x;
    x = (struct xp){.c = c};
    x.links = map((u64)XP_LINKS * sizeof *x.links);
    x.lnames = map(XP_LINK_NAMES);
    if (!x.links || !x.lnames) {
        unmap(x.links, (u64)XP_LINKS * sizeof *x.links);
        unmap(x.lnames, XP_LINK_NAMES);
        x.links = nullptr, x.lnames = nullptr;
    }
    const int dfd = (int)sys4(SYS_openat, upper_dir, (long)".", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    sys3(SYS_kill, -1, SIGSTOP, 0);
    if (dfd < 0)
        xp_fail(&x, "cannot open the changes directory", dfd);
    else
        xp_dir(&x, dfd, 0, 0);
    xp_put(&x, nullptr, 1024); // end of archive
    xp_send(&x);
    sys3(SYS_kill, -1, SIGCONT, 0);
    if (dfd >= 0)
        sys3(SYS_close, dfd, 0, 0);
    unmap(x.links, (u64)XP_LINKS * sizeof *x.links);
    unmap(x.lnames, XP_LINK_NAMES);
    if (c->dead)
        return conn_close(c);
    if (x.err)
        return reply_errno(c, x.errno_, x.err);
    u8 b[8];
    put64(b, x.total);
    reply_ok(c, b, 8);
}

// --- requests -------------------------------------------------------------------------------

static char *arena;
enum { ARENA = MVS_MAX_BODY + 64 * 1024 };

static void dispatch(struct conn *c, u8 type, const u8 *body, u32 n)
{
    struct rd r = {body, n, false, arena, 0, ARENA};
    switch (type) {
    case MVS_START: return op_start(c, &r);
    case MVS_CONNECT: return op_connect(c, &r);
    case MVS_PS: return op_ps(c, &r);
    case MVS_INPUT: return op_input(c, &r);
    case MVS_CLOSE_STDIN: return op_close_stdin(c, &r);
    case MVS_SIGNAL: return op_signal(c, &r);
    case MVS_RESIZE: return op_resize(c, &r);
    case MVS_STAT: return op_stat(c, &r);
    case MVS_MKDIR: return op_mkdir(c, &r);
    case MVS_MOVE: return op_move(c, &r);
    case MVS_LIST: return op_list(c, &r);
    case MVS_REMOVE: return op_remove(c, &r);
    case MVS_WATCH: return op_watch(c, &r);
    case MVS_READ: return op_read(c, &r);
    case MVS_WRITE: return op_write(c, &r);
    case MVS_PORT_CONNECT: return op_port(c, &r);
    case MVS_EXPORT: return op_export(c, n);
    case MVS_SET_ENV: {
        const u16 k = rd16(&r);
        char *buf = map(MVS_MAX_BODY);
        u32 used = 0;
        for (u16 i = 0; i < k && buf && !r.bad; i++) {
            const char *e = rdstr(&r, MVS_MAX_STRING);
            const u64 l = slen(e);
            bool eq = false;
            for (u64 j = 0; j < l; j++)
                eq |= e[j] == '=';
            if (!eq || e[0] == '=' || used + l + 1 > MVS_MAX_BODY)
                r.bad = true;
            else
                memcpy(buf + used, e, l + 1), used += (u32)l + 1;
        }
        if (!buf || r.bad || r.n) {
            unmap(buf, MVS_MAX_BODY);
            return reply_err(c, MVS_E_INVALID, 0, "bad SET_ENV");
        }
        unmap(s.def_env, MVS_MAX_BODY);
        s.def_env = buf, s.def_env_len = used, s.def_env_n = k;
        return reply_ok(c, nullptr, 0);
    }
    case MVS_SNAPSHOT: {
        if (n)
            return reply_err(c, MVS_E_INVALID, 0, "bad SNAPSHOT");
        // As in agent.c: nothing runs between the snapshot point and the
        // reseed, in this VM or in any restored from the snapshot.
        const long rnd = sys3(SYS_open, (long)"/dev/urandom", O_WRONLY | O_CLOEXEC, 0);
        sys3(SYS_kill, -1, SIGSTOP, 0);
        report_free_pages();
        if (ports)
            outb(PORT_SNAPSHOT, 1); // a restored VM continues here
        resume(rnd);
        sys3(SYS_kill, -1, SIGCONT, 0);
        s.resumes++;
        // Connections from before the snapshot are gone in a restored VM;
        // this one too. The host knows from the VMM having stopped.
        return reply_ok(c, nullptr, 0);
    }
    default:
        c->dead = true;
    }
}

// Takes the frames that have arrived (requests, or a WRITE's data).
static void conn_frames(struct conn *c)
{
    u32 at = 0;
    while (!c->dead && (c->state == C_REQ || c->state == C_WRITE) && c->ilen - at >= MVS_HDR) {
        const u8 *h = c->in + at;
        const u32 len = le32(h + 8);
        if (le32(h) != MVS_MAGIC || h[4] != MVS_VERSION || h[6] || h[7] || len > MVS_MAX_BODY) {
            c->dead = true;
            break;
        }
        if (c->ilen - at < MVS_HDR + len)
            break;
        const u8 type = h[5];
        at += MVS_HDR + len;
        if (c->state == C_WRITE)
            write_frame(c, type, h + MVS_HDR, len);
        else
            dispatch(c, type, h + MVS_HDR, len);
        if (c->state == C_FREE)
            return; // closed
    }
    if (c->state == C_FREE)
        return;
    if (at) {
        memmove(c->in, c->in + at, c->ilen - at);
        c->ilen -= at;
    }
    // Requests are one per connection: only a WRITE's data, or a port's
    // bytes, may follow one. After an answer, the rest is dropped (a WRITE
    // that failed: its data still arrives).
    if (c->state == C_CLOSING || c->state == C_LINGER)
        c->ilen = 0;
    if (c->ilen && c->state != C_REQ && c->state != C_WRITE && c->state != C_PORT_WAIT && c->state != C_PORT)
        c->dead = true;
    if (c->dead)
        conn_close(c);
}

static void conn_read(struct conn *c)
{
    if (c->state == C_PORT || c->state == C_PORT_WAIT) {
        if (c->ilen >= IN_CAP)
            return;
        long n = sys3(SYS_read, c->fd, (long)(c->in + c->ilen), IN_CAP - c->ilen);
        if (n > 0)
            c->ilen += (u32)n;
        else if (n == 0 || (n != -EAGAIN && n != -EINTR))
            c->in_eof = true;
        if (c->state == C_PORT)
            peer_ready(c, 0);
        else
            conn_events(c);
        return;
    }
    if (c->state != C_REQ && c->state != C_WRITE) {
        // Nothing more is expected: data is an error, the end is the host
        // hanging up.
        u8 junk[256];
        long n = sys3(SYS_read, c->fd, (long)junk, sizeof junk);
        if (n == 0 || (n < 0 && n != -EAGAIN && n != -EINTR) ||
            (n > 0 && c->state != C_LINGER && c->state != C_CLOSING))
            conn_close(c);
        return;
    }
    long n = sys3(SYS_read, c->fd, (long)(c->in + c->ilen), IN_CAP - c->ilen);
    if (n == 0 || (n < 0 && n != -EAGAIN && n != -EINTR))
        return conn_close(c);
    if (n > 0) {
        c->ilen += (u32)n;
        conn_frames(c);
    }
}

static void conn_events(struct conn *c)
{
    if (c->state == C_FREE)
        return;
    const int idx = (int)(c - s.c);
    u32 want = pending(c) ? EPOLLOUT : 0;
    if (c->state == C_PORT || c->state == C_PORT_WAIT)
        want |= !c->in_eof && c->ilen < IN_CAP ? EPOLLIN : 0;
    else
        want |= EPOLLIN;
    ep_set(c->fd, want, &c->ev, tag_of(K_CONN, c->gen, idx));
    if (c->state == C_WATCH)
        ep_set(c->ino, pending(c) <= HOLD ? EPOLLIN : 0, &c->ino_ev, tag_of(K_WATCH, c->gen, idx));
    if (c->state == C_PORT) {
        u32 pw = (c->ilen ? EPOLLOUT : 0) | (!c->peer_eof && pending(c) <= HOLD ? EPOLLIN : 0);
        ep_set(c->peer, pw, &c->peer_ev, tag_of(K_PEER, c->gen, idx));
        if (c->peer_eof && !pending(c) && (c->in_eof || c->dead)) {
            conn_close(c);
            return;
        }
        if (c->peer_eof && !pending(c) && !c->fd_shut) {
            // The guest side is done: tell the host, keep taking its bytes
            // until it is done too.
            sys3(SYS_shutdown, c->fd, SHUT_WR, 0);
            c->fd_shut = true;
        }
    }
}

static void conn_close(struct conn *c)
{
    if (c->state == C_FREE)
        return;
    unsubscribe(c);
    ep_del(c->fd);
    ep_del(c->peer);
    ep_del(c->ino);
    xclose(&c->fd);
    xclose(&c->peer);
    xclose(&c->file);
    xclose(&c->ino);
    unmap(c->in, IN_CAP);
    unmap(c->out, OUT_CAP);
    unmap(c->wds, MAX_WATCHES * sizeof(struct wd));
    unmap(c->wnames, WNAMES);
    unmap(c->root, PATHMAX);
    const u16 gen = (u16)(c->gen + 1);
    memset(c, 0, sizeof *c);
    c->gen = gen;
    c->fd = c->peer = c->file = c->ino = -1;
    c->proc = -1;
}

static void accept_all(void)
{
    for (;;) {
        const int fd = (int)sys4(SYS_accept4, s.ls, 0, 0, O_NONBLOCK | O_CLOEXEC);
        if (fd < 0)
            return;
        struct conn *c = nullptr;
        for (int i = 0; i < MAX_CONNS && !c; i++)
            if (s.c[i].state == C_FREE)
                c = &s.c[i];
        if (!c || !(c->in = map(IN_CAP)) || !(c->out = map(OUT_CAP))) {
            if (c)
                unmap(c->in, IN_CAP), c->in = nullptr;
            sys3(SYS_close, fd, 0, 0);
            continue;
        }
        c->fd = fd;
        c->state = C_REQ;
        u8 b[8];
        put32(b, MVS_VERSION);
        put32(b + 4, s.resumes);
        emit(c, MVS_HELLO, b, 8);
        ep_add(fd, 0, &c->ev, tag_of(K_CONN, c->gen, (int)(c - s.c)));
        flush(c);
    }
}

int sbx_run(void)
{
    if (enter_root() || !image_load())
        return 125;
    s.base_env = image_env();
    // The loopback interface, up as in any container: servers in the
    // sandbox listen on 127.0.0.1, and PORT_CONNECT reaches them there.
    const int ks = (int)sys3(SYS_socket, AF_INET, 2 /* SOCK_DGRAM */ | O_CLOEXEC, 0);
    struct {
        char name[16];
        short flags;
        char pad[22];
    } ifr = {"lo", 0, {0}};
    if (ks < 0 || sys3(SYS_ioctl, ks, 0x8913 /* SIOCGIFFLAGS */, (long)&ifr) < 0 ||
        (ifr.flags |= 0x41 /* IFF_UP | IFF_RUNNING */, sys3(SYS_ioctl, ks, 0x8914 /* SIOCSIFFLAGS */, (long)&ifr)) < 0)
        say("sandbox: cannot bring up the loopback interface", nullptr, 0);
    if (ks >= 0)
        sys3(SYS_close, ks, 0, 0);
    s.c = map(MAX_CONNS * sizeof *s.c);
    s.p = map(MVS_MAX_PROCS * sizeof *s.p);
    arena = map(ARENA);
    if (!s.base_env || !s.c || !s.p || !arena) {
        say("sandbox: out of memory", nullptr, -ENOMEM);
        return 125;
    }
    for (int i = 0; i < MAX_CONNS; i++) {
        s.c[i].fd = s.c[i].peer = s.c[i].file = s.c[i].ino = -1;
        s.c[i].proc = -1;
    }
    for (int i = 0; i < NPROCS; i++)
        s.p[i].out = s.p[i].err = s.p[i].in = -1;

    // SIGCHLD through a signalfd; every process we start unblocks it.
    const u64 chld = 1ul << (SIGCHLD - 1);
    sys4(SYS_rt_sigprocmask, 0 /* SIG_BLOCK */, (long)&chld, 0, 8);
    s.sigfd = (int)sys4(SYS_signalfd4, -1, (long)&chld, 8, O_NONBLOCK | O_CLOEXEC);
    s.ep = (int)sys3(SYS_epoll_create1, O_CLOEXEC, 0, 0);
    s.ls = (int)sys3(SYS_socket, AF_VSOCK, SOCK_STREAM | O_NONBLOCK | O_CLOEXEC, 0);
    struct {
        u16 family, reserved;
        u32 port, cid;
        u8 zero[4];
    } addr = {AF_VSOCK, 0, MVS_PORT, 0xffffffffu, {0}};
    long r = s.ls;
    if (s.sigfd < 0 || s.ep < 0 || r < 0 || (r = sys3(SYS_bind, s.ls, (long)&addr, sizeof addr)) < 0 ||
        (r = sys3(SYS_listen, s.ls, 128, 0)) < 0) {
        say("sandbox: cannot listen on vsock (is there a --vsock device?)", nullptr, r < 0 ? r : -EBADF);
        return 125;
    }
    ep_add(s.ls, EPOLLIN, nullptr, tag_of(K_LISTEN, 0, 0));
    ep_add(s.sigfd, EPOLLIN, nullptr, tag_of(K_SIG, 0, 0));
    say("sandbox: ready", nullptr, 0);

    static struct epev evs[64];
    for (;;) {
        const long n = sys4(SYS_epoll_wait, s.ep, (long)evs, 64, -1);
        for (long i = 0; i < n; i++) {
            const u64 d = evs[i].data;
            const u32 ev = evs[i].events;
            const int kind = (int)(d >> 48), idx = (int)(u32)d;
            const u16 gen = (u16)(d >> 32);
            if (kind == K_LISTEN) {
                accept_all();
                continue;
            }
            if (kind == K_SIG) {
                reap();
                continue;
            }
            if (kind == K_POUT || kind == K_PERR || kind == K_PIN) {
                struct proc *p = &s.p[idx];
                if (!p->pid || p->gen != gen)
                    continue;
                if (kind == K_PIN || (ev & EPOLLOUT && p->in == p->out))
                    stdin_pump(p);
                if (kind == K_PIN || !(ev & (EPOLLIN | EPOLLHUP | EPOLLERR)))
                    continue;
                if (!proc_room(p)) {
                    proc_events(p);
                    continue;
                }
                const bool err = kind == K_PERR;
                const int fd = err ? p->err : p->out;
                const u8 type = err ? MVS_P_STDERR : p->flags & MVS_S_PTY ? MVS_P_PTY : MVS_P_STDOUT;
                if (!proc_read(p, fd, type) && p->pid && p->gen == gen) {
                    // Its end: stop watching it; P_END waits for the exit.
                    ep_del(fd);
                    if (err)
                        p->err_eof = true, p->ev_err = 0;
                    else
                        p->out_eof = true, p->ev_out = 0;
                }
                continue;
            }
            struct conn *c = &s.c[idx];
            if (idx < 0 || idx >= MAX_CONNS || c->state == C_FREE || c->gen != gen)
                continue;
            if (kind == K_CONN) {
                if (ev & EPOLLOUT)
                    flush(c);
                if (c->state != C_FREE && c->gen == gen && ev & (EPOLLIN | EPOLLHUP | EPOLLERR))
                    conn_read(c);
            } else if (kind == K_PEER) {
                peer_ready(c, ev);
            } else if (kind == K_WATCH) {
                watch_read(c);
            }
        }
    }
}
