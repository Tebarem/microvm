// SPDX-License-Identifier: MIT
// End-to-end test of the sandbox agent (Linux, KVM): `/init sandbox` and
// /bin/sbx-demo, driven through the host side of the protocol
// (src/sbx/sbx.h), one operation per connection as microvm-sbxd does.
//
// 1. Processes: output, exit status, PATH lookup, users and groups, the
//    environment, stdin, a terminal (size, resize, input), background
//    processes (reconnect, list), signals, 8 MiB of output.
// 2. Files: write, read, stat, list, mkdir, move, remove; relative paths.
// 3. Watching a directory, recursively.
// 4. Forwarding a connection to a TCP port in the guest.
// 5. A snapshot (pause): restores continue with the processes running,
//    each with its own random numbers.
//
//   mvm_sbx_tests MICROVM VMLINUX IMAGE [--cpus N] [--jail MICROVM-JAIL]
//
// --cpus: boot (and snapshot) N vCPUs, VMLINUX an SMP kernel; every
// vCPU runs a process, before the snapshot and after each restore.
//
// IMAGE is the test image (out/test-layer.tar: /bin/probe, /bin/sbx-demo,
// /etc/passwd with "user"). Exits 77 (skipped) without a usable /dev/kvm.
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "jail_wrap.h"
#include "sbx/sbx.h"

static int fails;
static char dir[] = "/tmp/mvm-sbx-XXXXXX";
static jw_cfg jw;
static const char *K, *IMG, *CPUS = "1";
static char snap[128];

static void check(bool ok, const char *what)
{
    printf("  %-66s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok)
        fails++;
}

static double now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

typedef struct {
    pid_t pid;
    char sock[108], out[128];
} vmproc;

static void spawn(vmproc *v, const char *tag, const char *const *args)
{
    snprintf(v->sock, sizeof v->sock, "%s/%s.sock", dir, tag);
    snprintf(v->out, sizeof v->out, "%s/%s.out", dir, tag);
    unlink(v->sock);
    const char *vmm[32], *a[96];
    int n = 0;
    for (; args[n] && n < 31; n++)
        vmm[n] = strcmp(args[n], "@SOCK") ? args[n] : v->sock;
    vmm[n] = nullptr;
    if (jw_wrap(&jw, vmm, a, 96)) {
        v->pid = -1;
        return;
    }
    v->pid = fork_child();
    if (v->pid == 0) {
        const int o = open(v->out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        dup2(o, 1);
        dup2(o, 2);
        execv(a[0], (char **)a);
        _exit(127);
    }
}

static int reap_vm(vmproc *v, double ms, char *buf, size_t cap)
{
    int st = 0;
    const double end = now_ms() + ms;
    while (v->pid > 0 && waitpid(v->pid, &st, WNOHANG) == 0) {
        if (now_ms() > end) {
            kill(v->pid, SIGKILL);
            waitpid(v->pid, &st, 0);
            break;
        }
        usleep(500);
    }
    if (buf) {
        memset(buf, 0, cap);
        const int o = open(v->out, O_RDONLY);
        if (o >= 0) {
            (void)!read(o, buf, cap - 1);
            close(o);
        }
    }
    unlink(v->out);
    unlink(v->sock);
    return v->pid < 0 ? 127 : WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

// --- a blocking client: one connection per operation ----------------------

typedef struct {
    int fd;
    mvs_reader r;
    uint32_t resumes;
} sc;

static void sc_close(sc *c)
{
    if (c->fd >= 0)
        close(c->fd);
    c->fd = -1;
    mvs_reader_free(&c->r);
}

// The next frame: 1, or 0 at the end of the connection, -1 on an error or
// after ms.
static int sc_frame(sc *c, mvs_frame *f, int ms)
{
    const double end = now_ms() + ms;
    for (;;) {
        const int r = mvs_next(&c->r, f);
        if (r)
            return r;
        const int wait = (int)(end - now_ms());
        struct pollfd p = {.fd = c->fd, .events = POLLIN};
        if (wait <= 0 || poll(&p, 1, wait) <= 0)
            return -1;
        uint8_t buf[65536];
        const ssize_t n = recv(c->fd, buf, sizeof buf, 0);
        if (n <= 0)
            return n == 0 ? 0 : -1;
        if (!mvs_feed(&c->r, buf, (size_t)n))
            return -1;
    }
}

static bool sc_open(sc *c, const char *sock, int ms)
{
    *c = (sc){.fd = -1};
    const double end = now_ms() + ms;
    while (now_ms() < end) {
        struct sockaddr_un a = {.sun_family = AF_UNIX};
        strcpy(a.sun_path, sock);
        c->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (connect(c->fd, (struct sockaddr *)&a, sizeof a) == 0 &&
            send(c->fd, "CONNECT 53\n", 11, MSG_NOSIGNAL) == 11) {
            char line[32];
            size_t n = 0;
            while (n < sizeof line - 1) {
                struct pollfd p = {.fd = c->fd, .events = POLLIN};
                if (poll(&p, 1, 2000) <= 0 || recv(c->fd, line + n, 1, 0) != 1)
                    break;
                if (line[n++] == '\n')
                    break;
            }
            if (n > 3 && !memcmp(line, "OK ", 3) && line[n - 1] == '\n') {
                mvs_frame f;
                uint32_t v;
                if (sc_frame(c, &f, 2000) == 1 && mvs_dec_hello(&f, &v, &c->resumes))
                    return true;
                sc_close(c);
                return false;
            }
        }
        close(c->fd);
        c->fd = -1;
        usleep(2000);
    }
    return false;
}

static bool sc_send(sc *c, mvs_buf *b)
{
    bool ok = !b->oom && send(c->fd, b->p, b->len, MSG_NOSIGNAL) == (ssize_t)b->len;
    mvs_buf_free(b);
    return ok;
}

static const char *SOCK;

// A process's whole stream: stdout (or the terminal), stderr, its wait
// status. Returns false on a protocol error or ERROR (kind in *err).
typedef struct {
    char out[1 << 16], err[4096];
    size_t nout, nerr, total;
    uint32_t pid, status, errkind;
    bool started, ended;
} run;

static bool stream_(sc *c, run *r, int ms);
static bool stream(sc *c, run *r, int ms)
{
    const bool ok = stream_(c, r, ms);
    if (!ok && getenv("SBX_DEBUG"))
        printf("    [stream: started %d ended %d status %#x out %zu err %zu errkind %u reader '%s']\n", r->started,
               r->ended, r->status, r->nout, r->nerr, r->errkind, c->r.error);
    return ok;
}

static bool stream_(sc *c, run *r, int ms)
{
    mvs_frame f;
    for (int got; (got = sc_frame(c, &f, ms)) == 1;) {
        if (f.type == MVS_ERROR) {
            mvs_error e;
            r->errkind = mvs_dec_error(&f, &e) ? e.kind : 999;
            return false;
        }
        if (f.type == MVS_P_START && mvs_dec_u32(&f, &r->pid))
            r->started = true;
        else if (f.type == MVS_P_STDOUT || f.type == MVS_P_PTY) {
            r->total += f.len;
            const size_t k = f.len < sizeof r->out - 1 - r->nout ? f.len : sizeof r->out - 1 - r->nout;
            memcpy(r->out + r->nout, f.body, k);
            r->nout += k;
        } else if (f.type == MVS_P_STDERR) {
            const size_t k = f.len < sizeof r->err - 1 - r->nerr ? f.len : sizeof r->err - 1 - r->nerr;
            memcpy(r->err + r->nerr, f.body, k);
            r->nerr += k;
        } else if (f.type == MVS_P_END && mvs_dec_end(&f, &r->status)) {
            r->ended = true;
            return true;
        } else {
            if (getenv("SBX_DEBUG"))
                printf("    [unexpected frame type %u len %u]\n", f.type, f.len);
            return false;
        }
    }
    return false;
}

static bool exec(run *r, uint32_t flags, const char *user, const char *cwd, const char *const *argv,
                 const char *const *envs, size_t nenv)
{
    memset(r, 0, sizeof *r);
    sc c;
    if (!sc_open(&c, SOCK, 5000))
        return false;
    size_t nargs = 0;
    while (argv[nargs])
        nargs++;
    mvs_buf b = {0};
    mvs_req_start(&b, &(mvs_start){.flags = flags, .user = user, .cwd = cwd, .argv = argv, .nargs = nargs,
                                   .envs = envs, .nenv = nenv});
    bool ok = sc_send(&c, &b) && stream(&c, r, 10000);
    sc_close(&c);
    return ok;
}

static bool has(const char *s, size_t n, const char *needle)
{
    return memmem(s, n, needle, strlen(needle)) != nullptr;
}

// One request on a fresh connection: the frame that answers it.
static int request(mvs_buf *b, mvs_frame *f, sc *c)
{
    if (!sc_open(c, SOCK, 5000) || !sc_send(c, b))
        return -1;
    return sc_frame(c, f, 10000);
}

static bool simple(mvs_buf *b, uint32_t *errkind)
{
    sc c;
    mvs_frame f;
    *errkind = 0;
    const int r = request(b, &f, &c);
    bool ok = r == 1 && f.type == MVS_OK;
    mvs_error e;
    if (r == 1 && f.type == MVS_ERROR)
        *errkind = mvs_dec_error(&f, &e) ? e.kind : 999;
    sc_close(&c);
    return ok;
}

static mvs_sel tag_sel(const char *t) { return (mvs_sel){.kind = MVS_SEL_TAG, .tag = t}; }

static void processes(void)
{
    printf("processes:\n");
    run r;
    const char *probe[] = {"/bin/probe", "5", "w", nullptr};
    check(exec(&r, 0, "", "", probe, nullptr, 0) && r.started && (r.status >> 8) == 5 &&
              has(r.out, r.nout, "probe: [w] message: from the image") && has(r.err, r.nerr, "probe: stderr"),
          "stdout, stderr and the exit status");
    if (getenv("SBX_DEBUG"))
        printf("    [status %#x out '%.*s' err '%.*s']\n", r.status, (int)r.nout, r.out, (int)r.nerr, r.err);
    const char *bare[] = {"probe", nullptr};
    check(exec(&r, 0, "root", "", bare, nullptr, 0) && r.status == 0, "a command without '/' is looked up in PATH");
    const char *none[] = {"no-such-command", nullptr};
    check(!exec(&r, 0, "", "", none, nullptr, 0) && r.errkind == MVS_E_NOTFOUND,
          "a missing command: ERROR NOTFOUND");
    const char *id[] = {"probe", "id", "cwd", "env:HOME", "env:USER", nullptr};
    check(exec(&r, 0, "user", "", id, nullptr, 0) && has(r.out, r.nout, "uid=1000 gid=1000 groups=1000,1001") &&
              has(r.out, r.nout, "cwd: /") && has(r.out, r.nout, "HOME=/ USER=user"),
          "as \"user\": its uid, gid and groups, home and USER");
    check(!exec(&r, 0, "nobody-here", "", id, nullptr, 0) && r.errkind == MVS_E_NOTFOUND,
          "an unknown user: ERROR NOTFOUND");
    const char *cwd[] = {"probe", "cwd", nullptr};
    check(exec(&r, 0, "", "/etc", cwd, nullptr, 0) && has(r.out, r.nout, "cwd: /etc"), "the working directory");
    check(!exec(&r, 0, "", "/nowhere", cwd, nullptr, 0) && r.errkind == MVS_E_NOTFOUND,
          "a missing working directory: ERROR NOTFOUND");

    mvs_buf b = {0};
    const char *defs[] = {"A=1", "B=from-defaults"};
    mvs_req_set_env(&b, defs, 2);
    uint32_t ek;
    check(simple(&b, &ek), "SET_ENV");
    const char *env[] = {"probe", "env:A", "env:B", "env:C", "env:HOME", nullptr};
    const char *envs[] = {"B=2", "C=3"};
    check(exec(&r, 0, "", "", env, envs, 2) && has(r.out, r.nout, "A=1 B=2 C=3 HOME=/root"),
          "environment: defaults, then the request's");

    // stdin, through INPUT on other connections, by tag.
    sc c;
    const char *cat[] = {"sbx-demo", "cat", nullptr};
    mvs_req_start(&b, &(mvs_start){.flags = MVS_S_STDIN, .tag = "cat", .argv = cat, .nargs = 2});
    bool ok = sc_open(&c, SOCK, 5000) && sc_send(&c, &b);
    const mvs_sel cs = tag_sel("cat");
    mvs_req_input(&b, &cs, 0, "hello\n", 6);
    ok = ok && simple(&b, &ek);
    mvs_req_sel(&b, MVS_CLOSE_STDIN, &cs);
    ok = ok && simple(&b, &ek);
    memset(&r, 0, sizeof r);
    ok = ok && stream(&c, &r, 5000);
    sc_close(&c);
    check(ok && r.nout == 6 && !memcmp(r.out, "hello\n", 6) && (r.status >> 8) == 3,
          "stdin: INPUT by tag, CLOSE_STDIN ends it");

    // A terminal.
    const char *tty[] = {"sbx-demo", "tty", nullptr};
    mvs_req_start(&b, &(mvs_start){.flags = MVS_S_PTY, .cols = 100, .rows = 30, .tag = "tty", .argv = tty,
                                   .nargs = 2});
    ok = sc_open(&c, SOCK, 5000) && sc_send(&c, &b);
    usleep(100 * 1000);
    const mvs_sel ts = tag_sel("tty");
    mvs_req_input(&b, &ts, MVS_IN_PTY, "abc\n", 4);
    ok = ok && simple(&b, &ek);
    mvs_req_input(&b, &ts, 0, "x", 1);
    check(!simple(&b, &ek) && ek == MVS_E_INVALID, "INPUT to stdin of a terminal's process: ERROR INVALID");
    mvs_req_resize(&b, &ts, 120, 40);
    ok = ok && simple(&b, &ek);
    mvs_req_input(&b, &ts, MVS_IN_PTY, "q\n", 2);
    ok = ok && simple(&b, &ek);
    memset(&r, 0, sizeof r);
    ok = ok && stream(&c, &r, 5000);
    sc_close(&c);
    check(ok && has(r.out, r.nout, "tty 100x30") && has(r.out, r.nout, "got: abc") && r.status == 0,
          "a terminal: its size, input, resize");
    const char *notty[] = {"sbx-demo", "tty", nullptr};
    check(exec(&r, 0, "", "", notty, nullptr, 0) && has(r.out, r.nout, "notty"), "without one: no terminal");

    // A background process: the stream is dropped, then found again.
    const char *sl[] = {"sbx-demo", "sleep", "400", nullptr};
    mvs_req_start(&b, &(mvs_start){.tag = "bg", .argv = sl, .nargs = 3});
    mvs_frame f;
    ok = sc_open(&c, SOCK, 5000) && sc_send(&c, &b) && sc_frame(&c, &f, 5000) == 1 && f.type == MVS_P_START;
    sc_close(&c);
    mvs_req_empty(&b, MVS_PS);
    bool listed = false;
    if (ok && request(&b, &f, &c) == 1) {
        do {
            mvs_proc p;
            if (f.type == MVS_PROC && mvs_dec_proc(&f, &p) && p.tag.n == 2 && !memcmp(p.tag.p, "bg", 2)) {
                const uint8_t *s = p.strs;
                const mvs_str a0 = mvs_next_str(&s);
                listed = a0.n == 8 && !memcmp(a0.p, "sbx-demo", 8) && p.nargs == 3;
            }
        } while (f.type == MVS_PROC && sc_frame(&c, &f, 5000) == 1);
        listed = listed && f.type == MVS_OK;
    }
    sc_close(&c);
    check(listed, "PS lists a running process with its tag and arguments");
    const mvs_sel bs = tag_sel("bg");
    mvs_req_sel(&b, MVS_CONNECT, &bs);
    memset(&r, 0, sizeof r);
    ok = sc_open(&c, SOCK, 5000) && sc_send(&c, &b) && stream(&c, &r, 5000);
    sc_close(&c);
    check(ok && r.started && has(r.out, r.nout, "slept") && r.status == 0,
          "CONNECT to a background process: its later output and end");
    mvs_req_sel(&b, MVS_CONNECT, &bs);
    check(!simple(&b, &ek) && ek == MVS_E_NOTFOUND, "once it has ended: ERROR NOTFOUND");

    const char *long_sl[] = {"sbx-demo", "sleep", "60000", nullptr};
    mvs_req_start(&b, &(mvs_start){.tag = "kill", .argv = long_sl, .nargs = 3});
    ok = sc_open(&c, SOCK, 5000) && sc_send(&c, &b);
    const mvs_sel ks = tag_sel("kill");
    usleep(50 * 1000);
    mvs_req_signal(&b, &ks, 9);
    ok = ok && simple(&b, &ek);
    memset(&r, 0, sizeof r);
    ok = ok && stream(&c, &r, 5000);
    sc_close(&c);
    check(ok && (r.status & 0x7f) == 9, "SIGNAL 9: the process ends, killed");

    const char *spam[] = {"sbx-demo", "spam", "8388608", nullptr};
    const double t0 = now_ms();
    check(exec(&r, 0, "", "", spam, nullptr, 0) && r.total == 8u << 20 && has(r.err, r.nerr, "end") &&
              r.status == 0,
          "8 MiB of output, all of it, then stderr, then the end");
    printf("    (8 MiB in %.0f ms)\n", now_ms() - t0);
}

static bool entry_of(const mvs_frame *f, mvs_entry *e) { return f->type == MVS_OK && mvs_dec_entry(f->body, f->len, e); }

static bool str_is(mvs_str s, const char *t) { return s.n == strlen(t) && !memcmp(s.p, t, s.n); }

static void files(void)
{
    printf("files:\n");
    sc c;
    mvs_frame f;
    mvs_entry e;
    mvs_buf b = {0};
    uint32_t ek;
    static uint8_t data[200000];
    for (size_t i = 0; i < sizeof data; i++)
        data[i] = (uint8_t)(i * 7 + i / 300);
    mvs_req_path(&b, MVS_WRITE, "user", "/home/x/dir/f.bin");
    for (size_t at = 0; at < sizeof data; at += MVS_MAX_CHUNK)
        mvs_req_data(&b, data + at, sizeof data - at < MVS_MAX_CHUNK ? sizeof data - at : MVS_MAX_CHUNK);
    mvs_req_empty(&b, MVS_DONE);
    // e's strings point into c's buffer: checked before c is closed.
    bool ok = request(&b, &f, &c) == 1 && entry_of(&f, &e);
    check(ok && e.size == sizeof data && e.uid == 1000 && e.gid == 1000 && str_is(e.path, "/home/x/dir/f.bin") &&
              str_is(e.owner, "user") && (e.mode & 0170000) == 0100000,
          "WRITE: a new file and its directories, owned by the user");
    sc_close(&c);

    mvs_req_path(&b, MVS_READ, "", "/home/x/dir/f.bin");
    uint64_t size = 0;
    static uint8_t back[sizeof data];
    size_t got = 0;
    ok = request(&b, &f, &c) == 1 && f.type == MVS_OK && mvs_dec_u64(&f, &size);
    while (ok && sc_frame(&c, &f, 5000) == 1 && f.type == MVS_DATA && got + f.len <= sizeof back) {
        memcpy(back + got, f.body, f.len);
        got += f.len;
    }
    ok = ok && f.type == MVS_DONE;
    sc_close(&c);
    check(ok && size == sizeof data && got == sizeof data && !memcmp(back, data, got), "READ: the same bytes back");

    mvs_req_path(&b, MVS_STAT, "", "/home/x/dir");
    ok = request(&b, &f, &c) == 1 && entry_of(&f, &e);
    sc_close(&c);
    check(ok && (e.mode & 0170000) == 0040000 && e.uid == 1000, "STAT a directory");
    mvs_req_path(&b, MVS_STAT, "", "/home/x/none");
    check(!simple(&b, &ek) && ek == MVS_E_NOTFOUND, "STAT a missing file: ERROR NOTFOUND");

    mvs_req_path(&b, MVS_MKDIR, "user", "/home/x/dir");
    check(!simple(&b, &ek) && ek == MVS_E_EXIST, "MKDIR of an existing directory: ERROR EXIST");
    mvs_req_path(&b, MVS_MKDIR, "user", "/home/x/new/a");
    check(simple(&b, &ek), "MKDIR with parents");

    mvs_req_list(&b, "", "/home/x", 2);
    int n = 0;
    bool seen_f = false, seen_a = false;
    ok = request(&b, &f, &c) == 1;
    while (ok && f.type == MVS_ENTRY) {
        if (mvs_dec_entry(f.body, f.len, &e)) {
            n++;
            seen_f |= str_is(e.path, "/home/x/dir/f.bin");
            seen_a |= str_is(e.path, "/home/x/new/a");
        }
        ok = sc_frame(&c, &f, 5000) == 1;
    }
    ok = ok && f.type == MVS_OK;
    sc_close(&c);
    check(ok && n == 4 && seen_f && seen_a, "LIST depth 2: dir, dir/f.bin, new, new/a");

    mvs_req_move(&b, "", "/home/x/dir/f.bin", "/home/x/moved/g.bin");
    ok = request(&b, &f, &c) == 1 && entry_of(&f, &e);
    check(ok && str_is(e.path, "/home/x/moved/g.bin") && e.size == sizeof data, "MOVE, into a new directory");
    sc_close(&c);

    mvs_req_path(&b, MVS_WRITE, "user", "rel.txt");
    mvs_req_data(&b, "hi", 2);
    mvs_req_empty(&b, MVS_DONE);
    ok = request(&b, &f, &c) == 1 && entry_of(&f, &e);
    check(ok && str_is(e.path, "/rel.txt"), "a relative path is in the user's home (/ here)");
    sc_close(&c);

    mvs_req_path(&b, MVS_REMOVE, "", "/home/x");
    check(simple(&b, &ek), "REMOVE a tree");
    mvs_req_path(&b, MVS_STAT, "", "/home/x");
    check(!simple(&b, &ek) && ek == MVS_E_NOTFOUND, "it is gone");
    mvs_req_path(&b, MVS_REMOVE, "", "/home/x");
    check(!simple(&b, &ek) && ek == MVS_E_NOTFOUND, "REMOVE of a missing path: ERROR NOTFOUND");
}

static bool write_file(const char *path, const char *text)
{
    mvs_buf b = {0};
    mvs_req_path(&b, MVS_WRITE, "", path);
    mvs_req_data(&b, text, strlen(text));
    mvs_req_empty(&b, MVS_DONE);
    uint32_t ek;
    return simple(&b, &ek);
}

static void watching(void)
{
    printf("watching:\n");
    mvs_buf b = {0};
    uint32_t ek;
    mvs_req_path(&b, MVS_MKDIR, "", "/w");
    simple(&b, &ek);
    sc c;
    mvs_frame f;
    mvs_req_watch(&b, "", "/w", MVS_W_RECURSIVE);
    bool ok = request(&b, &f, &c) == 1 && f.type == MVS_OK;
    check(ok, "WATCH: OK");
    write_file("/w/a.txt", "1");
    mvs_req_path(&b, MVS_MKDIR, "", "/w/sub");
    simple(&b, &ek);
    usleep(50 * 1000);
    write_file("/w/sub/b.txt", "2");
    mvs_req_path(&b, MVS_REMOVE, "", "/w/a.txt");
    simple(&b, &ek);
    bool create_a = false, write_a = false, create_sub = false, create_b = false, remove_a = false, entry = false;
    while (ok && sc_frame(&c, &f, 500) == 1) {
        mvs_wevent w;
        if (!mvs_dec_wevent(&f, &w)) {
            ok = false;
            break;
        }
        create_a |= w.event == MVS_EV_CREATE && str_is(w.name, "a.txt");
        entry |= w.event == MVS_EV_CREATE && str_is(w.name, "a.txt") && w.has_entry && str_is(w.entry.path, "/w/a.txt");
        write_a |= w.event == MVS_EV_WRITE && str_is(w.name, "a.txt");
        create_sub |= w.event == MVS_EV_CREATE && str_is(w.name, "sub");
        create_b |= w.event == MVS_EV_CREATE && str_is(w.name, "sub/b.txt");
        remove_a |= w.event == MVS_EV_REMOVE && str_is(w.name, "a.txt") && !w.has_entry;
    }
    sc_close(&c);
    check(ok && create_a && entry && write_a && create_sub, "events: create (with its entry), write, a new directory");
    check(create_b, "recursive: an event in the new subdirectory");
    check(remove_a, "remove, without an entry");
}

static void ports(void)
{
    printf("ports:\n");
    sc c, s;
    mvs_frame f;
    mvs_buf b = {0};
    const char *srv[] = {"sbx-demo", "serve", "8080", nullptr};
    mvs_req_start(&b, &(mvs_start){.tag = "srv", .argv = srv, .nargs = 3});
    run r = {0};
    bool ok = sc_open(&s, SOCK, 5000) && sc_send(&s, &b);
    for (int i = 0; ok && i < 3 && !has(r.out, r.nout, "listening"); i++) {
        if (sc_frame(&s, &f, 2000) != 1)
            ok = false;
        else if (f.type == MVS_P_STDOUT) {
            memcpy(r.out + r.nout, f.body, f.len < 100 ? f.len : 100);
            r.nout += f.len < 100 ? f.len : 100;
        }
    }
    mvs_req_port(&b, 8080);
    ok = ok && request(&b, &f, &c) == 1 && f.type == MVS_OK;
    char got[64] = {0};
    size_t n = c.r.len - c.r.off; // raw bytes after OK
    memcpy(got, c.r.buf + c.r.off, n < 63 ? n : 63);
    while (ok && n < 11) {
        struct pollfd p = {.fd = c.fd, .events = POLLIN};
        ssize_t k = poll(&p, 1, 2000) > 0 ? recv(c.fd, got + n, 63 - n, 0) : -1;
        if (k <= 0)
            ok = false;
        else
            n += (size_t)k;
    }
    if (getenv("SBX_DEBUG"))
        printf("    [port: ok %d got %zu '%s' out '%.*s']\n", ok, n, got, (int)r.nout, r.out);
    check(ok && !strcmp(got, "hello 8080\n"), "PORT_CONNECT: the guest server's greeting");
    ok = ok && send(c.fd, "ping", 4, MSG_NOSIGNAL) == 4;
    memset(got, 0, sizeof got);
    n = 0;
    while (ok && n < 4) {
        struct pollfd p = {.fd = c.fd, .events = POLLIN};
        ssize_t k = poll(&p, 1, 2000) > 0 ? recv(c.fd, got + n, 63 - n, 0) : -1;
        if (k <= 0)
            ok = false;
        else
            n += (size_t)k;
    }
    check(ok && !strcmp(got, "ping"), "bytes both ways");
    shutdown(c.fd, SHUT_WR);
    struct pollfd p = {.fd = c.fd, .events = POLLIN};
    char x;
    check(poll(&p, 1, 2000) > 0 && recv(c.fd, &x, 1, 0) == 0, "the host's end: the guest's side ends too");
    sc_close(&c);
    mvs_req_port(&b, 9);
    uint32_t ek;
    check(!simple(&b, &ek) && ek != 0, "a port nobody listens on: ERROR");
    const mvs_sel ss = tag_sel("srv");
    mvs_req_signal(&b, &ss, 9);
    simple(&b, &ek);
    sc_close(&s);
}

static bool rand_of(char out[33])
{
    run r;
    const char *rd[] = {"sbx-demo", "rand", nullptr};
    if (!exec(&r, 0, "", "", rd, nullptr, 0) || r.nout != 33)
        return false;
    memcpy(out, r.out, 32);
    out[32] = 0;
    return true;
}

// Every vCPU runs a process: probe moves to each in turn.
static bool all_cpus(void)
{
    run r;
    const char *pc[] = {"probe", "cpus", nullptr};
    char want[48];
    snprintf(want, sizeof want, " cpus: %s ran on: %s ", CPUS, CPUS);
    const bool ok = exec(&r, 0, "", "", pc, nullptr, 0) && r.status == 0 && has(r.out, r.nout, want);
    if (!ok)
        printf("    [probe cpus: '%.*s', want '%s']\n", (int)r.nout, r.out, want);
    return ok;
}

// The guest's SNAPSHOT, saved by v's VMM: true once it stopped with status 0.
static bool pause_vm(vmproc *v)
{
    mvs_buf b = {0};
    mvs_req_empty(&b, MVS_SNAPSHOT);
    sc c;
    const bool ok = sc_open(&c, SOCK, 5000) && sc_send(&c, &b);
    const int st = reap_vm(v, 10000, nullptr, 0);
    sc_close(&c);
    return ok && st == 0;
}

static bool read_is(const char *path, const char *text)
{
    mvs_buf b = {0};
    mvs_frame f;
    sc c;
    mvs_req_path(&b, MVS_READ, "", path);
    const size_t n = strlen(text);
    const bool ok = request(&b, &f, &c) == 1 && f.type == MVS_OK && sc_frame(&c, &f, 2000) == 1 &&
                    f.type == MVS_DATA && f.len == n && !memcmp(f.body, text, n);
    sc_close(&c);
    return ok;
}

// A snapshot file's version (1 full, 2 diff), or -1.
static int snap_version(const char *path)
{
    unsigned char h[12];
    const int fd = open(path, O_RDONLY);
    const bool ok = fd >= 0 && pread(fd, h, sizeof h, 0) == (ssize_t)sizeof h && !memcmp(h, "MVMSNAP", 8);
    if (fd >= 0)
        close(fd);
    return ok ? h[8] | h[9] << 8 | h[10] << 16 | h[11] << 24 : -1;
}

static bool up(vmproc *v, const char *tag, const char *const *args)
{
    spawn(v, tag, args);
    SOCK = v->sock;
    sc h;
    const bool ok = sc_open(&h, SOCK, 5000);
    sc_close(&h);
    return ok;
}

// A restore that must be refused: the VMM stops with an error naming why.
static bool refused(const char *tag, const char *const *args, const char *why)
{
    vmproc v;
    spawn(&v, tag, args);
    char out[2048];
    const int st = reap_vm(&v, 10000, out, sizeof out);
    if (st == 0 || !strstr(out, why))
        printf("  status %d; console:\n%s\n", st, out);
    return st != 0 && strstr(out, why);
}

// --snapshot-diff: a VM restored from snap saves only the pages it
// changed; one restored from that diff (and snap, its base) saves another
// diff of snap, which alone has everything: never a chain.
static void diffs(void)
{
    char d1[160], d2[160];
    snprintf(d1, sizeof d1, "%s/d1", dir);
    snprintf(d2, sizeof d2, "%s/d2", dir);
    vmproc v;
    const char *const a1[] = {"--restore", snap, "--rootfs", IMG, "--vsock", "@SOCK",
                              "--snapshot", d1, "--snapshot-diff", nullptr};
    bool ok = up(&v, "d1", a1) && write_file("/d1.txt", "one") && pause_vm(&v);
    struct stat full, diff;
    check(ok && snap_version(d1) == 2 && !stat(snap, &full) && !stat(d1, &diff) && diff.st_blocks < full.st_blocks,
          "--snapshot-diff after a restore: a diff, smaller than the full snapshot");
    printf("    (full %lld KiB on disk, diff %lld KiB)\n", (long long)full.st_blocks / 2,
           (long long)diff.st_blocks / 2);

    const char *const a2[] = {"--restore", d1, "--base", snap, "--rootfs", IMG, "--vsock", "@SOCK",
                              "--snapshot", d2, "--snapshot-diff", nullptr};
    ok = up(&v, "d2", a2) && read_is("/kept.txt", "kept") && read_is("/d1.txt", "one") &&
         write_file("/d2.txt", "two") && pause_vm(&v);
    check(ok && snap_version(d2) == 2, "restored from the diff and its base: files kept; saves a diff again");
    unlink(d1);
    const char *const a3[] = {"--restore", d2, "--base", snap, "--rootfs", IMG, "--vsock", "@SOCK", nullptr};
    ok = up(&v, "d3", a3) && read_is("/kept.txt", "kept") && read_is("/d1.txt", "one") &&
         read_is("/d2.txt", "two");
    kill(v.pid, SIGKILL);
    reap_vm(&v, 2000, nullptr, 0);
    check(ok, "that diff and the base alone have everything (the first diff is gone)");

    const char *const nobase[] = {"--restore", d2, "--rootfs", IMG, "--vsock", "@SOCK", nullptr};
    const char *const diffbase[] = {"--restore", d2, "--base", d2, "--rootfs", IMG, "--vsock", "@SOCK", nullptr};
    const char *const other[] = {"--restore", d2, "--base", snap, "--rootfs", IMG, "--vsock", "@SOCK", nullptr};
    ok = refused("n1", nobase, "--base") && refused("n2", diffbase, "not a full snapshot");
    // Another full snapshot as the base: snap with another id.
    const int fd = open(snap, O_RDWR);
    unsigned char id;
    bool flipped = fd >= 0 && pread(fd, &id, 1, 80) == 1 && (id ^= 1, pwrite(fd, &id, 1, 80) == 1);
    ok = ok && flipped && refused("n3", other, "not the snapshot");
    if (flipped)
        id ^= 1, flipped = pwrite(fd, &id, 1, 80) != 1;
    if (fd >= 0)
        close(fd);
    check(ok && !flipped, "refused: a diff without --base, a diff as the base, another snapshot as the base");
    unlink(d2);
}

static void snapshots(void)
{
    printf("snapshot (pause) and restores:\n");
    snprintf(snap, sizeof snap, "%s/snap", dir);
    vmproc v;
    const char *const args[] = {"--kernel", K, "--quiet", "--mem", "256", "--cpus", CPUS, "--rootfs", IMG,
                                "--vsock", "@SOCK", "--append", "sandbox", "--snapshot", snap, nullptr};
    spawn(&v, "take", args);
    SOCK = v.sock;
    mvs_buf b = {0};
    const char *sl[] = {"sbx-demo", "sleep", "1500", nullptr};
    mvs_req_start(&b, &(mvs_start){.tag = "survivor", .argv = sl, .nargs = 3});
    sc c;
    mvs_frame f;
    bool ok = request(&b, &f, &c) == 1 && f.type == MVS_P_START;
    sc_close(&c);
    ok = ok && write_file("/kept.txt", "kept");
    mvs_req_empty(&b, MVS_SNAPSHOT);
    ok = ok && sc_open(&c, SOCK, 5000) && sc_send(&c, &b);
    char out[4096];
    const int st = reap_vm(&v, 10000, out, sizeof out);
    sc_close(&c);
    struct stat sb;
    check(ok && st == 0 && !stat(snap, &sb) && sb.st_size > 0, "SNAPSHOT: the VMM saved the VM and stopped");
    if (st)
        printf("  status %d; console:\n%s\n", st, out);
    char r1[33] = {0}, r2[33] = {0};
    bool all = true;
    for (int i = 0; i < 2; i++) {
        char tag[16];
        snprintf(tag, sizeof tag, "r%d", i);
        const char *const ra[] = {"--restore", snap, "--rootfs", IMG, "--vsock", "@SOCK", nullptr};
        spawn(&v, tag, ra);
        SOCK = v.sock;
        const double t0 = now_ms();
        sc h;
        const bool up = sc_open(&h, SOCK, 5000);
        const double t1 = now_ms();
        sc_close(&h);
        printf("    (restore %d: connected in %.1f ms)\n", i, t1 - t0);
        all = all && up && h.resumes == 1;
        // The process started before the snapshot goes on, and ends.
        const mvs_sel ss = tag_sel("survivor");
        mvs_req_sel(&b, MVS_CONNECT, &ss);
        run r = {0};
        all = all && sc_open(&c, SOCK, 5000) && sc_send(&c, &b) && stream(&c, &r, 5000) &&
              has(r.out, r.nout, "slept");
        sc_close(&c);
        mvs_req_path(&b, MVS_READ, "", "/kept.txt");
        all = all && request(&b, &f, &c) == 1 && f.type == MVS_OK && sc_frame(&c, &f, 2000) == 1 &&
              f.type == MVS_DATA && f.len == 4 && !memcmp(f.body, "kept", 4);
        sc_close(&c);
        all = all && rand_of(i ? r2 : r1) && all_cpus();
        kill(v.pid, SIGKILL);
        reap_vm(&v, 2000, nullptr, 0);
    }
    check(all, "each restore: HELLO says resumed, the process goes on, files kept, every vCPU runs");
    check(r1[0] && r2[0] && strcmp(r1, r2), "restores don't share random numbers");
    diffs();
    unlink(snap);
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: mvm_sbx_tests MICROVM VMLINUX IMAGE [--cpus N] [--jail MICROVM-JAIL]\n");
        return 2;
    }
    setvbuf(stdout, nullptr, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    jw.jail = jw_take_arg(&argc, argv);
    for (int i = 1; i + 1 < argc; i++)
        if (!strcmp(argv[i], "--cpus")) {
            CPUS = argv[i + 1];
            for (int k = i; k + 2 <= argc; k++)
                argv[k] = argv[k + 2];
            argc -= 2;
            break;
        }
    if (argc < 4)
        return 2;
    K = argv[2];
    IMG = argv[3];
    if (access("/dev/kvm", R_OK | W_OK)) {
        printf("skipped: no usable /dev/kvm\n");
        return 77;
    }
    if (jw.jail && !jw_usable()) {
        printf("skipped: microvm-jail needs root or unprivileged user namespaces\n");
        return 77;
    }
    if (!mkdtemp(dir))
        return 1;
    jw.vmm = argv[1], jw.kernel = K, jw.rootfs = IMG, jw.dir = dir;
    if (jw.jail)
        chmod(dir, 0777);
    vmproc v;
    const char *const args[] = {"--kernel", K, "--quiet", "--mem", "256", "--cpus", CPUS, "--rootfs", IMG,
                                "--vsock", "@SOCK", "--append", "sandbox", nullptr};
    const double t0 = now_ms();
    spawn(&v, "main", args);
    SOCK = v.sock;
    sc h;
    if (!sc_open(&h, SOCK, 10000)) {
        char out[4096];
        reap_vm(&v, 100, out, sizeof out);
        printf("the sandbox agent never answered; console:\n%s\n", out);
        return 1;
    }
    printf("  (boot -> agent answers: %.1f ms)\n", now_ms() - t0);
    sc_close(&h);
    check(all_cpus(), "every vCPU runs a process");
    processes();
    files();
    watching();
    ports();
    kill(v.pid, SIGKILL);
    char out[8192];
    reap_vm(&v, 2000, out, sizeof out);
    if (fails)
        printf("console:\n%s\n", out);
    snapshots();
    rmdir(dir);
    printf("%s (%d failed)\n", fails ? "FAIL" : "ok", fails);
    return fails ? 1 : 0;
}
