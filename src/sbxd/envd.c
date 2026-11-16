// SPDX-License-Identifier: MIT
// microvm-sbxd: E2B's envd API (Connect protocol, JSON codec, over
// HTTP/1.1), served by the sandbox's agent (/init sandbox) one guest
// operation per call. The services: process.Process (Start, Connect,
// List, SendInput, StreamInput, SendSignal, CloseStdin, Update),
// filesystem.Filesystem (Stat, MakeDir, Move, ListDir, Remove, WatchDir,
// CreateWatcher, GetWatcherEvents, RemoveWatcher), and the plain HTTP
// /files (download, multipart and octet-stream uploads, gzip) and /health.
//
// What the guest sends is checked by src/sbx/wire.c before anything here
// sees it; its strings may be anything (invalid UTF-8 becomes U+FFFD in
// JSON).
#include "sbxd/sbxd.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "image/inflate.h"
#include "image/json.h"

enum {
    M_NONE,
    M_START, M_CONNECT, M_LIST, M_SEND_INPUT, M_STREAM_INPUT, M_SIGNAL, M_CLOSE_STDIN, M_UPDATE,
    M_STAT, M_MKDIR, M_MOVE, M_LISTDIR, M_REMOVE, M_WATCHDIR, M_CREATE_WATCHER, M_GET_EVENTS, M_REMOVE_WATCHER,
    M_FILES_GET, M_FILES_PUT, M_EXPORT,
};

static const struct {
    const char *path;
    int m;
    bool stream; // server streaming (or client streaming: StreamInput)
} RPCS[] = {
    {"/process.Process/Start", M_START, true},
    {"/process.Process/Connect", M_CONNECT, true},
    {"/process.Process/List", M_LIST, false},
    {"/process.Process/SendInput", M_SEND_INPUT, false},
    {"/process.Process/StreamInput", M_STREAM_INPUT, true},
    {"/process.Process/SendSignal", M_SIGNAL, false},
    {"/process.Process/CloseStdin", M_CLOSE_STDIN, false},
    {"/process.Process/Update", M_UPDATE, false},
    {"/filesystem.Filesystem/Stat", M_STAT, false},
    {"/filesystem.Filesystem/MakeDir", M_MKDIR, false},
    {"/filesystem.Filesystem/Move", M_MOVE, false},
    {"/filesystem.Filesystem/ListDir", M_LISTDIR, false},
    {"/filesystem.Filesystem/Remove", M_REMOVE, false},
    {"/filesystem.Filesystem/WatchDir", M_WATCHDIR, true},
    {"/filesystem.Filesystem/CreateWatcher", M_CREATE_WATCHER, false},
    {"/filesystem.Filesystem/GetWatcherEvents", M_GET_EVENTS, false},
    {"/filesystem.Filesystem/RemoveWatcher", M_REMOVE_WATCHER, false},
};

enum : size_t {
    MAX_WATCH_EVENTS = 65536,
    MAX_WATCH_BYTES = 4u << 20,
    MAX_GZIP_BODY = 64u << 20,
    INPUT_CHUNK = 512u << 10,
};

// --- Connect errors ------------------------------------------------------------------

static int code_status(const char *code)
{
    static const struct {
        const char *c;
        int s;
    } map[] = {
        {"canceled", 499}, {"unknown", 500}, {"invalid_argument", 400}, {"deadline_exceeded", 504},
        {"not_found", 404}, {"already_exists", 409}, {"permission_denied", 403}, {"resource_exhausted", 429},
        {"failed_precondition", 400}, {"aborted", 409}, {"out_of_range", 400}, {"unimplemented", 501},
        {"internal", 500}, {"unavailable", 503}, {"data_loss", 500}, {"unauthenticated", 401},
    };
    for (size_t i = 0; i < sizeof map / sizeof *map; i++)
        if (!strcmp(map[i].c, code))
            return map[i].s;
    return 500;
}

static void error_json(sbuf *b, const char *code, const char *msg)
{
    sb_puts(b, "{\"code\":");
    jw_cstr(b, code);
    sb_puts(b, ",\"message\":");
    jw_cstr(b, msg);
    sb_puts(b, "}");
}

static void stream_begin(hconn *h)
{
    if (h->rq.started)
        return;
    h->rq.started = true;
    h->rq.last_out = now_ms();
    h_stream_begin(h, 200, "application/connect+json");
}

// One envelope: flags, big-endian length, the message.
static void envelope(hconn *h, uint8_t flags, const sbuf *msg)
{
    if (h->st == H_DEAD)
        return;
    if (msg->oom) {
        h_close(h);
        return;
    }
    sbuf e = {0};
    const uint8_t hd[5] = {flags, (uint8_t)(msg->len >> 24), (uint8_t)(msg->len >> 16), (uint8_t)(msg->len >> 8),
                           (uint8_t)msg->len};
    sb_put(&e, hd, 5);
    sb_put(&e, msg->p, msg->len);
    if (e.oom) {
        sb_free(&e);
        h_close(h);
        return;
    }
    h_chunk(h, e.p, e.len);
    sb_free(&e);
    h->rq.last_out = now_ms();
    if (h->st != H_DEAD && h->g && h_pending(h) >= G_HIGH)
        g_pause(h->g, true);
}

static void stream_msg(hconn *h, const sbuf *msg)
{
    stream_begin(h);
    envelope(h, 0, msg);
}

static void stream_end(hconn *h, const char *code, const char *msg)
{
    stream_begin(h);
    sbuf b = {0};
    if (code) {
        sb_puts(&b, "{\"error\":");
        error_json(&b, code, msg);
        sb_puts(&b, "}");
    } else {
        sb_puts(&b, "{}");
    }
    envelope(h, 2, &b);
    sb_free(&b);
    h_stream_end(h);
}

void connect_error(hconn *h, bool stream, const char *code, const char *msg)
{
    if (h->st == H_DEAD)
        return;
    if (stream) {
        stream_end(h, code, msg);
        return;
    }
    sbuf b = {0};
    error_json(&b, code, msg);
    // A 502 is how the SDKs learn the sandbox is gone (see main.c).
    const bool gone = !strcmp(code, "unavailable") && strstr(msg, "was not found");
    h_respond(h, gone ? 502 : code_status(code), "application/json", b.p, b.len, nullptr);
    sb_free(&b);
}

static bool is_stream(const hconn *h)
{
    const int m = h->rq.method;
    return m == M_START || m == M_CONNECT || m == M_WATCHDIR || m == M_STREAM_INPUT;
}

static void rpc_error(hconn *h, const char *code, const char *msg) { connect_error(h, is_stream(h), code, msg); }

// /files errors: E2B's REST form, {"code": status, "message": ...}.
static void files_error(hconn *h, int status, const char *msg)
{
    h_api_error(h, status, msg);
}

// The guest's ERROR, as a Connect code and an HTTP status.
static void guest_error(const mvs_frame *f, const char **code, int *status, char *msg, size_t cap)
{
    mvs_error e = {0};
    if (!mvs_dec_error(f, &e)) {
        *code = "internal", *status = 500;
        snprintf(msg, cap, "the sandbox answered nonsense");
        return;
    }
    switch (e.kind) {
    case MVS_E_INVALID: *code = "invalid_argument", *status = 400; break;
    case MVS_E_NOTFOUND: *code = "not_found", *status = 404; break;
    case MVS_E_EXIST: *code = "already_exists", *status = 409; break;
    case MVS_E_DENIED: *code = "permission_denied", *status = 403; break;
    case MVS_E_LIMIT: *code = "resource_exhausted", *status = 429; break;
    default:
        *code = "internal", *status = 500;
        if (e.err == (uint32_t)-ENOSPC || e.err == ENOSPC)
            *code = "resource_exhausted", *status = 507;
    }
    const size_t n = e.msg.n < 200 ? e.msg.n : 200;
    // The guest's words, kept printable.
    size_t k = 0;
    for (size_t i = 0; i < n && k + 1 < cap; i++) {
        const char c = e.msg.p[i];
        msg[k++] = (unsigned char)c >= 0x20 && (unsigned char)c < 0x7f ? c : '?';
    }
    msg[k] = 0;
}

static void rpc_guest_error(hconn *h, const mvs_frame *f)
{
    const char *code;
    int status;
    char msg[256];
    guest_error(f, &code, &status, msg, sizeof msg);
    rpc_error(h, code, msg);
}

// --- JSON in -----------------------------------------------------------------------

// A field by its JSON name or its proto name.
static const json_value *jf(const json_value *o, const char *camel, const char *snake)
{
    const json_value *v = json_get(o, camel);
    return v ? v : snake ? json_get(o, snake) : nullptr;
}

// ProtoJSON integers: numbers, or decimal strings.
static bool jint(const json_value *v, int64_t *out)
{
    if (!v || (v->type != JSON_NUMBER && v->type != JSON_STRING))
        return false;
    const char *s = v->str;
    const size_t n = v->len;
    if (!n || n > 19)
        return false;
    size_t i = 0;
    bool neg = false;
    if (s[0] == '-')
        neg = true, i = 1;
    if (i == n)
        return false;
    int64_t x = 0;
    for (; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        x = x * 10 + (s[i] - '0');
    }
    *out = neg ? -x : x;
    return true;
}

static bool jbool(const json_value *v) { return v && v->type == JSON_TRUE; }

static const char *jstr(const json_value *v) { return v && v->type == JSON_STRING ? json_cstr(v) : nullptr; }

// A unary request's body, or a server-streaming request's one envelope.
static const json_value *rpc_message(hconn *h, json_doc **doc, const char **err)
{
    *doc = nullptr;
    const uint8_t *p = (const uint8_t *)h->body.p;
    size_t n = h->body.len;
    if (is_stream(h)) {
        if (n < 5 || (p[0] & 1) || ((size_t)p[1] << 24 | (size_t)p[2] << 16 | (size_t)p[3] << 8 | p[4]) != n - 5) {
            *err = "expected one uncompressed envelope";
            return nullptr;
        }
        p += 5, n -= 5;
    }
    if (!n) { // an empty body is the empty message
        static const char empty[] = "{}";
        p = (const uint8_t *)empty, n = 2;
    }
    const json_limits lim = {16u << 20, 32, 1u << 18};
    *doc = json_parse(p, n, &lim, err);
    if (!*doc)
        return nullptr;
    const json_value *root = json_root(*doc);
    if (root->type != JSON_OBJECT) {
        *err = "the message is not a JSON object";
        return nullptr;
    }
    return root;
}

static bool selector(hconn *h, const json_value *sel)
{
    int64_t pid;
    const char *tag = jstr(json_get(sel, "tag"));
    if (jint(json_get(sel, "pid"), &pid) && pid > 0 && pid <= INT32_MAX) {
        h->rq.sel_kind = MVS_SEL_PID, h->rq.sel_pid = (uint32_t)pid;
        return true;
    }
    if (tag && tag[0] && strlen(tag) < sizeof h->rq.sel_tag) {
        h->rq.sel_kind = MVS_SEL_TAG;
        strcpy(h->rq.sel_tag, tag);
        return true;
    }
    return false;
}

static mvs_sel sel_of(const hconn *h)
{
    return (mvs_sel){.kind = h->rq.sel_kind, .pid = h->rq.sel_pid, .tag = h->rq.sel_tag};
}

// "Basic base64(user:)", or the template's default user.
static bool user_of(hconn *h, const sandbox *sb, const char *explicit_user)
{
    const char *u = explicit_user;
    char dec[128];
    if (!u) {
        const char *a = http_header(&h->req, "authorization");
        if (a) {
            if (strncmp(a, "Basic ", 6))
                return false;
            size_t n;
            if (!b64_decode(a + 6, strlen(a + 6), (uint8_t *)dec, sizeof dec - 1, &n))
                return false;
            dec[n] = 0;
            char *colon = memchr(dec, ':', n);
            if (colon)
                *colon = 0;
            u = dec;
        }
    }
    if (!u || !u[0])
        u = sb->t->user;
    const size_t n = strlen(u);
    if (n >= sizeof h->rq.user)
        return false;
    for (size_t i = 0; i < n; i++) {
        const char c = u[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' ||
              c == '.' || (c == '$' && i == n - 1)))
            return false;
    }
    strcpy(h->rq.user, u);
    return true;
}

// --- JSON out ------------------------------------------------------------------------

static void entry_json(sbuf *b, const mvs_entry *e)
{
    bool f = true;
    sb_puts(b, "{");
    // name: the last component (the path is absolute and clean).
    size_t s = e->path.n;
    while (s && e->path.p[s - 1] != '/')
        s--;
    jw_key(b, &f, "name");
    if (s == e->path.n)
        jw_cstr(b, "/");
    else
        jw_str(b, e->path.p + s, e->path.n - s);
    const uint32_t fmt = e->mode & S_IFMT;
    const bool sym = e->flags & MVS_E_SYMLINK;
    const char *type = fmt == S_IFDIR ? "FILE_TYPE_DIRECTORY" : fmt == S_IFREG ? "FILE_TYPE_FILE"
                       : sym          ? "FILE_TYPE_SYMLINK"
                                      : nullptr;
    if (type)
        jw_key(b, &f, "type"), jw_cstr(b, type);
    jw_key(b, &f, "path"), jw_str(b, e->path.p, e->path.n);
    if (e->size)
        jw_key(b, &f, "size"), sb_printf(b, "\"%llu\"", (unsigned long long)e->size);
    if (e->mode & 07777)
        jw_key(b, &f, "mode"), sb_printf(b, "%u", e->mode & 07777);
    char perm[11];
    perm[0] = sym ? 'L' : fmt == S_IFDIR ? 'd' : fmt == S_IFREG ? '-' : fmt == S_IFLNK ? 'L' : fmt == S_IFIFO ? 'p'
              : fmt == S_IFSOCK ? 'S' : fmt == S_IFCHR ? 'c' : fmt == S_IFBLK ? 'D' : '?';
    for (int i = 0; i < 9; i++)
        perm[1 + i] = e->mode & (0400u >> i) ? "rwxrwxrwx"[i] : '-';
    perm[10] = 0;
    jw_key(b, &f, "permissions"), jw_cstr(b, perm);
    if (e->owner.n)
        jw_key(b, &f, "owner"), jw_str(b, e->owner.p, e->owner.n);
    if (e->group.n)
        jw_key(b, &f, "group"), jw_str(b, e->group.p, e->group.n);
    jw_key(b, &f, "modifiedTime"), jw_time(b, e->mtime_sec, e->mtime_nsec < 1000000000u ? e->mtime_nsec : 0);
    if (sym) {
        jw_key(b, &f, "symlinkTarget"), jw_str(b, e->target.p, e->target.n);
        jw_key(b, &f, "isSymlink"), sb_puts(b, "true");
    }
    sb_puts(b, "}");
}

static const char *event_name(uint32_t ev)
{
    switch (ev) {
    case MVS_EV_CREATE: return "EVENT_TYPE_CREATE";
    case MVS_EV_WRITE: return "EVENT_TYPE_WRITE";
    case MVS_EV_REMOVE: return "EVENT_TYPE_REMOVE";
    case MVS_EV_RENAME: return "EVENT_TYPE_RENAME";
    case MVS_EV_CHMOD: return "EVENT_TYPE_CHMOD";
    default: return nullptr;
    }
}

// A FilesystemEvent; false if it isn't one the API knows.
static bool fs_event_json(sbuf *b, const mvs_wevent *w, bool include_entry)
{
    const char *t = event_name(w->event);
    if (!t)
        return false;
    sb_puts(b, "{\"name\":");
    jw_str(b, w->name.p, w->name.n);
    sb_puts(b, ",\"type\":");
    jw_cstr(b, t);
    if (include_entry && w->has_entry) {
        sb_puts(b, ",\"entry\":");
        entry_json(b, &w->entry);
    }
    sb_puts(b, "}");
    return true;
}

static void proc_json(sbuf *b, const mvs_proc *p)
{
    sb_puts(b, "{\"config\":{");
    const uint8_t *s = p->strs;
    bool f = true;
    for (uint16_t i = 0; i < p->nargs; i++) {
        const mvs_str a = mvs_next_str(&s);
        if (i == 0) {
            jw_key(b, &f, "cmd"), jw_str(b, a.p, a.n);
            if (p->nargs > 1)
                jw_key(b, &f, "args"), sb_puts(b, "[");
        } else {
            if (i > 1)
                sb_puts(b, ",");
            jw_str(b, a.p, a.n);
        }
    }
    if (p->nargs > 1)
        sb_puts(b, "]");
    if (p->nenv) {
        jw_key(b, &f, "envs");
        sb_puts(b, "{");
        bool g = true;
        for (uint16_t i = 0; i < p->nenv; i++) {
            const mvs_str e = mvs_next_str(&s);
            const char *eq = memchr(e.p, '=', e.n);
            const size_t kl = eq ? (size_t)(eq - e.p) : e.n;
            if (!g)
                sb_puts(b, ",");
            g = false;
            jw_str(b, e.p, kl);
            sb_puts(b, ":");
            jw_str(b, eq ? eq + 1 : "", eq ? e.n - kl - 1 : 0);
        }
        sb_puts(b, "}");
    }
    if (p->cwd.n)
        jw_key(b, &f, "cwd"), jw_str(b, p->cwd.p, p->cwd.n);
    sb_printf(b, "},\"pid\":%u", p->pid);
    if (p->tag.n) {
        sb_puts(b, ",\"tag\":");
        jw_str(b, p->tag.p, p->tag.n);
    }
    sb_puts(b, "}");
}

// The end of a process, as Go's os.ProcessState puts it (envd is Go).
static void end_event(sbuf *b, uint32_t st)
{
    sb_puts(b, "{\"event\":{\"end\":{");
    if (WIFEXITED(st)) {
        const int code = WEXITSTATUS(st);
        if (code)
            sb_printf(b, "\"exitCode\":%d,", code);
        sb_printf(b, "\"exited\":true,\"status\":\"exit status %d\"", code);
    } else {
        static const char *const names[] = {[1] = "hangup", [2] = "interrupt", [3] = "quit", [4] = "illegal instruction",
                                            [6] = "aborted", [7] = "bus error", [8] = "floating point exception",
                                            [9] = "killed", [11] = "segmentation fault", [13] = "broken pipe",
                                            [14] = "alarm clock", [15] = "terminated"};
        const int sig = WIFSIGNALED(st) ? WTERMSIG(st) : 0;
        if (sig > 0 && sig < (int)(sizeof names / sizeof *names) && names[sig])
            sb_printf(b, "\"exitCode\":-1,\"status\":\"signal: %s\"", names[sig]);
        else
            sb_printf(b, "\"exitCode\":-1,\"status\":\"signal: %d\"", sig);
    }
    sb_puts(b, "}}}");
}

// --- watchers (the Python SDK's polling API) -------------------------------------

struct watcher {
    char id[24];
    sandbox *sb;
    gconn *g;
    hconn *creating; // the CreateWatcher request, until the agent says OK
    sbuf events;     // FilesystemEvent JSON, comma-separated
    size_t nevents;
    bool include_entry, ended, overflow;
    watcher *next;
};

static void watcher_free(void *p)
{
    watcher *w = p;
    sb_free(&w->events);
    free(w);
}

static void watcher_remove(watcher *w)
{
    if (w->sb)
        for (watcher **pp = &w->sb->watchers; *pp; pp = &(*pp)->next)
            if (*pp == w) {
                *pp = w->next;
                break;
            }
    w->sb = nullptr;
    g_close(w->g);
    w->g = nullptr;
    graveyard_add(w, watcher_free);
}

static void w_frame(gconn *g, const mvs_frame *f)
{
    watcher *w = g->ctx;
    if (w->creating) {
        hconn *h = w->creating;
        w->creating = nullptr;
        h->rq.sb = nullptr;
        if (f->type != MVS_OK) {
            h->g = nullptr;
            rpc_guest_error(h, f);
            watcher_remove(w);
            return;
        }
        sbuf b = {0};
        sb_puts(&b, "{\"watcherId\":");
        jw_cstr(&b, w->id);
        sb_puts(&b, "}");
        h->g = nullptr; // the watch belongs to the watcher now
        h_respond(h, 200, "application/json", b.p, b.len, nullptr);
        sb_free(&b);
        return;
    }
    mvs_wevent ev;
    if (f->type != MVS_W_EVENT || !mvs_dec_wevent(f, &ev))
        return;
    if (w->nevents >= MAX_WATCH_EVENTS || w->events.len >= MAX_WATCH_BYTES) {
        w->overflow = true;
        return;
    }
    const size_t mark = w->events.len;
    if (w->nevents)
        sb_puts(&w->events, ",");
    if (!fs_event_json(&w->events, &ev, w->include_entry)) {
        w->events.len = mark;
        return;
    }
    w->nevents++;
}

static void w_end(gconn *g, const char *why)
{
    watcher *w = g->ctx;
    (void)why;
    w->g = nullptr;
    w->ended = true;
    if (w->creating) {
        hconn *h = w->creating;
        w->creating = nullptr;
        h->g = nullptr;
        rpc_error(h, "unavailable", "the sandbox closed the connection");
        watcher_remove(w);
    }
}

static const gconn_ops watcher_ops = {.frame = w_frame, .end = w_end};

void watchers_close(sandbox *sb)
{
    while (sb->watchers) {
        watcher *w = sb->watchers;
        if (w->creating) {
            hconn *h = w->creating;
            w->creating = nullptr;
            h->g = nullptr;
            rpc_error(h, "unavailable", "the sandbox was not found");
        }
        watcher_remove(w);
    }
}

static watcher *watcher_find(sandbox *sb, const char *id)
{
    for (watcher *w = sb->watchers; w; w = w->next)
        if (!strcmp(w->id, id))
            return w;
    return nullptr;
}

// --- guest operations for requests ------------------------------------------------

static const gconn_ops envd_ops;

static bool op_open(hconn *h, sandbox *sb, mvs_buf *req)
{
    bool retry;
    gconn *g = g_open(sb, &envd_ops, h, &retry);
    if (!g) {
        mvs_buf_free(req);
        if (h->rq.method == M_FILES_GET || h->rq.method == M_FILES_PUT || h->rq.method == M_EXPORT)
            files_error(h, 502, "the sandbox is unreachable");
        else
            rpc_error(h, "unavailable", "the sandbox is unreachable");
        return false;
    }
    h->g = g;
    g_send(g, req);
    return true;
}

static void files_put_pump(hconn *h);
static void input_pump(hconn *h);

static void e_frame(gconn *g, const mvs_frame *f)
{
    hconn *h = g->ctx;
    reqstate *q = &h->rq;
    switch (q->method) {
    case M_START:
    case M_CONNECT: {
        sbuf b = {0};
        uint32_t v;
        switch (f->type) {
        case MVS_P_START:
            if (!mvs_dec_u32(f, &v))
                break;
            sb_printf(&b, "{\"event\":{\"start\":{\"pid\":%u}}}", v);
            stream_msg(h, &b);
            break;
        case MVS_P_STDOUT:
        case MVS_P_STDERR:
        case MVS_P_PTY:
            if (!q->started)
                break;
            sb_printf(&b, "{\"event\":{\"data\":{\"%s\":",
                      f->type == MVS_P_STDOUT ? "stdout" : f->type == MVS_P_STDERR ? "stderr" : "pty");
            jw_b64(&b, f->body, f->len);
            sb_puts(&b, "}}}");
            stream_msg(h, &b);
            break;
        case MVS_P_END:
            if (!mvs_dec_end(f, &v))
                break;
            end_event(&b, v);
            stream_msg(h, &b);
            sb_free(&b);
            stream_end(h, nullptr, nullptr);
            return;
        case MVS_ERROR:
            sb_free(&b);
            rpc_guest_error(h, f);
            return;
        default:
            break;
        }
        sb_free(&b);
        return;
    }
    case M_WATCHDIR: {
        if (f->type == MVS_OK) {
            const sbuf b = {.p = (char *)"{\"start\":{}}", .len = 12};
            stream_msg(h, &b);
        } else if (f->type == MVS_W_EVENT) {
            mvs_wevent ev;
            sbuf b = {0};
            sb_puts(&b, "{\"filesystem\":");
            if (q->started && mvs_dec_wevent(f, &ev) && fs_event_json(&b, &ev, q->include_entry)) {
                sb_puts(&b, "}");
                stream_msg(h, &b);
            }
            sb_free(&b);
        } else if (f->type == MVS_ERROR) {
            rpc_guest_error(h, f);
        }
        return;
    }
    case M_LIST:
        if (f->type == MVS_PROC) {
            mvs_proc p;
            if (!mvs_dec_proc(f, &p))
                return;
            if (!q->first)
                sb_puts(&q->acc, ",");
            q->first = false;
            proc_json(&q->acc, &p);
        } else if (f->type == MVS_OK) {
            sb_puts(&q->acc, "]}");
            h_json(h, 200, &q->acc);
        } else if (f->type == MVS_ERROR) {
            rpc_guest_error(h, f);
        }
        return;
    case M_LISTDIR:
        if (f->type == MVS_ENTRY) {
            mvs_entry e;
            if (!mvs_dec_entry(f->body, f->len, &e))
                return;
            if (!q->first)
                sb_puts(&q->acc, ",");
            q->first = false;
            entry_json(&q->acc, &e);
        } else if (f->type == MVS_OK) {
            sb_puts(&q->acc, "]}");
            h_json(h, 200, &q->acc);
        } else if (f->type == MVS_ERROR) {
            rpc_guest_error(h, f);
        }
        return;
    case M_STAT:
    case M_MKDIR:
    case M_MOVE:
        if (f->type == MVS_OK) {
            mvs_entry e;
            sbuf b = {0};
            sb_puts(&b, "{\"entry\":");
            if (!mvs_dec_entry(f->body, f->len, &e)) {
                sb_free(&b);
                rpc_error(h, "internal", "the sandbox answered nonsense");
                return;
            }
            entry_json(&b, &e);
            sb_puts(&b, "}");
            h_json(h, 200, &b);
            sb_free(&b);
        } else if (f->type == MVS_ERROR) {
            rpc_guest_error(h, f);
        }
        return;
    case M_REMOVE:
    case M_SEND_INPUT:
    case M_SIGNAL:
    case M_CLOSE_STDIN:
    case M_UPDATE:
        if (f->type == MVS_OK)
            h_respond(h, 200, "application/json", "{}", 2, nullptr);
        else if (f->type == MVS_ERROR)
            rpc_guest_error(h, f);
        return;
    case M_STREAM_INPUT:
        if (f->type == MVS_OK) {
            h->g = nullptr;
            g_close(g);
            q->input_busy = false;
            input_pump(h);
        } else if (f->type == MVS_ERROR) {
            h->g = nullptr;
            g_close(g);
            rpc_guest_error(h, f);
        }
        return;
    case M_FILES_GET:
        if (f->type == MVS_OK && !q->started) {
            q->started = true;
            h_stream_begin(h, 200, "application/octet-stream");
        } else if (f->type == MVS_DATA && q->started) {
            h_chunk(h, f->body, f->len);
            if (h->st != H_DEAD && h->g && h_pending(h) >= G_HIGH)
                g_pause(h->g, true);
        } else if (f->type == MVS_DONE && q->started) {
            h_stream_end(h);
        } else if (f->type == MVS_ERROR && !q->started) {
            const char *code;
            int status;
            char msg[256];
            guest_error(f, &code, &status, msg, sizeof msg);
            files_error(h, status, msg);
        } else {
            h_close(h); // can't say it in a body that has begun
        }
        return;
    case M_EXPORT: // DATA... then OK, or ERROR (and a cut stream, once begun)
        if ((f->type == MVS_DATA || f->type == MVS_OK) && !q->started) {
            q->started = true;
            h_stream_begin(h, 200, "application/x-tar");
        }
        if (f->type == MVS_DATA) {
            h_chunk(h, f->body, f->len);
            if (h->st != H_DEAD && h->g && h_pending(h) >= G_HIGH)
                g_pause(h->g, true);
        } else if (f->type == MVS_OK) {
            h->g = nullptr;
            g_close(g);
            h_stream_end(h);
        } else if (f->type == MVS_ERROR && !q->started) {
            const char *code;
            int status;
            char msg[256];
            guest_error(f, &code, &status, msg, sizeof msg);
            files_error(h, status, msg);
        } else {
            if (f->type == MVS_ERROR) {
                mvs_error e = {0};
                if (mvs_dec_error(f, &e))
                    logf_("%s: export: %.*s", q->sb ? q->sb->id : "?", (int)e.msg.n, e.msg.p);
            }
            h_close(h);
        }
        return;
    case M_FILES_PUT:
        if (f->type == MVS_OK) {
            mvs_entry e;
            if (!mvs_dec_entry(f->body, f->len, &e)) {
                files_error(h, 500, "the sandbox answered nonsense");
                return;
            }
            if (q->nfiles++)
                sb_puts(&q->acc, ",");
            size_t s = e.path.n;
            while (s && e.path.p[s - 1] != '/')
                s--;
            sb_puts(&q->acc, "{\"name\":");
            jw_str(&q->acc, e.path.p + s, e.path.n - s);
            sb_puts(&q->acc, ",\"type\":\"file\",\"path\":");
            jw_str(&q->acc, e.path.p, e.path.n);
            sb_puts(&q->acc, "}");
            h->g = nullptr;
            g_close(g);
            q->part_open = false;
            files_put_pump(h);
        } else if (f->type == MVS_ERROR) {
            const char *code;
            int status;
            char msg[256];
            guest_error(f, &code, &status, msg, sizeof msg);
            h->g = nullptr;
            files_error(h, status, msg);
        }
        return;
    default:
        return;
    }
}

static void e_end(gconn *g, const char *why)
{
    hconn *h = g->ctx;
    if (h->g != g)
        return;
    h->g = nullptr;
    const char *msg = why ? why : "the sandbox closed the connection";
    switch (h->rq.method) {
    case M_FILES_GET:
    case M_EXPORT:
        if (h->rq.started)
            h_close(h);
        else
            files_error(h, 502, msg);
        return;
    case M_FILES_PUT:
        files_error(h, 502, msg);
        return;
    default:
        rpc_error(h, "unavailable", msg);
    }
}

static void e_drained(gconn *g)
{
    hconn *h = g->ctx;
    if (h->rq.method == M_FILES_PUT)
        files_put_pump(h);
    else if (h->rq.method == M_STREAM_INPUT)
        h_body_more(h);
}

static const gconn_ops envd_ops = {.frame = e_frame, .end = e_end, .drained = e_drained};

// --- uploads -------------------------------------------------------------------------

// DATA frames for bytes going to the open WRITE.
static void put_data(hconn *h, const uint8_t *p, size_t n)
{
    if (!h->g)
        return;
    mvs_buf b = {0};
    for (size_t off = 0; off < n;) {
        const size_t k = n - off < MVS_MAX_CHUNK ? n - off : MVS_MAX_CHUNK;
        mvs_req_data(&b, p + off, k);
        off += k;
    }
    g_send(h->g, &b);
}

static bool put_open(hconn *h, const char *path)
{
    if (!h->rq.sb) {
        files_error(h, 502, "the sandbox was not found");
        return false;
    }
    mvs_buf b = {0};
    mvs_req_path(&b, MVS_WRITE, h->rq.user, path);
    if (!op_open(h, h->rq.sb, &b))
        return false;
    h->rq.part_open = true;
    return true;
}

static void put_done(hconn *h)
{
    mvs_buf b = {0};
    mvs_req_empty(&b, MVS_DONE);
    if (h->g)
        g_send(h->g, &b);
    else
        mvs_buf_free(&b);
    h->rq.part_ok = false; // now waiting for its OK
}

typedef struct {
    const uint8_t *p;
    size_t n, off;
} mem_src;

static int mem_pull(void *ctx, uint8_t *buf, size_t cap, size_t *got)
{
    mem_src *m = ctx;
    const size_t k = m->n - m->off < cap ? m->n - m->off : cap;
    memcpy(buf, m->p + m->off, k);
    m->off += k;
    *got = k;
    return 0;
}

static void files_put_pump(hconn *h)
{
    reqstate *q = &h->rq;
    while (h->st != H_DEAD && q->kind == RQ_FILES_PUT) {
        if (h->g && g_pending(h->g) >= G_HIGH) {
            h_pause_read(h, true);
            return; // drained() comes back here
        }
        if (q->part_open && !q->part_ok)
            return; // a file's DONE is out: its OK comes back here
        if (q->multipart) {
            const mp_event ev = mp_next(&q->mp, h->body_done);
            switch (ev) {
            case MP_NONE:
                h_body_more(h);
                return;
            case MP_PART:
                if (strcmp(q->mp.name, "file")) { // other fields are skipped
                    q->part_ok = false;
                    break;
                }
                {
                    const char *dest = q->path[0] ? q->path : q->mp.filename;
                    if (!dest[0]) {
                        files_error(h, 400, "a file part has no file name (its path)");
                        return;
                    }
                    if (!put_open(h, dest))
                        return;
                    q->part_ok = true;
                }
                break;
            case MP_DATA:
                if (q->part_open && q->part_ok)
                    put_data(h, q->mp.data, q->mp.ndata);
                break;
            case MP_END_PART:
                if (q->part_open && q->part_ok)
                    put_done(h);
                break;
            case MP_DONE:
                if (!h->body_done) {
                    h_body_more(h); // the epilogue, if any
                    return;
                }
                if (!q->nfiles) {
                    files_error(h, 400, "no file in the upload");
                    return;
                }
                sb_puts(&q->acc, "]");
                h_json(h, 200, &q->acc);
                return;
            case MP_ERROR:
                files_error(h, 400, "malformed multipart body");
                return;
            }
            continue;
        }
        // application/octet-stream: one file. gzip: inflated once whole.
        if (!h->body_done) {
            h_body_more(h);
            return;
        }
        if (!q->part_open) { // written and answered
            sb_puts(&q->acc, "]");
            h_json(h, 200, &q->acc);
            return;
        }
        if (!q->gzip) {
            if (!q->body_over) {
                q->body_over = true;
                put_done(h);
                continue;
            }
            return;
        }
        if (q->part_open && q->gzip) {
            inflate_stream *s = q->inf;
            if (!s) {
                const inflate_limits lim = {4ull << 30, 1032, 1 << 20};
                if (!(s = q->inf = inflate_new(INFLATE_GZIP, &lim))) {
                    files_error(h, 500, "out of memory");
                    return;
                }
                q->src = calloc(1, sizeof(mem_src));
                if (!q->src) {
                    files_error(h, 500, "out of memory");
                    return;
                }
                *(mem_src *)q->src = (mem_src){(const uint8_t *)q->gz.p, q->gz.len, 0};
                inflate_start(s, mem_pull, q->src);
            }
            const uint8_t *p;
            size_t n;
            if (inflate_peek(s, &p, &n)) {
                files_error(h, 400, "bad gzip body");
                return;
            }
            if (!n) {
                if (!q->body_over) {
                    q->body_over = true;
                    put_done(h);
                    continue;
                }
                return;
            }
            const size_t k = n < MVS_MAX_CHUNK ? n : MVS_MAX_CHUNK;
            put_data(h, p, k);
            inflate_consume(s, k);
            continue;
        }
        return;
    }
}

// --- StreamInput ------------------------------------------------------------------------

// Input that has arrived goes to the process one INPUT at a time; the
// answer ({} then the end) once the client's stream is over and all of it
// has been delivered.
static void input_pump(hconn *h)
{
    reqstate *q = &h->rq;
    if (h->st == H_DEAD || q->kind != RQ_INPUT || q->input_busy)
        return;
    if (q->pend.len) {
        if (!q->sb) {
            rpc_error(h, "unavailable", "the sandbox was not found");
            return;
        }
        const size_t k = q->pend.len < INPUT_CHUNK ? q->pend.len : INPUT_CHUNK;
        const mvs_sel sel = sel_of(h);
        mvs_buf b = {0};
        mvs_req_input(&b, &sel, q->in_pty ? MVS_IN_PTY : 0, q->pend.p, k);
        memmove(q->pend.p, q->pend.p + k, q->pend.len - k);
        q->pend.len -= k;
        q->input_busy = true;
        if (op_open(h, q->sb, &b) && h->read_paused && q->pend.len < INPUT_CHUNK)
            h_body_more(h);
        return;
    }
    if (q->body_over) {
        const sbuf b = {.p = (char *)"{}", .len = 2};
        stream_msg(h, &b);
        stream_end(h, nullptr, nullptr);
        return;
    }
    if (h->read_paused)
        h_body_more(h);
}

// Appends base64 v, decoded, to b. false if it isn't base64.
static bool append_b64(sbuf *b, const json_value *v)
{
    const size_t cap = v->len / 4 * 3 + 3;
    uint8_t *tmp = malloc(cap);
    size_t got;
    if (!tmp || !b64_decode(v->str, v->len, tmp, cap, &got)) {
        free(tmp);
        return false;
    }
    sb_put(b, tmp, got);
    free(tmp);
    return !b->oom;
}

// Envelopes of the client stream: start (the process), data, keepalive.
static void input_frames(hconn *h)
{
    reqstate *q = &h->rq;
    size_t off = 0;
    while (h->st != H_DEAD && q->kind == RQ_INPUT && q->inbuf.len - off >= 5) {
        const uint8_t *e = (const uint8_t *)q->inbuf.p + off;
        const size_t n = (size_t)e[1] << 24 | (size_t)e[2] << 16 | (size_t)e[3] << 8 | e[4];
        if (n > (8u << 20) || (e[0] & 1)) {
            rpc_error(h, "invalid_argument", "bad envelope");
            return;
        }
        if (q->inbuf.len - off - 5 < n)
            break;
        off += 5 + n;
        if (e[0] & 2) // an end-stream from the client: nothing in it for us
            continue;
        const char *err;
        const json_limits lim = {8u << 20, 16, 4096};
        json_doc *doc = json_parse(e + 5, n, &lim, &err);
        const json_value *o = doc ? json_root(doc) : nullptr;
        const json_value *start = json_get(o, "start"), *data = json_get(o, "data");
        const char *fail = nullptr;
        if (!o || o->type != JSON_OBJECT) {
            fail = "a message is not a JSON object";
        } else if (start) {
            if (selector(h, json_get(start, "process")))
                q->in_started = true;
            else
                fail = "start: no process";
        } else if (data) {
            const json_value *in = json_get(data, "input");
            const json_value *v = json_get(in, "stdin");
            const bool pty = !v;
            if (!v)
                v = json_get(in, "pty");
            if (!q->in_started)
                fail = "data before start";
            else if (!v || v->type != JSON_STRING)
                fail = "data: no input";
            else if (q->pend.len && q->in_pty != pty)
                fail = "data: stdin and pty mixed";
            else if (!append_b64(&q->pend, v))
                fail = "data: bad base64";
            else
                q->in_pty = pty;
        } else if (!json_get(o, "keepalive")) {
            fail = "expected start, data or keepalive";
        }
        json_free(doc);
        if (fail) {
            rpc_error(h, "invalid_argument", fail);
            return;
        }
    }
    if (off) {
        memmove(q->inbuf.p, q->inbuf.p + off, q->inbuf.len - off);
        q->inbuf.len -= off;
    }
    if (q->pend.len >= INPUT_CHUNK * 2)
        h_pause_read(h, true);
    input_pump(h);
}

// --- body consumers ------------------------------------------------------------------

void envd_body(hconn *h, const uint8_t *p, size_t n)
{
    reqstate *q = &h->rq;
    switch (q->kind) {
    case RQ_INPUT:
        if (q->inbuf.len + n > (9u << 20)) {
            rpc_error(h, "resource_exhausted", "a message is too large");
            return;
        }
        sb_put(&q->inbuf, p, n);
        input_frames(h);
        return;
    case RQ_FILES_PUT:
        if (q->multipart) {
            if (!mp_feed(&q->mp, p, n)) {
                files_error(h, 413, "too much at once");
                return;
            }
            files_put_pump(h);
        } else if (q->gzip) {
            if (q->gz.len + n > MAX_GZIP_BODY) {
                files_error(h, 413, "a gzip upload is at most 64 MiB");
                return;
            }
            sb_put(&q->gz, p, n);
            if (q->gz.oom)
                files_error(h, 500, "out of memory");
        } else {
            put_data(h, p, n);
            files_put_pump(h);
        }
        return;
    default:
        return;
    }
}

void envd_body_end(hconn *h)
{
    reqstate *q = &h->rq;
    if (q->kind == RQ_INPUT) {
        q->body_over = true;
        input_pump(h);
    } else if (q->kind == RQ_FILES_PUT) {
        files_put_pump(h);
    }
}

void envd_abort(hconn *h)
{
    // A CreateWatcher still waiting: the watcher goes too.
    if (h->rq.method == M_CREATE_WATCHER && h->rq.sb)
        for (watcher *w = h->rq.sb->watchers; w; w = w->next)
            if (w->creating == h) {
                w->creating = nullptr;
                watcher_remove(w);
                break;
            }
}

void envd_rq_free(reqstate *q)
{
    if (q->inf)
        inflate_free(q->inf);
    free(q->src);
    q->inf = q->src = nullptr;
}

void envd_tick(hconn *h, int64_t now)
{
    reqstate *q = &h->rq;
    if (!q->started || h->resp_done || q->keepalive_s <= 0 || now - q->last_out < (int64_t)q->keepalive_s * 1000)
        return;
    const bool fs = q->method == M_WATCHDIR;
    const char *ka = fs ? "{\"keepalive\":{}}" : "{\"event\":{\"keepalive\":{}}}";
    const sbuf b = {.p = (char *)ka, .len = strlen(ka)};
    stream_msg(h, &b);
}

// --- requests ------------------------------------------------------------------------

static bool token_ok(hconn *h, const sandbox *sb)
{
    const char *t = http_header(&h->req, "x-access-token");
    if (!t)
        return false;
    const size_t n = strlen(sb->token);
    if (strlen(t) != n)
        return false;
    unsigned char d = 0;
    for (size_t i = 0; i < n; i++)
        d |= (unsigned char)(t[i] ^ sb->token[i]);
    return d == 0;
}

static void files_get(hconn *h, sandbox *sb)
{
    char path[4096], user[64];
    const bool has_user = http_query(&h->req, "username", user, sizeof user);
    h->rq.kind = RQ_FILES_GET;
    h->rq.method = M_FILES_GET;
    if (!http_query(&h->req, "path", path, sizeof path) || !path[0]) {
        files_error(h, 400, "path: missing");
        return;
    }
    if (!user_of(h, sb, has_user ? user : "")) {
        files_error(h, 400, "username: not a user name");
        return;
    }
    mvs_buf b = {0};
    mvs_req_path(&b, MVS_READ, h->rq.user, path);
    op_open(h, sb, &b);
}

// Control plane: GET /sandboxes/ID/export, the root filesystem's changes
// as a tar layer (image builds).
void envd_export(hconn *h, sandbox *sb)
{
    h->rq.kind = RQ_FILES_GET;
    h->rq.method = M_EXPORT;
    h->rq.sb = sb;
    mvs_buf b = {0};
    mvs_req_empty(&b, MVS_EXPORT);
    op_open(h, sb, &b);
}

static void files_put(hconn *h, sandbox *sb)
{
    reqstate *q = &h->rq;
    char user[64];
    const bool has_user = http_query(&h->req, "username", user, sizeof user);
    q->kind = RQ_FILES_PUT;
    q->method = M_FILES_PUT;
    q->sb = sb;
    if (!user_of(h, sb, has_user ? user : "")) {
        files_error(h, 400, "username: not a user name");
        return;
    }
    if (!http_query(&h->req, "path", q->path, sizeof q->path))
        q->path[0] = 0;
    const char *ce = http_header(&h->req, "content-encoding");
    q->gzip = ce && !strcmp(ce, "gzip");
    if (ce && !q->gzip && strcmp(ce, "identity")) {
        files_error(h, 415, "Content-Encoding: gzip or none");
        return;
    }
    sb_puts(&q->acc, "[");
    const char *ct = http_header(&h->req, "content-type");
    if (ct && !strncmp(ct, "multipart/", 10)) {
        if (q->gzip) {
            files_error(h, 415, "gzip is for application/octet-stream uploads");
            return;
        }
        if (!mp_init(&q->mp, ct)) {
            files_error(h, 400, "multipart/form-data without a usable boundary");
            return;
        }
        q->multipart = true;
        return; // the parts come with the body
    }
    if (!q->path[0]) {
        files_error(h, 400, "path: missing");
        return;
    }
    if (put_open(h, q->path))
        q->part_ok = true;
}

static bool valid_path(const char *p) { return p && p[0] && strlen(p) < 4096; }

// process.Process/Start's request: START.
static const char *start_req(hconn *h, sandbox *sb, const json_value *o, mvs_buf *b)
{
    reqstate *q = &h->rq;
    const json_value *pr = json_get(o, "process");
    const char *cmd = jstr(json_get(pr, "cmd"));
    const json_value *args = json_get(pr, "args"), *envs = json_get(pr, "envs");
    const json_value *pty = json_get(o, "pty");
    const char *tag = jstr(json_get(o, "tag"));
    const char *cwd = jstr(json_get(pr, "cwd"));
    if (!cmd || !cmd[0])
        return "process.cmd: missing";
    if (!user_of(h, sb, nullptr))
        return "Authorization: not a user name";
    if (args && args->type != JSON_ARRAY && args->type != JSON_NULL)
        return "process.args: an array";
    if (envs && envs->type != JSON_OBJECT && envs->type != JSON_NULL)
        return "process.envs: an object";
    const size_t na = args && args->type == JSON_ARRAY ? args->len : 0;
    const size_t ne = envs && envs->type == JSON_OBJECT ? envs->len : 0;
    if (na + 1 + ne > MVS_MAX_STRINGS)
        return "too many arguments and variables";
    const char **av = calloc(na + 2, sizeof *av);
    const char **ev = calloc(ne + 1, sizeof *ev);
    char **evs = calloc(ne + 1, sizeof *evs);
    const char *bad = nullptr;
    size_t k = 0;
    if (!av || !ev || !evs)
        bad = "out of memory";
    if (!bad)
        av[0] = cmd;
    for (size_t i = 0; !bad && i < na; i++)
        if (!(av[1 + i] = jstr(&args->kids[i])))
            bad = "process.args: strings";
    for (size_t i = 0; !bad && i < ne; i++) {
        const json_value *kv = &envs->kids[i];
        const char *v = jstr(kv);
        if (!v || !kv->key[0] || strchr(kv->key, '=') || strlen(kv->key) != kv->klen) {
            bad = "process.envs: NAME: value strings";
            break;
        }
        const size_t l = kv->klen + 1 + strlen(v) + 1;
        if (!(evs[k] = malloc(l))) {
            bad = "out of memory";
            break;
        }
        snprintf(evs[k], l, "%s=%s", kv->key, v);
        ev[k] = evs[k];
        k++;
    }
    int64_t cols = 80, rows = 24;
    if (pty && pty->type == JSON_OBJECT) {
        const json_value *size = json_get(pty, "size");
        if (!jint(json_get(size, "cols"), &cols) || !jint(json_get(size, "rows"), &rows) || cols < 1 ||
            cols > 65535 || rows < 1 || rows > 65535)
            cols = 80, rows = 24;
    }
    const bool is_pty = pty && pty->type == JSON_OBJECT;
    if (!bad) {
        uint32_t flags = (is_pty ? MVS_S_PTY | MVS_S_STDIN : 0) | (jbool(json_get(o, "stdin")) ? MVS_S_STDIN : 0);
        if (tag && tag[0])
            flags |= MVS_S_TAG;
        mvs_req_start(b, &(mvs_start){.flags = flags, .cols = (uint16_t)cols, .rows = (uint16_t)rows,
                                      .user = q->user, .cwd = cwd && cwd[0] ? cwd : sb->t->workdir ? sb->t->workdir : "", .tag = tag, .argv = av,
                                      .nargs = na + 1, .envs = ev, .nenv = k});
    }
    for (size_t i = 0; evs && i < k; i++)
        free(evs[i]);
    free(av), free(ev), free(evs);
    return bad;
}

// The calls that name a process: CONNECT, CLOSE_STDIN, SIGNAL, RESIZE, INPUT.
static const char *process_req(hconn *h, int method, const json_value *o, mvs_buf *b, bool *nothing)
{
    if (!selector(h, json_get(o, "process")))
        return "process: a pid or a tag";
    const mvs_sel sel = sel_of(h);
    switch (method) {
    case M_CONNECT:
        mvs_req_sel(b, MVS_CONNECT, &sel);
        return nullptr;
    case M_CLOSE_STDIN:
        mvs_req_sel(b, MVS_CLOSE_STDIN, &sel);
        return nullptr;
    case M_SIGNAL: {
        const json_value *s = json_get(o, "signal");
        int64_t n = 0;
        const char *name = jstr(s);
        if (name && !strcmp(name, "SIGNAL_SIGKILL"))
            n = 9;
        else if (name && !strcmp(name, "SIGNAL_SIGTERM"))
            n = 15;
        else if (!name)
            jint(s, &n);
        if (n != 9 && n != 15)
            return "signal: SIGNAL_SIGKILL or SIGNAL_SIGTERM";
        mvs_req_signal(b, &sel, (uint32_t)n);
        return nullptr;
    }
    case M_UPDATE: {
        const json_value *size = json_get(json_get(o, "pty"), "size");
        int64_t cols = 0, rows = 0;
        if (!size) {
            *nothing = true;
            return nullptr;
        }
        if (!jint(json_get(size, "cols"), &cols) || !jint(json_get(size, "rows"), &rows) || cols < 1 ||
            cols > 65535 || rows < 1 || rows > 65535)
            return "pty.size: cols and rows";
        mvs_req_resize(b, &sel, (uint16_t)cols, (uint16_t)rows);
        return nullptr;
    }
    default: { // SendInput
        const json_value *in = json_get(o, "input");
        const json_value *v = json_get(in, "stdin");
        const bool pty = !v;
        if (!v)
            v = json_get(in, "pty");
        if (!v || v->type != JSON_STRING)
            return "input: stdin or pty";
        sbuf data = {0};
        if (!append_b64(&data, v)) {
            sb_free(&data);
            return "input: not base64";
        }
        if (data.len > MVS_MAX_BODY - 1024) {
            sb_free(&data);
            return "input: at most 1000 KiB per call";
        }
        mvs_req_input(b, &sel, pty ? MVS_IN_PTY : 0, data.p, data.len);
        sb_free(&data);
        return nullptr;
    }
    }
}

static void watcher_events(hconn *h, sandbox *sb, int method, const json_value *o)
{
    const char *id = jstr(jf(o, "watcherId", "watcher_id"));
    watcher *w = id ? watcher_find(sb, id) : nullptr;
    if (!w) {
        rpc_error(h, "not_found", "no such watcher");
        return;
    }
    if (method == M_REMOVE_WATCHER) {
        watcher_remove(w);
        h_respond(h, 200, "application/json", "{}", 2, nullptr);
        return;
    }
    if (w->ended && !w->nevents) {
        rpc_error(h, "unavailable", "the watch ended");
        return;
    }
    sbuf r = {0};
    sb_puts(&r, "{\"events\":[");
    sb_put(&r, w->events.p, w->events.len);
    sb_puts(&r, "]}");
    w->events.len = 0;
    w->nevents = 0;
    h_json(h, 200, &r);
    sb_free(&r);
}

void envd_request(hconn *h, sandbox *sb)
{
    reqstate *q = &h->rq;
    const char *path = h->req.path, *m = h->req.method;
    q->sb = sb;
    q->first = true;
    q->keepalive_s = 50;
    if (!strcmp(path, "/health")) {
        q->kind = RQ_SIMPLE;
        if (sb->st == SB_RUNNING)
            h_respond(h, 204, "", "", 0, nullptr);
        else
            h_api_error(h, 502, "the sandbox was not found (it is not running)");
        return;
    }
    const bool files = !strcmp(path, "/files");
    int method = M_NONE;
    bool stream = false;
    for (size_t i = 0; i < sizeof RPCS / sizeof *RPCS; i++)
        if (!strcmp(RPCS[i].path, path))
            method = RPCS[i].m, stream = RPCS[i].stream;
    q->method = files ? (!strcmp(m, "GET") ? M_FILES_GET : M_FILES_PUT) : method;
    q->kind = files ? RQ_SIMPLE : method == M_STREAM_INPUT ? RQ_INPUT : stream ? RQ_STREAM : RQ_UNARY;
    if (!files && method == M_NONE) {
        q->kind = RQ_SIMPLE;
        connect_error(h, false, "unimplemented", "no such method");
        return;
    }
    if (!token_ok(h, sb)) {
        if (files)
            files_error(h, 401, "invalid access token");
        else
            rpc_error(h, "unauthenticated", "invalid access token");
        return;
    }
    if (sb->st != SB_RUNNING) {
        if (files)
            files_error(h, 502, "the sandbox was not found (it is not running)");
        else
            rpc_error(h, "unavailable", "the sandbox was not found (it is not running)");
        return;
    }
    if (files) {
        if (!strcmp(m, "GET"))
            files_get(h, sb);
        else if (!strcmp(m, "POST"))
            files_put(h, sb);
        else
            files_error(h, 405, "GET or POST");
        return;
    }
    if (strcmp(m, "POST")) {
        rpc_error(h, "unimplemented", "Connect calls are POSTs");
        return;
    }
    // The codec: JSON only (the SDKs never send protobuf).
    const char *ct = http_header(&h->req, "content-type");
    const bool ct_ok = ct && (stream ? !strcmp(ct, "application/connect+json")
                                     : !strcmp(ct, "application/json") || !strncmp(ct, "application/json;", 17));
    if (!ct_ok) {
        q->kind = RQ_SIMPLE;
        h_respond(h, 415, "application/json", "{\"code\":\"unimplemented\",\"message\":\"JSON only\"}", 47, nullptr);
        return;
    }
    const char *kp = http_header(&h->req, "keepalive-ping-interval");
    if (kp) {
        const int s = atoi(kp);
        q->keepalive_s = s < 1 ? 1 : s > 290 ? 290 : s;
    }
    if (method == M_STREAM_INPUT)
        return; // its messages come with the body
    json_doc *doc;
    const char *err = "";
    const json_value *o = rpc_message(h, &doc, &err);
    if (!o) {
        json_free(doc);
        rpc_error(h, "invalid_argument", err);
        return;
    }
    mvs_buf b = {0};
    const char *bad = nullptr;
    bool nothing = false;
    switch (method) {
    case M_START:
        bad = start_req(h, sb, o, &b);
        break;
    case M_CONNECT:
    case M_SEND_INPUT:
    case M_SIGNAL:
    case M_CLOSE_STDIN:
    case M_UPDATE:
        bad = process_req(h, method, o, &b, &nothing);
        break;
    case M_LIST:
        sb_puts(&q->acc, "{\"processes\":[");
        mvs_req_empty(&b, MVS_PS);
        break;
    case M_STAT:
    case M_MKDIR:
    case M_REMOVE:
    case M_LISTDIR:
    case M_WATCHDIR:
    case M_CREATE_WATCHER: {
        const char *p = jstr(json_get(o, "path"));
        if (!valid_path(p)) {
            bad = "path: missing";
            break;
        }
        if (!user_of(h, sb, nullptr)) {
            bad = "Authorization: not a user name";
            break;
        }
        if (method == M_LISTDIR) {
            int64_t depth = 1;
            jint(json_get(o, "depth"), &depth);
            depth = depth < 1 ? 1 : depth > MVS_MAX_DEPTH ? MVS_MAX_DEPTH : depth;
            sb_puts(&q->acc, "{\"entries\":[");
            mvs_req_list(&b, q->user, p, (uint32_t)depth);
        } else if (method == M_WATCHDIR || method == M_CREATE_WATCHER) {
            q->include_entry = jbool(jf(o, "includeEntry", "include_entry"));
            mvs_req_watch(&b, q->user, p, jbool(json_get(o, "recursive")) ? MVS_W_RECURSIVE : 0);
        } else {
            mvs_req_path(&b, method == M_STAT ? MVS_STAT : method == M_MKDIR ? MVS_MKDIR : MVS_REMOVE, q->user, p);
        }
        break;
    }
    case M_MOVE: {
        const char *from = jstr(json_get(o, "source")), *to = jstr(json_get(o, "destination"));
        if (!valid_path(from) || !valid_path(to))
            bad = "source and destination: paths";
        else if (!user_of(h, sb, nullptr))
            bad = "Authorization: not a user name";
        else
            mvs_req_move(&b, q->user, from, to);
        break;
    }
    case M_GET_EVENTS:
    case M_REMOVE_WATCHER:
        watcher_events(h, sb, method, o);
        json_free(doc);
        return;
    default:
        bad = "no such method";
    }
    json_free(doc);
    if (nothing) {
        mvs_buf_free(&b);
        h_respond(h, 200, "application/json", "{}", 2, nullptr);
        return;
    }
    if (bad || b.oom) {
        mvs_buf_free(&b);
        rpc_error(h, "invalid_argument", bad ? bad : "out of memory");
        return;
    }
    if (method == M_CREATE_WATCHER) {
        watcher *w = calloc(1, sizeof *w);
        bool retry;
        gconn *g = w ? g_open(sb, &watcher_ops, w, &retry) : nullptr;
        if (!g) {
            free(w);
            mvs_buf_free(&b);
            rpc_error(h, "unavailable", "the sandbox is unreachable");
            return;
        }
        static uint64_t seq;
        snprintf(w->id, sizeof w->id, "w%llx", (unsigned long long)++seq);
        w->sb = sb;
        w->g = g;
        w->creating = h;
        w->include_entry = q->include_entry;
        w->next = sb->watchers;
        sb->watchers = w;
        g_send(g, &b);
        return;
    }
    op_open(h, sb, &b);
}
