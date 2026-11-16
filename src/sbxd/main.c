// SPDX-License-Identifier: MIT
// microvm-sbxd: the loop, guest connections, HTTP connections, routing and
// port tunnels. See sbxd.h and SANDBOX.md.
//
//   microvm-sbxd --vmm MICROVM --kernel VMLINUX [--kernel-smp VMLINUX] --dir DIR
//                [--template NAME=IMAGE[,mem=MIB][,cpus=N][,user=NAME][,net]]...
//                [--listen ADDR:PORT] [--api-key-file FILE] [--domain DOMAIN]
//                [--jail MICROVM-JAIL] [--max-sandboxes N] [--verbose]
//                [--net-deny-port PORT|none]... [--net-flow-rate N] [--net-max-dests N]
//                [--net-tx-rate BYTES] [--cgroup DIR] [--max-timeout SECONDS|none]
#include "sbxd/sbxd.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

config C = {.max_sandboxes = 64, .max_conns = 1024, .max_timeout_s = 86400};

static int epfd = -1;
static hconn *conns;
static int nconns;
static volatile sig_atomic_t stopping;

// --- the loop's pieces --------------------------------------------------------------

int64_t now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

void logf_(const char *fmt, ...)
{
    char buf[1024];
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    struct tm tm;
    gmtime_r(&t.tv_sec, &tm);
    int n = snprintf(buf, sizeof buf, "%02d:%02d:%02d.%03ld sbxd: ", tm.tm_hour, tm.tm_min, tm.tm_sec,
                     t.tv_nsec / 1000000);
    va_list ap;
    va_start(ap, fmt);
    const int m = vsnprintf(buf + n, sizeof buf - (size_t)n - 1, fmt, ap);
    va_end(ap);
    n += m < 0 ? 0 : m >= (int)(sizeof buf - (size_t)n - 1) ? (int)(sizeof buf - (size_t)n - 2) : m;
    buf[n++] = '\n';
    (void)!write(2, buf, (size_t)n);
}

void ev_set(int fd, void *obj, bool in, bool out)
{
    struct epoll_event e = {.events = (in ? EPOLLIN : 0u) | (out ? EPOLLOUT : 0u), .data.ptr = obj};
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &e) && errno == ENOENT)
        epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &e);
}

void ev_del(int fd) { epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr); }

typedef struct grave {
    void *p;
    void (*fn)(void *);
    struct grave *next;
} grave;
static grave *graves;

void graveyard_add(void *p, void (*fn)(void *))
{
    grave *g = malloc(sizeof *g);
    if (!g) { // never: but leaking beats a use-after-free
        logf_("out of memory (a %p leaks)", p);
        return;
    }
    *g = (grave){p, fn, graves};
    graves = g;
}

static void graveyard_empty(void)
{
    while (graves) {
        grave *g = graves;
        graves = g->next;
        g->fn(g->p);
        free(g);
    }
}

// --- guest connections -----------------------------------------------------------

gconn *g_open(const sandbox *sb, const gconn_ops *ops, void *ctx, bool *retry)
{
    *retry = false;
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    if (strlen(sb->sock) >= sizeof a.sun_path)
        return nullptr;
    strcpy(a.sun_path, sb->sock);
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return nullptr;
    if (connect(fd, (struct sockaddr *)&a, sizeof a)) {
        *retry = errno == ENOENT || errno == ECONNREFUSED || errno == EAGAIN;
        close(fd);
        return nullptr;
    }
    // A fresh stream socket takes 11 bytes at once.
    if (send(fd, "CONNECT 53\n", 11, MSG_NOSIGNAL) != 11) {
        close(fd);
        *retry = true;
        return nullptr;
    }
    gconn *g = calloc(1, sizeof *g);
    if (!g) {
        close(fd);
        return nullptr;
    }
    *g = (gconn){.kind = EV_GUEST, .fd = fd, .st = G_LINE, .ops = ops, .ctx = ctx};
    ev_set(fd, g, true, false);
    return g;
}

size_t g_pending(const gconn *g) { return g->out.len - g->out_off; }

// A paused connection with nothing to send is out of the epoll set: a
// hang-up would otherwise be reported over and over while its data waits.
static void g_update(gconn *g)
{
    if (g->st == G_DEAD)
        return;
    const bool in = !g->paused && !g->read_eof, out = g->st >= G_OPEN && g->st != G_DEAD && g_pending(g) > 0;
    if (!in && !out)
        ev_del(g->fd);
    else
        ev_set(g->fd, g, in, out);
}

static void g_free(void *p)
{
    gconn *g = p;
    mvs_reader_free(&g->r);
    mvs_buf_free(&g->out);
    free(g);
}

void g_close(gconn *g)
{
    if (!g || g->st == G_DEAD)
        return;
    g->st = G_DEAD;
    ev_del(g->fd);
    close(g->fd);
    g->fd = -1;
    graveyard_add(g, g_free);
}

static void g_fail(gconn *g, const char *why)
{
    if (g->st == G_DEAD)
        return;
    const gconn_ops *ops = g->ops;
    g->st = G_DEAD; // no callbacks after this one
    ev_del(g->fd);
    close(g->fd);
    g->fd = -1;
    graveyard_add(g, g_free);
    ops->end(g, why);
}

static void g_flush(gconn *g)
{
    while (g->st >= G_OPEN && g->st != G_DEAD && g_pending(g)) {
        const ssize_t n = send(g->fd, g->out.p + g->out_off, g_pending(g), MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR)
                break;
            g_fail(g, "the sandbox closed the connection");
            return;
        }
        g->out_off += (size_t)n;
    }
    if (g->st == G_DEAD)
        return;
    if (g->out_off == g->out.len) {
        g->out_off = g->out.len = 0;
        if (g->want_shut && g->st == G_RAW) {
            shutdown(g->fd, SHUT_WR);
            g->want_shut = false;
        }
    }
    else if (g->out_off > (1u << 20)) {
        memmove(g->out.p, g->out.p + g->out_off, g->out.len - g->out_off);
        g->out.len -= g->out_off;
        g->out_off = 0;
    }
    g_update(g);
    if (g->was_full && g_pending(g) < G_LOW) {
        g->was_full = false;
        if (g->ops->drained)
            g->ops->drained(g);
    }
}

void g_send(gconn *g, mvs_buf *b)
{
    if (g->st == G_DEAD || b->oom) {
        if (g->st != G_DEAD)
            g_fail(g, "out of memory");
        mvs_buf_free(b);
        return;
    }
    g_send_raw(g, b->p, b->len);
    mvs_buf_free(b);
}

void g_send_raw(gconn *g, const void *p, size_t n)
{
    if (g->st == G_DEAD)
        return;
    mvs_buf_put(&g->out, p, n);
    if (g->out.oom) {
        g_fail(g, "out of memory");
        return;
    }
    if (g_pending(g) >= G_HIGH)
        g->was_full = true;
    g_flush(g);
}

void g_shutdown_write(gconn *g)
{
    if (g->st == G_DEAD)
        return;
    g->want_shut = true;
    g_flush(g);
}

void g_pause(gconn *g, bool on)
{
    if (g->st == G_DEAD || g->paused == on)
        return;
    g->paused = on;
    g_update(g);
}

void g_raw_mode(gconn *g) { g->st = G_RAW; }

static void g_readable(gconn *g)
{
    uint8_t buf[65536];
    for (int rounds = 0; rounds < 16 && g->st != G_DEAD && !g->paused; rounds++) {
        const ssize_t n = recv(g->fd, buf, sizeof buf, MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR)
                return;
            g_fail(g, "the sandbox's connection failed");
            return;
        }
        if (n == 0) {
            if (g->st == G_RAW) {
                g->read_eof = true;
                g->ops->raw(g, nullptr, 0); // the guest is done sending
                g_update(g);
                return;
            }
            g_fail(g, g->st == G_OPEN ? nullptr : "the sandbox did not answer");
            return;
        }
        size_t off = 0;
        if (g->st == G_RAW) {
            g->ops->raw(g, buf, (size_t)n);
            continue;
        }
        if (g->st == G_LINE) { // "OK <port>\n" from the VMM
            while (off < (size_t)n && g->st == G_LINE) {
                const char c = (char)buf[off++];
                if (g->nline == sizeof g->line - 1) {
                    g_fail(g, "the VMM said something else");
                    return;
                }
                g->line[g->nline++] = c;
                if (c == '\n') {
                    g->line[g->nline] = 0;
                    if (strncmp(g->line, "OK ", 3)) {
                        g_fail(g, "the sandbox agent is not listening");
                        return;
                    }
                    g->st = G_HELLO;
                }
            }
        }
        if (off < (size_t)n && !mvs_feed(&g->r, buf + off, (size_t)n - off)) {
            g_fail(g, "out of memory");
            return;
        }
        mvs_frame f;
        for (;;) {
            if (g->st == G_DEAD || g->st == G_RAW || g->paused)
                break;
            const int r = mvs_next(&g->r, &f);
            if (r == 0)
                break;
            if (r < 0) {
                logf_("bad frame from the sandbox: %s", g->r.error);
                g_fail(g, "the sandbox sent a malformed frame");
                return;
            }
            if (g->st == G_HELLO) {
                uint32_t v;
                if (f.type != MVS_HELLO || !mvs_dec_hello(&f, &v, &g->resumes)) {
                    g_fail(g, "the sandbox agent did not say HELLO");
                    return;
                }
                g->st = G_OPEN;
                g->was_open = true;
                g_flush(g);
                if (g->st != G_DEAD && g->ops->ready)
                    g->ops->ready(g);
                continue;
            }
            g->ops->frame(g, &f);
        }
        if (g->st == G_RAW && g->r.len > g->r.off) { // bytes after PORT_CONNECT's OK
            const size_t k = g->r.len - g->r.off;
            uint8_t *rest = malloc(k);
            if (!rest) {
                g_fail(g, "out of memory");
                return;
            }
            memcpy(rest, g->r.buf + g->r.off, k);
            g->r.off = g->r.len;
            g->ops->raw(g, rest, k);
            free(rest);
        }
    }
}

// --- HTTP connections ---------------------------------------------------------------

enum { IN_CAP = 64 * 1024 + HTTP_MAX_HEAD, HEAD_MS = 15000, IDLE_MS = 300000 };

size_t h_pending(const hconn *h) { return h->out.len - h->out_off; }

static void h_update(hconn *h)
{
    if (h->st != H_DEAD)
        ev_set(h->fd, h, !h->read_paused && !h->peer_eof, h_pending(h) > 0);
}

static void h_free(void *p)
{
    hconn *h = p;
    free(h->in);
    sb_free(&h->out);
    sb_free(&h->body);
    http_req_free(&h->req);
    free(h);
}

static void rq_reset(hconn *h)
{
    reqstate *q = &h->rq;
    envd_rq_free(q);
    sb_free(&q->acc);
    sb_free(&q->inbuf);
    sb_free(&q->pend);
    sb_free(&q->gz);
    mp_free(&q->mp);
    *q = (reqstate){0};
}

void h_close(hconn *h)
{
    if (h->st == H_DEAD)
        return;
    if (h->rq.kind == RQ_WAIT_SB)
        api_abort(h);
    else if (h->rq.kind != RQ_NONE && h->rq.kind != RQ_SIMPLE)
        envd_abort(h);
    g_close(h->g);
    h->g = nullptr;
    rq_reset(h);
    h->st = H_DEAD;
    ev_del(h->fd);
    close(h->fd);
    h->fd = -1;
    if (h->prev)
        h->prev->next = h->next;
    else
        conns = h->next;
    if (h->next)
        h->next->prev = h->prev;
    nconns--;
    graveyard_add(h, h_free);
}

void h_pause_read(hconn *h, bool on)
{
    if (h->read_paused != on) {
        h->read_paused = on;
        h_update(h);
    }
}

static void h_process(hconn *h);

static void h_flush(hconn *h)
{
    while (h->st != H_DEAD && h_pending(h)) {
        const ssize_t n = send(h->fd, h->out.p + h->out_off, h_pending(h), MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR)
                break;
            h_close(h);
            return;
        }
        h->out_off += (size_t)n;
    }
    if (h->st == H_DEAD)
        return;
    if (h->out_off == h->out.len) {
        h->out_off = h->out.len = 0;
        if (h->close_after) {
            h_close(h);
            return;
        }
        if ((h->st == H_TUNNEL && h->g == nullptr) || (h->peer_eof && h->st == H_HEAD)) {
            h_close(h); // the guest side is over, or the client and its last answer
            return;
        }
    } else if (h->out_off > (1u << 20)) {
        memmove(h->out.p, h->out.p + h->out_off, h->out.len - h->out_off);
        h->out.len -= h->out_off;
        h->out_off = 0;
    }
    if (h->g && h->g->paused && h_pending(h) < G_LOW)
        g_pause(h->g, false);
    h_update(h);
}

static void h_put(hconn *h, const void *p, size_t n)
{
    sb_put(&h->out, p, n);
    if (h->out.oom) {
        h_close(h);
        return;
    }
}

static const char *reason(int status)
{
    switch (status) {
    case 100: return "Continue";
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 409: return "Conflict";
    case 411: return "Length Required";
    case 413: return "Content Too Large";
    case 415: return "Unsupported Media Type";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 499: return "Client Closed Request";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    case 505: return "HTTP Version Not Supported";
    case 507: return "Insufficient Storage";
    default: return "Unknown";
    }
}

static void h_finish(hconn *h);

void h_respond(hconn *h, int status, const char *ctype, const void *body, size_t n, const char *extra)
{
    if (h->st == H_DEAD)
        return;
    char head[512];
    int k;
    if (status == 204 || status == 304)
        k = snprintf(head, sizeof head, "HTTP/1.1 %d %s\r\n%s%s", status, reason(status), extra ? extra : "",
                     h->close_after ? "Connection: close\r\n\r\n" : "\r\n");
    else
        k = snprintf(head, sizeof head, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n%s%s", status,
                     reason(status), ctype, n, extra ? extra : "", h->close_after ? "Connection: close\r\n\r\n" : "\r\n");
    if (k < 0 || k >= (int)sizeof head) {
        h_close(h);
        return;
    }
    h_put(h, head, (size_t)k);
    if (h->st != H_DEAD && status != 204 && status != 304)
        h_put(h, body, n);
    if (h->st == H_DEAD)
        return;
    h->resp_done = true;
    h_finish(h);
}

void h_json(hconn *h, int status, const sbuf *b)
{
    if (b->oom) {
        h_api_error(h, 500, "out of memory");
        return;
    }
    h_respond(h, status, "application/json", b->p, b->len, nullptr);
}

void h_api_error(hconn *h, int status, const char *msg)
{
    sbuf b = {0};
    sb_printf(&b, "{\"code\":%d,\"message\":", status);
    jw_cstr(&b, msg);
    sb_puts(&b, "}");
    // Errors the client shouldn't retry say so (the Python SDK retries 5xx).
    h_respond(h, status, "application/json", b.p, b.len,
              status == 502 || status == 503 || status == 504 || status == 429 ? "Should-Retry: false\r\n" : nullptr);
    sb_free(&b);
}

void h_stream_begin(hconn *h, int status, const char *ctype)
{
    char head[256];
    const int k = snprintf(head, sizeof head, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nTransfer-Encoding: chunked\r\n%s",
                           status, reason(status), ctype, h->close_after ? "Connection: close\r\n\r\n" : "\r\n");
    h_put(h, head, (size_t)k);
    h->resp_chunked = true;
}

void h_chunk(hconn *h, const void *p, size_t n)
{
    if (!n || h->st == H_DEAD)
        return;
    char sz[24];
    const int k = snprintf(sz, sizeof sz, "%zx\r\n", n);
    h_put(h, sz, (size_t)k);
    if (h->st != H_DEAD)
        h_put(h, p, n);
    if (h->st != H_DEAD)
        h_put(h, "\r\n", 2);
    if (h->st != H_DEAD)
        h_flush(h);
}

void h_stream_end(hconn *h)
{
    if (h->st == H_DEAD)
        return;
    h_put(h, "0\r\n\r\n", 5);
    if (h->st == H_DEAD)
        return;
    h->resp_done = true;
    h_finish(h);
}

// The response is complete: on to the next request (after the body, which
// must have been read whole, or the connection can't be reused).
static void h_finish(hconn *h)
{
    if (!h->body_done)
        h->close_after = true;
    g_close(h->g);
    h->g = nullptr;
    rq_reset(h);
    http_req_free(&h->req);
    h->have_req = false;
    sb_free(&h->body);
    h->body_stream = false;
    h->resp_chunked = h->resp_done = false;
    h->st = H_HEAD;
    h->deadline = now_ms() + IDLE_MS;
    // A body consumer may have paused reading and then finished without
    // asking for more (its last bytes were buffered already): the next
    // request has to be read.
    h_pause_read(h, false);
    h_flush(h);
    if (h->st != H_DEAD && !h->busy && !h->close_after && h->in_len)
        h_process(h); // a pipelined request
}

static void h_error_close(hconn *h, int status, const char *msg)
{
    h->close_after = true;
    h->body_done = true;
    h_api_error(h, status, msg);
}

// --- routing --------------------------------------------------------------------------

// "<port>-<id>.<anything>": the E2B form of a sandbox's port as a host name.
static bool host_port(const char *host, uint32_t *port, char *id, size_t cap)
{
    if (!host)
        return false;
    uint32_t p = 0;
    const char *c = host;
    if (*c < '0' || *c > '9')
        return false;
    for (; *c >= '0' && *c <= '9'; c++) {
        p = p * 10 + (uint32_t)(*c - '0');
        if (p > 65535)
            return false;
    }
    if (*c++ != '-')
        return false;
    size_t n = 0;
    for (; *c && *c != '.' && *c != ':'; c++) {
        if (n + 1 >= cap || !((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9')))
            return false;
        id[n++] = *c;
    }
    id[n] = 0;
    *port = p;
    return n > 0 && (*c == '.' || *c == ':' || !*c);
}

// Which sandbox an envd request is for: from E2b-Sandbox-Id, or a
// 49983-<id>.<domain> host. 1 found, 0 not an envd request, -1 unknown id.
static int envd_target(hconn *h, sandbox **out)
{
    const char *id = http_header(&h->req, "e2b-sandbox-id");
    char hid[32];
    uint32_t port;
    if (!id && host_port(http_header(&h->req, "host"), &port, hid, sizeof hid) && port == 49983)
        id = hid;
    if (!id)
        return 0;
    *out = sb_find(id);
    return *out ? 1 : -1;
}

static void h_on_head(hconn *h)
{
    http_req *r = &h->req;
    h->body_done = false;
    h->body_chunked = r->chunked;
    h->body_left = r->chunked ? 0 : r->length < 0 ? 0 : r->length;
    h->ck = (http_chunked){0};
    h->body_max = 1u << 20;
    if (r->close)
        h->close_after = true;
    const bool has_body = r->chunked || r->length > 0;
    if (!has_body)
        h->body_done = true;

    // A port: the connection becomes a tunnel to it, head and all.
    char id[32];
    uint32_t port;
    if (host_port(http_header(r, "host"), &port, id, sizeof id) && port != 49983) {
        sandbox *sb = sb_find(id);
        if (!sb || sb->st != SB_RUNNING) {
            h_error_close(h, 502, sb ? "the sandbox is not running" : "the sandbox was not found");
            return;
        }
        tunnel_start(h, sb, port);
        return;
    }
    if (r->expect_100 && has_body)
        h_put(h, "HTTP/1.1 100 Continue\r\n\r\n", 25);
    sandbox *sb = nullptr;
    const int t = envd_target(h, &sb);
    if (t < 0) {
        // The SDKs read a 502 whose message says "was not found" as "this
        // sandbox is gone" (not "unreachable").
        h->close_after = !h->body_done;
        connect_error(h, false, "unavailable", "the sandbox was not found");
        return;
    }
    if (t > 0) {
        // Bodies that are streamed instead of read whole: StreamInput and
        // uploads.
        if (!strcmp(r->method, "POST") &&
            (!strcmp(r->path, "/files") || !strcmp(r->path, "/process.Process/StreamInput"))) {
            h->body_stream = true;
            h->st = H_BODY;
            envd_request(h, sb);
            if (h->st == H_BODY && h->body_done && h->rq.kind != RQ_NONE)
                envd_body_end(h); // an empty body
            return;
        }
        h->st = H_BODY;
        h->rq.envd = true;
        h->rq.sb = sb;
        return; // dispatched when the body is in
    }
    h->st = H_BODY;
}

static void h_body_complete(hconn *h)
{
    if (h->body.oom) {
        h_error_close(h, 500, "out of memory");
        return;
    }
    if (h->rq.envd) {
        sandbox *sb = h->rq.sb;
        h->rq.envd = false;
        h->rq.sb = nullptr;
        if (!sb)
            connect_error(h, false, "unavailable", "the sandbox was not found");
        else
            envd_request(h, sb);
    } else {
        api_request(h);
    }
}

// Body bytes for the request: whole, or to the consumer.
static void h_body_bytes(hconn *h, const uint8_t *p, size_t n)
{
    if (!n)
        return;
    if (h->body_stream) {
        envd_body(h, p, n);
        return;
    }
    if (h->body.len + n > h->body_max) {
        h_error_close(h, 413, "the request body is too large");
        return;
    }
    sb_put(&h->body, p, n);
}

static void h_consume(hconn *h, size_t n)
{
    memmove(h->in, h->in + n, h->in_len - n);
    h->in_len -= n;
}

static void h_process_(hconn *h);
static void h_process(hconn *h)
{
    if (h->busy)
        return; // the loop below will see it
    h->busy = true;
    h_process_(h);
    h->busy = false;
}

static void h_process_(hconn *h)
{
    while (h->st != H_DEAD) {
        if (h->st == H_TUNNEL) {
            if (h->in_len && h->g && h->g->st == G_RAW) {
                g_send_raw(h->g, h->in, h->in_len);
                h->in_len = 0;
                if (h->g && g_pending(h->g) >= G_HIGH)
                    h_pause_read(h, true);
            }
            return;
        }
        if (h->st == H_HEAD) {
            if (!h->in_len || h->close_after)
                return;
            size_t used;
            const int r = http_parse_head(h->in, h->in_len, &h->req, &used);
            if (r == 0)
                return;
            if (r != 1) {
                h_error_close(h, r, r == 431 ? "the request head is too large" : r == 505 ? "HTTP/1.1 only"
                                                                             : r == 501 ? "only chunked transfer coding"
                                                                                        : "malformed request");
                return;
            }
            h->have_req = true;
            if (C.verbose)
                logf_("%s %s", h->req.method, h->req.target);
            // Tunnels forward the head as it came: keep it in the buffer.
            char id[32];
            uint32_t port;
            const bool tunnel =
                host_port(http_header(&h->req, "host"), &port, id, sizeof id) && port != 49983;
            if (!tunnel)
                h_consume(h, used);
            h_on_head(h);
            continue;
        }
        // H_BODY
        if (h->body_done) {
            if (h->rq.kind == RQ_NONE && !h->body_stream && h->st == H_BODY) {
                h_body_complete(h);
                continue;
            }
            return; // the answer is still being made
        }
        if (h->read_paused || !h->in_len)
            return;
        if (h->body_chunked) {
            size_t used, outn;
            const int r = http_chunked_feed(&h->ck, h->in, h->in_len, &used, h->in, &outn);
            if (r < 0) {
                h_error_close(h, 400, "malformed chunked body");
                return;
            }
            // The decoded bytes are at the front; the input taken was `used`.
            uint8_t *copy = nullptr;
            if (outn) {
                if (!(copy = malloc(outn))) {
                    h_close(h);
                    return;
                }
                memcpy(copy, h->in, outn);
            }
            h_consume(h, used);
            if (r == 1)
                h->body_done = true;
            h_body_bytes(h, copy, outn);
            free(copy);
        } else {
            const size_t k = (uint64_t)h->body_left < h->in_len ? (size_t)h->body_left : h->in_len;
            uint8_t *copy = malloc(k ? k : 1);
            if (!copy) {
                h_close(h);
                return;
            }
            memcpy(copy, h->in, k);
            h_consume(h, k);
            h->body_left -= (int64_t)k;
            if (!h->body_left)
                h->body_done = true;
            h_body_bytes(h, copy, k);
            free(copy);
        }
        if (h->st == H_DEAD)
            return;
        if (h->body_done && h->body_stream && h->rq.kind != RQ_NONE)
            envd_body_end(h);
    }
}

void h_body_more(hconn *h)
{
    if (h->st == H_DEAD)
        return;
    h_pause_read(h, false);
    h_process(h);
}

static void h_readable(hconn *h)
{
    for (int rounds = 0; rounds < 8 && h->st != H_DEAD && !h->read_paused; rounds++) {
        if (h->in_len == h->in_cap) {
            if (h->st == H_HEAD) {
                h_error_close(h, 431, "the request head is too large");
                return;
            }
            return; // the body consumer is behind: wait
        }
        const ssize_t n = recv(h->fd, h->in + h->in_len, h->in_cap - h->in_len, MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR)
                return;
            h_close(h);
            return;
        }
        if (n == 0) {
            h->peer_eof = true;
            if (h->st == H_TUNNEL && h->g) {
                g_shutdown_write(h->g);
                h_update(h);
                return;
            }
            // The client is gone or done: nothing more will come.
            if (h->st == H_HEAD && !h_pending(h))
                h_close(h);
            else if (h->st == H_BODY && !h->body_done)
                h_close(h);
            else
                h_update(h);
            return;
        }
        h->in_len += (size_t)n;
        if (h->st == H_HEAD && h->deadline > now_ms() + HEAD_MS)
            h->deadline = now_ms() + HEAD_MS; // a head has begun: it has a while to arrive
        h_process(h);
    }
}

static void h_accept(int lfd)
{
    for (;;) {
        const int fd = accept4(lfd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0)
            return;
        if (nconns >= C.max_conns) {
            close(fd);
            continue;
        }
        const int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        hconn *h = calloc(1, sizeof *h);
        uint8_t *in = malloc(IN_CAP);
        if (!h || !in) {
            free(h);
            free(in);
            close(fd);
            continue;
        }
        *h = (hconn){.kind = EV_HTTP, .fd = fd, .st = H_HEAD, .in = in, .in_cap = IN_CAP,
                     .deadline = now_ms() + HEAD_MS, .next = conns};
        if (conns)
            conns->prev = h;
        conns = h;
        nconns++;
        ev_set(fd, h, true, false);
    }
}

void h_forget_sandbox(sandbox *sb)
{
    for (hconn *h = conns; h; h = h->next)
        if (h->rq.sb == sb)
            h->rq.sb = nullptr;
}

// --- port tunnels -------------------------------------------------------------------

static void tun_frame(gconn *g, const mvs_frame *f)
{
    hconn *h = g->ctx;
    if (f->type == MVS_OK) {
        g_raw_mode(g);
        h->rq.started = true;
        h_process(h); // the head, and whatever followed it
        return;
    }
    mvs_error e = {0};
    const bool known = f->type == MVS_ERROR && mvs_dec_error(f, &e);
    h->g = nullptr;
    g_close(g);
    h->st = H_BODY;
    h->body_done = true;
    h->close_after = true;
    // The SDKs' word for it ("port is not open": SandboxUnreachable).
    h_api_error(h, 502, known && e.kind == MVS_E_LIMIT ? "too many connections" : "the port is not open");
}

static void tun_raw(gconn *g, const uint8_t *p, size_t n)
{
    hconn *h = g->ctx;
    if (!n) { // the guest's side is done: so is the connection, once flushed
        h->g = nullptr;
        g_close(g);
        if (!h_pending(h))
            h_close(h);
        return;
    }
    h_put(h, p, n);
    if (h->st == H_DEAD)
        return;
    h_flush(h);
    if (h->st != H_DEAD && h_pending(h) >= G_HIGH && h->g)
        g_pause(h->g, true);
}

static void tun_end(gconn *g, const char *why)
{
    hconn *h = g->ctx;
    h->g = nullptr;
    if (g->st != G_RAW && !h->rq.started) { // never got to the port: answer in HTTP
        h->st = H_BODY;
        h->body_done = true;
        h->close_after = true;
        h_api_error(h, 502, why ? why : "the sandbox is unreachable");
        return;
    }
    if (!h_pending(h))
        h_close(h);
}

static void tun_drained(gconn *g)
{
    hconn *h = g->ctx;
    h_body_more(h);
}

static const gconn_ops tunnel_ops = {.frame = tun_frame, .raw = tun_raw, .end = tun_end, .drained = tun_drained};

void tunnel_start(hconn *h, sandbox *sb, uint32_t port)
{
    bool retry;
    gconn *g = g_open(sb, &tunnel_ops, h, &retry);
    if (!g) {
        h_error_close(h, 502, "the sandbox is unreachable");
        return;
    }
    h->st = H_TUNNEL;
    h->rq.kind = RQ_TUNNEL;
    h->g = g;
    h->deadline = INT64_MAX;
    mvs_buf b = {0};
    mvs_req_port(&b, port);
    g_send(g, &b);
}

// --- start-up ----------------------------------------------------------------------

[[noreturn]] static void usage(void)
{
    fprintf(stderr,
            "usage: microvm-sbxd --vmm MICROVM --kernel VMLINUX [--kernel-smp VMLINUX] --dir DIR\n"
            "       microvm-sbxd --version\n"
            "                    [--template NAME=IMAGE[,mem=MIB][,cpus=N][,user=NAME][,net]]...\n"
            "  (or none: templates pushed at run time, PUT /templates/NAME)\n"
            "  cpus=N (1..8, default 1) needs --kernel-smp, a kernel built with SMP\n"
            "                    [--listen ADDR:PORT] [--api-key-file FILE] [--domain DOMAIN]\n"
            "                    [--jail MICROVM-JAIL] [--max-sandboxes N] [--verbose]\n"
            "                    [--net-deny-port PORT|none]... [--net-flow-rate N] [--net-max-dests N]\n"
            "                    [--net-tx-rate BYTES] [--cgroup DIR] [--max-timeout SECONDS|none]\n"
            "  the network of sandboxes with the internet: ports refused (default: 25, 465, 587),\n"
            "  new flows a second, different addresses a minute, bytes a second out (default: no\n"
            "  limit); a create request's \"netLimits\" object overrides the limits\n"
            "  --cgroup: a cgroup v2 directory this daemon may write: a create's \"pool\" puts the\n"
            "  sandbox in its team's cgroup there, with the team's vCPUs and memory\n"
            "  --max-timeout: the longest a sandbox's timeout may be (default 86400; none: no limit)\n");
    exit(2);
}

static void parse_template(const char *arg)
{
    if (C.ntmpl == (int)(sizeof C.tmpl / sizeof *C.tmpl)) {
        fprintf(stderr, "too many templates\n");
        exit(2);
    }
    tmpl *t = &C.tmpl[C.ntmpl++];
    *t = (tmpl){.mem_mib = 512, .cpus = 1};
    char buf[1024];
    if (strlen(arg) >= sizeof buf)
        usage();
    strcpy(buf, arg);
    char *eq = strchr(buf, '=');
    if (!eq || eq == buf || (size_t)(eq - buf) >= sizeof t->name)
        usage();
    *eq = 0;
    for (const char *c = buf; *c; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '-' || *c == '_' || *c == '.'))
            usage();
    strcpy(t->name, buf);
    char *save, *tok = strtok_r(eq + 1, ",", &save);
    if (!tok || strlen(tok) >= sizeof t->image)
        usage();
    strcpy(t->image, tok);
    while ((tok = strtok_r(nullptr, ",", &save))) {
        if (!strncmp(tok, "mem=", 4)) {
            char *end;
            const unsigned long m = strtoul(tok + 4, &end, 10);
            if (*end || m < 64 || m > 3072)
                usage();
            t->mem_mib = (uint32_t)m;
        } else if (!strncmp(tok, "cpus=", 5)) {
            char *end;
            const unsigned long n = strtoul(tok + 5, &end, 10);
            if (*end || n < 1 || n > 8)
                usage();
            t->cpus = (uint32_t)n;
        } else if (!strncmp(tok, "user=", 5) && strlen(tok + 5) < sizeof t->user) {
            strcpy(t->user, tok + 5);
        } else if (!strcmp(tok, "net")) {
            t->net = true;
        } else {
            usage();
        }
    }
}

static int listen_on(const char *spec)
{
    char host[128];
    const char *colon = strrchr(spec, ':');
    if (!colon || (size_t)(colon - spec) >= sizeof host)
        usage();
    memcpy(host, spec, (size_t)(colon - spec));
    host[colon - spec] = 0;
    char *end;
    const unsigned long port = strtoul(colon + 1, &end, 10);
    if (*end || !port || port > 65535)
        usage();
    struct sockaddr_storage ss = {0};
    socklen_t sl;
    int fam;
    if (host[0] == '[' && host[strlen(host) - 1] == ']') {
        host[strlen(host) - 1] = 0;
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, host + 1, &a->sin6_addr) != 1)
            usage();
        sl = sizeof *a, fam = AF_INET6;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, host, &a->sin_addr) != 1)
            usage();
        sl = sizeof *a, fam = AF_INET;
    }
    const int fd = socket(fam, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    const int one = 1;
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) ||
        bind(fd, (struct sockaddr *)&ss, sl) || listen(fd, 512)) {
        fprintf(stderr, "microvm-sbxd: cannot listen on %s: %s\n", spec, strerror(errno));
        exit(1);
    }
    return fd;
}

// Empties a directory: its files, and directories of files (a sandbox's).
static void clean_dir_at(int dfd, int depth)
{
    DIR *d = fdopendir(dfd);
    if (!d) {
        close(dfd);
        return;
    }
    for (struct dirent *e; (e = readdir(d));) {
        if (e->d_name[0] == '.' && (!e->d_name[1] || (e->d_name[1] == '.' && !e->d_name[2])))
            continue;
        if (!unlinkat(dirfd(d), e->d_name, 0) || depth == 0)
            continue;
        const int sub = openat(dirfd(d), e->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (sub >= 0) {
            clean_dir_at(sub, depth - 1);
            unlinkat(dirfd(d), e->d_name, AT_REMOVEDIR);
        }
    }
    closedir(d);
}

// The sandboxes' directory holds nothing from an earlier run.
static void clean_dir(const char *dir)
{
    const int fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0)
        clean_dir_at(fd, 1);
}

static void on_signal(int sig)
{
    (void)sig;
    stopping = 1;
}

static void tick(int64_t now)
{
    for (hconn *h = conns, *next; h; h = next) {
        next = h->next;
        if (h->st == H_HEAD && now > h->deadline) {
            if (h->have_req || h->in_len)
                h_error_close(h, 408, "the request took too long");
            else
                h_close(h);
            continue;
        }
        if (h->rq.kind == RQ_STREAM)
            envd_tick(h, now);
    }
    sb_tick(now);
    fetch_tick(now);
    tmpl_tick();
}

// The controllers a team's cgroup (api.c, pools) needs in DIR's children:
// on, or turned on here.
static bool cgroup_ok(const char *dir)
{
    char p[600], b[256];
    snprintf(p, sizeof p, "%s/cgroup.subtree_control", dir);
    int fd = open(p, O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        (void)!write(fd, "+cpu +memory +pids", 18);
        close(fd);
    }
    fd = open(p, O_RDONLY | O_CLOEXEC);
    const ssize_t n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
    if (fd >= 0)
        close(fd);
    if (n <= 0)
        return false;
    b[n] = 0;
    bool cpu = false, mem = false;
    for (char *save, *w = strtok_r(b, " \n", &save); w; w = strtok_r(nullptr, " \n", &save))
        cpu |= !strcmp(w, "cpu"), mem |= !strcmp(w, "memory");
    // Teams' cgroups a daemon before this one left: gone, once empty.
    DIR *d = opendir(dir);
    for (struct dirent *e; d && (e = readdir(d));) {
        if (strncmp(e->d_name, "t-", 2) || e->d_type != DT_DIR)
            continue;
        char t[600];
        snprintf(t, sizeof t, "%s/%s", dir, e->d_name);
        DIR *v = opendir(t);
        for (struct dirent *f; v && (f = readdir(v));) {
            char vm[900];
            snprintf(vm, sizeof vm, "%s/%s", t, f->d_name);
            if (f->d_type == DT_DIR && f->d_name[0] != '.')
                rmdir(vm); // a jailed VM's
        }
        if (v)
            closedir(v);
        rmdir(t);
    }
    if (d)
        closedir(d);
    return cpu && mem;
}

int main(int argc, char **argv)
{
    const char *listen_spec = "127.0.0.1:3000", *key_file = nullptr;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const bool v = i + 1 < argc;
        if (!strcmp(a, "--version")) {
            printf("microvm-sbxd %s\n", MICROVM_VERSION);
            return 0;
        }
        if (!strcmp(a, "--vmm") && v) C.vmm = argv[++i];
        else if (!strcmp(a, "--jail") && v) C.jail = argv[++i];
        else if (!strcmp(a, "--kernel") && v) C.kernel = argv[++i];
        else if (!strcmp(a, "--kernel-smp") && v) C.kernel_smp = argv[++i];
        else if (!strcmp(a, "--dir") && v) C.dir = argv[++i];
        else if (!strcmp(a, "--domain") && v) C.domain = argv[++i];
        else if (!strcmp(a, "--listen") && v) listen_spec = argv[++i];
        else if (!strcmp(a, "--api-key-file") && v) key_file = argv[++i];
        else if (!strcmp(a, "--template") && v) parse_template(argv[++i]);
        else if (!strcmp(a, "--max-sandboxes") && v) C.max_sandboxes = atoi(argv[++i]);
        else if (!strcmp(a, "--cgroup") && v) C.cgroup = argv[++i];
        else if (!strcmp(a, "--max-timeout") && v) {
            const char *p = argv[++i];
            char *end;
            const unsigned long long s = strtoull(p, &end, 10);
            if (!strcmp(p, "none"))
                C.max_timeout_s = 0;
            else if (*p >= '1' && *p <= '9' && !*end && s <= 10ULL * 365 * 86400)
                C.max_timeout_s = (int64_t)s;
            else
                usage();
        }
        else if (!strcmp(a, "--net-deny-port") && v) {
            const char *p = argv[++i];
            char *end;
            const unsigned long port = strtoul(p, &end, 10);
            if (!strcmp(p, "none") && C.nnet_deny <= 0)
                C.nnet_deny = -1;
            else if (C.nnet_deny >= 0 && C.nnet_deny < 16 && *p && !*end && port && port <= 65535)
                C.net_deny[C.nnet_deny++] = (uint16_t)port;
            else
                usage();
        } else if ((!strcmp(a, "--net-flow-rate") || !strcmp(a, "--net-max-dests") || !strcmp(a, "--net-tx-rate")) && v) {
            const char *p = argv[++i];
            char *end;
            const unsigned long long n = strtoull(p, &end, 10);
            const unsigned long long max = a[6] == 'f' ? 1000000 : a[6] == 'm' ? 4096 : 1000000000;
            if (*p < '1' || *p > '9' || *end || n > max)
                usage();
            if (a[6] == 'f')
                C.net_flow_rate = (uint32_t)n;
            else if (a[6] == 'm')
                C.net_max_dests = (uint32_t)n;
            else
                C.net_tx_rate = n;
        }
        else if (!strcmp(a, "--verbose")) C.verbose = true;
        else usage();
    }
    if (!C.nnet_deny) { // mail: a sandbox never sends it itself
        static const uint16_t MAIL[] = {25, 465, 587};
        for (size_t k = 0; k < sizeof MAIL / sizeof MAIL[0]; k++)
            C.net_deny[C.nnet_deny++] = MAIL[k];
    }
    // No --template: templates come at run time (PUT /templates/NAME).
    if (!C.vmm || !C.kernel || !C.dir || C.max_sandboxes < 1 || C.dir[0] != '/' || strlen(C.dir) > 200)
        usage();
    for (int i = 0; i < C.ntmpl; i++)
        if (C.tmpl[i].cpus > 1 && !C.kernel_smp) {
            fprintf(stderr, "template %s: cpus=%u needs --kernel-smp\n", C.tmpl[i].name, C.tmpl[i].cpus);
            exit(2);
        }
    if (key_file) {
        const int fd = open(key_file, O_RDONLY | O_CLOEXEC);
        const ssize_t n = fd < 0 ? -1 : read(fd, C.api_key, sizeof C.api_key - 1);
        if (fd >= 0)
            close(fd);
        if (n <= 0) {
            fprintf(stderr, "microvm-sbxd: cannot read the API key from '%s'\n", key_file);
            return 1;
        }
        C.api_key[n] = 0;
        C.api_key[strcspn(C.api_key, "\r\n")] = 0;
        if (!C.api_key[0]) {
            fprintf(stderr, "microvm-sbxd: '%s' is empty\n", key_file);
            return 1;
        }
    }
    umask(077);
    char sub[1024], images[1024];
    snprintf(sub, sizeof sub, "%s/sbx", C.dir);
    snprintf(images, sizeof images, "%s/images", C.dir);
    if ((mkdir(C.dir, 0700) && errno != EEXIST) || (mkdir(sub, 0700) && errno != EEXIST) ||
        (mkdir(images, 0700) && errno != EEXIST)) {
        fprintf(stderr, "microvm-sbxd: cannot make '%s': %s\n", sub, strerror(errno));
        return 1;
    }
    clean_dir(sub); // images/ stays: a cache of checked template images
    if (C.cgroup && !cgroup_ok(C.cgroup)) {
        fprintf(stderr, "microvm-sbxd: --cgroup %s: not a cgroup v2 directory with the cpu and memory controllers on "
                        "in its cgroup.subtree_control (and this daemon can't turn them on)\n", C.cgroup);
        return 1;
    }
    struct sigaction sa = {.sa_handler = SIG_IGN};
    sigaction(SIGPIPE, &sa, nullptr);
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);

    epfd = epoll_create1(EPOLL_CLOEXEC);
    const int lfd = listen_on(listen_spec);
    static ev_head listener = {EV_LISTEN};
    struct epoll_event le = {.events = EPOLLIN, .data.ptr = &listener};
    epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &le);
    if (!C.api_key[0])
        logf_("no --api-key-file: any API key is accepted");
    logf_("listening on %s", listen_spec);
    if (!sb_notify_start())
        logf_("no inotify: a pause ends when its VMM has exited (~40 ms later)");
    templates_prepare();

    int64_t next_tick = now_ms() + 1000;
    while (!stopping) {
        int64_t now = now_ms();
        int64_t until = next_tick;
        const int64_t sd = sb_next_deadline();
        if (sd < until)
            until = sd;
        const int timeout = until <= now ? 0 : (int)(until - now);
        struct epoll_event evs[64];
        const int n = epoll_wait(epfd, evs, 64, timeout);
        if (n < 0 && errno != EINTR)
            break;
        for (int i = 0; i < n; i++) {
            ev_head *o = evs[i].data.ptr;
            const uint32_t e = evs[i].events;
            switch (o->kind) {
            case EV_LISTEN:
                h_accept(lfd);
                break;
            case EV_HTTP: {
                // A hang-up means nothing more can be sent either.
                hconn *h = (hconn *)o;
                if (e & (EPOLLERR | EPOLLHUP)) {
                    h_close(h);
                    break;
                }
                if (h->st != H_DEAD && (e & EPOLLOUT))
                    h_flush(h);
                if (h->st != H_DEAD && (e & EPOLLIN))
                    h_readable(h);
                break;
            }
            case EV_GUEST: {
                // A hang-up still leaves what the guest sent to be read.
                gconn *g = (gconn *)o;
                if (e & EPOLLERR) {
                    g_fail(g, "the sandbox's connection failed");
                    break;
                }
                if (g->st != G_DEAD && (e & EPOLLOUT))
                    g_flush(g);
                if (g->st != G_DEAD && (e & (EPOLLIN | EPOLLHUP))) {
                    if (g->read_eof)
                        g_fail(g, nullptr);
                    else
                        g_readable(g);
                }
                break;
            }
            case EV_PIDFD:
                sb_vmm_exited((sandbox *)o);
                break;
            case EV_NOTIFY:
                sb_notify_readable();
                break;
            case EV_REAP:
                sb_reaped(o);
                break;
            case EV_FETCH:
                fetch_event(o, e);
                break;
            }
            graveyard_empty();
        }
        now = now_ms();
        if (now >= next_tick) {
            tick(now);
            next_tick = now + 1000;
        } else {
            sb_tick(now); // connect retries are due on their own clock
        }
        graveyard_empty();
    }
    logf_("stopping: killing %d sandboxes", sb_count());
    for (sandbox *sb = sandboxes; sb; sb = sb->next)
        if (sb->pid > 0)
            kill(sb->pid, SIGKILL);
    clean_dir(sub);
    return 0;
}
