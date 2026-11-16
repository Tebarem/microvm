// SPDX-License-Identifier: MIT
// Template images fetched at run time: an HTTP GET (an S3 presigned URL,
// from the control plane) streamed to DIR/images/SHA256.part, hashed on the
// way, and renamed to SHA256.erofs only when its size and SHA-256 are the
// ones asked for. Nothing unchecked is ever named like an image.
//
// Plain HTTP to an address literal: the store is on the nodes' private
// network, the control plane signs the URL, and the hash is what makes the
// bytes trustworthy, not the transport. No DNS (no blocking lookups in the
// loop), no redirects, no chunked bodies (S3 GETs carry Content-Length).
// One download per image however many templates want it; MAX_ACTIVE at a
// time, the rest queued.
#include "sbxd/sbxd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "image/sha256.h"

enum { F_QUEUED, F_CONNECT, F_SEND, F_HEAD, F_BODY };
enum : int64_t { IDLE_MS = 30000 };
enum { MAX_ACTIVE = 4, HEAD_MAX = 8192 };

typedef struct fetch fetch;
struct fetch {
    int kind; // EV_FETCH
    int fd, out;
    int st;
    char sha[65];
    uint64_t size, got;
    struct sockaddr_storage addr;
    socklen_t alen;
    char *req;
    size_t req_len, req_off;
    char head[HEAD_MAX];
    size_t head_len;
    sha256_ctx h;
    char part[600], dst[600];
    int64_t deadline, started;
    fetch *next;
};

static fetch *fetches;

static bool hexdigits(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return !s[n];
}

bool fetch_sha_ok(const char *sha) { return sha && strlen(sha) == 64 && hexdigits(sha, 64); }

// http://IPV4[:PORT]/PATH or http://[IPV6][:PORT]/PATH. *hostport: the
// authority as written (the Host header the URL was signed with).
static bool parse_url(const char *url, struct sockaddr_storage *ss, socklen_t *alen, char *hostport, size_t hcap,
                      const char **path)
{
    if (strncmp(url, "http://", 7))
        return false;
    const char *a = url + 7, *slash = strchr(a, '/');
    *path = slash ? slash : "/";
    const size_t al = slash ? (size_t)(slash - a) : strlen(a);
    if (!al || al >= hcap)
        return false;
    memcpy(hostport, a, al);
    hostport[al] = 0;
    for (const char *p = *path; *p; p++)
        if ((unsigned char)*p <= 0x20 || (unsigned char)*p >= 0x7f)
            return false; // no spaces, controls or raw UTF-8 in a request line
    char host[64];
    const char *port = nullptr;
    if (hostport[0] == '[') {
        const char *e = strchr(hostport, ']');
        if (!e || (size_t)(e - hostport - 1) >= sizeof host)
            return false;
        memcpy(host, hostport + 1, (size_t)(e - hostport - 1));
        host[e - hostport - 1] = 0;
        if (e[1] == ':')
            port = e + 2;
        else if (e[1])
            return false;
    } else {
        const char *c = strchr(hostport, ':');
        const size_t hl = c ? (size_t)(c - hostport) : al;
        if (hl >= sizeof host)
            return false;
        memcpy(host, hostport, hl);
        host[hl] = 0;
        port = c ? c + 1 : nullptr;
    }
    unsigned long pn = 80;
    if (port) {
        char *end;
        pn = strtoul(port, &end, 10);
        if (!*port || *end || pn < 1 || pn > 65535)
            return false;
    }
    memset(ss, 0, sizeof *ss);
    struct sockaddr_in *v4 = (struct sockaddr_in *)ss;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ss;
    if (inet_pton(AF_INET, host, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons((uint16_t)pn);
        *alen = sizeof *v4;
    } else if (inet_pton(AF_INET6, host, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons((uint16_t)pn);
        *alen = sizeof *v6;
    } else {
        return false; // a name: not resolved here
    }
    return true;
}

static int active(void)
{
    int n = 0;
    for (fetch *f = fetches; f; f = f->next)
        n += f->st != F_QUEUED;
    return n;
}

static void begin(fetch *f);

static void done(fetch *f, bool ok, const char *why)
{
    if (f->fd >= 0) {
        ev_del(f->fd);
        close(f->fd);
    }
    if (f->out >= 0)
        close(f->out);
    if (!ok)
        unlink(f->part);
    for (fetch **pp = &fetches; *pp; pp = &(*pp)->next)
        if (*pp == f) {
            *pp = f->next;
            break;
        }
    if (ok)
        logf_("image %.12s: fetched and checked (%llu MiB in %lld ms)", f->sha,
              (unsigned long long)(f->size >> 20), (long long)(now_ms() - f->started));
    else
        logf_("image %.12s: %s", f->sha, why);
    char sha[65];
    memcpy(sha, f->sha, sizeof sha);
    free(f->req);
    graveyard_add(f, free);
    tmpl_fetched(sha, ok, why);
    for (fetch *q = fetches; q && active() < MAX_ACTIVE; q = q->next)
        if (q->st == F_QUEUED)
            begin(q);
}

static void begin(fetch *f)
{
    f->started = now_ms();
    f->deadline = f->started + IDLE_MS;
    f->out = open(f->part, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (f->out < 0) {
        f->st = F_CONNECT;
        done(f, false, "cannot write the image file");
        return;
    }
    f->fd = socket(f->addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    f->st = F_CONNECT;
    if (f->fd < 0) {
        done(f, false, "no socket");
        return;
    }
    const int one = 1;
    setsockopt(f->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (connect(f->fd, (struct sockaddr *)&f->addr, f->alen) && errno != EINPROGRESS) {
        done(f, false, "cannot connect to the store");
        return;
    }
    ev_set(f->fd, f, false, true);
}

bool fetch_start(const char *sha, const char *url, uint64_t size, const char **why)
{
    for (fetch *f = fetches; f; f = f->next)
        if (!strcmp(f->sha, sha))
            return true; // under way: everyone waiting hears when it ends
    fetch *f = calloc(1, sizeof *f);
    if (!f) {
        *why = "out of memory";
        return false;
    }
    char hostport[300];
    const char *path;
    if (!parse_url(url, &f->addr, &f->alen, hostport, sizeof hostport, &path)) {
        free(f);
        *why = "the URL must be http://ADDRESS[:PORT]/PATH, with an address, not a name";
        return false;
    }
    sbuf r = {0};
    sb_printf(&r, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: microvm-sbxd\r\nConnection: close\r\n\r\n", path,
              hostport);
    if (r.oom) {
        sb_free(&r);
        free(f);
        *why = "out of memory";
        return false;
    }
    f->kind = EV_FETCH;
    f->fd = f->out = -1;
    f->req = r.p, f->req_len = r.len;
    memcpy(f->sha, sha, 65);
    f->size = size;
    sha256_init(&f->h);
    snprintf(f->part, sizeof f->part, "%s/images/%s.part", C.dir, sha);
    snprintf(f->dst, sizeof f->dst, "%s/images/%s.erofs", C.dir, sha);
    f->st = F_QUEUED;
    f->next = fetches;
    fetches = f;
    if (active() < MAX_ACTIVE)
        begin(f);
    return true;
}

static void finish(fetch *f)
{
    uint8_t d[32];
    char hex[65];
    sha256_final(&f->h, d);
    sha256_hex(d, hex);
    if (strcmp(hex, f->sha)) {
        done(f, false, "the image's SHA-256 is not the one asked for");
        return;
    }
    if (fchmod(f->out, 0444) || fsync(f->out) || rename(f->part, f->dst)) {
        done(f, false, "cannot keep the image");
        return;
    }
    done(f, true, nullptr);
}

// Body bytes: to the file and the hash.
static bool body(fetch *f, const uint8_t *p, size_t n)
{
    if (n > f->size - f->got) {
        done(f, false, "the store sent more than the image's size");
        return false;
    }
    sha256_update(&f->h, p, n);
    for (size_t off = 0; off < n;) {
        const ssize_t w = write(f->out, p + off, n - off);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0) {
            done(f, false, "cannot write the image file (disk full?)");
            return false;
        }
        off += (size_t)w;
    }
    f->got += n;
    if (f->got == f->size) {
        finish(f);
        return false;
    }
    return true;
}

static bool head_line_value(const char *head, const char *name, char *out, size_t cap)
{
    const size_t nl = strlen(name);
    for (const char *l = strstr(head, "\r\n"); l && l[2]; l = strstr(l + 2, "\r\n")) {
        const char *s = l + 2;
        if (!strncasecmp(s, name, nl) && s[nl] == ':') {
            s += nl + 1;
            while (*s == ' ' || *s == '\t')
                s++;
            const char *e = strstr(s, "\r\n");
            size_t n = e ? (size_t)(e - s) : strlen(s);
            while (n && (s[n - 1] == ' ' || s[n - 1] == '\t'))
                n--;
            if (n >= cap)
                return false;
            memcpy(out, s, n);
            out[n] = 0;
            return true;
        }
    }
    return false;
}

static void got_head(fetch *f, size_t end)
{
    f->head[end] = 0;
    int status = 0;
    if (sscanf(f->head, "HTTP/1.%*d %d", &status) != 1) {
        done(f, false, "the store's answer is not HTTP");
        return;
    }
    if (status != 200) {
        char why[96];
        snprintf(why, sizeof why, "the store answered %d", status);
        logf_("image %.12s: %.200s", f->sha, f->head);
        done(f, false, why);
        return;
    }
    char v[32];
    if (head_line_value(f->head, "transfer-encoding", v, sizeof v)) {
        done(f, false, "the store sent a chunked body");
        return;
    }
    char *e;
    if (!head_line_value(f->head, "content-length", v, sizeof v) || strtoull(v, &e, 10) != f->size || *e) {
        done(f, false, "the store's Content-Length is not the image's size");
        return;
    }
    f->st = F_BODY;
    const size_t rest = f->head_len - (end + 4);
    if (rest)
        body(f, (const uint8_t *)f->head + end + 4, rest);
}

void fetch_event(void *obj, uint32_t events)
{
    fetch *f = obj;
    (void)events;
    f->deadline = now_ms() + IDLE_MS;
    if (f->st == F_CONNECT) {
        int err = 0;
        socklen_t l = sizeof err;
        if (getsockopt(f->fd, SOL_SOCKET, SO_ERROR, &err, &l) || err) {
            done(f, false, "cannot connect to the store");
            return;
        }
        f->st = F_SEND;
    }
    if (f->st == F_SEND) {
        while (f->req_off < f->req_len) {
            const ssize_t w = send(f->fd, f->req + f->req_off, f->req_len - f->req_off, MSG_NOSIGNAL);
            if (w < 0 && errno == EINTR)
                continue;
            if (w < 0 && errno == EAGAIN)
                return;
            if (w <= 0) {
                done(f, false, "the store closed the connection");
                return;
            }
            f->req_off += (size_t)w;
        }
        f->st = F_HEAD;
        ev_set(f->fd, f, true, false);
        return;
    }
    if (f->st == F_HEAD) {
        const ssize_t r = recv(f->fd, f->head + f->head_len, sizeof f->head - 1 - f->head_len, 0);
        if (r < 0 && (errno == EAGAIN || errno == EINTR))
            return;
        if (r <= 0) {
            done(f, false, "the store closed the connection before answering");
            return;
        }
        f->head_len += (size_t)r;
        f->head[f->head_len] = 0;
        const char *e = strstr(f->head, "\r\n\r\n");
        if (e)
            got_head(f, (size_t)(e - f->head));
        else if (f->head_len == sizeof f->head - 1)
            done(f, false, "the store's answer has too large a head");
        return;
    }
    if (f->st == F_BODY) {
        // One read per event: other connections get their turn.
        static uint8_t buf[256 << 10];
        const ssize_t r = recv(f->fd, buf, sizeof buf, 0);
        if (r < 0 && (errno == EAGAIN || errno == EINTR))
            return;
        if (r <= 0) {
            done(f, false, "the store closed the connection before the end of the image");
            return;
        }
        body(f, buf, (size_t)r);
    }
}

void fetch_tick(int64_t now)
{
    for (fetch *f = fetches, *next; f; f = next) {
        next = f->next;
        if (f->st != F_QUEUED && now > f->deadline)
            done(f, false, "the store went quiet for 30 s");
    }
}

#ifdef SBXD_TESTING
bool fetch_parse_url_for_test(const char *url, char *hostport, size_t cap, const char **path)
{
    struct sockaddr_storage ss;
    socklen_t l;
    return parse_url(url, &ss, &l, hostport, cap, path);
}
#endif
