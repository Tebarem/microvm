// SPDX-License-Identifier: MIT
// The host's client for one VM's agent (POSIX): the vsock handshake on the
// VMM's Unix socket, then INVOKE out and the parser on what comes back,
// both directions at once under one wall-clock limit.
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"

static double now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

static int fail(mva_client *c, const char *why)
{
    c->error = why;
    c->dead = true;
    return -1;
}

// One attempt: 0 connected, 1 try again (no socket yet, or the agent isn't
// listening yet), -1 a real error.
static int try_connect(mva_client *c, const char *uds_path, double end)
{
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    if (strlen(uds_path) >= sizeof a.sun_path)
        return -1;
    strcpy(a.sun_path, uds_path);
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (connect(fd, (struct sockaddr *)&a, sizeof a)) {
        close(fd);
        return errno == ENOENT || errno == ECONNREFUSED ? 1 : -1;
    }
    static const char line[] = "CONNECT 52\n";
    static_assert(MVA_PORT == 52);
    if (send(fd, line, sizeof line - 1, MSG_NOSIGNAL) != (ssize_t)(sizeof line - 1)) {
        close(fd);
        return 1;
    }
    // "OK <n>\n", strictly, then frames. Whatever follows the line is the
    // start of the agent's stream.
    size_t n = 0;
    for (;;) {
        const int wait = (int)(end - now_ms());
        struct pollfd p = {.fd = fd, .events = POLLIN};
        if (wait <= 0 || poll(&p, 1, wait) <= 0) {
            close(fd);
            return -1;
        }
        const ssize_t r = recv(fd, c->buf + n, 32 - n, 0);
        if (r <= 0) { // the guest refused: nobody listens on the port yet
            close(fd);
            return 1;
        }
        n += (size_t)r;
        const uint8_t *nl = memchr(c->buf, '\n', n);
        if (!nl) {
            if (n >= 32) {
                close(fd);
                return -1;
            }
            continue;
        }
        const size_t line_len = (size_t)(nl - c->buf) + 1;
        bool ok = line_len >= 5 && !memcmp(c->buf, "OK ", 3);
        for (size_t i = 3; ok && i + 1 < line_len; i++)
            ok = c->buf[i] >= '0' && c->buf[i] <= '9';
        if (!ok) {
            close(fd);
            return -1;
        }
        memmove(c->buf, c->buf + line_len, n - line_len);
        c->blen = n - line_len;
        c->fd = fd;
        return 0;
    }
}

int mva_connect(mva_client *c, const char *uds_path, int timeout_ms)
{
    c->fd = -1;
    c->next_id = 1;
    c->dead = false;
    c->error = nullptr;
    c->blen = 0;
    mva_parser_init(&c->p);
    const double end = now_ms() + timeout_ms;
    for (;;) {
        const int r = try_connect(c, uds_path, end);
        if (r == 0)
            return 0;
        if (r < 0 || now_ms() >= end)
            return fail(c, "cannot connect to the agent");
        const struct timespec ts = {0, 100 * 1000};
        nanosleep(&ts, nullptr);
    }
}

// Parse what is buffered. -1 on a protocol error.
static int drain(mva_client *c, mva_response *rs)
{
    const size_t k = mva_parse(&c->p, c->buf, c->blen, rs);
    if (c->p.error)
        return fail(c, c->p.error);
    if (k < c->blen) // only after DONE: the guest sent more than the invocation
        return fail(c, "data after DONE");
    c->blen = 0;
    return 0;
}

static int read_some(mva_client *c, mva_response *rs)
{
    const ssize_t r = recv(c->fd, c->buf, sizeof c->buf, MSG_DONTWAIT);
    if (r == 0)
        return fail(c, "the agent closed the connection");
    if (r < 0)
        return errno == EAGAIN || errno == EINTR ? 0 : fail(c, "read from the agent failed");
    c->blen = (size_t)r;
    return drain(c, rs);
}

int mva_hello(mva_client *c, int timeout_ms)
{
    mva_response none = {0};
    const double end = now_ms() + timeout_ms;
    if (c->blen && drain(c, &none))
        return -1;
    while (!c->p.hello) {
        const int wait = (int)(end - now_ms());
        struct pollfd p = {.fd = c->fd, .events = POLLIN};
        if (wait <= 0 || poll(&p, 1, wait) <= 0)
            return fail(c, "no HELLO from the agent");
        if (read_some(c, &none))
            return -1;
    }
    return 0;
}

int mva_invoke(mva_client *c, const mva_request *rq, mva_response *rs, int grace_ms)
{
    if (c->dead || c->fd < 0)
        return fail(c, c->error ? c->error : "not connected");
    size_t len = 0;
    const uint32_t id = c->next_id++;
    uint8_t *frame = mva_encode_invoke(rq, id, &len);
    if (!frame) {
        c->error = "the request breaks a protocol limit";
        return -1; // nothing was sent: the VM is fine
    }
    mva_parser_expect(&c->p, id, rq->max_result, rq->max_output);
    const double end = now_ms() + rq->deadline_ms + grace_ms;
    size_t sent = 0;
    int ret = 0;
    if (c->blen) // the HELLO may have come with the handshake's reply
        ret = drain(c, rs);
    while (!ret && !rs->done) {
        const int wait = (int)(end - now_ms());
        if (wait <= 0) {
            ret = fail(c, "no DONE within the deadline");
            break;
        }
        struct pollfd p = {.fd = c->fd, .events = (short)(POLLIN | (sent < len ? POLLOUT : 0))};
        if (poll(&p, 1, wait) < 0 && errno != EINTR) {
            ret = fail(c, "poll failed");
            break;
        }
        if ((p.revents & POLLOUT) && sent < len) {
            const ssize_t w = send(c->fd, frame + sent, len - sent, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (w > 0)
                sent += (size_t)w;
            else if (w < 0 && errno != EAGAIN && errno != EINTR)
                ret = fail(c, "write to the agent failed");
        }
        if (!ret && (p.revents & (POLLIN | POLLHUP | POLLERR)))
            ret = read_some(c, rs);
    }
    free(frame);
    // DONE before the whole request was read: only as the VM's last word
    // (a runtime that stopped reading, killed at its deadline, say).
    if (!ret && sent < len && !(rs->flags & MVA_DONE_VM_ENDS))
        ret = fail(c, "DONE before the request was read");
    if (!ret && (rs->flags & MVA_DONE_VM_ENDS)) {
        // The agent waits for this before it stops the VM, so that the
        // VMM has passed on everything it sent.
        shutdown(c->fd, SHUT_WR);
        c->dead = true;
    }
    return ret;
}

void mva_close(mva_client *c)
{
    if (c->fd >= 0)
        close(c->fd);
    c->fd = -1;
    c->dead = true;
}
