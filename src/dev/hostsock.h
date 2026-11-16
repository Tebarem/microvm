// SPDX-License-Identifier: MIT
// Host sockets for the devices that have a host side (vsock, net): one set
// of calls over Winsock and POSIX. Include it before anything that pulls in
// <windows.h>.
#pragma once

#include "../common.h"

// ---- host sockets -----------------------------------------------------------
// What the device needs of the host: non-blocking stream sockets, a Unix
// listening socket, a wait on many sockets, and a way to interrupt that
// wait. Reads and writes return the bytes moved (a read: 0 at end of
// file), SOCK_AGAIN where they would block, SOCK_GONE for any other error.
constexpr intptr_t SOCK_AGAIN = -1;
constexpr intptr_t SOCK_GONE = -2;

#if defined(_WIN32)
// Winsock. Unix sockets are there since Windows 10 1803; the wait is
// WSAPoll, which takes sockets only, so the wake-up is a loopback pair.
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
// after winsock2.h
#  include <afunix.h>
#  include <ws2tcpip.h>

typedef SOCKET sock;
constexpr sock NOSOCK = INVALID_SOCKET;
typedef WSABUF sock_iov;
typedef WSAPOLLFD sock_pollfd;
#  define SOCK_IOV(p, n) ((WSABUF){.len = (ULONG)(n), .buf = (CHAR *)(p)})
constexpr short SOCK_POLLIN = POLLRDNORM;
constexpr short SOCK_POLLOUT = POLLWRNORM;

static inline intptr_t sock_result(int rc, DWORD moved)
{
    if (rc == 0)
        return (intptr_t)moved;
    return WSAGetLastError() == WSAEWOULDBLOCK ? SOCK_AGAIN : SOCK_GONE;
}

static inline intptr_t sock_readv(sock fd, sock_iov *iov, int n)
{
    DWORD got = 0, flags = 0;
    const int rc = WSARecv(fd, iov, (DWORD)n, &got, &flags, nullptr, nullptr);
    return sock_result(rc, got); // (not in one expression: got must be read after the call)
}

static inline intptr_t sock_writev(sock fd, sock_iov *iov, int n)
{
    DWORD sent = 0;
    const int rc = WSASend(fd, iov, (DWORD)n, &sent, 0, nullptr, nullptr);
    return sock_result(rc, sent);
}

static inline void sock_close(sock fd) { (void)closesocket(fd); }
static inline void sock_shut_wr(sock fd) { (void)shutdown(fd, SD_SEND); }

static inline bool sock_nonblock(sock fd)
{
    u_long on = 1;
    return ioctlsocket(fd, (long)FIONBIO, &on) == 0;
}

// The next connection waiting on a listening socket, non-blocking; NOSOCK
// if there is none.
static inline sock sock_accept(sock listen_fd)
{
    const sock fd = accept(listen_fd, nullptr, nullptr);
    if (fd != NOSOCK && !sock_nonblock(fd)) {
        sock_close(fd);
        return NOSOCK;
    }
    return fd;
}

// Wait up to wait_ns (negative: no limit) for any of the sockets. Returns
// what poll() does. The timeout is in milliseconds here, rounded up.
static inline int sock_wait(sock_pollfd *p, int n, int64_t wait_ns)
{
    const int rc = WSAPoll(p, (ULONG)n, wait_ns < 0 ? -1 : (INT)((wait_ns + 999999) / 1000000));
    return rc == SOCKET_ERROR ? -1 : rc;
}

// Winsock, once a process (true if it is there).
static inline bool sock_init(void)
{
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
}

// Whether a socket whose connect() was started has failed (call when the
// wait reports it; WSAPoll may say only "writable").
static inline bool sock_connect_failed(sock fd, short revents)
{
    int err = 0, len = sizeof err;
    return (revents & (POLLERR | POLLHUP)) || getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len) || err;
}

// Two connected loopback sockets, both non-blocking: what is written to
// *wr can be read from *rd. (Windows has no socketpair().)
static inline bool wake_pair(sock *rd, sock *wr)
{
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct sockaddr_in mine = {0}, peer = {0};
    int alen = sizeof a, mlen = sizeof mine, plen = sizeof peer;
    const sock l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sock c = NOSOCK, r = NOSOCK;
    bool ok = l != NOSOCK && !bind(l, (const struct sockaddr *)&a, sizeof a) &&
              !getsockname(l, (struct sockaddr *)&a, &alen) && !listen(l, 1) &&
              (c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != NOSOCK &&
              !connect(c, (const struct sockaddr *)&a, sizeof a) &&
              (r = accept(l, (struct sockaddr *)&peer, &plen)) != NOSOCK &&
              !getsockname(c, (struct sockaddr *)&mine, &mlen);
    // Whoever connected must be us, not another local process that got in first.
    ok = ok && peer.sin_port == mine.sin_port && peer.sin_addr.s_addr == mine.sin_addr.s_addr &&
         sock_nonblock(c) && sock_nonblock(r);
    if (l != NOSOCK)
        sock_close(l);
    if (!ok) {
        if (c != NOSOCK)
            sock_close(c);
        if (r != NOSOCK)
            sock_close(r);
        return false;
    }
    const int nodelay = 1;
    (void)setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof nodelay);
    *rd = r;
    *wr = c;
    return true;
}

#else
#  include <errno.h>
#  include <poll.h>
#  include <signal.h>
#  include <sys/eventfd.h>
#  include <sys/socket.h>
#  include <sys/uio.h>
#  include <sys/un.h>
#  include <unistd.h>

typedef int sock;
constexpr sock NOSOCK = -1;
typedef struct iovec sock_iov;
typedef struct pollfd sock_pollfd;
#  define SOCK_IOV(p, n) ((struct iovec){.iov_base = (p), .iov_len = (n)})
constexpr short SOCK_POLLIN = POLLIN;
constexpr short SOCK_POLLOUT = POLLOUT;

static inline intptr_t sock_result(ssize_t rc)
{
    if (rc >= 0)
        return rc;
    return errno == EAGAIN || errno == EWOULDBLOCK ? SOCK_AGAIN : SOCK_GONE;
}

static inline intptr_t sock_readv(sock fd, sock_iov *iov, int n)
{
    ssize_t r;
    do
        r = readv(fd, iov, n);
    while (r < 0 && errno == EINTR);
    return sock_result(r);
}

static inline intptr_t sock_writev(sock fd, sock_iov *iov, int n)
{
    ssize_t w;
    do
        w = writev(fd, iov, n);
    while (w < 0 && errno == EINTR);
    return sock_result(w);
}

static inline void sock_close(sock fd) { (void)close(fd); }
static inline void sock_shut_wr(sock fd) { (void)shutdown(fd, SHUT_WR); }

static inline sock sock_accept(sock listen_fd)
{
    return accept4(listen_fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
}

static inline int sock_wait(sock_pollfd *p, int n, int64_t wait_ns)
{
    const struct timespec ts = {(time_t)(wait_ns / 1000000000), (long)(wait_ns % 1000000000)};
    const int rc = ppoll(p, (nfds_t)n, wait_ns < 0 ? nullptr : &ts, nullptr);
    return rc < 0 && errno == EINTR ? 0 : rc;
}

static inline bool sock_init(void) { return true; }

// (No getsockopt() here: the VMM's seccomp filter has none.)
static inline bool sock_connect_failed(sock fd, short revents)
{
    (void)fd;
    return revents & (POLLERR | POLLHUP);
}

#endif

static inline intptr_t sock_read(sock fd, void *buf, size_t len)
{
    sock_iov iov = SOCK_IOV(buf, len);
    return sock_readv(fd, &iov, 1);
}

static inline intptr_t sock_write(sock fd, const void *buf, size_t len)
{
    sock_iov iov = SOCK_IOV((void *)buf, len);
    return sock_writev(fd, &iov, 1);
}
