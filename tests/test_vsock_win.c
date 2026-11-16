// SPDX-License-Identifier: MIT
// End-to-end virtio-vsock test, Windows hosts (test_vsock.c is the Linux
// one; this covers the same ground minus snapshots, which WHP doesn't
// have). Boots the test image twice:
// - /bin/vsock-echo as a server: the host connects through the Unix socket
//   (CONNECT) and checks what comes back;
// - vsock-echo -c: the guest connects to the host, which waits with LISTEN.
//
//   mvm_vsock_tests MICROVM VMLINUX IMAGE [--bench]
//
// Exits 77 (skipped) where the VMM can't run a guest.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
// after winsock2.h
#include <afunix.h>
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
static char sock_path[108];
static HANDLE job; // the VMs die with the test

static void check(bool ok, const char *what)
{
    printf("  %-58s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok)
        fails++;
}

static double now_ms(void)
{
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart * 1e3 / (double)f.QuadPart;
}

static bool write_all(SOCKET fd, const void *p, size_t n)
{
    for (size_t off = 0; off < n;) {
        const int w = send(fd, (const char *)p + off, (int)(n - off > 65536 ? 65536 : n - off), 0);
        if (w <= 0)
            return false;
        off += (size_t)w;
    }
    return true;
}

static bool read_all(SOCKET fd, void *p, size_t n)
{
    for (size_t off = 0; off < n;) {
        const int r = recv(fd, (char *)p + off, (int)(n - off), 0);
        if (r <= 0)
            return false;
        off += (size_t)r;
    }
    return true;
}

// A connected socket whose reads give up after 5 s, or INVALID_SOCKET.
static SOCKET uconnect(void)
{
    const SOCKET fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    strcpy(a.sun_path, sock_path);
    if (fd == INVALID_SOCKET || connect(fd, (const struct sockaddr *)&a, sizeof a)) {
        if (fd != INVALID_SOCKET)
            closesocket(fd);
        return INVALID_SOCKET;
    }
    const DWORD ms = 5000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms);
    return fd;
}

constexpr SOCKET REFUSED = INVALID_SOCKET - 1; // closed without "OK"

// Connect and do the handshake. Returns the socket, REFUSED if the guest
// refused, INVALID_SOCKET if the socket isn't there.
static SOCKET vconnect(const char *line)
{
    const SOCKET fd = uconnect();
    if (fd == INVALID_SOCKET)
        return INVALID_SOCKET;
    char reply[32];
    size_t n = 0;
    if (write_all(fd, line, strlen(line)))
        while (n < sizeof reply - 1) {
            if (recv(fd, reply + n, 1, 0) <= 0 || reply[n++] == '\n')
                break;
        }
    reply[n] = 0;
    if (strncmp(reply, "OK ", 3) || reply[n - 1] != '\n') {
        closesocket(fd);
        return REFUSED;
    }
    return fd;
}

static bool is_sock(SOCKET fd) { return fd != INVALID_SOCKET && fd != REFUSED; }

// Retry until the VM is up and the guest listens.
static SOCKET vconnect_wait(const char *line, double timeout_ms)
{
    const double end = now_ms() + timeout_ms;
    for (;;) {
        const SOCKET fd = vconnect(line);
        if (is_sock(fd) || now_ms() > end)
            return fd;
        Sleep(1);
    }
}

// Open a connection and send `line` without waiting for an answer (LISTEN).
static SOCKET vsend(const char *line, double timeout_ms)
{
    const double end = now_ms() + timeout_ms;
    for (;;) {
        const SOCKET fd = uconnect();
        if (fd != INVALID_SOCKET) {
            if (write_all(fd, line, strlen(line)))
                return fd;
            closesocket(fd);
        }
        if (now_ms() > end)
            return INVALID_SOCKET;
        Sleep(1);
    }
}

static bool readable(SOCKET fd, int ms)
{
    WSAPOLLFD p = {.fd = fd, .events = POLLRDNORM};
    return WSAPoll(&p, 1, ms) > 0;
}

// Read until EOF (or `cap` bytes, or a 5 s stall). Returns the length.
static size_t read_to_eof(SOCKET fd, char *buf, size_t cap)
{
    size_t n = 0;
    while (n < cap) {
        const int r = recv(fd, buf + n, (int)(cap - n), 0);
        if (r <= 0)
            break;
        n += (size_t)r;
    }
    return n;
}

// Start the VMM with its output in out_path. Returns the process, or nullptr.
static HANDLE spawn_vm(char **argv, const char *out_path, const char *const *cmd)
{
    char line[2048];
    int n = snprintf(line, sizeof line, "\"%s\" --kernel \"%s\" --quiet --rootfs \"%s\" --vsock \"%s\" --", argv[1],
                     argv[2], argv[3], sock_path);
    for (; *cmd; cmd++)
        n += snprintf(line + n, sizeof line - (size_t)n, " \"%s\"", *cmd);
    SECURITY_ATTRIBUTES sa = {.nLength = sizeof sa, .bInheritHandle = TRUE};
    const HANDLE out = CreateFileA(out_path, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
    if (out == INVALID_HANDLE_VALUE)
        return nullptr;
    STARTUPINFOA si = {.cb = sizeof si, .dwFlags = STARTF_USESTDHANDLES, .hStdOutput = out,
                       .hStdError = GetStdHandle(STD_ERROR_HANDLE), .hStdInput = INVALID_HANDLE_VALUE};
    PROCESS_INFORMATION pi;
    const BOOL ok = CreateProcessA(nullptr, line, nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi);
    CloseHandle(out);
    if (!ok)
        return nullptr;
    AssignProcessToJobObject(job, pi.hProcess);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

// Wait up to 5 s for the VMM, read what it printed. Returns its exit status
// (-1: it had to be killed).
static int wait_vm(HANDLE proc, const char *out_path, char *out, size_t cap)
{
    DWORD st = (DWORD)-1;
    memset(out, 0, cap);
    if (!proc)
        return -1;
    if (WaitForSingleObject(proc, 5000) != WAIT_OBJECT_0) {
        printf("  (the VM was still running after 5 s: killed)\n");
        TerminateProcess(proc, 1);
        WaitForSingleObject(proc, INFINITE);
    } else {
        GetExitCodeProcess(proc, &st);
        if (st)
            printf("  (the VMM ended with status %lu)\n", (unsigned long)st);
    }
    CloseHandle(proc);
    FILE *f = fopen(out_path, "rb");
    if (f) {
        (void)!fread(out, 1, cap - 1, f);
        fclose(f);
    }
    return (int)st;
}

// The guest connects to the host: two connections wait in LISTEN on port
// 5000; the guest's connection must take the first, the second keeps
// waiting. Port 5001 has nobody: the guest's connect is refused.
static void guest_to_host(char **argv, const char *dir)
{
    char out_path[MAX_PATH + 8], out[512];
    if (snprintf(out_path, sizeof out_path, "%s\\out2", dir) >= (int)sizeof out_path ||
        snprintf(sock_path, sizeof sock_path, "%s\\v2.sock", dir) >= (int)sizeof sock_path)
        return;
    static const char *const cmd[] = {"/bin/vsock-echo", "-c", "5000", "5001", "ping from the guest", nullptr};
    const HANDLE proc = spawn_vm(argv, out_path, cmd);
    const SOCKET l1 = vsend("LISTEN 5000\n", 5000);
    const SOCKET l2 = l1 != INVALID_SOCKET ? vsend("LISTEN 5000\n", 1000) : INVALID_SOCKET;
    check(l1 != INVALID_SOCKET && l2 != INVALID_SOCKET, "two LISTEN connections on port 5000");
    char line[32] = {0}, got[64] = {0};
    size_t n = 0;
    while (l1 != INVALID_SOCKET && n < sizeof line - 1 && recv(l1, line + n, 1, 0) == 1 && line[n++] != '\n') {
    }
    const bool ok = n > 3 && !strncmp(line, "OK ", 3) && line[n - 1] == '\n';
    check(ok, "the guest connected: OK <guest port> on the first one");
    check(l2 != INVALID_SOCKET && !readable(l2, 50), "the second LISTEN is still waiting");
    if (ok) {
        check(read_to_eof(l1, got, sizeof got - 1) == strlen("ping from the guest") &&
                  !strcmp(got, "ping from the guest"),
              "the guest's message, then its EOF");
        check(write_all(l1, "pong from the host", 18), "the host answers");
        shutdown(l1, SD_SEND);
    }
    if (l1 != INVALID_SOCKET)
        closesocket(l1);
    if (l2 != INVALID_SOCKET)
        closesocket(l2);
    const int st = wait_vm(proc, out_path, out, sizeof out);
    check(st == 0, "the guest exits 0");
    const bool said = strstr(out, "vsock-echo: refused 5001; reply: pong from the host") != nullptr;
    check(said, "the guest was refused on 5001 and got the reply on 5000");
    if (!said)
        printf("  guest said: %s\n", out);
    DeleteFileA(out_path);
    DeleteFileA(sock_path);
}

// Send `n` patterned bytes while reading the echo, then compare.
static bool bulk(SOCKET fd, size_t n, double *ms)
{
    uint8_t *out = malloc(n), *in = malloc(n);
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)(i * 131 + (i >> 9));
    size_t sent = 0, got = 0;
    u_long on = 1;
    ioctlsocket(fd, (long)FIONBIO, &on);
    const double t0 = now_ms();
    bool ok = true;
    while (ok && got < n) {
        WSAPOLLFD p = {.fd = fd, .events = (SHORT)(POLLRDNORM | (sent < n ? POLLWRNORM : 0))};
        if (WSAPoll(&p, 1, 5000) <= 0) {
            ok = false;
            break;
        }
        if ((p.revents & POLLWRNORM) && sent < n) {
            const int w = send(fd, (const char *)out + sent, (int)(n - sent > 65536 ? 65536 : n - sent), 0);
            if (w > 0)
                sent += (size_t)w;
            else if (WSAGetLastError() != WSAEWOULDBLOCK)
                ok = false;
        }
        if (p.revents & (POLLRDNORM | POLLHUP | POLLERR)) {
            const int r = recv(fd, (char *)in + got, (int)(n - got > (64u << 20) ? 64u << 20 : n - got), 0);
            if (r > 0)
                got += (size_t)r;
            else if (r == 0 || WSAGetLastError() != WSAEWOULDBLOCK)
                ok = false;
        }
    }
    *ms = now_ms() - t0;
    on = 0;
    ioctlsocket(fd, (long)FIONBIO, &on);
    ok = ok && !memcmp(out, in, n);
    free(out);
    free(in);
    return ok;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s MICROVM VMLINUX IMAGE [--bench]\n", argv[0]);
        return 2;
    }
    setvbuf(stdout, nullptr, _IONBF, 0);
    const bool bench = argc > 4 && !strcmp(argv[4], "--bench");
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa))
        return 1;
    job = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION lim = {0};
    lim.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &lim, sizeof lim))
        return 1;
    // A short directory of our own: a Unix socket's path holds 108 bytes.
    char tmp[MAX_PATH], dir[MAX_PATH];
    if (!GetTempPathA(sizeof tmp, tmp))
        return 1;
    if (snprintf(dir, sizeof dir, "%smvm-vsock-%lu", tmp, (unsigned long)GetCurrentProcessId()) >= (int)sizeof dir ||
        !CreateDirectoryA(dir, nullptr))
        return 1;
    char out_path[MAX_PATH + 8];
    if (snprintf(out_path, sizeof out_path, "%s\\out", dir) >= (int)sizeof out_path)
        return 1;
    if (snprintf(sock_path, sizeof sock_path, "%s\\v.sock", dir) >= (int)sizeof sock_path) {
        printf("the temporary directory's path is too long for a Unix socket: %s\n", dir);
        return 1;
    }

    const double t_spawn = now_ms();
    static const char *const serve[] = {"/bin/vsock-echo", "1234", "3", nullptr};
    const HANDLE proc = spawn_vm(argv, out_path, serve);

    // 1. A small message, as soon as the guest listens.
    const SOCKET c1 = vconnect_wait("CONNECT 1234\n", 5000);
    const double t_conn = now_ms();
    check(is_sock(c1), "connect to the guest's port 1234");
    char msg[] = "hello over vsock\n", back[sizeof msg] = {0};
    check(is_sock(c1) && write_all(c1, msg, sizeof msg - 1) && read_all(c1, back, sizeof msg - 1) &&
              !memcmp(msg, back, sizeof msg - 1),
          "a message comes back");

    // Refusals, while the guest's first connection is open.
    check(vconnect("CONNECT 999\n") == REFUSED, "a port nobody listens on: closed, no OK");
    check(vconnect("HELLO 1234\n") == REFUSED, "a bad handshake line: closed");
    check(vconnect("CONNECT 4294967296\n") == REFUSED, "a port past 32 bits: closed");
    check(vconnect("LISTEN 1073741824\n") == REFUSED, "LISTEN on a port in the host-initiated range: closed");

    // Round trips (latency) on the first connection.
    double rtt_us = 0;
    const int trips = bench ? 2000 : 200;
    if (is_sock(c1)) {
        char b = 'x';
        bool ok = true;
        const double t0 = now_ms();
        for (int i = 0; ok && i < trips; i++)
            ok = send(c1, &b, 1, 0) == 1 && recv(c1, &b, 1, 0) == 1;
        rtt_us = (now_ms() - t0) * 1000 / trips;
        check(ok, "1-byte round trips");
        shutdown(c1, SD_SEND);
        char e;
        check(recv(c1, &e, 1, 0) == 0, "half-close: the guest sees EOF and closes too");
        closesocket(c1);
    }

    // 2. Bulk both ways at once: more than any buffer on the way.
    const size_t big = bench ? 64u << 20 : 8u << 20;
    const SOCKET c2 = vconnect_wait("CONNECT 1234\n", 2000);
    double bulk_ms = 0;
    check(is_sock(c2) && bulk(c2, big, &bulk_ms), "8 MiB echoed intact (credit flow control)");
    if (is_sock(c2)) {
        shutdown(c2, SD_SEND);
        char e;
        (void)recv(c2, &e, 1, 0);
        closesocket(c2);
    }

    // 3. The host hangs up mid-stream without reading: the VMM must
    // survive and the guest sees a reset or EOF.
    const SOCKET c3 = vconnect_wait("CONNECT 1234\n", 2000);
    static uint8_t junk[64 << 10]; // less than the buffers on the way: we never read the echo
    check(is_sock(c3) && write_all(c3, junk, sizeof junk), "third connection: 64 KiB, then hang up");
    if (is_sock(c3))
        closesocket(c3);

    char out[512];
    const int st = wait_vm(proc, out_path, out, sizeof out);
    if (st == 77) {
        printf("skipped: %s", out);
        DeleteFileA(out_path);
        DeleteFileA(sock_path);
        RemoveDirectoryA(dir);
        return 77;
    }
    // Bytes the guest read: all of connections 1 and 2, any part of 3.
    const size_t base = sizeof msg - 1 + (size_t)trips + big;
    unsigned long long nconn = 0, nbytes = 0;
    const char *at = strstr(out, "vsock-echo: ");
    const bool parsed = at && sscanf(at, "vsock-echo: %llu connections, %llu bytes", &nconn, &nbytes) == 2;
    check(st == 0, "the guest exits 0");
    check(parsed && nconn == 3 && nbytes >= base && nbytes <= base + sizeof junk,
          "the guest read every byte of connections 1 and 2");
    if (!parsed || nconn != 3 || nbytes < base || nbytes > base + sizeof junk)
        printf("  guest said: %s\n", out);
    printf("connected %.2f ms after spawn; round trip %.1f us; bulk %.0f MiB/s each way\n", t_conn - t_spawn,
           rtt_us, bulk_ms > 0 ? (double)big / (1 << 20) / (bulk_ms / 1000) : 0.0);

    DeleteFileA(out_path);
    DeleteFileA(sock_path);
    if (!bench)
        guest_to_host(argv, dir);
    RemoveDirectoryA(dir);
    printf(fails ? "%d checks FAILED\n" : "all checks passed\n", fails);
    return fails ? 1 : 0;
}
