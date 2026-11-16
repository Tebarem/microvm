// SPDX-License-Identifier: MIT
// End-to-end virtio-vsock test (Linux). Boots the test image twice:
// - /bin/vsock-echo as a server: the host connects through the Unix socket
//   (CONNECT) and checks what comes back;
// - vsock-echo -c: the guest connects to the host, which waits with LISTEN.
// Then snapshots (--snapshot / --restore, KVM): restored VMs run, get the
// host's clock and fresh randomness, and their vsock device works.
//
//   mvm_vsock_tests MICROVM VMLINUX IMAGE [--bench]
//
// Exits 77 (skipped) where the VMM can't run a guest.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
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

static int fails;
static char sock_path[108];

static void check(bool ok, const char *what)
{
    printf("  %-58s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok)
        fails++;
}

static double now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

static bool write_all(int fd, const void *p, size_t n)
{
    for (size_t off = 0; off < n;) {
        const ssize_t w = write(fd, (const char *)p + off, n - off);
        if (w <= 0)
            return false;
        off += (size_t)w;
    }
    return true;
}

static bool read_all(int fd, void *p, size_t n)
{
    for (size_t off = 0; off < n;) {
        const ssize_t r = read(fd, (char *)p + off, n - off);
        if (r <= 0)
            return false;
        off += (size_t)r;
    }
    return true;
}

// Connect and do the handshake. Returns the fd, -1 if the guest refused
// (closed without "OK"), -2 if the socket isn't there or the line was wrong.
static int vconnect(const char *line)
{
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    strcpy(a.sun_path, sock_path);
    if (connect(fd, (struct sockaddr *)&a, sizeof a)) {
        close(fd);
        return -2;
    }
    if (!write_all(fd, line, strlen(line))) {
        close(fd);
        return -1;
    }
    char reply[32];
    size_t n = 0;
    while (n < sizeof reply - 1) {
        const ssize_t r = read(fd, reply + n, 1);
        if (r <= 0)
            break;
        if (reply[n++] == '\n')
            break;
    }
    reply[n] = 0;
    if (strncmp(reply, "OK ", 3) || reply[n - 1] != '\n') {
        close(fd);
        return -1;
    }
    return fd;
}

// Open a connection and send `line` without waiting for an answer (LISTEN).
static int vsend(const char *line, double timeout_ms)
{
    const double end = now_ms() + timeout_ms;
    for (;;) {
        const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un a = {.sun_family = AF_UNIX};
        strcpy(a.sun_path, sock_path);
        if (!connect(fd, (struct sockaddr *)&a, sizeof a)) {
            if (write_all(fd, line, strlen(line)))
                return fd;
        }
        close(fd);
        if (now_ms() > end)
            return -1;
        usleep(100);
    }
}

// Read until EOF (or `cap` bytes, or a 5 s stall). Returns the length.
static size_t read_to_eof(int fd, char *buf, size_t cap)
{
    size_t n = 0;
    while (n < cap) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        if (poll(&p, 1, 5000) <= 0)
            break;
        const ssize_t r = read(fd, buf + n, cap - n);
        if (r <= 0)
            break;
        n += (size_t)r;
    }
    return n;
}

// Read one line ("OK 1234\n") within 5 s.
static bool read_line(int fd, char *buf, size_t cap)
{
    size_t n = 0;
    while (n + 1 < cap) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        if (poll(&p, 1, 5000) <= 0 || read(fd, buf + n, 1) != 1)
            break;
        if (buf[n++] == '\n') {
            buf[n] = 0;
            return true;
        }
    }
    buf[n] = 0;
    return false;
}

static int wait_vm(pid_t pid, const char *out_path, char *out, size_t cap)
{
    int st = 0;
    const double t_wait = now_ms();
    while (waitpid(pid, &st, WNOHANG) == 0 && now_ms() - t_wait < 5000)
        usleep(1000);
    if (waitpid(pid, &st, WNOHANG) == 0) {
        printf("  (the VM was still running after 5 s: killed)\n");
        kill(pid, SIGKILL);
        waitpid(pid, &st, 0);
    } else if (!WIFEXITED(st) || WEXITSTATUS(st)) {
        printf("  (the VMM ended with %s %d)\n", WIFEXITED(st) ? "status" : "signal",
               WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st));
    }
    memset(out, 0, cap);
    const int o = open(out_path, O_RDONLY);
    if (o >= 0) {
        (void)!read(o, out, cap - 1);
        close(o);
    }
    return st;
}

static pid_t spawn_vm(char **argv, const char *out_path, const char *const *cmd)
{
    const pid_t pid = fork_child();
    if (pid == 0) {
        const int o = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        dup2(o, 1);
        const char *args[16] = {argv[1], "--kernel", argv[2], "--quiet", "--rootfs", argv[3], "--vsock", sock_path,
                                "--"};
        int n = 9;
        for (; cmd[n - 9] && n < 15; n++)
            args[n] = cmd[n - 9];
        args[n] = nullptr;
        execv(argv[1], (char **)args);
        _exit(127);
    }
    return pid;
}

// The guest connects to the host: two connections wait in LISTEN on port
// 5000; the guest's connection must take the first, the second keeps
// waiting. Port 5001 has nobody: the guest's connect is refused.
static void guest_to_host(char **argv, const char *dir)
{
    char out_path[64], out[512];
    snprintf(out_path, sizeof out_path, "%s/out2", dir);
    snprintf(sock_path, sizeof sock_path, "%s/v2.sock", dir);
    static const char *const cmd[] = {"/bin/vsock-echo", "-c", "5000", "5001", "ping from the guest", nullptr};
    const pid_t pid = spawn_vm(argv, out_path, cmd);
    const int l1 = vsend("LISTEN 5000\n", 5000);
    const int l2 = l1 >= 0 ? vsend("LISTEN 5000\n", 1000) : -1;
    check(l1 >= 0 && l2 >= 0, "two LISTEN connections on port 5000");
    char line[32], got[64] = {0};
    const bool ok = l1 >= 0 && read_line(l1, line, sizeof line) && !strncmp(line, "OK ", 3);
    check(ok, "the guest connected: OK <guest port> on the first one");
    // (Checked before we answer: once answered, the guest exits and the
    // VMM closes everything.)
    struct pollfd p = {.fd = l2, .events = POLLIN};
    check(l2 >= 0 && poll(&p, 1, 50) == 0, "the second LISTEN is still waiting");
    if (ok) {
        check(read_to_eof(l1, got, sizeof got - 1) == strlen("ping from the guest") &&
                  !strcmp(got, "ping from the guest"),
              "the guest's message, then its EOF");
        check(write_all(l1, "pong from the host", 18), "the host answers");
        shutdown(l1, SHUT_WR);
    }
    if (l1 >= 0)
        close(l1);
    if (l2 >= 0)
        close(l2);
    const int st = wait_vm(pid, out_path, out, sizeof out);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "the guest exits 0");
    const bool said = strstr(out, "vsock-echo: refused 5001; reply: pong from the host") != nullptr;
    check(said, "the guest was refused on 5001 and got the reply on 5000");
    if (!said)
        printf("  guest said: %s\n", out);
    unlink(out_path);
    unlink(sock_path);
}

static pid_t spawn_args(const char *const *args, const char *out_path)
{
    const pid_t pid = fork_child();
    if (pid == 0) {
        const int o = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        dup2(o, 1);
        execv(args[0], (char **)args);
        _exit(127);
    }
    return pid;
}

static double unix_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (double)t.tv_sec + t.tv_nsec / 1e9;
}

static int vconnect_wait(const char *line, double timeout_ms);

// Save at /init's snapshot point, then restore: twice running /bin/probe
// (each restore gets its own randomness and the clock of the moment it
// was restored, not of the snapshot), once with vsock.
static void snapshots(char **argv, const char *dir)
{
    char snap[64], out_path[64], out[2][1024];
    snprintf(snap, sizeof snap, "%s/snap", dir);
    snprintf(out_path, sizeof out_path, "%s/out3", dir);
    const char *const take[] = {argv[1], "--kernel", argv[2], "--quiet", "--rootfs", argv[3],
                                "--append", "snapshot", "--snapshot", snap,
                                "--", "/bin/probe", "7", "random", "time", nullptr};
    int st = wait_vm(spawn_args(take, out_path), out_path, out[0], sizeof out[0]);
    struct stat sb;
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0 && !stat(snap, &sb) && sb.st_size > 0,
          "snapshot taken: the VMM saved and stopped with status 0");
    check(!strstr(out[0], "probe:"), "the command didn't run before the snapshot");
    usleep(1200 * 1000); // the snapshot's clock falls behind
    const char *const back[] = {argv[1], "--restore", snap, "--rootfs", argv[3], nullptr};
    char rnd[2][40] = {{0}};
    for (int i = 0; i < 2; i++) {
        st = wait_vm(spawn_args(back, out_path), out_path, out[i], sizeof out[i]);
        const double host = unix_s();
        check(WIFEXITED(st) && WEXITSTATUS(st) == 7, "restored: the command's status");
        const char *r = strstr(out[i], " random: "), *t = strstr(out[i], " time: ");
        double guest = 0;
        check(r && sscanf(r, " random: %32s", rnd[i]) == 1 && t && sscanf(t, " time: %lf", &guest) == 1 &&
                  strstr(out[i], "message: from the image"),
              "restored: the command ran in the image");
        check(guest > host - 1.0 && guest <= host + 0.1, "restored: the guest's clock is the host's");
        if (!(guest > host - 1.0 && guest <= host + 0.1))
            printf("  guest %.3f, host %.3f\n", guest, host);
    }
    check(rnd[0][0] && strcmp(rnd[0], rnd[1]), "two restores don't share random numbers");

    // A device: vsock-echo after the restore.
    snprintf(sock_path, sizeof sock_path, "%s/v3.sock", dir);
    const char *const take2[] = {argv[1], "--kernel", argv[2], "--quiet", "--rootfs", argv[3],
                                 "--vsock", sock_path, "--append", "snapshot", "--snapshot", snap,
                                 "--", "/bin/vsock-echo", "1234", "1", nullptr};
    st = wait_vm(spawn_args(take2, out_path), out_path, out[0], sizeof out[0]);
    unlink(sock_path);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "snapshot with a vsock device");
    const char *const back2[] = {argv[1], "--restore", snap, "--rootfs", argv[3], "--vsock", sock_path,
                                 nullptr};
    const pid_t pid = spawn_args(back2, out_path);
    const int c = vconnect_wait("CONNECT 1234\n", 5000);
    char msg[] = "hello after restore", got[sizeof msg] = {0};
    check(c >= 0 && write_all(c, msg, sizeof msg - 1) && read_all(c, got, sizeof msg - 1) &&
              !memcmp(msg, got, sizeof msg - 1),
          "restored vsock: a message comes back");
    if (c >= 0) {
        shutdown(c, SHUT_WR);
        char e;
        (void)!read(c, &e, 1);
        close(c);
    }
    st = wait_vm(pid, out_path, out[0], sizeof out[0]);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0 && strstr(out[0], "vsock-echo: 1 connections"),
          "restored vsock: the guest served one connection and exited 0");
    unlink(sock_path);
    unlink(snap);
    unlink(out_path);
}

// Retry until the VM is up and the guest listens.
static int vconnect_wait(const char *line, double timeout_ms)
{
    const double end = now_ms() + timeout_ms;
    for (;;) {
        const int fd = vconnect(line);
        if (fd >= 0 || now_ms() > end)
            return fd;
        usleep(100);
    }
}

// Send `n` patterned bytes while reading the echo, then compare.
static bool bulk(int fd, size_t n, double *ms)
{
    uint8_t *out = malloc(n), *in = malloc(n);
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)(i * 131 + (i >> 9));
    size_t sent = 0, got = 0;
    const double t0 = now_ms();
    bool ok = true;
    while (ok && got < n) {
        struct pollfd p = {.fd = fd, .events = POLLIN | (sent < n ? POLLOUT : 0)};
        if (poll(&p, 1, 5000) <= 0) {
            ok = false;
            break;
        }
        if ((p.revents & POLLOUT) && sent < n) {
            const ssize_t w = send(fd, out + sent, n - sent > 65536 ? 65536 : n - sent, MSG_DONTWAIT);
            if (w > 0)
                sent += (size_t)w;
            else if (w < 0 && errno != EAGAIN)
                ok = false;
        }
        if (p.revents & POLLIN) {
            const ssize_t r = recv(fd, in + got, n - got, MSG_DONTWAIT);
            if (r > 0)
                got += (size_t)r;
            else if (r == 0 || errno != EAGAIN)
                ok = false;
        }
    }
    *ms = now_ms() - t0;
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
    if (access("/dev/kvm", R_OK | W_OK)) {
        printf("skipped: no usable /dev/kvm\n");
        return 77;
    }
    char dir[] = "/tmp/mvm-vsock-XXXXXX";
    if (!mkdtemp(dir))
        return 1;
    snprintf(sock_path, sizeof sock_path, "%s/v.sock", dir);
    char out_path[64];
    snprintf(out_path, sizeof out_path, "%s/out", dir);

    const double t_spawn = now_ms();
    const pid_t pid = fork_child();
    if (pid == 0) {
        const int o = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        dup2(o, 1);
        execl(argv[1], argv[1], "--kernel", argv[2], "--quiet", "--rootfs", argv[3], "--vsock", sock_path,
              "--", "/bin/vsock-echo", "1234", "3", (char *)nullptr);
        _exit(127);
    }

    // 1. A small message, as soon as the guest listens.
    const int c1 = vconnect_wait("CONNECT 1234\n", 5000);
    const double t_conn = now_ms();
    check(c1 >= 0, "connect to the guest's port 1234");
    char msg[] = "hello over vsock\n", back[sizeof msg] = {0};
    check(c1 >= 0 && write_all(c1, msg, sizeof msg - 1) && read_all(c1, back, sizeof msg - 1) &&
              !memcmp(msg, back, sizeof msg - 1),
          "a message comes back");

    // Refusals, while the guest's first connection is open.
    check(vconnect("CONNECT 999\n") == -1, "a port nobody listens on: closed, no OK");
    check(vconnect("HELLO 1234\n") == -1, "a bad handshake line: closed");
    check(vconnect("CONNECT 4294967296\n") == -1, "a port past 32 bits: closed");
    check(vconnect("LISTEN 1073741824\n") == -1, "LISTEN on a port in the host-initiated range: closed");

    // Round trips (latency) on the first connection.
    double rtt_us = 0;
    if (c1 >= 0) {
        const int n = bench ? 2000 : 200;
        char b = 'x';
        bool ok = true;
        const double t0 = now_ms();
        for (int i = 0; ok && i < n; i++)
            ok = write(c1, &b, 1) == 1 && read(c1, &b, 1) == 1;
        rtt_us = (now_ms() - t0) * 1000 / n;
        check(ok, "1-byte round trips");
        shutdown(c1, SHUT_WR);
        char e;
        check(read(c1, &e, 1) == 0, "half-close: the guest sees EOF and closes too");
        close(c1);
    }

    // 2. Bulk both ways at once: more than any buffer on the way.
    const size_t big = bench ? 64u << 20 : 8u << 20;
    const int c2 = vconnect_wait("CONNECT 1234\n", 2000);
    double bulk_ms = 0;
    check(c2 >= 0 && bulk(c2, big, &bulk_ms), "8 MiB echoed intact (credit flow control)");
    if (c2 >= 0) {
        shutdown(c2, SHUT_WR);
        char e;
        (void)!read(c2, &e, 1);
        close(c2);
    }

    // 3. The host hangs up mid-stream without reading: the VMM must
    // survive (no SIGPIPE) and the guest sees a reset or EOF.
    const int c3 = vconnect_wait("CONNECT 1234\n", 2000);
    static uint8_t junk[64 << 10]; // less than the buffers on the way: we never read the echo
    check(c3 >= 0 && write_all(c3, junk, sizeof junk), "third connection: 64 KiB, then hang up");
    if (c3 >= 0)
        close(c3);

    char out[512];
    const int st = wait_vm(pid, out_path, out, sizeof out);
    if (WIFEXITED(st) && WEXITSTATUS(st) == 77) {
        printf("skipped: %s", out);
        unlink(out_path);
        unlink(sock_path);
        rmdir(dir);
        return 77;
    }
    // Bytes the guest read: all of connections 1 and 2, any part of 3.
    const size_t base = sizeof msg - 1 + (size_t)(bench ? 2000 : 200) + big;
    unsigned long long nconn = 0, nbytes = 0;
    const char *at = strstr(out, "vsock-echo: ");
    const bool parsed = at && sscanf(at, "vsock-echo: %llu connections, %llu bytes", &nconn, &nbytes) == 2;
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "the guest exits 0");
    check(parsed && nconn == 3 && nbytes >= base && nbytes <= base + sizeof junk,
          "the guest read every byte of connections 1 and 2");
    if (!parsed || nconn != 3 || nbytes < base || nbytes > base + sizeof junk)
        printf("  guest said: %s\n", out);
    printf("connected %.2f ms after spawn; round trip %.1f us; bulk %.0f MiB/s each way\n",
           t_conn - t_spawn, rtt_us, bulk_ms > 0 ? (double)big / (1 << 20) / (bulk_ms / 1000) : 0.0);

    unlink(out_path);
    unlink(sock_path);
    if (!bench) {
        guest_to_host(argv, dir);
        snapshots(argv, dir);
    }
    rmdir(dir);
    printf(fails ? "%d checks FAILED\n" : "all checks passed\n", fails);
    return fails ? 1 : 0;
}
