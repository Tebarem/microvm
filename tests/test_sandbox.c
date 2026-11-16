// SPDX-License-Identifier: MIT
// Sandbox escape probes. Each probe runs in a fresh child process that
// enters the sandbox and then tries one thing it must not be able to do.
//
//   mvm_sandbox_tests            run every probe, report, exit 0 if all held
//   mvm_sandbox_tests --child N  (internal) enter the sandbox, run probe N
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sandbox.h"

// Child exit codes.
enum { BLOCKED = 0, ESCAPED = 42, SETUP_FAILED = 43, SKIPPED = 44 };

static char g_report[160]; // sandbox_enter's summary, for probes that depend on it

typedef struct {
    const char *name;
    int (*probe)(void); // returns BLOCKED or ESCAPED; may also be killed (Linux)
    bool killed_ok;     // being killed by the sandbox counts as blocked
    sandbox_cfg cfg;
    bool control;       // without the sandbox this probe must report ESCAPED
                        // (proves the probe can detect an escape at all)
    void (*prepare)(void); // runs before the sandbox is entered
} probe_def;

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>

static int p_spawn(void)
{
    STARTUPINFOW si = {.cb = sizeof si};
    PROCESS_INFORMATION pi;
    wchar_t cmd[] = L"cmd.exe /c exit 0";
    if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        TerminateProcess(pi.hProcess, 0);
        return ESCAPED;
    }
    return BLOCKED;
}

static int p_write_file(void)
{
    // %TEMP% is a Medium-integrity directory the user can normally write.
    wchar_t dir[MAX_PATH], path[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, dir) || !GetTempFileNameW(dir, L"mvm", 0, path))
        return BLOCKED; // GetTempFileName creates the file: failing here is blocked
    DeleteFileW(path);
    return ESCAPED;
}

static int p_exec_memory(void)
{
    void *p = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    return p ? ESCAPED : BLOCKED;
}

static int p_open_parent(void)
{
    // Write access to another process of the same user (Medium integrity).
    DWORD ppid = (DWORD)strtoul(getenv("MVM_TEST_PARENT"), nullptr, 10);
    HANDLE h = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, ppid);
    if (h) {
        CloseHandle(h);
        return ESCAPED;
    }
    return BLOCKED;
}

static int p_registry(void)
{
    HKEY k;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\microvm-sandbox-test", 0, nullptr, 0,
                        KEY_WRITE, nullptr, &k, nullptr) == ERROR_SUCCESS) {
        RegCloseKey(k);
        RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\microvm-sandbox-test");
        return ESCAPED;
    }
    return BLOCKED;
}

static int p_memory_cap(void)
{
    // Headroom is 64 MiB: committing 256 MiB more must fail.
    void *p = VirtualAlloc(nullptr, 256u << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return p ? ESCAPED : BLOCKED;
}

static const probe_def PROBES[] = {
    {"spawn a process", p_spawn, true, {.mem_headroom = 64u << 20}, true, nullptr},
    {"write a file in %TEMP%", p_write_file, true, {.mem_headroom = 64u << 20}, true, nullptr},
    {"allocate executable memory", p_exec_memory, true, {.mem_headroom = 64u << 20}, true, nullptr},
    {"open the parent for writing", p_open_parent, true, {.mem_headroom = 64u << 20}, true, nullptr},
    {"write HKCU registry", p_registry, true, {.mem_headroom = 64u << 20}, true, nullptr},
    {"exceed the memory cap", p_memory_cap, true, {.mem_headroom = 64u << 20}, true, nullptr},
};

static int run_child(const char *self, int idx, bool sandboxed, bool *killed)
{
    wchar_t cmd[1024];
    swprintf(cmd, 1024, L"\"%hs\" %hs %d", self, sandboxed ? "--child" : "--control", idx);
    STARTUPINFOW si = {.cb = sizeof si};
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
        return -1;
    WaitForSingleObject(pi.hProcess, 10000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    *killed = code != BLOCKED && code != ESCAPED && code != SETUP_FAILED && code != SKIPPED;
    return (int)code;
}

static void set_parent_env(void)
{
    char buf[32];
    snprintf(buf, sizeof buf, "%lu", (unsigned long)GetCurrentProcessId());
    SetEnvironmentVariableA("MVM_TEST_PARENT", buf);
}

#else
#  include <errno.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <signal.h>
#  include <sys/ioctl.h>
#  include <sys/mman.h>
#  include <sys/socket.h>
#  include <poll.h>
#  include <sys/syscall.h>
#  include <sys/uio.h>
#  include <sys/un.h>
#  include <sys/wait.h>
#  include <termios.h>
#  include <unistd.h>

static int p_open(void)
{
    int fd = open("/etc/hostname", O_RDONLY);
    return fd >= 0 ? ESCAPED : BLOCKED;
}

static int p_socket(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    return fd >= 0 ? ESCAPED : BLOCKED;
}

static int p_exec_mmap(void)
{
    void *p = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p != MAP_FAILED ? ESCAPED : BLOCKED;
}

static int p_mprotect_exec(void)
{
    void *p = mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return SETUP_FAILED; // plain RW mappings must keep working
    return mprotect(p, 4096, PROT_READ | PROT_EXEC) == 0 ? ESCAPED : BLOCKED;
}

static int p_fork(void)
{
    pid_t pid = (pid_t)syscall(SYS_fork);
    if (pid == 0)
        _exit(0);
    return pid > 0 ? ESCAPED : BLOCKED;
}

static int p_clone3(void)
{
    // Only refused if seccomp kills it or it fails; ENOSYS from an old
    // kernel would also be "blocked".
    long r = syscall(435 /* clone3 */, nullptr, 0);
    return r >= 0 ? ESCAPED : BLOCKED;
}

static int p_execve(void)
{
    char *argv[] = {(char *)"/bin/true", nullptr};
    execve("/bin/true", argv, nullptr);
    return BLOCKED;
}

static int p_ptrace(void)
{
    return syscall(SYS_ptrace, 0 /* PTRACE_TRACEME */, 0, 0, 0) == 0 ? ESCAPED : BLOCKED;
}

static int p_ioctl_denied(void)
{
    struct termios t;
    (void)ioctl(1, TCGETS, &t); // not on the allowlist
    return ESCAPED;
}

// Positive control: allowlisted ioctl and ordinary I/O keep working.
static int p_ioctl_allowed(void)
{
    struct winsize ws;
    (void)ioctl(2, TIOCGWINSZ, &ws); // ENOTTY is fine; it must not kill us
    void *p = malloc(1 << 20);       // malloc (brk/mmap without EXEC) works
    free(p);
    return write(2, "", 0) == 0 ? ESCAPED /* = "it ran" */ : SETUP_FAILED;
}

// Many vCPUs: each fd of 100..107 allows the same 16 requests, the last
// TIOCGWINSZ (main.c's list for 8 vCPUs is this size). Not open: EBADF.
static int p_ioctl_many(void)
{
    struct winsize ws;
    for (int fd = 100; fd < 108; fd++)
        (void)ioctl(fd, TIOCGWINSZ, &ws);
    (void)ioctl(100, 0xae80, 0);
    (void)ioctl(107, 0xae80 + 14, 0);
    (void)ioctl(2, TIOCGWINSZ, &ws);
    return ESCAPED;
}

// A request listed for the vCPU fds, on another fd.
static int p_ioctl_many_other_fd(void)
{
    (void)ioctl(99, 0xae80 + 3, 0);
    return ESCAPED;
}

// A request listed for no fd at all.
static int p_ioctl_many_other_req(void)
{
    (void)ioctl(100, 0xae80 + 15, 0);
    return ESCAPED;
}

static int p_landlock_open(void)
{
    if (strstr(g_report, "landlock=unavailable"))
        return SKIPPED; // kernel without Landlock
    int fd = open("/etc/hostname", O_RDONLY);
    if (fd >= 0)
        return ESCAPED;
    return errno == EACCES ? BLOCKED : SETUP_FAILED;
}

// Positive control: a FILE opened before the sandbox, given its buffer up
// front the way microvm does, can still be written and closed afterwards.
static FILE *g_pre;
static char g_pre_buf[4096];

static void prepare_stdio(void)
{
    g_pre = tmpfile();
    if (g_pre)
        setvbuf(g_pre, g_pre_buf, _IOFBF, sizeof g_pre_buf);
}

static int p_stdio_after(void)
{
    if (!g_pre)
        return SETUP_FAILED;
    for (int i = 0; i < 2000; i++) // > one buffer: forces real writes
        fprintf(g_pre, "%x %x r\n", i, i * 3);
    return fclose(g_pre) == 0 ? ESCAPED /* = "it ran" */ : SETUP_FAILED;
}

// Device I/O (the vsock thread): fd 50 is the listening socket it may
// accept on, fd 51 another listening socket, 52/53 a connected pair.
enum { DEV_LISTEN = 50, DEV_OTHER = 51, DEV_A = 52, DEV_B = 53 };

static void prepare_device_fds(void)
{
    const int l = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    const int o = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int sp[2];
    // Binding just the family autobinds an abstract name: no file.
    const struct sockaddr_un any = {.sun_family = AF_UNIX};
    if (l < 0 || o < 0 || bind(l, (const struct sockaddr *)&any, sizeof(sa_family_t)) ||
        bind(o, (const struct sockaddr *)&any, sizeof(sa_family_t)) || listen(l, 1) || listen(o, 1) ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sp) || dup2(l, DEV_LISTEN) < 0 ||
        dup2(o, DEV_OTHER) < 0 || dup2(sp[0], DEV_A) < 0 || dup2(sp[1], DEV_B) < 0)
        _exit(SETUP_FAILED);
}

// Positive control: what the device thread does keeps working.
static int p_device_io_allowed(void)
{
    struct pollfd p = {.fd = DEV_A, .events = POLLOUT};
    char b[4] = "abc";
    struct iovec iov = {b, 3};
    if (poll(&p, 1, 0) != 1 || writev(DEV_A, &iov, 1) != 3 || readv(DEV_B, &iov, 1) != 3)
        return SETUP_FAILED;
    if (accept4(DEV_LISTEN, nullptr, nullptr, SOCK_NONBLOCK) >= 0 || errno != EAGAIN)
        return SETUP_FAILED; // nobody connected: EAGAIN, not killed
    return shutdown(DEV_A, SHUT_WR) == 0 ? ESCAPED /* = "it ran" */ : SETUP_FAILED;
}

static int p_device_accept_other(void)
{
    (void)accept4(DEV_OTHER, nullptr, nullptr, SOCK_NONBLOCK); // EAGAIN without the sandbox
    return ESCAPED;
}

// The VMM reads the network helper's replies (recvmsg, for the fds they
// carry) on the channel, DEV_A here, and nowhere else.
static int p_recvmsg_chan(void)
{
    char b = 'x';
    struct iovec iov = {&b, 1};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1};
    if (write(DEV_B, "y", 1) != 1 || recvmsg(DEV_A, &m, MSG_DONTWAIT) != 1)
        return SETUP_FAILED;
    return ESCAPED; // = "it ran"
}

static int p_recvmsg_other(void)
{
    char b = 'x';
    struct iovec iov = {&b, 1};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1};
    if (write(DEV_A, "y", 1) != 1)
        return SETUP_FAILED;
    (void)recvmsg(DEV_B, &m, MSG_DONTWAIT);
    return ESCAPED;
}

// The network helper (sandbox_enter_net_helper(DEV_A, DEV_B)): requests on
// the channel DEV_A, route lookups on the "netlink" socket DEV_B.
static int p_helper_works(void)
{
    const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0 || setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)))
        return SETUP_FAILED;
    const struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(9), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (connect(fd, (const struct sockaddr *)&a, sizeof a) && errno != EINPROGRESS && errno != ECONNREFUSED)
        return SETUP_FAILED;
    char b = 'x';
    struct iovec iov = {&b, 1};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1};
    if (sendmsg(DEV_A, &m, 0) != 1 || recvfrom(DEV_B, &b, 1, MSG_DONTWAIT, nullptr, nullptr) != 1)
        return SETUP_FAILED;
    if (sendto(DEV_B, &b, 1, 0, nullptr, 0) != 1 || recvfrom(DEV_A, &b, 1, MSG_DONTWAIT, nullptr, nullptr) != 1)
        return SETUP_FAILED;
    return close(fd) == 0 ? ESCAPED : SETUP_FAILED;
}

static int p_helper_unix(void)
{
    return socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) >= 0 ? ESCAPED : BLOCKED;
}

static int p_helper_raw(void)
{
    return socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP) >= 0 ? ESCAPED : BLOCKED;
}

static int p_helper_sockopt(void)
{
    const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return SETUP_FAILED;
    return setsockopt(fd, IPPROTO_TCP, TCP_CORK, &(int){1}, sizeof(int)) == 0 ? ESCAPED : BLOCKED;
}

static int p_helper_bind(void)
{
    const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return SETUP_FAILED;
    const struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    return bind(fd, (const struct sockaddr *)&a, sizeof a) == 0 ? ESCAPED : BLOCKED;
}

// Sending on a socket of its own, past connect()'s checks in the VMM's
// request: only the netlink socket may sendto.
static int p_helper_sendto(void)
{
    const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return SETUP_FAILED;
    const struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(9), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    return sendto(fd, "x", 1, 0, (const struct sockaddr *)&a, sizeof a) == 1 ? ESCAPED : BLOCKED;
}

// ASan builds let the helper ask where its signal stack is; setting one
// stays killed in every build.
static int p_helper_sigaltstack(void)
{
    static char stack[16384];
    const stack_t ss = {.ss_sp = stack, .ss_size = sizeof stack};
    return syscall(SYS_sigaltstack, &ss, nullptr) == 0 ? ESCAPED : BLOCKED;
}

static int p_helper_sendmsg_other(void)
{
    char b = 'x';
    struct iovec iov = {&b, 1};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1};
    return sendmsg(DEV_B, &m, 0) == 1 ? ESCAPED : BLOCKED;
}

static const sandbox_ioctl ALLOWED[] = {{2, TIOCGWINSZ}};
#  define CFG {.ioctls = ALLOWED, .nioctls = 1, .mem_headroom = 64u << 20}
static sandbox_ioctl MANY[8 * 16 + 1]; // filled by main
#  define MANY_CFG {.ioctls = MANY, .nioctls = sizeof MANY / sizeof MANY[0], .mem_headroom = 64u << 20}
#  define DEV_CFG                                                                     \
      {.ioctls = ALLOWED, .nioctls = 1, .mem_headroom = 64u << 20, .device_io = true, \
       .accept_fd = DEV_LISTEN, .nofile = 64}
#  define NET_CFG                                                                     \
      {.ioctls = ALLOWED, .nioctls = 1, .mem_headroom = 64u << 20, .device_io = true, \
       .accept_fd = DEV_LISTEN, .recvmsg_fd = DEV_A, .nofile = 64}

static const probe_def PROBES[] = {
    {"open a file", p_open, true, CFG, true, nullptr},
    {"create a socket", p_socket, true, CFG, true, nullptr},
    {"mmap executable memory", p_exec_mmap, true, CFG, true, nullptr},
    {"mprotect memory executable", p_mprotect_exec, true, CFG, true, nullptr},
    {"fork", p_fork, true, CFG, true, nullptr},
    {"clone3", p_clone3, true, CFG, false, nullptr},
    {"execve", p_execve, true, CFG, false, nullptr},
    {"ptrace", p_ptrace, true, CFG, true, nullptr},
    {"ioctl not on the allowlist", p_ioctl_denied, true, CFG, true, nullptr},
    {"allowlisted ioctl still works (control)", p_ioctl_allowed, false, CFG, false, nullptr},
    {"8 vCPUs' ioctls: each fd, each request (control)", p_ioctl_many, false, MANY_CFG, false, nullptr},
    {"8 vCPUs' ioctls: a vCPU request on another fd", p_ioctl_many_other_fd, true, MANY_CFG, true, nullptr},
    {"8 vCPUs' ioctls: a request on no list", p_ioctl_many_other_req, true, MANY_CFG, true, nullptr},
    {"buffered stdio on a pre-opened file (control)", p_stdio_after, false, CFG, false,
     prepare_stdio},
    {"Landlock alone denies open", p_landlock_open, false,
     {.no_seccomp = true, .no_rlimits = true}, true, nullptr},
    {"device I/O: poll/readv/writev/accept4 (control)", p_device_io_allowed, false, DEV_CFG, false,
     prepare_device_fds},
    {"device I/O: accept4 on another socket", p_device_accept_other, true, DEV_CFG, true,
     prepare_device_fds},
    {"device I/O: still no new sockets", p_socket, true, DEV_CFG, true, nullptr},
    {"device I/O: still no open", p_open, true, DEV_CFG, true, nullptr},
    {"--net: recvmsg on the helper channel (control)", p_recvmsg_chan, false, NET_CFG, false,
     prepare_device_fds},
    {"--net: recvmsg on another socket", p_recvmsg_other, true, NET_CFG, true, prepare_device_fds},
    {"--net: recvmsg without --net", p_recvmsg_chan, true, DEV_CFG, true, prepare_device_fds},
    {"net helper: socket/connect/NODELAY (control)", p_helper_works, false, {}, false,
     prepare_device_fds},
    {"net helper: open a file", p_open, true, {}, true, nullptr},
    {"net helper: an AF_UNIX socket", p_helper_unix, true, {}, true, nullptr},
    {"net helper: a raw socket", p_helper_raw, true, {}, false, nullptr},
    {"net helper: a blocking socket", p_socket, true, {}, true, nullptr},
    {"net helper: another socket option", p_helper_sockopt, true, {}, true, nullptr},
    {"net helper: bind", p_helper_bind, true, {}, true, nullptr},
    {"net helper: sendto on its own socket", p_helper_sendto, true, {}, true, nullptr},
    {"net helper: sendmsg off the channel", p_helper_sendmsg_other, true, {}, true,
     prepare_device_fds},
    {"net helper: fork", p_fork, true, {}, true, nullptr},
    {"net helper: set a signal stack", p_helper_sigaltstack, true, {}, true, nullptr},
};

static int run_child(const char *self, int idx, bool sandboxed, bool *killed)
{
    (void)self;
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (PROBES[idx].prepare)
            PROBES[idx].prepare();
        // "net helper: ..." probes run in the network helper's sandbox.
        if (sandboxed && !strncmp(PROBES[idx].name, "net helper:", 11)) {
            if (sandbox_enter_net_helper(DEV_A, DEV_B, g_report, sizeof g_report)) {
                fprintf(stderr, "sandbox_enter_net_helper: errno %d: %s\n", errno, strerror(errno));
                _exit(SETUP_FAILED);
            }
        } else if (sandboxed && sandbox_enter(&PROBES[idx].cfg, g_report, sizeof g_report)) {
            fprintf(stderr, "sandbox_enter: %s (errno %d: %s)\n", g_report, errno, strerror(errno));
            _exit(SETUP_FAILED);
        }
        _exit(PROBES[idx].probe());
    }
    int st = 0;
    waitpid(pid, &st, 0);
    *killed = WIFSIGNALED(st);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

static void set_parent_env(void) {}
#endif

int main(int argc, char **argv)
{
    constexpr int N = (int)(sizeof PROBES / sizeof PROBES[0]);
#ifndef _WIN32
    for (int c = 0; c < 8; c++)
        for (int k = 0; k < 16; k++)
            MANY[c * 16 + k] = (sandbox_ioctl){100 + c, k < 15 ? 0xae80ul + (unsigned)k : TIOCGWINSZ};
    MANY[8 * 16] = (sandbox_ioctl){2, TIOCGWINSZ};
#endif
    if (argc == 3 && !strcmp(argv[1], "--control")) {
        const int idx = atoi(argv[2]);
        return idx >= 0 && idx < N ? PROBES[idx].probe() : SETUP_FAILED;
    }
    if (argc == 3 && !strcmp(argv[1], "--child")) {
        const int idx = atoi(argv[2]);
        if (idx < 0 || idx >= N)
            return SETUP_FAILED;
        if (PROBES[idx].prepare)
            PROBES[idx].prepare();
        if (sandbox_enter(&PROBES[idx].cfg, g_report, sizeof g_report)) {
            fprintf(stderr, "sandbox_enter failed: %s\n", g_report);
            return SETUP_FAILED;
        }
        return PROBES[idx].probe();
    }

    set_parent_env();
    int failures = 0;
    for (int i = 0; i < N; i++) {
        bool killed = false;
        const probe_def *p = &PROBES[i];
        if (p->control) {
            bool ck = false;
            const int cc = run_child(argv[0], i, false, &ck);
            if (cc != ESCAPED) {
                printf("%-44s %-12s FAIL (control run without sandbox did not escape: %d)\n",
                       p->name, "-", cc);
                failures++;
                continue;
            }
        }
        const int code = run_child(argv[0], i, true, &killed);
        bool ok;
        const char *how;
        if (p->probe == nullptr) {
            ok = false;
            how = "?";
        } else if (!p->killed_ok) {
            // Control / non-kill probes: Landlock must refuse with EACCES;
            // the control must run to completion (reported as ESCAPED).
            const bool control = strstr(p->name, "control") != nullptr;
            ok = control ? code == ESCAPED : code == BLOCKED || code == SKIPPED;
            how = killed ? "killed" : code == BLOCKED ? "refused" : code == ESCAPED ? "ran"
                : code == SKIPPED ? "skipped" : "setup failed";
        } else {
            ok = killed || code == BLOCKED;
            how = killed ? "killed" : code == BLOCKED ? "refused" : code == ESCAPED ? "ESCAPED" : "setup failed";
        }
        printf("%-44s %-12s %s\n", p->name, how, ok ? "ok" : "FAIL");
        failures += !ok;
    }
    printf("%d/%d sandbox probes held\n", N - failures, N);
    return failures ? 1 : 0;
}
