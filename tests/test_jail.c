// SPDX-License-Identifier: MIT
// microvm-jail, from both sides (Linux).
//
//   mvm_jail_tests PATH/TO/microvm-jail
//
// Jails this binary (static, like the VMM) and has it check from inside
// what it can and can't reach. Then the jail's refusals: arguments that
// would escape, or reach outside the new root, must exit with 125 and leave
// nothing behind. As root it also checks the per-VM uid/gid and a cgroup
// with limits (cgroup v2). As anyone else it needs unprivileged user
// namespaces; without them the test is skipped (77).
//
// --net: the jailed process gets the network helper's channel as fd 3 and
// asks it for sockets (net_helper_open, as the VMM's device does) to a
// listener of the test's on the host's loopback, which the jail's
// --net-allow lets through, and to destinations the policy refuses. It
// still has no network of its own. From outside, the helper: its own PID
// namespace, the VM's uid, seccomp, no capabilities, in the VM's cgroup,
// and gone once the VM is.
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "net_helper.h"

extern char **environ;

static int fails;

static void check(bool ok, const char *what)
{
    printf("  %-58s %s\n", what, ok ? "ok" : "FAIL");
    fails += !ok;
}

// ---- inside the jail ----------------------------------------------------------
static int inside(int argc, char **argv)
{
    // argv: --inside UID KVM(0/1) CGROUP(0/1)
    if (argc < 5)
        return 2;
    const uid_t want_uid = (uid_t)strtoul(argv[2], nullptr, 10);
    const bool want_kvm = argv[3][0] == '1', want_cg = argv[4][0] == '1';
    printf("inside the jail:\n");
    check(environ[0] == nullptr, "empty environment");
    bool fds_closed = true;
    for (int fd = 3; fd < 1024; fd++)
        if (fcntl(fd, F_GETFD) >= 0)
            fds_closed = false;
    check(fds_closed, "no file descriptors but 0-2");
    check(getpid() == 1, "pid 1 of its own PID namespace");
    check(getuid() == want_uid && geteuid() == want_uid, "the expected uid");
    struct __user_cap_header_struct h = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct d[2];
    const bool capget_ok = syscall(SYS_capget, &h, d) == 0;
    check(capget_ok && !d[0].effective && !d[0].permitted && !d[0].inheritable && !d[1].effective &&
              !d[1].permitted && !d[1].inheritable,
          "no capabilities");
    bool bset_empty = true;
    for (int cap = 0; cap < 64; cap++)
        if (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) > 0)
            bset_empty = false;
    check(bset_empty, "empty capability bounding set");
    check(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "no_new_privs");
#ifdef __SANITIZE_ADDRESS__
    // An ASan build's jail adds the host's library directories, which its
    // dynamically linked VMM needs (jail.c): /usr exists, but holds only them.
    const char *const usr = "/usr/bin";
#else
    const char *const usr = "/usr";
#endif
    check(access("/etc/passwd", F_OK) && access(usr, F_OK) && access("/sys", F_OK) &&
              access("/home", F_OK) && access("/tmp", F_OK),
          "no host files (/etc, /usr, /sys, /home, /tmp)");
    char buf[64] = {0};
    const int fd = open("/data/file", O_RDONLY);
    check(fd >= 0 && read(fd, buf, sizeof buf - 1) > 0 && !strcmp(buf, "jail data\n"),
          "a read-only bind is readable");
    if (fd >= 0)
        close(fd);
    errno = 0;
    check(open("/data/file", O_WRONLY) < 0 && (errno == EROFS || errno == EACCES),
          "... and not writable");
    const int wfd = open("/out/written", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    check(wfd >= 0 && write(wfd, "from the jail\n", 14) == 14, "a :rw bind is writable");
    if (wfd >= 0)
        close(wfd);
    errno = 0;
    check(mkdir("/newdir", 0755) && errno == EROFS, "the root is read-only");
    struct statvfs vfs;
    check(!statvfs("/data", &vfs) && (vfs.f_flag & ST_NOEXEC) && (vfs.f_flag & ST_NOSUID) &&
              (vfs.f_flag & ST_NODEV),
          "binds are noexec, nosuid, nodev");
    DIR *pd = opendir("/proc");
    int procs = 0;
    bool only_pid1 = pd != nullptr;
    for (struct dirent *e; pd && (e = readdir(pd));) {
        if (e->d_name[0] >= '0' && e->d_name[0] <= '9') {
            procs++;
            if (strcmp(e->d_name, "1"))
                only_pid1 = false;
        }
    }
    if (pd)
        closedir(pd);
    check(only_pid1 && procs == 1, "/proc shows this process only");
    char host[64] = {0};
    check(!gethostname(host, sizeof host - 1) && !strcmp(host, "microvm"), "hostname 'microvm'");
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sin = {.sin_family = AF_INET, .sin_port = htons(9)};
    inet_pton(AF_INET, "192.0.2.1", &sin.sin_addr);
    errno = 0;
    check(s < 0 || (connect(s, (struct sockaddr *)&sin, sizeof sin) < 0 && errno == ENETUNREACH),
          "no network (only a down loopback)");
    if (s >= 0)
        close(s);
    struct stat st;
    if (want_kvm)
        check(!stat("/dev/kvm", &st) && S_ISCHR(st.st_mode), "/dev/kvm is there");
    else
        check(access("/dev/kvm", F_OK) != 0, "no /dev/kvm (the host has none)");
    if (want_cg) {
        char cg[128] = {0};
        const int cfd = open("/proc/self/cgroup", O_RDONLY);
        check(cfd >= 0 && read(cfd, cg, sizeof cg - 1) > 0 && !strcmp(cg, "0::/\n"),
              "its own cgroup namespace, rooted at the VM's cgroup");
        if (cfd >= 0)
            close(cfd);
    }
    printf(fails ? "inside: %d checks FAILED\n" : "inside: all checks passed\n", fails);
    return fails ? 1 : 0;
}

// argv: --net-fd 3 (added by the jail) --inside-net PORT. Asks the helper
// for sockets, says "ready", then holds the VM up until stdin closes.
static int inside_net(int argc, char **argv)
{
    if (argc < 5 || strcmp(argv[2], "3") || strcmp(argv[3], "--inside-net"))
        return 2;
    const uint16_t port = (uint16_t)atoi(argv[4]);
    printf("inside the jail, with --net:\n");
    int type = 0;
    socklen_t tl = sizeof type;
    check(!getsockopt(3, SOL_SOCKET, SO_TYPE, &type, &tl) && type == SOCK_SEQPACKET,
          "fd 3 is the helper's channel (SOCK_SEQPACKET)");
    bool others_closed = true;
    for (int fd = 4; fd < 1024; fd++)
        if (fcntl(fd, F_GETFD) >= 0)
            others_closed = false;
    check(others_closed, "no other fds past 2");
    // The helper opens the socket in the host's network namespace.
    net_dst d = {.proto = NET_TCP, .port = port, .addr = {127, 0, 0, 1}};
    const int s = net_helper_open((void *)(intptr_t)3, &d);
    bool sent = false;
    if (s >= 0) {
        struct pollfd p = {.fd = s, .events = POLLOUT};
        sent = poll(&p, 1, 3000) == 1 && write(s, "via the helper", 14) == 14;
        close(s);
    }
    check(s >= 0 && sent, "a socket from the helper reaches the host's loopback (--net-allow)");
    d.addr[0] = 10, d.addr[1] = 0, d.addr[2] = 2, d.addr[3] = 2; // the gateway: the host's 127.0.0.1
    const int g = net_helper_open((void *)(intptr_t)3, &d);
    check(g >= 0, "10.0.2.2 maps to it too");
    if (g >= 0)
        close(g);
    const uint8_t refused[][4] = {{169, 254, 169, 254}, {192, 168, 1, 1}, {100, 100, 100, 100}};
    bool all_refused = true;
    for (size_t i = 0; i < sizeof refused / sizeof *refused; i++) {
        net_dst r = {.proto = NET_TCP, .port = 80};
        memcpy(r.addr, refused[i], 4);
        const int x = net_helper_open((void *)(intptr_t)3, &r);
        all_refused = all_refused && x == -EACCES;
        if (x >= 0)
            close(x);
    }
    check(all_refused, "refused by the helper: metadata, RFC 1918, CGNAT");
    const int own = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sin = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);
    errno = 0;
    check(own < 0 || (connect(own, (struct sockaddr *)&sin, sizeof sin) < 0 && errno == ENETUNREACH),
          "still no network of its own (its loopback is down)");
    if (own >= 0)
        close(own);
    printf(fails ? "inside: %d checks FAILED\n" : "inside: all checks passed\n", fails);
    printf("ready\n");
    fflush(stdout);
    char c;
    while (read(0, &c, 1) > 0)
        ;
    return fails ? 1 : 0;
}

// ---- outside --------------------------------------------------------------------
static const char *jail;
static char self[4096], tmp[64];
static bool root;
static const char *base; // --base FILE for run_jailed, if set

// Runs the jail with ARGS (nullptr-terminated); returns its exit status and
// the first part of its output in out.
static int run(char *const args[], char *out, size_t outlen, int kill_after_ms)
{
    int p[2];
    if (pipe(p))
        return -1;
    const pid_t pid = fork();
    if (pid == 0) {
        dup2(p[1], 1);
        dup2(p[1], 2);
        close(p[0]);
        close(p[1]);
        // A descriptor without CLOEXEC: the jail must not pass it on.
        (void)open("/dev/null", O_RDONLY);
        char *argv[64];
        int n = 0;
        argv[n++] = (char *)jail;
        for (int i = 0; args[i] && n < 63; i++)
            argv[n++] = args[i];
        argv[n] = nullptr;
        char *envp[] = {(char *)"SECRET=1", nullptr};
        execve(jail, argv, envp);
        _exit(127);
    }
    close(p[1]);
    if (kill_after_ms) {
        struct timespec ts = {0, kill_after_ms * 1000000L};
        nanosleep(&ts, nullptr);
        kill(pid, SIGTERM);
    }
    size_t got = 0;
    ssize_t r;
    while ((r = read(p[0], out + got, outlen - 1 - got)) > 0 && got + (size_t)r < outlen - 1)
        got += (size_t)r;
    if (r > 0)
        got += (size_t)r;
    out[got] = 0;
    close(p[0]);
    int st;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

static bool userns_works(void)
{
    const pid_t pid = fork();
    if (pid == 0)
        _exit(unshare(CLONE_NEWUSER) ? 1 : 0);
    int st;
    return waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

// The jail with the standard binds (and cgroup CG if not ""), running this
// binary with TAIL.
static int run_jailed(const char *cg, char *bind_data, char *bind_out, char *const tail[], char *out,
                      size_t outlen, int kill_after_ms)
{
    char *args[48];
    int k = 0;
    if (root) {
        args[k++] = (char *)"--uid";
        args[k++] = (char *)"65534";
        args[k++] = (char *)"--gid";
        args[k++] = (char *)"65534";
    }
    if (base) {
        args[k++] = (char *)"--base";
        args[k++] = (char *)base;
    }
    if (cg[0]) {
        args[k++] = (char *)"--cgroup";
        args[k++] = (char *)cg;
        args[k++] = (char *)"--pids-max";
        args[k++] = (char *)"8";
        args[k++] = (char *)"--mem-max";
        args[k++] = (char *)"67108864";
    }
    args[k++] = (char *)"--bind";
    args[k++] = bind_data;
    args[k++] = (char *)"--bind";
    args[k++] = bind_out;
    args[k++] = (char *)"--";
    args[k++] = self;
    for (int i = 0; tail[i] && k < 47; i++)
        args[k++] = tail[i];
    args[k] = nullptr;
    return run(args, out, outlen, kill_after_ms);
}

// The fields of /proc/PID/status, as one string.
static void proc_status(pid_t pid, char *buf, size_t cap)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/status", (int)pid);
    memset(buf, 0, cap);
    const int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        (void)!read(fd, buf, cap - 1);
        close(fd);
    }
}

static bool status_has(const char *st, const char *field, const char *val)
{
    const char *f = strstr(st, field);
    if (!f)
        return false;
    f += strlen(field);
    while (*f == ' ' || *f == '\t')
        f++;
    return !strncmp(f, val, strlen(val));
}

// The jail with --net, running inside_net(); checked from outside while
// the jailed process waits on its stdin.
static void net_checks(const char *cg, const char *uid_s)
{
    const int l = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t sl = sizeof sin;
    if (l < 0 || bind(l, (struct sockaddr *)&sin, sizeof sin) || listen(l, 8) ||
        getsockname(l, (struct sockaddr *)&sin, &sl)) {
        check(false, "--net: a listener on 127.0.0.1");
        return;
    }
    char port[16];
    snprintf(port, sizeof port, "%u", ntohs(sin.sin_port));
    char *args[40];
    int k = 0;
    if (root) {
        args[k++] = (char *)"--uid";
        args[k++] = (char *)"65534";
        args[k++] = (char *)"--gid";
        args[k++] = (char *)"65534";
    }
    if (cg[0]) {
        args[k++] = (char *)"--cgroup";
        args[k++] = (char *)cg;
        args[k++] = (char *)"--pids-max";
        args[k++] = (char *)"8";
    }
    args[k++] = (char *)"--net";
    args[k++] = (char *)"--net-allow";
    args[k++] = (char *)"127.0.0.1/32";
    args[k++] = (char *)"--";
    args[k++] = self;
    args[k++] = (char *)"--inside-net";
    args[k++] = port;
    args[k] = nullptr;
    int in[2], out[2];
    if (pipe2(in, O_CLOEXEC) || pipe2(out, O_CLOEXEC))
        return;
    const pid_t pid = fork();
    if (pid == 0) {
        dup2(in[0], 0);
        dup2(out[1], 1);
        dup2(out[1], 2);
        char *argv[48];
        int n = 0;
        argv[n++] = (char *)jail;
        for (int i = 0; args[i]; i++)
            argv[n++] = args[i];
        argv[n] = nullptr;
        char *envp[] = {nullptr};
        execve(jail, argv, envp);
        _exit(127);
    }
    close(in[0]);
    close(out[1]);
    // Read until "ready" (or EOF: the jail failed).
    static char text[8192];
    size_t got = 0;
    for (ssize_t r; got < sizeof text - 1 && !strstr(text, "ready\n") &&
                    (r = read(out[0], text + got, sizeof text - 1 - got)) > 0;)
        got += (size_t)r;
    fputs(text, stdout);
    printf("outside, with --net:\n");
    check(strstr(text, "inside: all checks passed") != nullptr, "the jailed --net checks passed");
    const int c = accept4(l, nullptr, nullptr, SOCK_CLOEXEC);
    char msg[32] = {0};
    check(c >= 0 && read(c, msg, sizeof msg - 1) == 14 && !strcmp(msg, "via the helper"),
          "the host listener got the bytes");
    if (c >= 0)
        close(c);
    // The jail's two children: the VM's process and the helper.
    char path[96], kids[128] = {0};
    snprintf(path, sizeof path, "/proc/%d/task/%d/children", (int)pid, (int)pid);
    const int kf = open(path, O_RDONLY);
    if (kf >= 0) {
        (void)!read(kf, kids, sizeof kids - 1);
        close(kf);
    }
    pid_t helper = 0, vm = 0;
    char st[4096];
    for (char *p = kids, *e; (e = strchr(p, ' ')); p = e + 1) {
        const pid_t q = (pid_t)strtol(p, nullptr, 10);
        proc_status(q, st, sizeof st);
        if (status_has(st, "Name:", "microvm-jail"))
            helper = q; // a fork of the jail; the VM's process runs /microvm
        else
            vm = q;
    }
    check(helper > 0 && vm > 0, "two processes: the VM's and the helper");
    if (helper > 0) {
        proc_status(helper, st, sizeof st);
        char uid_line[64];
        snprintf(uid_line, sizeof uid_line, "%s\t%s\t%s\t%s", uid_s, uid_s, uid_s, uid_s);
        check(status_has(st, "Uid:", uid_line), "the helper has the VM's uid");
        const char *ns = strstr(st, "NSpid:");
        char want[48];
        snprintf(want, sizeof want, "%d\t1\n", (int)helper);
        check(ns && status_has(ns, "NSpid:", want), "... is pid 1 of a PID namespace of its own");
        check(status_has(st, "Seccomp:", "2") && status_has(st, "NoNewPrivs:", "1"),
              "... runs under seccomp, with no_new_privs");
        check(status_has(st, "CapEff:", "0000000000000000") && status_has(st, "CapPrm:", "0000000000000000") &&
                  status_has(st, "CapBnd:", "0000000000000000"),
              "... has no capabilities, an empty bounding set");
        if (root) { // its namespace links (it is not dumpable: root only)
            bool net_same = true, rest_differ = true;
            static const char *const nss[] = {"net", "mnt", "pid", "ipc", "uts"};
            for (size_t i = 0; i < sizeof nss / sizeof *nss; i++) {
                char a[96], b[96], la[64] = {0}, lb[64] = {0};
                snprintf(a, sizeof a, "/proc/%d/ns/%s", (int)helper, nss[i]);
                snprintf(b, sizeof b, "/proc/self/ns/%s", nss[i]);
                const bool ok = readlink(a, la, sizeof la - 1) > 0 && readlink(b, lb, sizeof lb - 1) > 0;
                if (i == 0)
                    net_same = ok && !strcmp(la, lb);
                else
                    rest_differ = rest_differ && ok && strcmp(la, lb);
            }
            check(net_same && rest_differ, "... in the host's network namespace, and its own mount, PID, IPC, UTS");
            snprintf(path, sizeof path, "/proc/%d/root/etc", (int)helper);
            check(access(path, F_OK) != 0, "... with an empty root");
        }
        if (cg[0]) {
            char cgs[256] = {0};
            snprintf(path, sizeof path, "/proc/%d/cgroup", (int)helper);
            const int cf = open(path, O_RDONLY);
            if (cf >= 0) {
                (void)!read(cf, cgs, sizeof cgs - 1);
                close(cf);
            }
            check(strstr(cgs, cg + strlen("/sys/fs/cgroup")) != nullptr, "... in the VM's cgroup");
        }
    }
    close(in[1]); // the VM's process exits
    while (read(out[0], text, sizeof text) > 0)
        ;
    close(out[0]);
    int wst;
    waitpid(pid, &wst, 0);
    check(WIFEXITED(wst) && WEXITSTATUS(wst) == 0, "the jail exits 0");
    check(helper > 0 && kill(helper, 0) && errno == ESRCH, "the helper is gone with the VM");
    close(l);
    if (cg[0])
        check(rmdir(cg) == 0, "the cgroup is empty after the VM and its helper");
}

static void put(const char *path, const char *data, mode_t mode)
{
    const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0 || write(fd, data, strlen(data)) != (ssize_t)strlen(data))
        perror(path);
    close(fd);
    chmod(path, mode);
}

int main(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "--inside"))
        return inside(argc, argv);
    if (argc >= 4 && !strcmp(argv[1], "--net-fd"))
        return inside_net(argc, argv);
    if (argc >= 3 && !strcmp(argv[1], "--exit"))
        return atoi(argv[2]);
    if (argc >= 2 && !strcmp(argv[1], "--sleep")) {
        pause();
        return 0;
    }
    if (argc < 2) {
        fprintf(stderr, "usage: %s PATH/TO/microvm-jail\n", argv[0]);
        return 2;
    }
    jail = argv[1];
    root = geteuid() == 0;
    if (!root && !userns_works()) {
        printf("skipped: not root and no unprivileged user namespaces\n");
        return 77;
    }
    const ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n <= 0)
        return 1;
    self[n] = 0;
    snprintf(tmp, sizeof tmp, "/tmp/mvm-jail-XXXXXX");
    if (!mkdtemp(tmp))
        return 1;
    chmod(tmp, 0755);
    char data[128], file[160], outd[128], written[160];
    snprintf(data, sizeof data, "%s/data", tmp);
    snprintf(file, sizeof file, "%s/file", data);
    snprintf(outd, sizeof outd, "%s/out", tmp);
    snprintf(written, sizeof written, "%s/written", outd);
    mkdir(data, 0755);
    mkdir(outd, 0777);
    chmod(outd, 0777);
    put(file, "jail data\n", 0644);

    char bind_data[200], bind_out[200], uid_s[16];
    snprintf(bind_data, sizeof bind_data, "%s:/data", data);
    snprintf(bind_out, sizeof bind_out, "%s:/out:rw", outd);
    const uid_t vm_uid = root ? 65534 : getuid();
    snprintf(uid_s, sizeof uid_s, "%u", (unsigned)vm_uid);
    struct stat kst;
    const bool kvm = !stat("/dev/kvm", &kst) && S_ISCHR(kst.st_mode);
    // A cgroup (root, cgroup v2 with the memory and pids controllers on).
    char cg[96] = "";
    if (root && !access("/sys/fs/cgroup/cgroup.subtree_control", W_OK)) {
        char ctl[256] = {0};
        const int cfd = open("/sys/fs/cgroup/cgroup.subtree_control", O_RDONLY);
        if (cfd >= 0 && read(cfd, ctl, sizeof ctl - 1) > 0 && strstr(ctl, "memory") && strstr(ctl, "pids"))
            snprintf(cg, sizeof cg, "/sys/fs/cgroup/mvm-jail-test-%d", (int)getpid());
        if (cfd >= 0)
            close(cfd);
    }
    printf("mode: %s%s\n", root ? "root (per-VM uid 65534)" : "unprivileged (user namespace)",
           cg[0] ? ", with a cgroup" : "");

    static char out[16384];
    char *happy[] = {(char *)"--inside", uid_s, (char *)(kvm ? "1" : "0"), (char *)(cg[0] ? "1" : "0"),
                     nullptr};
    const int rc = run_jailed(cg, bind_data, bind_out, happy, out, sizeof out, 0);
    fputs(out, stdout);
    printf("outside:\n");
    check(rc == 0 && strstr(out, "inside: all checks passed"), "the jailed checks passed");
    struct stat wst;
    check(!stat(written, &wst) && wst.st_uid == vm_uid, "the :rw write reached the host, as the VM's uid");
    if (cg[0]) {
        char path[160], val[64] = {0};
        snprintf(path, sizeof path, "%s/pids.max", cg);
        const int pfd = open(path, O_RDONLY);
        check(pfd >= 0 && read(pfd, val, sizeof val - 1) > 0 && !strcmp(val, "8\n"), "pids.max was set");
        if (pfd >= 0)
            close(pfd);
        // An existing cgroup: reused when empty, refused while in use.
        char *ex7[] = {(char *)"--exit", (char *)"7", nullptr};
        check(run_jailed(cg, bind_data, bind_out, ex7, out, sizeof out, 0) == 7,
              "an existing empty cgroup is reused");
        const pid_t holder = fork();
        if (holder == 0) {
            pause();
            _exit(0);
        }
        char procs[160], pid_s[16];
        snprintf(procs, sizeof procs, "%s/cgroup.procs", cg);
        snprintf(pid_s, sizeof pid_s, "%d", (int)holder);
        const int qfd = open(procs, O_WRONLY);
        const bool moved = qfd >= 0 && write(qfd, pid_s, strlen(pid_s)) == (ssize_t)strlen(pid_s);
        if (qfd >= 0)
            close(qfd);
        check(moved && run_jailed(cg, bind_data, bind_out, ex7, out, sizeof out, 0) == 125,
              "refused: a cgroup that is in use");
        kill(holder, SIGKILL);
        waitpid(holder, nullptr, 0);
        check(rmdir(cg) == 0, "the cgroup is empty after the VM, and removable");
    }

    // A base mount namespace (root): made once, then every VM starts from
    // it; the same checks pass inside.
    char based[96] = "", basef[128] = "";
    if (root) {
        snprintf(based, sizeof based, "%s/base", tmp);
        snprintf(basef, sizeof basef, "%s/mnt", based);
        mkdir(based, 0755);
        const bool priv = !mount(based, based, nullptr, MS_BIND, nullptr) &&
                          !mount(nullptr, based, nullptr, MS_PRIVATE, nullptr);
        char *mk[] = {(char *)"--make-base", basef, nullptr};
        check(priv && run(mk, out, sizeof out, 0) == 0, "--make-base pins a base");
        check(run(mk, out, sizeof out, 0) == 125, "--make-base refuses an existing FILE");
        base = basef;
        char *happy_nocg[] = {(char *)"--inside", uid_s, (char *)(kvm ? "1" : "0"), (char *)"0", nullptr};
        const int brc = run_jailed("", bind_data, bind_out, happy_nocg, out, sizeof out, 0);
        check(brc == 0 && strstr(out, "inside: all checks passed"), "with --base: the jailed checks passed");
        if (brc)
            fputs(out, stdout);
        char *ex42[] = {(char *)"--exit", (char *)"42", nullptr};
        check(run_jailed("", bind_data, bind_out, ex42, out, sizeof out, 0) == 42,
              "with --base: the VMM's exit status comes back");
        base = nullptr;
        check(!umount2(basef, 0) && !unlink(basef), "the base is dropped with umount");
        umount2(based, MNT_DETACH);
        rmdir(based);
    } else {
        char *mk[] = {(char *)"--make-base", (char *)"/tmp/mvm-jail-nobase", nullptr};
        check(run(mk, out, sizeof out, 0) == 125 && access("/tmp/mvm-jail-nobase", F_OK),
              "refused: --make-base without root");
    }

    // Exit status and signals.
    char *ex[] = {(char *)"--exit", (char *)"42", nullptr};
    check(run_jailed("", bind_data, bind_out, ex, out, sizeof out, 0) == 42,
          "the VMM's exit status comes back");
    char *sl[] = {(char *)"--sleep", nullptr};
    check(run_jailed("", bind_data, bind_out, sl, out, sizeof out, 200) == 128 + SIGKILL,
          "SIGTERM to the jail kills the VM");

    net_checks(cg, uid_s);

    // Refusals: exit 125, nothing created on the host.
    char nested[200], bad_src[200];
    snprintf(nested, sizeof nested, "%s:/data/x", file);
    snprintf(bad_src, sizeof bad_src, "%s/nosuch:/x", tmp);
    struct {
        const char *what;
        char *argv[12];
    } bad[] = {
        {"--bind to a relative path", {"--bind", bind_data, "--bind", (char *)"x:rel", "--", self, nullptr}},
        {"--bind with ..", {"--bind", (char *)"/etc:/a/../../etc", "--", self, nullptr}},
        {"--bind to a trailing /.", {"--bind", (char *)"/etc:/a/.", "--", self, nullptr}},
        {"--bind over /proc", {"--bind", (char *)"/etc:/proc", "--", self, nullptr}},
        {"--bind over /microvm", {"--bind", (char *)"/etc/passwd:/microvm", "--", self, nullptr}},
        {"--bind under /dev", {"--bind", (char *)"/etc/passwd:/dev/sda", "--", self, nullptr}},
        {"--bind to /", {"--bind", (char *)"/etc:/", "--", self, nullptr}},
        {"nested --bind destinations", {"--bind", bind_data, "--bind", nested, "--", self, nullptr}},
        {"--bind with a bad mode", {"--bind", (char *)"/etc:/e:rwx", "--", self, nullptr}},
        {"--bind of a missing source", {"--bind", bad_src, "--", self, nullptr}},
        {"limits without --cgroup", {"--pids-max", (char *)"4", "--", self, nullptr}},
        {"a cgroup value that isn't one", {"--cgroup", (char *)"/sys/fs/cgroup/x", "--pids-max",
                                           (char *)"4\n+cpu", "--", self, nullptr}},
        {"a relative --cgroup", {"--cgroup", (char *)"x", "--", self, nullptr}},
        {"--uid 0", {"--uid", (char *)"0", "--gid", (char *)"0", "--", self, nullptr}},
        {"no -- before the VMM", {"--bind", bind_data, self, nullptr}},
        {"a VMM that doesn't exist", {"--", (char *)"/nonexistent/microvm", nullptr}},
        {"a --base that isn't a namespace", {"--base", (char *)"/etc/passwd", "--", self, nullptr}},
        {"a relative --base", {"--base", (char *)"mnt", "--", self, nullptr}},
        {"--net-allow without --net", {"--net-allow", (char *)"127.0.0.1/32", "--", self, nullptr}},
        {"a bad --net-allow", {"--net", "--net-allow", (char *)"127.0.0.1/33", "--", self, nullptr}},
        {"a bad --net-dns", {"--net", "--net-dns", (char *)"resolver", "--", self, nullptr}},
        {"--net given to the VMM", {"--", self, (char *)"--net", nullptr}},
        {"--net-fd given to the VMM", {"--net", "--", self, (char *)"--net-fd", (char *)"0", nullptr}},
        {"--net-allow given to the VMM", {"--", self, (char *)"--net-allow", (char *)"0.0.0.0/0", nullptr}},
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        char *a[16];
        int m = 0;
        if (root && strcmp(bad[i].what, "--uid 0")) {
            a[m++] = (char *)"--uid";
            a[m++] = (char *)"65534";
            a[m++] = (char *)"--gid";
            a[m++] = (char *)"65534";
        }
        for (int j = 0; bad[i].argv[j]; j++)
            a[m++] = bad[i].argv[j];
        a[m] = nullptr;
        char what[96];
        snprintf(what, sizeof what, "refused: %s", bad[i].what);
        check(run(a, out, sizeof out, 0) == 125, what);
    }
    if (root) {
        char *a[] = {(char *)"--", self, (char *)"--exit", (char *)"0", nullptr};
        check(run(a, out, sizeof out, 0) == 125, "refused: root without --uid/--gid");
    } else {
        char *a[] = {(char *)"--uid", (char *)"12345", (char *)"--gid", (char *)"12345", (char *)"--",
                     self, (char *)"--exit", (char *)"0", nullptr};
        check(run(a, out, sizeof out, 0) == 125, "refused: --uid without root");
    }
    // "--net" in the guest's command (after the VMM's own "--") is no option of the VMM's.
    char *gw[] = {(char *)"--exit", (char *)"0", (char *)"--", (char *)"--net", nullptr};
    check(run_jailed("", bind_data, bind_out, gw, out, sizeof out, 0) == 0,
          "\"--net\" in the guest's command is left alone");
    check(access("/a", F_OK) && access("/e", F_OK) && access("/x", F_OK) &&
              access("/sys/fs/cgroup/x", F_OK),
          "nothing created on the host");

    unlink(written);
    unlink(file);
    rmdir(data);
    rmdir(outd);
    rmdir(tmp);
    printf(fails ? "%d checks FAILED\n" : "all checks passed\n", fails);
    return fails ? 1 : 0;
}
