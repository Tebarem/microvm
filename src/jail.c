// SPDX-License-Identifier: MIT
// microvm-jail: run one VMM isolated from the host and from every other VM
// (Linux). The service starts each VM through it:
//
//   microvm-jail [--uid N --gid N] [--base FILE] [--cgroup DIR [--mem-max BYTES]
//                [--pids-max N] [--cpu-max "QUOTA PERIOD"] [--cpu-weight N]]
//                [--bind SRC:DST[:rw]]... [--net [--net-allow CIDR]... [--net-dns ADDR]...
//                [--net-deny-all]] -- VMM [ARG...]
//   microvm-jail --make-base FILE
//
// The VMM (a host path) runs as /microvm inside a new root that holds only:
//   /microvm         the VMM binary (read-only)
//   /dev/kvm         if the host has one
//   /proc            this VM's PID namespace only (subset=pid)
//   each --bind      SRC at DST, read-only unless ":rw"
// The root itself is an empty read-only tmpfs. ARGs name files by their DST.
//
// Namespaces: mount, PID (the VMM is pid 1 and sees nothing else), network
// (only a down loopback), IPC, UTS (hostname "microvm"), cgroup.
//
// Two modes:
//   started as root   --uid/--gid are required (not 0): the VM's own host
//                     identity, with the group of /dev/kvm as its only
//                     supplementary group. Every other privilege is dropped
//                     before the VMM runs.
//   started as anyone else   a user namespace gives the rights to build the
//                     namespaces; the VMM keeps the caller's uid and groups
//                     (per-VM uids need privilege).
// Either way the VMM starts with no capabilities, an empty bounding set,
// no_new_privs, no file descriptors but 0-2 and an empty environment. Its own
// sandbox (seccomp, Landlock, rlimits) goes on top.
//
// --cgroup DIR creates DIR (cgroup v2), or reuses it if it exists and is
// empty, writes the limits (on a reused one, the defaults for those not
// given), and starts the VM in it (clone3 CLONE_INTO_CGROUP: a process is
// never moved between cgroups, which costs an RCU grace period). The
// controllers must be enabled in the parent's cgroup.subtree_control; as
// non-root the parent must be delegated to the caller. --mem-max also sets
// memory.swap.max to 0. Guest RAM counts against memory.max, and pids.max
// counts threads, KVM's per-VM worker included. The caller removes DIR (or
// keeps it for the next VM) once the jail has exited. Making cgroups takes
// a global lock, so with many VMs starting at once a pool made ahead of
// time saves several ms per start.
//
// --base FILE (root only) starts from the mount namespace FILE pins, made
// once with --make-base: an empty read-only tmpfs and nothing else. Without
// it each VM's mount namespace starts as a copy of the host's whole mount
// table, all of which is then detached again; those are global locks, and
// with many VMs starting at once they dominate (N=256 in flight: 12 ms
// instead of 3 ms from launch to the VMM's main). The VM ends up with the
// same root either way. FILE has to be on a mount with private propagation
// (mount --bind D D; mount --make-private D); umount FILE drops the base.
//
// One process stays outside the VM's namespaces and cgroup, with the VM's
// credentials, to wait for it: it exits with the VMM's status (128 + N for
// a signal), turns SIGTERM / SIGINT / SIGHUP into SIGKILL for the VM, and
// the VM gets SIGKILL if it dies. Setup failures exit with 125.
//
// --net gives the VM a network (the VMM's --net, which must not be given
// to the VMM itself): the VMM stays in its empty network namespace, and
// the jail starts the network helper (net_helper.h), the one process that
// opens host sockets for the guest, in the host's. The helper is forked
// from the jail, not the VMM: under the same identity, in the VM's cgroup
// (so the guest's socket buffers count against its memory.max), and in
// mount (an empty read-only root), PID, IPC and UTS namespaces of its own;
// only the network namespace is the host's, which the egress policy needs
// (its route check asks the host's routing table). Its channel reaches the
// VMM as fd 3, with --net-fd 3 added to the VMM's arguments. --net-allow,
// --net-dns, --net-deny-port, --net-flow-rate and --net-max-dests set the
// helper's policy, as they would the VMM's. --net-tx-rate paces the
// helper's sockets and goes on to the VMM, whose device caps all its flows
// together.
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __SANITIZE_ADDRESS__
#  include <sanitizer/lsan_interface.h>
#endif

#include "net_helper.h"

constexpr int JAIL_ERR = 125;
constexpr int MAX_BINDS = 32;
constexpr size_t PATH_MAX_JAIL = 4096;
static const char NEWROOT[] = "/tmp"; // mount point of the new root, in our own mount ns only

typedef struct {
    const char *src, *dst;
    bool rw;
} bind_spec;

static struct {
    bool root;
    long uid, gid;
    const char *cgroup;
    const char *base; // --base: a pinned mount namespace to start from
    const char *mem_max, *pids_max, *cpu_max, *cpu_weight;
    bind_spec binds[MAX_BINDS];
    int nbinds;
    char **vmm_argv; // [0] = the VMM's host path
    gid_t kvm_gid;
    bool have_kvm;
    bool net;          // --net: a network helper outside the VM's network namespace
    bool net_policy_given;
    net_policy npol;   // --net-allow, --net-dns and the limits
    const char *tx_rate; // --net-tx-rate, for the VMM too
} J = {.uid = -1, .gid = -1};

static pid_t child_pid, helper_pid;

[[noreturn]] static void die(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf - 1, fmt, ap);
    va_end(ap);
    if (n < 0)
        n = 0;
    if ((size_t)n > sizeof buf - 2)
        n = (int)sizeof buf - 2;
    buf[n++] = '\n';
    (void)!write(2, "microvm-jail: ", 14);
    (void)!write(2, buf, (size_t)n);
    _exit(JAIL_ERR);
}

[[noreturn]] static void die_errno(const char *what, const char *arg)
{
    die("%s%s%s: %s", what, arg ? " " : "", arg ? arg : "", strerror(errno));
}

static void usage(void)
{
    die("usage: microvm-jail [--uid N --gid N] [--base FILE] [--cgroup DIR [--mem-max BYTES] [--pids-max N] "
        "[--cpu-max \"QUOTA PERIOD\"] [--cpu-weight N]] [--bind SRC:DST[:rw]]... "
        "[--net [--net-allow CIDR]... [--net-dns ADDR]... [--net-deny-all] [--net-only] [--net-deny-port PORT]... "
        "[--net-flow-rate N] [--net-max-dests N] [--net-tx-rate BYTES]] -- VMM [ARG...]\n"
        "       microvm-jail --make-base FILE\n"
        "       microvm-jail --version");
}

static long parse_id(const char *s)
{
    char *end;
    errno = 0;
    const long v = strtol(s, &end, 10);
    if (errno || end == s || *end || v < 1 || v > 0x7ffffffe)
        die("bad id '%s' (1..2147483646; 0 is root)", s);
    return v;
}

// A value written to a cgroup file: digits, spaces and "max" only.
static const char *cg_value(const char *s)
{
    if (!*s || strlen(s) > 64)
        die("bad cgroup value '%s'", s);
    for (const char *p = s; *p; p++)
        if (!((*p >= '0' && *p <= '9') || *p == ' ' || *p == 'm' || *p == 'a' || *p == 'x'))
            die("bad cgroup value '%s'", s);
    return s;
}

// Absolute, and no empty, "." or ".." components.
static bool path_clean(const char *p)
{
    if (p[0] != '/' || strlen(p) >= 256)
        return false;
    for (const char *c = p + 1;;) {
        const char *e = strchr(c, '/');
        const size_t n = e ? (size_t)(e - c) : strlen(c);
        if (n == 0 || (n == 1 && c[0] == '.') || (n == 2 && c[0] == '.' && c[1] == '.'))
            return false;
        if (!e)
            return true;
        c = e + 1;
    }
}

// A --bind DST: clean, and not a path the jail itself provides.
static bool jail_path_ok(const char *p)
{
    if (!path_clean(p))
        return false;
    static const char *const reserved[] = {"/microvm", "/dev", "/proc"};
    for (size_t i = 0; i < sizeof reserved / sizeof *reserved; i++) {
        const size_t n = strlen(reserved[i]);
        if (!strncmp(p, reserved[i], n) && (p[n] == 0 || p[n] == '/'))
            return false;
    }
    return true;
}

static void parse_bind(char *arg)
{
    if (J.nbinds == MAX_BINDS)
        die("too many --bind (max %d)", MAX_BINDS);
    bind_spec *b = &J.binds[J.nbinds++];
    char *c1 = strchr(arg, ':');
    if (!c1 || c1 == arg)
        die("bad --bind '%s' (SRC:DST[:rw])", arg);
    *c1 = 0;
    char *dst = c1 + 1, *c2 = strchr(dst, ':');
    if (c2) {
        if (strcmp(c2 + 1, "rw"))
            die("bad --bind mode '%s' (only :rw)", c2 + 1);
        *c2 = 0;
        b->rw = true;
    }
    if (!jail_path_ok(dst))
        die("bad --bind destination '%s' (absolute, no . or .., not /microvm, /dev or /proc)", dst);
    // Equal or nested destinations are refused: the mount point for the
    // inner one would be created inside the outer bind, i.e. on the host.
    for (int i = 0; i < J.nbinds - 1; i++) {
        const char *o = J.binds[i].dst;
        const size_t lo = strlen(o), ld = strlen(dst), m = lo < ld ? lo : ld;
        if (!strncmp(o, dst, m) && (lo == ld || (lo < ld ? dst[m] : o[m]) == '/'))
            die("--bind destinations '%s' and '%s' overlap", o, dst);
    }
    b->src = arg;
    b->dst = dst;
}

static void parse_args(int argc, char **argv)
{
    int i = 1;
    for (; i < argc; i++) {
        const char *a = argv[i];
        const bool val = i + 1 < argc;
        if (!strcmp(a, "--"))
            break;
        if (!strcmp(a, "--version")) {
            printf("microvm-jail %s\n", MICROVM_VERSION);
            exit(0);
        }
        if (!strcmp(a, "--net")) {
            J.net = true;
            continue;
        }
        if (!strcmp(a, "--net-deny-all")) {
            J.net_policy_given = true;
            J.npol.deny_all = true;
            continue;
        }
        if (!strcmp(a, "--net-only")) {
            J.net_policy_given = true;
            J.npol.allow_only = true;
            continue;
        }
        if (!val)
            usage();
        if (!strcmp(a, "--uid"))
            J.uid = parse_id(argv[++i]);
        else if (!strcmp(a, "--gid"))
            J.gid = parse_id(argv[++i]);
        else if (!strcmp(a, "--cgroup"))
            J.cgroup = argv[++i];
        else if (!strcmp(a, "--base"))
            J.base = argv[++i];
        else if (!strcmp(a, "--mem-max"))
            J.mem_max = cg_value(argv[++i]);
        else if (!strcmp(a, "--pids-max"))
            J.pids_max = cg_value(argv[++i]);
        else if (!strcmp(a, "--cpu-max"))
            J.cpu_max = cg_value(argv[++i]);
        else if (!strcmp(a, "--cpu-weight"))
            J.cpu_weight = cg_value(argv[++i]);
        else if (!strcmp(a, "--bind"))
            parse_bind(argv[++i]);
        else if (!strcmp(a, "--net-allow")) {
            J.net_policy_given = true;
            if (net_policy_allow(&J.npol, argv[++i]))
                die("bad --net-allow '%s' (ADDR[/BITS][,PORT], at most %d)", argv[i], NET_MAX_ALLOW);
        } else if (!strcmp(a, "--net-dns")) {
            J.net_policy_given = true;
            if (net_policy_dns(&J.npol, argv[++i]))
                die("bad --net-dns '%s' (ADDR, IPV4:PORT or [IPV6]:PORT, at most %d)", argv[i], NET_MAX_DNS);
        } else if (!strcmp(a, "--net-deny-port")) {
            J.net_policy_given = true;
            if (net_policy_deny_port(&J.npol, argv[++i]))
                die("bad --net-deny-port '%s' (1-65535, at most %d)", argv[i], NET_MAX_DENY_PORTS);
        } else if (!strcmp(a, "--net-flow-rate") || !strcmp(a, "--net-max-dests")) {
            J.net_policy_given = true;
            const bool rate = a[6] == 'f';
            uint64_t v;
            if (net_policy_number(argv[++i], rate ? 1000000 : NET_MAX_DESTS, &v))
                die("bad %s '%s' (1 to %u)", a, argv[i], rate ? 1000000u : NET_MAX_DESTS);
            *(rate ? &J.npol.flow_rate : &J.npol.max_dests) = (uint32_t)v;
        } else if (!strcmp(a, "--net-tx-rate")) {
            J.net_policy_given = true;
            J.tx_rate = argv[++i];
            if (net_policy_number(J.tx_rate, NET_MAX_TX_RATE, &J.npol.tx_rate))
                die("bad --net-tx-rate '%s' (bytes a second, 1 to %llu)", J.tx_rate,
                    (unsigned long long)NET_MAX_TX_RATE);
        } else
            usage();
    }
    if (i + 1 >= argc)
        usage();
    J.vmm_argv = argv + i + 1;
    if (J.net_policy_given && !J.net)
        die("--net-allow, --net-dns, --net-deny-all and the network limits need --net");
    // The VMM's own network options (up to its "--", where the guest's
    // command starts): its helper would sit in the VM's empty network
    // namespace, and a policy given to it would not be the helper's.
    for (char **a = J.vmm_argv + 1; *a && strcmp(*a, "--"); a++)
        if (!strncmp(*a, "--net", 5))
            die("VMM option '%s': give --net and its options to microvm-jail instead", *a);
    J.root = geteuid() == 0;
    if (J.root && (J.uid < 0 || J.gid < 0))
        die("running as root: --uid and --gid are required (the VM's own host identity)");
    if (!J.root && (J.uid >= 0 || J.gid >= 0) &&
        ((uid_t)J.uid != getuid() || (gid_t)J.gid != getgid()))
        die("--uid/--gid need root (without it the VM keeps the caller's ids)");
    if (J.base && !J.root)
        die("--base needs root");
    if (J.base && J.base[0] != '/')
        die("bad --base '%s' (an absolute path)", J.base);
    if ((J.mem_max || J.pids_max || J.cpu_max || J.cpu_weight) && !J.cgroup)
        die("limits need --cgroup");
    if (J.cgroup && !path_clean(J.cgroup))
        die("bad --cgroup '%s' (an absolute path, no . or ..)", J.cgroup);
    int n = 0;
    while (J.vmm_argv[n])
        n++;
    if (n > 254)
        die("too many VMM arguments");
}

static void write_file(const char *dir, const char *name, const char *val)
{
    char path[PATH_MAX_JAIL];
    if (snprintf(path, sizeof path, "%s%s%s", dir, name ? "/" : "", name ? name : "") >= (int)sizeof path)
        die("path too long");
    const int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        die_errno("open", path);
    const size_t n = strlen(val);
    if (write(fd, val, n) != (ssize_t)n)
        die_errno("write", path);
    if (close(fd))
        die_errno("close", path);
}

// One limit: VAL if given; on a reused cgroup the default otherwise, so it
// ends up as a new one would be (a file whose controller is off is skipped).
static void set_limit(const char *name, const char *val, const char *dflt, bool reuse)
{
    if (val) {
        write_file(J.cgroup, name, val);
        return;
    }
    if (!reuse)
        return;
    char path[PATH_MAX_JAIL];
    snprintf(path, sizeof path, "%s/%s", J.cgroup, name);
    if (access(path, F_OK) == 0)
        write_file(J.cgroup, name, dflt);
}

// The VM's cgroup, with its limits; returns an fd for clone3(). Nothing is
// moved into it: the VM's first process is created there
// (CLONE_INTO_CGROUP). Moving a running process in instead (writing
// cgroup.procs) waits for an RCU grace period: ~27 ms per VM.
//
// DIR is created, or reused if it exists and is empty: creating a cgroup
// takes the global cgroup_mutex, and with many VMs starting at once that
// costs several ms each, so a service can make them ahead of time.
static int setup_cgroup(void)
{
    // Owned by whoever runs the jail, not the VM: owning it would let the VM
    // make sub-cgroups (it can't reach cgroupfs anyway: nothing mounts it).
    bool reuse = false;
    if (mkdir(J.cgroup, 0755)) {
        if (errno != EEXIST)
            die_errno("mkdir", J.cgroup);
        char path[PATH_MAX_JAIL], ev[256] = {0};
        snprintf(path, sizeof path, "%s/cgroup.events", J.cgroup);
        const int efd = open(path, O_RDONLY | O_CLOEXEC);
        const ssize_t n = efd >= 0 ? read(efd, ev, sizeof ev - 1) : -1;
        if (efd >= 0)
            close(efd);
        if (n <= 0 || strncmp(ev, "populated 0\n", 12))
            die("--cgroup %s exists and is in use (or is not a cgroup)", J.cgroup);
        reuse = true;
    }
    set_limit("memory.max", J.mem_max, "max", reuse);
    set_limit("memory.swap.max", J.mem_max ? "0" : nullptr, "max", reuse);
    set_limit("pids.max", J.pids_max, "max", reuse);
    set_limit("cpu.max", J.cpu_max, "max", reuse);
    set_limit("cpu.weight", J.cpu_weight, "100", reuse);
    const int fd = open(J.cgroup, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        die_errno("open", J.cgroup);
    return fd;
}

// clone3() as fork(): the child returns 0 on a copy of this stack.
struct clone_args_v2 {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls, set_tid,
        set_tid_size, cgroup;
};
#ifndef CLONE_INTO_CGROUP
#  define CLONE_INTO_CGROUP 0x200000000ULL
#endif

static pid_t spawn_vm(int cgroup_fd)
{
    struct clone_args_v2 ca = {
        .flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS |
                 (cgroup_fd >= 0 ? CLONE_INTO_CGROUP : 0),
        .exit_signal = SIGCHLD,
        .cgroup = cgroup_fd >= 0 ? (uint64_t)cgroup_fd : 0,
    };
    return (pid_t)syscall(SYS_clone3, &ca, sizeof ca);
}

// One of the new user namespace's id files. EACCES or EPERM here is most
// likely the AppArmor restriction (kernel.apparmor_restrict_unprivileged_userns,
// on by default on Ubuntu 24.04): unshare(CLONE_NEWUSER) succeeds, but the
// namespace gets no capabilities, so these writes are refused.
static void write_userns_file(const char *path, const char *val)
{
    int err = 0;
    const int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        err = errno;
    } else {
        const size_t n = strlen(val);
        if (write(fd, val, n) != (ssize_t)n)
            err = errno ? errno : EIO;
        if (close(fd) && !err)
            err = errno;
    }
    if (!err)
        return;
    if (err == EACCES || err == EPERM)
        die("%s: %s (on Ubuntu this is usually the AppArmor user namespace restriction: "
            "kernel.apparmor_restrict_unprivileged_userns=1)",
            path, strerror(err));
    errno = err;
    die_errno("write", path);
}

static void enter_userns(void)
{
    const uid_t uid = getuid();
    const gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER))
        die_errno("unshare(CLONE_NEWUSER)", nullptr);
    char map[64];
    write_userns_file("/proc/self/setgroups", "deny");
    snprintf(map, sizeof map, "%u %u 1", (unsigned)uid, (unsigned)uid);
    write_userns_file("/proc/self/uid_map", map);
    snprintf(map, sizeof map, "%u %u 1", (unsigned)gid, (unsigned)gid);
    write_userns_file("/proc/self/gid_map", map);
}

static void mkdirs(char *path) // under NEWROOT, every component we create is ours
{
    for (char *p = path + strlen(NEWROOT) + 1; (p = strchr(p, '/')); p++) {
        *p = 0;
        if (mkdir(path, 0755) && errno != EEXIST)
            die_errno("mkdir", path);
        *p = '/';
    }
}

// A bind is taken in two steps. First, while every host path is still
// reachable, a detached copy of the source's mount (open_tree) with its
// flags set (mount_setattr only adds flags, so whatever the source has
// locked, nosuid or nodev say, stays). Then, once the new root exists, the
// copy is moved onto its mount point there.
typedef struct {
    int fd;
    bool dir;
    const char *dst;
} tree;

static tree take(const char *src, const char *dst, uint64_t attrs)
{
    const int fd = open_tree(AT_FDCWD, src, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    if (fd < 0)
        die_errno("open_tree", src);
    struct mount_attr ma = {.attr_set = attrs | MOUNT_ATTR_NOSUID};
    if (mount_setattr(fd, "", AT_EMPTY_PATH, &ma, sizeof ma))
        die_errno("mount_setattr", src);
    struct stat st;
    if (fstat(fd, &st))
        die_errno("stat", src);
    return (tree){.fd = fd, .dir = S_ISDIR(st.st_mode), .dst = dst};
}

static void place(const tree *t)
{
    char path[PATH_MAX_JAIL];
    if (snprintf(path, sizeof path, "%s%s", NEWROOT, t->dst) >= (int)sizeof path)
        die("path too long");
    mkdirs(path);
    if (t->dir) {
        if (mkdir(path, 0755) && errno != EEXIST)
            die_errno("mkdir", path);
    } else {
        const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0444);
        if (fd < 0)
            die_errno("create", path);
        close(fd);
    }
    if (move_mount(t->fd, "", AT_FDCWD, path, MOVE_MOUNT_F_EMPTY_PATH))
        die_errno("move_mount", t->dst);
    close(t->fd);
}

#ifdef __SANITIZE_ADDRESS__
// ASan builds only. The release VMM is a static PIE and needs nothing but
// itself; an ASan one can't be static (libasan needs the dynamic libc), so
// without its loader and libraries execve() of /microvm fails with ENOENT.
// The host's library directories go in read-only (not noexec: the loader
// maps them executable). A symlink like Debian's /lib -> usr/lib is
// followed, so the directory lands at the path the loader looks in.
static const char *const LIB_DIRS[] = {"/lib", "/lib64", "/usr/lib", "/usr/lib64"};
#endif

static tree t[MAX_BINDS + 2 + 4];
static int nt;

// Everything the new root will hold, taken from the host's view.
static void take_all(void)
{
#ifdef __SANITIZE_ADDRESS__
    for (size_t i = 0; i < sizeof LIB_DIRS / sizeof LIB_DIRS[0]; i++)
        if (!access(LIB_DIRS[i], F_OK))
            t[nt++] = take(LIB_DIRS[i], LIB_DIRS[i], MOUNT_ATTR_RDONLY | MOUNT_ATTR_NODEV);
#endif
    t[nt++] = take(J.vmm_argv[0], "/microvm", MOUNT_ATTR_RDONLY | MOUNT_ATTR_NODEV);
    if (J.have_kvm)
        t[nt++] = take("/dev/kvm", "/dev/kvm", MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC);
    for (int i = 0; i < J.nbinds; i++)
        t[nt++] = take(J.binds[i].src, J.binds[i].dst,
                       (J.binds[i].rw ? 0 : MOUNT_ATTR_RDONLY) | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODEV);
}

// In the child, pid 1 of the new PID namespace: build the root and switch.
// With --base the trees were taken before joining the base (whose only
// mount is its empty root); otherwise the host's mounts are still here.
static void build_root(void)
{
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr))
        die_errno("make mounts private", nullptr);
    if (!J.base)
        take_all();
    if (mount("microvm", NEWROOT, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
              "size=64k,nr_inodes=256,mode=0755"))
        die_errno("mount tmpfs on", NEWROOT);
    for (int i = 0; i < nt; i++)
        place(&t[i]);
    // procfs for this PID namespace: /proc/self for the VMM's own use
    // (statm, pagemap), and no other process to see. Mounted while the
    // host's /proc is still visible, as a user namespace requires.
    char proc[64];
    snprintf(proc, sizeof proc, "%s/proc", NEWROOT);
    if (mkdir(proc, 0555))
        die_errno("mkdir", proc);
    const unsigned long pf = MS_NOSUID | MS_NODEV | MS_NOEXEC;
    if (mount("proc", proc, "proc", pf, "subset=pid,hidepid=invisible") &&
        mount("proc", proc, "proc", pf, nullptr)) // kernels before 5.8
        die_errno("mount proc", nullptr);
    // The new root replaces the old one, which is detached: nothing of the
    // host's filesystem (or of the base) stays reachable.
    if (chdir(NEWROOT) || syscall(SYS_pivot_root, ".", "."))
        die_errno("pivot_root", nullptr);
    if (umount2(".", MNT_DETACH) || chdir("/"))
        die_errno("detach the old root", nullptr);
    if (mount(nullptr, "/", nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
              nullptr))
        die_errno("make the root read-only", nullptr);
}

static void drop_bounding_set(void)
{
    for (int cap = 0; cap < 64; cap++)
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) && errno != EINVAL)
            die_errno("PR_CAPBSET_DROP", nullptr);
}

static void drop_all_caps(void)
{
    struct __user_cap_header_struct h = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct d[2] = {0};
    if (syscall(SYS_capset, &h, d))
        die_errno("capset", nullptr);
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) && errno != EINVAL)
        die_errno("clear ambient capabilities", nullptr);
}

// Root mode: become the VM's identity. setresuid() away from 0 clears the
// capability sets; the bounding set goes first, while CAP_SETPCAP is held.
static void become_vm_user(bool with_kvm_group)
{
    drop_bounding_set();
    const gid_t groups[1] = {J.kvm_gid};
    if (setgroups(with_kvm_group && J.have_kvm ? 1 : 0, groups))
        die_errno("setgroups", nullptr);
    if (setresgid((gid_t)J.gid, (gid_t)J.gid, (gid_t)J.gid) ||
        setresuid((uid_t)J.uid, (uid_t)J.uid, (uid_t)J.uid))
        die_errno("drop to the VM's uid/gid", nullptr);
    uid_t r, e, s;
    if (getresuid(&r, &e, &s) || r != (uid_t)J.uid || e != r || s != r || geteuid() == 0)
        die("still privileged after setresuid");
}

static void forward(int sig)
{
    (void)sig;
    if (child_pid > 0)
        kill(child_pid, SIGKILL);
    if (helper_pid > 0)
        kill(helper_pid, SIGKILL);
}

// The helper's root: an empty read-only tmpfs, the old root detached. With
// --base the mount namespace is already a copy of one (nothing else in it).
static void empty_root(void)
{
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr))
        die_errno("make mounts private", nullptr);
    if (J.base)
        return;
    if (mount("microvm-net", NEWROOT, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k,nr_inodes=4,mode=0555"))
        die_errno("mount tmpfs on", NEWROOT);
    if (chdir(NEWROOT) || syscall(SYS_pivot_root, ".", "."))
        die_errno("pivot_root", nullptr);
    if (umount2(".", MNT_DETACH) || chdir("/"))
        die_errno("detach the old root", nullptr);
    if (mount(nullptr, "/", nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
              nullptr))
        die_errno("make the root read-only", nullptr);
}

// --net: the network helper (net_helper.h). In the VM's cgroup and in new
// mount, PID, IPC, UTS (and cgroup) namespaces, with the VM's identity
// minus /dev/kvm's group; only the network namespace stays the host's. It
// keeps nothing but CHAN (its end of the channel) and fds 0-2, and enters
// its own sandbox (seccomp, Landlock, rlimits) before reading a request.
// It exits when the VMM's end closes, and dies with the jail.
static pid_t spawn_helper(int cgroup_fd, int chan, int vmm_end)
{
    struct clone_args_v2 ca = {
        .flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS |
                 (cgroup_fd >= 0 ? CLONE_INTO_CGROUP : 0),
        .exit_signal = SIGCHLD,
        .cgroup = cgroup_fd >= 0 ? (uint64_t)cgroup_fd : 0,
    };
    const pid_t pid = (pid_t)syscall(SYS_clone3, &ca, sizeof ca);
    if (pid)
        return pid;
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    close(vmm_end);
    if (cgroup_fd >= 0)
        close(cgroup_fd);
    for (int i = 0; i < nt; i++) // --base: the VM's trees, taken already
        close(t[i].fd);
    if (J.cgroup && unshare(CLONE_NEWCGROUP))
        die_errno("unshare(CLONE_NEWCGROUP)", nullptr);
    if (sethostname("microvm", 7))
        die_errno("sethostname", nullptr);
    empty_root();
    if (J.root) {
        become_vm_user(false);
    } else {
        drop_bounding_set();
        drop_all_caps();
    }
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        die_errno("prctl", nullptr);
    net_helper_main(chan, &J.npol); // closes every other fd, then sandboxes itself
}

// --make-base FILE: a mount namespace whose whole tree is one empty
// read-only tmpfs (with NEWROOT to mount on), pinned by a bind mount of its
// nsfs file on FILE. A child builds it; this process, still in the host's
// namespace, pins it.
static int make_base(const char *file)
{
    if (geteuid() != 0)
        die("--make-base needs root");
    if (file[0] != '/')
        die("bad --make-base '%s' (an absolute path)", file);
    int ready[2], done[2];
    if (pipe2(ready, O_CLOEXEC) || pipe2(done, O_CLOEXEC))
        die_errno("pipe", nullptr);
    const pid_t pid = fork();
    if (pid < 0)
        die_errno("fork", nullptr);
    if (pid == 0) {
        close(ready[0]);
        close(done[1]); // so the parent closing its end reads as EOF here
        if (unshare(CLONE_NEWNS) || mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr))
            die_errno("new mount namespace", nullptr);
        if (mount("microvm-base", NEWROOT, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                  "size=4k,nr_inodes=8,mode=0755"))
            die_errno("mount tmpfs on", NEWROOT);
        char sub[64];
        snprintf(sub, sizeof sub, "%s%s", NEWROOT, NEWROOT);
        if (mkdir(sub, 0755))
            die_errno("mkdir", sub);
        if (chdir(NEWROOT) || syscall(SYS_pivot_root, ".", ".") || umount2(".", MNT_DETACH) || chdir("/"))
            die_errno("switch to the base root", nullptr);
        if (mount(nullptr, "/", nullptr, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                  nullptr))
            die_errno("make the base read-only", nullptr);
        char c = 0;
        if (write(ready[1], &c, 1) != 1 || read(done[0], &c, 1) < 0)
            _exit(JAIL_ERR);
        _exit(0);
    }
    close(ready[1]);
    close(done[0]);
    char c;
    if (read(ready[0], &c, 1) != 1) { // the child failed (and said why)
        int st;
        waitpid(pid, &st, 0);
        return WIFEXITED(st) && WEXITSTATUS(st) ? WEXITSTATUS(st) : JAIL_ERR;
    }
    // Fails if FILE exists: a pinned base is dropped with umount, then rm.
    const int fd = open(file, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        die_errno("create", file);
    close(fd);
    char ns[64];
    snprintf(ns, sizeof ns, "/proc/%d/ns/mnt", (int)pid);
    if (mount(ns, file, nullptr, MS_BIND, nullptr)) {
        const int e = errno;
        unlink(file);
        if (e == EINVAL)
            die("pin %s: %s (is its mount shared? mount --bind D D; mount --make-private D)", file,
                strerror(e));
        errno = e;
        die_errno("pin", file);
    }
    close(done[1]);
    int st;
    waitpid(pid, &st, 0);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--make-base"))
        return make_base(argv[2]);
    parse_args(argc, argv);
    struct stat kst;
    J.have_kvm = stat("/dev/kvm", &kst) == 0 && S_ISCHR(kst.st_mode);
    J.kvm_gid = J.have_kvm ? kst.st_gid : 0;
    if (access(J.vmm_argv[0], X_OK))
        die_errno("VMM", J.vmm_argv[0]);

    const int cgroup_fd = J.cgroup ? setup_cgroup() : -1;
    if (!J.root)
        enter_userns();

    // Signals that end the VM: set before the fork so none is missed.
    struct sigaction sa = {.sa_handler = forward};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);

#ifdef __SANITIZE_ADDRESS__
    // ASan builds only. LeakSanitizer's end-of-process check stops the
    // world by way of /proc/self/task, which this process loses below: a
    // base has no /proc, and becoming the VM's uid makes it non-dumpable,
    // so /proc/self is root's. The check then fails, and with it the
    // VMM's exit status. Check now instead; this turns the exit check off.
    __lsan_do_leak_check();
#endif

    // With a base: take the VM's files while the host's paths are visible,
    // then join the base, so the child's mount namespace is a copy of it.
    // This process's root moves into the base too; it needs no files.
    if (J.base) {
        take_all();
        const int nsfd = open(J.base, O_RDONLY | O_CLOEXEC);
        if (nsfd < 0)
            die_errno("open --base", J.base);
        if (setns(nsfd, CLONE_NEWNS))
            die_errno("setns --base (made with --make-base?)", J.base);
        close(nsfd);
    }

    // --net: the helper first, so the VM's process starts with its channel.
    // The host's resolver is read now: the helper's root has no files.
    int chan[2] = {-1, -1}; // [0] the VMM's end, [1] the helper's
    if (J.net) {
        net_policy_host_dns(&J.npol);
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, chan))
            die_errno("socketpair", nullptr);
        helper_pid = spawn_helper(cgroup_fd, chan[1], chan[0]);
        if (helper_pid < 0)
            die_errno("clone3 (network helper)", nullptr);
    }

    // The VM's first process: in its cgroup and its own mount, PID,
    // network, IPC and UTS namespaces from the start.
    child_pid = spawn_vm(cgroup_fd);
    if (child_pid < 0) {
        const int e = errno;
        if (helper_pid > 0)
            kill(helper_pid, SIGKILL);
        errno = e;
        die_errno("clone3", nullptr);
    }
    if (child_pid == 0) {
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        if (J.net)
            close(chan[1]);
        // A cgroup namespace rooted at the VM's cgroup (clone3 would root it
        // at the jail's), so the VM doesn't learn even the cgroup's name.
        if (J.cgroup && unshare(CLONE_NEWCGROUP))
            die_errno("unshare(CLONE_NEWCGROUP)", nullptr);
        if (sethostname("microvm", 7))
            die_errno("sethostname", nullptr);
        build_root();
        if (J.root) {
            become_vm_user(true);
        } else {
            drop_bounding_set();
            drop_all_caps();
        }
        // After the last credential change, which clears it.
        if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
            die_errno("prctl", nullptr);
        // Only fds 0-2, and with --net the helper's channel as fd 3 (dup2
        // clears its close-on-exec flag).
        if (J.net && (chan[0] == 3 ? fcntl(3, F_SETFD, 0) : dup2(chan[0], 3)) < 0)
            die_errno("dup2", nullptr);
        if (syscall(SYS_close_range, J.net ? 4u : 3u, ~0u, 0u))
            die_errno("close_range", nullptr);
        // Whatever the VMM creates (the vsock socket in a :rw bind, a
        // snapshot) is the VM's uid's alone.
        umask(077);
        char *vargv[262];
        int n = 0;
        vargv[n++] = (char *)"/microvm";
        if (J.net) {
            vargv[n++] = (char *)"--net-fd";
            vargv[n++] = (char *)"3";
        }
        if (J.tx_rate) {
            vargv[n++] = (char *)"--net-tx-rate";
            vargv[n++] = (char *)J.tx_rate;
        }
        for (char **a = J.vmm_argv + 1; *a; a++) // at most 254 (parse_args)
            vargv[n++] = *a;
        vargv[n] = nullptr;
        char *envp[] = {nullptr};
        execve("/microvm", vargv, envp);
        die_errno("exec", J.vmm_argv[0]);
    }

    // The waiter: no privileges either, just the child's exit status.
    if (J.root)
        become_vm_user(false);
    else
        drop_all_caps();
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        die_errno("prctl", nullptr);
    syscall(SYS_close_range, 3u, ~0u, 0u); // the channel's ends too: the helper sees EOF when the VMM goes
    int st;
    while (waitpid(child_pid, &st, 0) < 0)
        if (errno != EINTR)
            die_errno("waitpid", nullptr);
    if (helper_pid > 0) {
        kill(helper_pid, SIGKILL);
        while (waitpid(helper_pid, nullptr, 0) < 0 && errno == EINTR)
            ;
    }
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    return WIFSIGNALED(st) ? 128 + WTERMSIG(st) : JAIL_ERR;
}
