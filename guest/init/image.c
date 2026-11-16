// SPDX-License-Identifier: MIT
// Container images in the guest: part of /init, freestanding like init.c.
//
// enter_root() makes the root filesystem a container expects:
// - the image (/dev/pmem0, read-only EROFS) with a tmpfs layer on top
//   (overlayfs), so the root is writable as under Docker. Writes live in
//   guest RAM and are gone when the VM ends; the image is never written.
//   An image in layers (the VMM's --rootfs given more than once) is
//   /dev/pmem0 (the bottom), pmem1, ... each EROFS, stacked in that order
//   under the tmpfs; an upper layer's whiteouts (0/0 character devices)
//   hide what is below them;
// - /proc, /sys (read-only, if the kernel has it), and a /dev of its own: null, zero, full,
//   random, urandom, tty, a private devpts with ptmx, /dev/shm, and the
//   fd links. None of the VM's own devices (pmem, vsock, the console)
//   appear there;
// - the hostname, /etc/hostname and /etc/hosts, and /etc/resolv.conf when
//   the VM has a network (the address the kernel was given with ip=).
//
// image_load() reads /.microvm/image-config, which microvm-mkrootfs writes
// from the OCI image config (IMAGES.md has the format), and image_exec()
// runs a command the way Docker runs it: Entrypoint, then the caller's
// arguments or else Cmd; the image's Env plus PATH, HOSTNAME and HOME;
// WorkingDir (created if missing); then User's groups, gid and uid. An
// image without the file (a bare tar layer) runs the caller's command as
// root in /, as before.
//
// The image is the guest's own data: a malformed config can only break
// this guest, never reach the host. Still, every limit is checked, so a
// bad image fails with a message instead of misbehaving.
#include "init.h"

typedef unsigned long u64;
typedef unsigned int u32;

static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
    long r;
    register long r10 __asm__("r10") = d, r8 __asm__("r8") = e, r9 __asm__("r9") = f;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return r;
}

static long sys3(long n, long a, long b, long c) { return sys6(n, a, b, c, 0, 0, 0); }

enum {
    SYS_read = 0, SYS_write = 1, SYS_open = 2, SYS_close = 3, SYS_fstat = 5, SYS_mmap = 9, SYS_nanosleep = 35,
    SYS_chdir = 80, SYS_mkdir = 83, SYS_unlink = 87, SYS_symlink = 88, SYS_umask = 95,
    SYS_setgroups = 116, SYS_setresuid = 117, SYS_setresgid = 119, SYS_mknod = 133,
    SYS_chroot = 161, SYS_mount = 165, SYS_umount2 = 166, SYS_sethostname = 170,
};
enum {
    O_RDONLY = 0, O_WRONLY = 1, O_CREAT = 0100, O_EXCL = 0200, O_NOFOLLOW = 0400000,
    O_DIRECTORY = 0200000, O_CLOEXEC = 02000000,
    MS_RDONLY = 1, MS_NOSUID = 2, MS_NODEV = 4, MS_NOEXEC = 8,
    PROT_RW = 3, MAP_PRIVATE_ANON = 0x22, S_IFCHR = 020000, S_IFBLK = 060000, MNT_DETACH = 2,
    EEXIST = 17, ENOMEM = 12, E2BIG = 7, ENODEV = 19,
};

// --- small helpers ---------------------------------------------------------

static u64 slen(const char *s)
{
    u64 n = 0;
    while (s[n])
        n++;
    return n;
}

static bool seq(const char *a, const char *b)
{
    while (*a && *a == *b)
        a++, b++;
    return *a == *b;
}

// "NAME=..." starts with `name` followed by '='.
static bool env_is(const char *e, const char *name)
{
    while (*name && *e == *name)
        e++, name++;
    return !*name && *e == '=';
}

// `word` followed by a space at s.
static bool env_is_word(const char *s, const char *word)
{
    while (*word && *s == *word)
        s++, word++;
    return !*word && *s == ' ';
}

static void *alloc(u64 n)
{
    const long p = sys6(SYS_mmap, 0, (long)((n + 4095) & ~4095ul), PROT_RW, MAP_PRIVATE_ANON, -1, 0);
    return p < 0 && p > -4096 ? nullptr : (void *)p;
}

// A whole small file into memory, NUL-terminated. nullptr if it isn't
// there or is bigger than `max` (err says which). Files that report no
// size (those in /proc) are read to their end, up to `max`.
static char *slurp(const char *path, u64 max, u64 *len, long *err)
{
    const long fd = sys3(SYS_open, (long)path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        *err = fd;
        return nullptr;
    }
    long st[18]; // struct stat: st_size at byte 48
    long r = sys3(SYS_fstat, fd, (long)st, 0);
    const u64 size = (u64)st[6], cap = size ? size : max;
    char *b = nullptr;
    if (r >= 0 && size > max)
        r = -E2BIG;
    if (r >= 0 && !(b = alloc(cap + 1)))
        r = -ENOMEM;
    u64 n = 0;
    while (r >= 0 && n < cap) {
        r = sys3(SYS_read, fd, (long)(b + n), (long)(cap - n));
        if (r == 0)
            break;
        if (r > 0)
            n += (u64)r;
    }
    sys3(SYS_close, fd, 0, 0);
    if (r < 0) {
        *err = r;
        return nullptr;
    }
    b[n] = 0;
    *len = n;
    return b;
}

// Replace a file (or symlink) at `path` with `text`, mode 0644.
static void put_file(const char *path, const char *text)
{
    sys3(SYS_unlink, (long)path, 0, 0);
    const long fd = sys3(SYS_open, (long)path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    long r = fd;
    if (fd >= 0) {
        r = sys3(SYS_write, fd, (long)text, (long)slen(text));
        sys3(SYS_close, fd, 0, 0);
    }
    if (r < 0)
        say("cannot write ", path, r);
}

// mkdir -p, as root, for the working directory.
static long mkdir_p(const char *path)
{
    char p[4096];
    const u64 n = slen(path);
    if (n >= sizeof p)
        return -E2BIG;
    for (u64 i = 0; i <= n; i++) {
        p[i] = path[i];
        if ((path[i] == '/' || !path[i]) && i > 0 && p[i - 1] != '/') {
            p[i] = 0;
            const long r = sys3(SYS_mkdir, (long)p, 0755, 0);
            if (r < 0 && r != -EEXIST)
                return r;
            p[i] = path[i];
        }
    }
    return 0;
}

// --- the root filesystem ---------------------------------------------------

static long mnt(const char *src, const char *dst, const char *type, long flags, const char *opts)
{
    return sys6(SYS_mount, (long)src, (long)dst, (long)type, flags, (long)opts, 0);
}

static void dev_node(const char *path, u32 major, u32 minor)
{
    const long r = sys3(SYS_mknod, (long)path, S_IFCHR | 0666, (long)(major << 8 | minor));
    if (r < 0 && r != -EEXIST)
        say("mknod ", path, r);
}

static void link_to(const char *target, const char *path)
{
    const long r = sys3(SYS_symlink, (long)target, (long)path, 0);
    if (r < 0 && r != -EEXIST)
        say("symlink ", path, r);
}

// The rest of a container's root, once inside the image. Problems with
// these are reported but not fatal: the command may not need them.
static void container_root(void)
{
    sys3(SYS_umask, 0, 0, 0);
    sys3(SYS_mkdir, (long)"/proc", 0555, 0);
    sys3(SYS_mkdir, (long)"/sys", 0555, 0);
    sys3(SYS_mkdir, (long)"/dev", 0755, 0);
    sys3(SYS_mkdir, (long)"/tmp", 01777, 0); // kept as the image has it, if it has one
    sys3(SYS_mkdir, (long)"/etc", 0755, 0);
    long r;
    if ((r = mnt("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr)) < 0)
        say("mount /proc", nullptr, r);
    // Not in the default kernel (config.fragment says why): no message then.
    if ((r = mnt("sysfs", "/sys", "sysfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr)) < 0 && r != -ENODEV)
        say("mount /sys", nullptr, r);
    if ((r = mnt("tmpfs", "/dev", "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=755,size=64k")) < 0) {
        say("mount /dev", nullptr, r);
    } else {
        dev_node("/dev/null", 1, 3);
        dev_node("/dev/zero", 1, 5);
        dev_node("/dev/full", 1, 7);
        dev_node("/dev/random", 1, 8);
        dev_node("/dev/urandom", 1, 9);
        dev_node("/dev/tty", 5, 0);
        sys3(SYS_mkdir, (long)"/dev/pts", 0755, 0);
        if ((r = mnt("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620,gid=5")) < 0)
            say("mount /dev/pts", nullptr, r);
        link_to("pts/ptmx", "/dev/ptmx");
        sys3(SYS_mkdir, (long)"/dev/shm", 01777, 0);
        if ((r = mnt("shm", "/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=1777")) < 0)
            say("mount /dev/shm", nullptr, r);
        link_to("/proc/self/fd", "/dev/fd");
        link_to("/proc/self/fd/0", "/dev/stdin");
        link_to("/proc/self/fd/1", "/dev/stdout");
        link_to("/proc/self/fd/2", "/dev/stderr");
    }
    sys3(SYS_umask, 022, 0, 0);

    static const char host[] = "microvm";
    sys3(SYS_sethostname, (long)host, sizeof host - 1, 0);
    put_file("/etc/hostname", "microvm\n");
    put_file("/etc/hosts", "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n127.0.1.1\tmicrovm\n");
    // With a network, the kernel's IP autoconfiguration (ip= on the command
    // line, from the VMM) lists the resolver in /proc/net/pnp, already in
    // resolv.conf's format.
    u64 n = 0;
    long err = 0;
    const char *pnp = slurp("/proc/net/pnp", 4096, &n, &err);
    // It starts with a "#MANUAL" comment: copy from the first nameserver on.
    for (const char *c = pnp; c && *c; c++)
        if ((c == pnp || c[-1] == '\n') && env_is_word(c, "nameserver")) {
            put_file("/etc/resolv.conf", c);
            break;
        }
}

int upper_dir = -1;
unsigned image_layers = 1;

// /dev/pmem0 .. pmem<n-1>, as the kernel numbered them. The initramfs has
// pmem0 as 259:0, right for one image; the kernel registers several
// asynchronously, so their minors needn't follow their names:
// /proc/partitions says ("major minor #blocks name" lines).
static long layer_nodes(unsigned n)
{
    sys3(SYS_mkdir, (long)"/proc", 0555, 0);
    long r = mnt("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr);
    if (r < 0) {
        say("mount /proc (for the image's layers)", nullptr, r);
        return r;
    }
    u32 maj[8] = {0}, min[8] = {0};
    unsigned found = 0;
    // Registered before /init runs, but give a late one 200 ms.
    for (int tries = 0; found != (1u << n) - 1 && tries < 200; tries++) {
        if (tries) {
            static const long ms[2] = {0, 1000000};
            sys3(SYS_nanosleep, (long)ms, 0, 0);
        }
        u64 len = 0;
        long err = 0;
        char *t = slurp("/proc/partitions", 16384, &len, &err);
        for (const char *c = t; c && *c;) {
            u32 v[2] = {0, 0};
            int k = 0;
            while (*c == ' ')
                c++;
            for (; k < 2 && *c >= '0' && *c <= '9'; k++) { // major, minor
                while (*c >= '0' && *c <= '9' && v[k] < 100000000)
                    v[k] = v[k] * 10 + (u32)(*c++ - '0');
                while (*c == ' ')
                    c++;
            }
            while (*c >= '0' && *c <= '9') // #blocks
                c++;
            while (*c == ' ')
                c++;
            const char *name = c;
            while (*c && *c != '\n')
                c++;
            if (k == 2 && c - name == 5 && name[0] == 'p' && name[1] == 'm' && name[2] == 'e' && name[3] == 'm' &&
                name[4] >= '0' && (unsigned)(name[4] - '0') < n) {
                const unsigned i = (unsigned)(name[4] - '0');
                maj[i] = v[0], min[i] = v[1], found |= 1u << i;
            }
            if (*c)
                c++;
        }
    }
    sys3(SYS_umount2, (long)"/proc", MNT_DETACH, 0);
    for (unsigned k = 0; k < n; k++) {
        char dev[] = "/dev/pmem0";
        dev[9] = (char)('0' + k);
        if (!(found & 1u << k)) {
            say("no such image layer: ", dev, -ENODEV);
            return -ENODEV;
        }
        sys3(SYS_unlink, (long)dev, 0, 0);
        const long devt = (long)((min[k] & 0xff) | (maj[k] & 0xfff) << 8 | (u64)(min[k] & ~0xffu) << 12);
        if ((r = sys3(SYS_mknod, (long)dev, S_IFBLK | 0400, devt)) < 0) {
            say("mknod ", dev, r);
            return r;
        }
    }
    return 0;
}

int enter_root(void)
{
    // The image's layers under /lower/0 (the bottom), 1, ..., a tmpfs for
    // the changes under /upper, all in the initramfs; the overlay of them
    // becomes the root. The layers are pmem0, 1, ...: the kernel names
    // them in the order the VMM placed them (image_layers, from its
    // "layersN" word; 1 without it).
    const unsigned nl = image_layers;
    sys3(SYS_mkdir, (long)"/lower", 0755, 0);
    sys3(SYS_mkdir, (long)"/upper", 0755, 0);
    long r = 0;
    if (nl > 1 && layer_nodes(nl))
        return 125;
    for (unsigned k = 0; k < nl; k++) {
        char dev[] = "/dev/pmem0", dir[] = "/lower/0";
        dev[9] = dir[7] = (char)('0' + k);
        sys3(SYS_mkdir, (long)dir, 0755, 0);
        if ((r = mnt(dev, dir, "erofs", MS_RDONLY, nullptr)) < 0) {
            say("mount (erofs) ", dev, r);
            return 125;
        }
    }
    // "lowerdir=/lower/N-1:...:/lower/0,upperdir=...": the top layer first.
    char opts[128] = "lowerdir=";
    unsigned o = 9;
    for (unsigned k = nl; k-- > 0;) {
        for (const char *c = "/lower/"; *c; c++)
            opts[o++] = *c;
        opts[o++] = (char)('0' + k);
        if (k)
            opts[o++] = ':';
    }
    for (const char *c = ",upperdir=/upper/data,workdir=/upper/work"; *c; c++)
        opts[o++] = *c;
    opts[o] = 0;
    if ((r = mnt("tmpfs", "/upper", "tmpfs", 0, "mode=755")) < 0 ||
        (r = sys3(SYS_mkdir, (long)"/upper/data", 0755, 0)) < 0 ||
        (r = sys3(SYS_mkdir, (long)"/upper/work", 0755, 0)) < 0 ||
        (r = mnt("overlay", "/rootfs", "overlay", 0, opts)) < 0) {
        say("cannot make the root filesystem writable (overlay on tmpfs)", nullptr, r);
        return 125;
    }
    // The changes, for EXPORT (sbx.c); out of reach of the root once in it.
    upper_dir = (int)sys3(SYS_open, (long)"/upper/data", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if ((r = sys3(SYS_chdir, (long)"/rootfs", 0, 0)) < 0 || (r = sys3(SYS_chroot, (long)".", 0, 0)) < 0 ||
        (r = sys3(SYS_chdir, (long)"/", 0, 0)) < 0) {
        say("cannot enter the root filesystem", nullptr, r);
        return 125;
    }
    container_root();
    return 0;
}

// --- the image config --------------------------------------------------------

enum { MAX_GROUPS = 32, CONFIG_MAX = 4u << 20 };

static struct {
    bool have;
    char **ep, **cmd, **env; // nullptr-terminated
    const char *workdir;
    u32 uid, gid, groups[MAX_GROUPS];
    int ngroups;
} img;

static bool dec_u32(const char *s, u32 *out)
{
    u64 v = 0;
    const char *p = s;
    for (; *p >= '0' && *p <= '9' && p - s < 10; p++)
        v = v * 10 + (u64)(*p - '0');
    if (p == s || *p || v > 0xfffffffeu) // -1 means "unchanged" to setresuid
        return false;
    *out = (u32)v;
    return true;
}

bool image_load(void)
{
    u64 n = 0;
    long err = 0;
    char *b = slurp("/.microvm/image-config", CONFIG_MAX, &n, &err);
    if (!b) {
        if (err == -2) // ENOENT: an image without a config
            return true;
        say("cannot read /.microvm/image-config", nullptr, err);
        return false;
    }
    if (!n || b[n - 1]) {
        say("/.microvm/image-config: not NUL-terminated strings", nullptr, 0);
        return false;
    }
    u64 strs = 0;
    for (u64 i = 0; i < n; i++)
        strs += !b[i];
    char **v = alloc(3 * (strs + 1) * sizeof(char *));
    if (!v) {
        say("/.microvm/image-config", nullptr, -ENOMEM);
        return false;
    }
    img.ep = v, img.cmd = v + strs + 1, img.env = v + 2 * (strs + 1);
    u64 nep = 0, ncmd = 0, nenv = 0;
    bool uid = false, gid = false;
    char *p = b, *end = b + n;
    char *magic = p;
    p += slen(p) + 1;
    char *ver = p < end ? p : (char *)"";
    if (!seq(magic, "microvm-image-config") || !seq(ver, "1")) {
        say("/.microvm/image-config: not format version 1 (rebuild the image with this microvm-mkrootfs)", nullptr, 0);
        return false;
    }
    p += slen(ver) + 1;
    while (p < end) {
        char *k = p;
        p += slen(p) + 1;
        if (p >= end) {
            say("/.microvm/image-config: a key without a value: ", k, 0);
            return false;
        }
        char *val = p;
        p += slen(p) + 1;
        bool ok = true;
        if (seq(k, "entrypoint"))
            img.ep[nep++] = val;
        else if (seq(k, "cmd"))
            img.cmd[ncmd++] = val;
        else if (seq(k, "env"))
            img.env[nenv++] = val;
        else if (seq(k, "workdir"))
            img.workdir = val;
        else if (seq(k, "uid"))
            ok = uid = dec_u32(val, &img.uid);
        else if (seq(k, "gid"))
            ok = gid = dec_u32(val, &img.gid);
        else if (seq(k, "group"))
            ok = img.ngroups < MAX_GROUPS && dec_u32(val, &img.groups[img.ngroups++]);
        // Other keys (digests, the User string) are for the host; unknown
        // ones are skipped, as the format requires.
        if (!ok) {
            say("/.microvm/image-config: bad value for ", k, 0);
            return false;
        }
    }
    if (!uid || !gid) {
        say("/.microvm/image-config: no uid or gid", nullptr, 0);
        return false;
    }
    img.ep[nep] = img.cmd[ncmd] = img.env[nenv] = nullptr;
    img.have = true;
    return true;
}

// HOME for uid from the image's /etc/passwd, or "/".
static const char *home_of(u32 uid)
{
    u64 n = 0;
    long err = 0;
    char *b = slurp("/etc/passwd", 1u << 20, &n, &err);
    for (char *line = b; line && *line;) {
        char *eol = line;
        while (*eol && *eol != '\n')
            eol++;
        const bool last = !*eol;
        *eol = 0;
        // name:pw:uid:gid:gecos:dir:shell
        char *f[7] = {line};
        int nf = 1;
        for (char *c = line; *c && nf < 7; c++)
            if (*c == ':')
                *c = 0, f[nf++] = c + 1;
        u32 u;
        if (nf >= 6 && dec_u32(f[2], &u) && u == uid && f[5][0])
            return f[5];
        if (last)
            break;
        line = eol + 1;
    }
    return "/";
}

static int count(char *const *v)
{
    int n = 0;
    while (v && v[n])
        n++;
    return n;
}

// ---- --env ---------------------------------------------------------------
// The VMM's limits (src/dev/devices.h).
enum { ENV_MAX = 1 << 20, ENV_MAX_STRINGS = 4096 };
static char **run_env; // NAME=VALUE (set) or NAME (unset), in order

bool env_read(void)
{
    unsigned char h[4] = {0};
    ctl_latch(1);
    ctl_read(h, sizeof h);
    const u64 n = (u64)h[0] | (u64)h[1] << 8 | (u64)h[2] << 16 | (u64)h[3] << 24;
    if (n > ENV_MAX) {
        say("--env: too long", nullptr, 0);
        return false;
    }
    char *b = alloc(n + 1);
    if (!b) {
        say("--env", nullptr, -ENOMEM);
        return false;
    }
    for (u64 i = 0; i < n; i += 4096) // map the pages: no fault inside rep insb
        ((volatile char *)b)[i] = 0;
    ctl_read(b, n);
    b[n] = 0;
    u64 strs = 0;
    for (u64 i = 0; i < n; i++)
        strs += !b[i];
    if ((n && b[n - 1]) || strs > ENV_MAX_STRINGS || !(run_env = alloc((strs + 1) * sizeof(char *)))) {
        say("--env: not NUL-terminated strings, or too many", nullptr, 0);
        return false;
    }
    u64 k = 0;
    for (char *p = b; p < b + n; p += slen(p) + 1)
        run_env[k++] = p;
    run_env[k] = nullptr;
    return true;
}

// The same variable: e is NAME=... or NAME, s's name is its first kl bytes.
static bool same_name(const char *e, const char *s, u64 kl)
{
    for (u64 i = 0; i < kl; i++)
        if (e[i] != s[i])
            return false;
    return e[kl] == '=' || !e[kl];
}

// add on top of envp[0..k): NAME=VALUE replaces NAME or is appended, a bare
// NAME removes it. Returns the new count.
static int env_apply(char **envp, int k, char *const *add)
{
    for (; add && *add; add++) {
        char *s = *add;
        u64 kl = 0;
        while (s[kl] && s[kl] != '=')
            kl++;
        int j = 0;
        while (j < k && !same_name(envp[j], s, kl))
            j++;
        if (s[kl] && j < k) {
            envp[j] = s;
        } else if (s[kl]) {
            envp[k++] = s;
        } else if (j < k) {
            for (k--; j < k; j++)
                envp[j] = envp[j + 1];
        }
    }
    return k;
}

char **image_env(void)
{
    static char *const ENV_ROOT[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOSTNAME=microvm",
        nullptr,
    };
    char *const *base = img.have ? img.env : ENV_ROOT;
    char **envp = alloc((u64)(count(base) + count(run_env) + 3) * sizeof(char *));
    if (!envp)
        return nullptr;
    int k = env_apply(envp, 0, base);
    k = env_apply(envp, k, run_env);
    bool path = false, host = false;
    for (int i = 0; i < k; i++) {
        path |= env_is(envp[i], "PATH");
        host |= env_is(envp[i], "HOSTNAME");
    }
    if (!path)
        envp[k++] = ENV_ROOT[0];
    if (!host)
        envp[k++] = ENV_ROOT[1];
    envp[k] = nullptr;
    return envp;
}

int image_exec(char **args)
{
    static char *const ENV_ROOT[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOSTNAME=microvm",
        "HOME=/root",
        nullptr,
    };
    // Environment: the image's (or, without a config, root's), then --env
    // on top, then what Docker adds when it is missing.
    char *const *base = img.have ? img.env : ENV_ROOT;
    char **envp = alloc((u64)(count(base) + count(run_env) + 4) * sizeof(char *));
    if (!envp) {
        say("exec", nullptr, -ENOMEM);
        return 125;
    }
    int k = env_apply(envp, 0, base);
    k = env_apply(envp, k, run_env);
    bool path = false, host = false, home = false;
    for (int i = 0; i < k; i++) {
        path |= env_is(envp[i], "PATH");
        host |= env_is(envp[i], "HOSTNAME");
        home |= env_is(envp[i], "HOME");
    }
    if (!path)
        envp[k++] = ENV_ROOT[0];
    if (!host)
        envp[k++] = ENV_ROOT[1];
    if (!img.have) {
        if (!home)
            envp[k++] = ENV_ROOT[2];
        envp[k] = nullptr;
        if (!args[0]) {
            say("no command given, and the image has no config to take one from", nullptr, 0);
            return 125;
        }
        return exec_env(args, envp);
    }
    // argv: Entrypoint, then the caller's arguments or else Cmd.
    char **rest = args[0] ? args : img.cmd;
    const int ne = count(img.ep), nr = count(rest);
    if (!ne && !nr) {
        say("the image has no Entrypoint or Cmd, and no command was given", nullptr, 0);
        return 125;
    }
    char **argv = alloc((u64)(ne + nr + 1) * sizeof(char *));
    if (!argv) {
        say("exec", nullptr, -ENOMEM);
        return 125;
    }
    for (int i = 0; i < ne; i++)
        argv[i] = img.ep[i];
    for (int i = 0; i < nr; i++)
        argv[ne + i] = rest[i];
    argv[ne + nr] = nullptr;
    static char home_var[4200];
    if (!home) {
        const char *h = home_of(img.uid);
        const u64 hl = slen(h);
        if (hl + 6 < sizeof home_var) {
            for (u64 i = 0; i < 5; i++)
                home_var[i] = "HOME="[i];
            for (u64 i = 0; i <= hl; i++)
                home_var[5 + i] = h[i];
            envp[k++] = home_var;
        }
    }
    envp[k] = nullptr;
    // WorkingDir: created (by root) if the image lacks it, as Docker does.
    long r;
    if (img.workdir && img.workdir[0] && (r = mkdir_p(img.workdir)) < 0) {
        say("cannot create the working directory ", img.workdir, r);
        return 125;
    }
    // User: groups, then gid, then uid; root's power ends here.
    if ((r = sys3(SYS_setgroups, img.ngroups, (long)img.groups, 0)) < 0 ||
        (r = sys3(SYS_setresgid, img.gid, img.gid, img.gid)) < 0 ||
        (r = sys3(SYS_setresuid, img.uid, img.uid, img.uid)) < 0) {
        say("cannot switch to the image's user", nullptr, r);
        return 125;
    }
    // Then the working directory, as that user (it may not be allowed in).
    const char *wd = img.workdir && img.workdir[0] ? img.workdir : "/";
    if ((r = sys3(SYS_chdir, (long)wd, 0, 0)) < 0) {
        say("cannot enter the working directory ", wd, r);
        return 125;
    }
    return exec_env(argv, envp);
}
