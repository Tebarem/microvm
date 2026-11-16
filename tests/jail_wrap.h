// SPDX-License-Identifier: MIT
// The end-to-end suites' --jail JAIL mode (Linux): every VM is started
// through microvm-jail, as production starts it. jw_wrap() turns a VMM
// command line into the jail's:
//   - the kernel and the image are bound read-only at /vmlinux and /rootfs;
//   - the suite's scratch directory is bound :rw at /work, and each VMM
//     argument naming a path in it (snapshot, vsock socket) is rewritten
//     to the same path under /work: the jail is the only way out of the
//     new root, so the host side keeps using the host path;
//   - --net, --net-allow, --net-dns and the limits go to the jail, which starts the
//     network helper outside the VM's network namespace;
//   - as root, the VM runs as uid and gid 65534 (the scratch directory must
//     be writable for it).
// Words after the VMM's own "--" (the guest's command) are left alone.
#pragma once

#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    const char *jail; // nullptr: run the VMM directly
    const char *vmm, *kernel, *rootfs, *dir;
} jw_cfg;

// Strings made for one command line: valid until the next jw_wrap().
static char jw_pool[48][192];
static int jw_npool;

static const char *jw_join(const char *a, const char *b)
{
    if (jw_npool == (int)(sizeof jw_pool / sizeof *jw_pool))
        return nullptr;
    char *s = jw_pool[jw_npool++];
    if (snprintf(s, sizeof *jw_pool, "%s%s", a, b) >= (int)sizeof *jw_pool)
        return nullptr;
    return s;
}

// ARGS: the VMM's arguments (after its path), nullptr-terminated. OUT gets
// the full command line, OUT[0] the program to exec. Returns 0 or -1.
static int jw_wrap(const jw_cfg *c, const char *const *args, const char **out, int cap)
{
    int n = 0;
    if (!c->jail) {
        out[n++] = c->vmm;
        for (int i = 0; args[i] && n < cap - 1; i++)
            out[n++] = args[i];
        out[n] = nullptr;
        return args[n - 1] ? -1 : 0;
    }
    jw_npool = 0;
    const char *vm[96];
    int nv = 0;
    out[n++] = c->jail;
    if (geteuid() == 0) {
        out[n++] = "--uid";
        out[n++] = "65534";
        out[n++] = "--gid";
        out[n++] = "65534";
    }
    out[n++] = "--bind";
    out[n++] = jw_join(c->kernel, ":/vmlinux");
    out[n++] = "--bind";
    out[n++] = jw_join(c->rootfs, ":/rootfs");
    out[n++] = "--bind";
    out[n++] = jw_join(c->dir, ":/work:rw");
    const size_t dl = strlen(c->dir);
    bool guest = false;
    for (int i = 0; args[i]; i++) {
        const char *a = args[i];
        if (n > cap - 8 || nv > 90)
            return -1;
        if (guest || !strcmp(a, "--")) {
            guest = true;
            vm[nv++] = a;
        } else if (!strcmp(a, "--net")) {
            out[n++] = a;
        } else if ((!strcmp(a, "--net-allow") || !strcmp(a, "--net-dns") || !strcmp(a, "--net-deny-port") ||
                    !strcmp(a, "--net-flow-rate") || !strcmp(a, "--net-max-dests") || !strcmp(a, "--net-tx-rate")) &&
                   args[i + 1]) {
            out[n++] = a;
            out[n++] = args[++i];
        } else if (!strcmp(a, c->kernel)) {
            vm[nv++] = "/vmlinux";
        } else if (!strcmp(a, c->rootfs)) {
            vm[nv++] = "/rootfs";
        } else if (!strncmp(a, c->dir, dl) && a[dl] == '/') {
            vm[nv++] = jw_join("/work", a + dl);
        } else {
            vm[nv++] = a;
        }
    }
    out[n++] = "--";
    out[n++] = c->vmm;
    for (int i = 0; i < nv; i++)
        out[n++] = vm[i];
    out[n] = nullptr;
    for (int i = 0; i < n; i++)
        if (!out[i])
            return -1; // a path too long for the pool
    return 0;
}

// The jail can run here: as root, or with unprivileged user namespaces.
static bool jw_usable(void)
{
    if (geteuid() == 0)
        return true;
    const pid_t pid = fork();
    if (pid == 0)
        _exit(unshare(CLONE_NEWUSER) ? 1 : 0);
    int st;
    return pid > 0 && waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

// Takes "--jail JAIL" out of argv (anywhere after argv[0]); returns JAIL or nullptr.
static const char *jw_take_arg(int *argc, char **argv)
{
    for (int i = 1; i + 1 < *argc; i++) {
        if (strcmp(argv[i], "--jail"))
            continue;
        const char *j = argv[i + 1];
        for (int k = i; k + 2 <= *argc; k++)
            argv[k] = argv[k + 2];
        *argc -= 2;
        return j;
    }
    return nullptr;
}
