// SPDX-License-Identifier: MIT
// Whether unprivileged user namespaces work all the way, as microvm-jail
// sets them up (enter_userns in src/jail.c): unshare(CLONE_NEWUSER), then
// the id maps. Only unshare() isn't enough: on Ubuntu 24.04, with
// kernel.apparmor_restrict_unprivileged_userns=1, unshare() succeeds but the
// new namespace has no capabilities, so writing /proc/self/setgroups and the
// maps fails. The check runs in a child, so this process is unchanged.
#pragma once

#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Writes VAL to PATH; false on any failure.
static inline bool userns_write(const char *path, const char *val)
{
    const int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    const size_t n = strlen(val);
    const bool ok = write(fd, val, n) == (ssize_t)n;
    return close(fd) == 0 && ok;
}

static inline bool userns_usable(void)
{
    const pid_t pid = fork();
    if (pid == 0) {
        const uid_t uid = getuid();
        const gid_t gid = getgid();
        char map[64];
        if (unshare(CLONE_NEWUSER))
            _exit(1);
        if (!userns_write("/proc/self/setgroups", "deny"))
            _exit(2);
        snprintf(map, sizeof map, "%u %u 1", (unsigned)uid, (unsigned)uid);
        if (!userns_write("/proc/self/uid_map", map))
            _exit(3);
        snprintf(map, sizeof map, "%u %u 1", (unsigned)gid, (unsigned)gid);
        if (!userns_write("/proc/self/gid_map", map))
            _exit(4);
        _exit(0);
    }
    int st;
    return pid > 0 && waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0;
}
