// SPDX-License-Identifier: MIT
// fork() for a test's VMs and helpers: the child gets SIGKILL when the test
// dies (a ctest timeout, say), so nothing is left running. A jailed VMM
// sets this again itself after its credentials change.
#pragma once

#include <signal.h>
#include <sys/prctl.h>
#include <unistd.h>

static pid_t fork_child(void)
{
    const pid_t parent = getpid();
    const pid_t pid = fork();
    if (pid == 0 && (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) || getppid() != parent))
        _exit(127);
    return pid;
}
