// SPDX-License-Identifier: MIT
// What init.c shares with agent.c (both freestanding, linked into /init).
#pragma once

extern bool ports;     // /init has the control ports (ioperm)
extern bool to_stderr; // in a child about to exec: messages go to fd 2

void say(const char *a, const char *b, long err);
[[noreturn]] void stop(int status);
// execve argv with envp (PATH search); returns the status to report if it can't.
int exec_env(char **argv, char *const *envp);
// After a snapshot point: the host's clock and fresh randomness. `rnd` is
// /dev/urandom, opened before the root filesystem was entered; closed here.
void resume(long rnd);
// Right before a snapshot point: the kernel reports every free page to the
// host now (kernel patch 0040; with the VMM's --balloon), so the snapshot
// leaves them out. Nothing happens without a balloon device.
void report_free_pages(void);
// image.c: enter the root filesystem image, made writable and set up as
// a container's root (/proc, /sys, /dev, /etc/hosts...): 0, or 125 (said why).
int enter_root(void);
// The image's layers (/dev/pmem0, 1, ...): the VMM's "layersN" word; 1.
extern unsigned image_layers;
// After enter_root(): the overlay's upper directory (the root filesystem's
// changes, whiteouts included), or -1.
extern int upper_dir;
// After enter_root(): the image's config (/.microvm/image-config), if it
// has one. false (said why) if it has one that can't be used.
bool image_load(void);
// In the command's process: run args as the image's config says
// (Entrypoint + args or Cmd, Env, WorkingDir, User), or args as root
// without a config. Returns the status to report if it can't.
int image_exec(char **args);

// The control port's records (0x707): latch one (0 resume, 1 --env), then
// read it, n bytes at a time, in one exit per page.
void ctl_latch(unsigned char which);
void ctl_read(void *p, unsigned long n);
// `init env ...`: the VMM's --env strings (image.c), read before anything
// else runs; image_exec puts them over the image's Env. false: said why.
bool env_read(void);

// After image_load(): the image's Env (or root's defaults: PATH,
// HOSTNAME), with --env on top. nullptr-terminated; nullptr if out of memory.
char **image_env(void);

// `init agent run COMMAND...` (agent.c): serve function invocations.
int agent_run(char **argv);
// `init sandbox run` (sbx.c): serve an E2B-style sandbox (src/sbx/proto.h).
int sbx_run(void);
