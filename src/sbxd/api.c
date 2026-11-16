// SPDX-License-Identifier: MIT
// microvm-sbxd: E2B's control plane (REST + X-API-KEY) and the VMs behind
// it.
//
// A template is an image booted once at start-up and paused as soon as its
// agent answers: every sandbox is a restore of that snapshot (copy-on-write,
// so its RAM is shared until written). Pausing a sandbox is the agent's
// SNAPSHOT: the VMM saves the VM and exits; resuming restores the saved
// file. A restored VMM maps its file, so a sandbox alternates between two
// (a.snap, b.snap): it saves into the one it didn't start from. Those are
// diffs of the template's snapshot (their base): only the pages the
// sandbox changed are written.
//
// Each sandbox has a directory of its own (DIR/sbx/ID: the vsock socket,
// its snapshots, the console log), which is all a jailed VMM can write.
#include "sbxd/sbxd.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "image/json.h"

extern char **environ;

sandbox *sandboxes;

enum : int64_t {
    START_GIVE_UP_MS = 30000,   // a VM's agent must answer within this
    BOOT_GIVE_UP_MS = 60000,    // a template's first boot
    READY_GIVE_UP_MS = 300000,  // its start and ready commands, from the agent being up
    READY_EVERY_MS = 100,       // between runs of its ready command
    DEFAULT_TIMEOUT_S = 300,
    NO_TIMEOUT_S = 10 * 365 * 86400LL, // --max-timeout none: ten years
};

static int64_t now_unix(void) { return (int64_t)time(nullptr); }

sandbox *sb_find(const char *id)
{
    for (sandbox *sb = sandboxes; sb; sb = sb->next)
        if (!sb->is_template && sb->st != SB_DEAD && !strcmp(sb->id, id))
            return sb;
    return nullptr;
}

int sb_count(void)
{
    int n = 0;
    for (sandbox *sb = sandboxes; sb; sb = sb->next)
        n += !sb->is_template && sb->st != SB_DEAD;
    return n;
}

static void random_id(char *out, size_t n, const char *alphabet)
{
    const size_t al = strlen(alphabet);
    uint8_t r[64];
    if (n > sizeof r || getrandom(r, n, 0) != (ssize_t)n) {
        logf_("no randomness from the kernel");
        abort();
    }
    for (size_t i = 0; i < n; i++)
        out[i] = alphabet[r[i] % al]; // 256 % 36 = 4: a slight bias, irrelevant for ids
    out[n] = 0;
}

static void sb_dir(const sandbox *sb, char *out, size_t cap)
{
    snprintf(out, cap, "%s/sbx/%s", C.dir, sb->id);
}

static void sb_remove_files(sandbox *sb)
{
    char d[512];
    sb_dir(sb, d, sizeof d);
    unlink(sb->sock);
    unlink(sb->snap[0]);
    unlink(sb->snap[1]);
    unlink(sb->log);
    unlink(sb->stats);
    rmdir(d);
}

static void sandbox_free(void *p)
{
    sandbox *sb = p;
    free(sb->metadata);
    for (size_t i = 0; i < sb->nenv; i++)
        free(sb->envs[i]);
    free(sb->envs);
    free(sb);
}

// Gone for good: out of the list once its VMM (if any) has been reaped.
static void sb_destroy(sandbox *sb)
{
    sb->st = SB_DEAD;
    watchers_close(sb);
    g_close(sb->ctl);
    sb->ctl = nullptr;
    sb_waiters_wake(sb);
    if (sb->pid > 0) {
        kill(sb->pid, SIGKILL); // sb_vmm_exited() finishes the job
        return;
    }
    h_forget_sandbox(sb);
    sb_remove_files(sb);
    for (sandbox **pp = &sandboxes; *pp; pp = &(*pp)->next)
        if (*pp == sb) {
            *pp = sb->next;
            break;
        }
    graveyard_add(sb, sandbox_free);
}

// --- team pools (--cgroup) ---------------------------------------------------------
// A team's sandboxes on this node share its plan's vCPUs and memory: their
// VMMs run in the cgroup --cgroup/t-TEAM (jailed: each in a cgroup of its
// own under it), and the kernel holds them to its cpu.max and memory.max.
// Over the memory, its OOM killer stops the VMM using the most. With none
// of the team's VMMs left, the cgroup goes.

static bool cg_write(const char *dir, const char *file, const char *val)
{
    char p[700];
    snprintf(p, sizeof p, "%s/%s", dir, file);
    const int fd = open(p, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    const size_t n = strlen(val);
    const bool ok = write(fd, val, n) == (ssize_t)n;
    close(fd);
    return ok;
}

// A number in a cgroup file: the first, or the one after "KEY " on a line.
static unsigned long long cg_u64(const char *dir, const char *file, const char *key)
{
    char p[700], b[4096];
    snprintf(p, sizeof p, "%s/%s", dir, file);
    const int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    const ssize_t n = read(fd, b, sizeof b - 1);
    close(fd);
    if (n <= 0)
        return 0;
    b[n] = 0;
    const char *at = b;
    if (key) {
        const size_t kl = strlen(key);
        for (at = b; at; at = strchr(at, '\n'), at = at ? at + 1 : nullptr)
            if (!strncmp(at, key, kl) && at[kl] == ' ')
                break;
        if (!at)
            return 0;
        at += kl + 1;
    }
    return strtoull(at, nullptr, 10);
}

static void team_cg(const char *team, char *out, size_t cap) { snprintf(out, cap, "%s/t-%s", C.cgroup, team); }

// The team's cgroup, made if it isn't there, with this sandbox's pool (the
// latest create's: a plan changed applies from the team's next sandbox).
static bool pool_ready(const sandbox *sb, char *dir, size_t cap)
{
    team_cg(sb->team, dir, cap);
    if (mkdir(dir, 0700) && errno != EEXIST) {
        logf_("%s: cannot make the cgroup %s: %s", sb->id, dir, strerror(errno));
        return false;
    }
    char v[64];
    if (sb->pool_cpus)
        snprintf(v, sizeof v, "%llu 100000", sb->pool_cpus * 100000ULL);
    else
        snprintf(v, sizeof v, "max 100000");
    bool ok = cg_write(dir, "cpu.max", v);
    if (sb->pool_mem)
        snprintf(v, sizeof v, "%llu", (unsigned long long)sb->pool_mem);
    else
        snprintf(v, sizeof v, "max");
    ok = ok && cg_write(dir, "memory.max", v);
    if (!ok)
        logf_("%s: cannot set the limits of %s: %s", sb->id, dir, strerror(errno));
    (void)cg_write(dir, "memory.swap.max", "0"); // not round the limit through swap (absent without swap)
    return ok;
}

// A VMM of the team's is gone: its cgroup (jailed), then the team's if it
// was the last (EBUSY otherwise).
static void pool_release(const char *team, const char *id)
{
    if (!team[0] || !C.cgroup)
        return;
    char d[600], v[700];
    team_cg(team, d, sizeof d);
    if (C.jail) {
        snprintf(v, sizeof v, "%s/%s", d, id);
        rmdir(v);
    }
    rmdir(d);
}

// A VMM of the team's (of this sandbox, with an id) runs here now.
static bool vmm_in(const char *team, const char *id)
{
    for (const sandbox *sb = sandboxes; sb; sb = sb->next)
        if (sb->pid > 0 && !strcmp(sb->team, team) && (!id || !strcmp(sb->id, id)))
            return true;
    return false;
}

// Cgroups pool_release() couldn't remove yet (a jailed VM's empties only
// once the jail's children are gone): every 2 s, those no VMM here is in.
// rmdir() removes only an empty cgroup, and a team's is made and entered in
// the same event (pool_ready, spawn_vmm), so none is taken from under one.
static void pool_sweep(int64_t now)
{
    static int64_t next;
    if (!C.cgroup || now < next)
        return;
    next = now + 2000;
    DIR *d = opendir(C.cgroup);
    for (struct dirent *e; d && (e = readdir(d));) {
        if (strncmp(e->d_name, "t-", 2) || e->d_type != DT_DIR)
            continue;
        const char *team = e->d_name + 2;
        char t[600];
        snprintf(t, sizeof t, "%s/%s", C.cgroup, e->d_name);
        DIR *v = C.jail ? opendir(t) : nullptr;
        for (struct dirent *f; v && (f = readdir(v));) {
            if (f->d_type != DT_DIR || f->d_name[0] == '.' || vmm_in(team, f->d_name))
                continue;
            char vm[900];
            snprintf(vm, sizeof vm, "%s/%s", t, f->d_name);
            rmdir(vm);
        }
        if (v)
            closedir(v);
        if (!vmm_in(team, nullptr))
            rmdir(t);
    }
    if (d)
        closedir(d);
}

// GET /pools: each team's use of this node, for the control plane (its
// plan's pool, billing, the storage its paused sandboxes take).
static void pools(hconn *h)
{
    sbuf b = {0};
    sb_puts(&b, "[");
    bool first = true;
    for (sandbox *sb = sandboxes; sb; sb = sb->next) {
        if (!sb->team[0] || sb->is_template || sb->st == SB_DEAD)
            continue;
        bool seen = false; // the team's first sandbox in the list speaks for it
        for (const sandbox *o = sandboxes; o != sb && !seen; o = o->next)
            seen = o->team[0] && !o->is_template && o->st != SB_DEAD && !strcmp(o->team, sb->team);
        if (seen)
            continue;
        unsigned running = 0, paused = 0;
        unsigned long long snap = 0;
        for (const sandbox *o = sb; o; o = o->next) {
            if (o->is_template || o->st == SB_DEAD || strcmp(o->team, sb->team))
                continue;
            if (o->st != SB_PAUSED) {
                running++;
                continue;
            }
            paused++;
            struct stat st;
            for (int i = 0; i < 2; i++)
                if (!stat(o->snap[i], &st))
                    snap += (unsigned long long)st.st_blocks * 512;
        }
        char d[600];
        team_cg(sb->team, d, sizeof d);
        sb_printf(&b,
                  "%s{\"team\":\"%s\",\"running\":%u,\"paused\":%u,\"memoryBytes\":%llu,\"cpuUsec\":%llu,"
                  "\"oomKills\":%llu,\"snapshotBytes\":%llu}",
                  first ? "" : ",", sb->team, running, paused, cg_u64(d, "memory.current", nullptr),
                  cg_u64(d, "cpu.stat", "usage_usec"), cg_u64(d, "memory.events", "oom_kill"), snap);
        first = false;
    }
    sb_puts(&b, "]");
    h_json(h, 200, &b);
    sb_free(&b);
}

// --- VMM processes ---------------------------------------------------------------

static bool spawn_vmm(sandbox *sb, const char *restore_from)
{
    tmpl *t = sb->t;
    const char *save = sb->snap[sb->gen & 1];
    // The VMM's own arguments, with host paths; jailed, they're rewritten.
    const char *args[64];
    int n = 0;
    char membuf[16], cpubuf[16];
    snprintf(membuf, sizeof membuf, "%u", t->mem_mib);
    snprintf(cpubuf, sizeof cpubuf, "%u", t->cpus);
    // A template of several vCPUs boots the SMP kernel (the UP one has no
    // SMP code at all); a restore takes the count from the snapshot.
    const char *kernel = t->cpus > 1 ? C.kernel_smp : C.kernel;
    if (restore_from) {
        args[n++] = "--restore", args[n++] = restore_from;
        if (restore_from != t->snap)
            args[n++] = "--base", args[n++] = t->snap;
        args[n++] = "--snapshot-diff";
    } else {
        args[n++] = "--kernel", args[n++] = kernel;
        args[n++] = "--quiet";
        args[n++] = "--mem", args[n++] = membuf;
        args[n++] = "--cpus", args[n++] = cpubuf;
    }
    for (uint32_t i = 0; i < t->nlower; i++) // bottom first, the image on top
        args[n++] = "--rootfs", args[n++] = t->lower[i].path;
    args[n++] = "--rootfs", args[n++] = t->image;
    args[n++] = "--vsock", args[n++] = sb->sock;
    args[n++] = "--snapshot", args[n++] = save;
    args[n++] = "--balloon"; // free memory goes back to the host, and out of pauses
    const bool net = t->net;
    if (net)
        args[n++] = "--stats", args[n++] = sb->stats;
    // The network's limits (the jail's options, or the VMM's): a sandbox
    // with the internet only; one without has nowhere to go anyway.
    const char *nargs[48];
    int nn = 0;
    char nbuf[20][24];
    if (net && sb->internet) {
        for (int i = 0; i < C.nnet_deny; i++) {
            snprintf(nbuf[i], sizeof nbuf[i], "%u", C.net_deny[i]);
            nargs[nn++] = "--net-deny-port", nargs[nn++] = nbuf[i];
        }
        const uint32_t fr = sb->net_flow_rate ? sb->net_flow_rate : C.net_flow_rate;
        const uint32_t md = sb->net_max_dests ? sb->net_max_dests : C.net_max_dests;
        const uint64_t tr = sb->net_tx_rate ? sb->net_tx_rate : C.net_tx_rate;
        if (fr)
            snprintf(nbuf[16], sizeof nbuf[16], "%u", fr), nargs[nn++] = "--net-flow-rate", nargs[nn++] = nbuf[16];
        if (md)
            snprintf(nbuf[17], sizeof nbuf[17], "%u", md), nargs[nn++] = "--net-max-dests", nargs[nn++] = nbuf[17];
        if (tr)
            snprintf(nbuf[18], sizeof nbuf[18], "%llu", (unsigned long long)tr), nargs[nn++] = "--net-tx-rate",
                nargs[nn++] = nbuf[18];
    }
    if (!restore_from)
        args[n++] = "--append", args[n++] = "sandbox";
    args[n] = nullptr;

    const char *argv[128];
    int k = 0;
    char dir[512], b_kernel[700], b_image[700], b_work[700], b_snap[700], jr[5][700];
    char cg[600], cg_vm[700];
    if (sb->team[0] && !pool_ready(sb, cg, sizeof cg))
        return false;
    char b_lower[TMPL_MAX_LOWER][700], j_lower[TMPL_MAX_LOWER][16];
    sb_dir(sb, dir, sizeof dir);
    if (!C.jail) {
        argv[k++] = C.vmm;
        for (int i = 0; i < n; i++)
            argv[k++] = args[i];
        if (net) {
            argv[k++] = "--net";
            if (!sb->internet)
                argv[k++] = "--net-deny-all";
            for (int i = 0; i < nn; i++)
                argv[k++] = nargs[i];
        }
    } else {
        argv[k++] = C.jail;
        if (geteuid() == 0)
            argv[k++] = "--uid", argv[k++] = "65534", argv[k++] = "--gid", argv[k++] = "65534";
        if (sb->team[0]) { // a cgroup of its own in the team's: the jail's
            snprintf(cg_vm, sizeof cg_vm, "%s/%s", cg, sb->id);
            argv[k++] = "--cgroup", argv[k++] = cg_vm;
        }
        snprintf(b_kernel, sizeof b_kernel, "%s:/vmlinux", kernel);
        snprintf(b_image, sizeof b_image, "%s:/rootfs", t->image);
        snprintf(b_work, sizeof b_work, "%s:/work:rw", dir);
        argv[k++] = "--bind", argv[k++] = b_image;
        for (uint32_t i = 0; i < t->nlower; i++) {
            snprintf(j_lower[i], sizeof j_lower[i], "/layer%u", i);
            snprintf(b_lower[i], sizeof b_lower[i], "%s:%s", t->lower[i].path, j_lower[i]);
            argv[k++] = "--bind", argv[k++] = b_lower[i];
        }
        argv[k++] = "--bind", argv[k++] = b_work;
        if (!restore_from)
            argv[k++] = "--bind", argv[k++] = b_kernel;
        if (restore_from) { // the template's snapshot: restored, or a diff's base
            snprintf(b_snap, sizeof b_snap, "%s:/template.snap", t->snap);
            argv[k++] = "--bind", argv[k++] = b_snap;
        }
        if (net) {
            argv[k++] = "--net";
            if (!sb->internet)
                argv[k++] = "--net-deny-all";
            for (int i = 0; i < nn; i++)
                argv[k++] = nargs[i];
        }
        argv[k++] = "--";
        argv[k++] = C.vmm;
        const size_t dl = strlen(dir);
        int nj = 0;
        for (int i = 0; i < n; i++) {
            const char *a = args[i];
            if (a == kernel) {
                a = "/vmlinux";
            } else if (a == t->image) {
                a = "/rootfs";
            } else if (a == t->snap) {
                a = "/template.snap";
            } else if (!strncmp(a, dir, dl) && a[dl] == '/') {
                snprintf(jr[nj], sizeof jr[nj], "/work%s", a + dl);
                a = jr[nj++];
            } else {
                for (uint32_t l = 0; l < t->nlower; l++)
                    if (a == t->lower[l].path) {
                        a = j_lower[l];
                        break;
                    }
            }
            argv[k++] = a;
        }
    }
    argv[k] = nullptr;

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 1, sb->log, O_WRONLY | O_CREAT | O_APPEND, 0600);
    posix_spawn_file_actions_adddup2(&fa, 1, 2);
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    sigset_t none;
    sigemptyset(&none);
    posix_spawnattr_setsigmask(&at, &none);
    sigset_t def;
    sigemptyset(&def);
    sigaddset(&def, SIGPIPE);
    sigaddset(&def, SIGTERM);
    sigaddset(&def, SIGINT);
    posix_spawnattr_setsigdefault(&at, &def);
    short flags = POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
    // Not jailed, in its team's cgroup from its first instruction
    // (clone3's CLONE_INTO_CGROUP): what it allocates is the team's.
    int cgfd = -1;
    if (sb->team[0] && !C.jail) {
        cgfd = open(cg, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (cgfd < 0) {
            logf_("%s: cannot open %s: %s", sb->id, cg, strerror(errno));
            posix_spawn_file_actions_destroy(&fa);
            posix_spawnattr_destroy(&at);
            return false;
        }
        posix_spawnattr_setcgroup_np(&at, cgfd);
        flags |= POSIX_SPAWN_SETCGROUP;
    }
    posix_spawnattr_setflags(&at, flags);
    char *const envp[] = {nullptr};
    pid_t pid;
    const int rc = posix_spawn(&pid, argv[0], &fa, &at, (char *const *)argv, envp);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&at);
    if (cgfd >= 0)
        close(cgfd);
    if (rc) {
        logf_("%s: cannot start %s: %s", sb->id, argv[0], strerror(rc));
        return false;
    }
    const int pfd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (pfd < 0) {
        logf_("pidfd_open: %s", strerror(errno));
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
        return false;
    }
    fcntl(pfd, F_SETFD, FD_CLOEXEC);
    sb->pid = pid;
    sb->pidfd = pfd;
    sb->kind = EV_PIDFD;
    ev_set(pfd, sb, true, false);
    sb->st = SB_STARTING;
    sb->restored = restore_from != nullptr;
    sb->started_ms = now_ms();
    sb->retry_at = sb->started_ms;
    sb->give_up_at = sb->started_ms + (restore_from ? START_GIVE_UP_MS : BOOT_GIVE_UP_MS);
    VLOG("%s: VMM %d started (%s)", sb->id, (int)pid, restore_from ? restore_from : "boot");
    return true;
}

static void sb_kill_vmm(sandbox *sb)
{
    if (sb->pid > 0)
        kill(sb->pid, SIGKILL);
}

// --- the start-up and SNAPSHOT operations ------------------------------------------

static void tmpl_done(tmpl *t, bool ok);
static void sb_start_from(sandbox *sb);

// A template's boot, once its agent is up: the start command (left
// running), then the ready command until it succeeds, then the snapshot.
// One operation per connection: each step gets a new one.
enum { TP_UP, TP_STARTING, TP_PROBE, TP_PROBING, TP_SNAP };

static void tmpl_cmd(gconn *g, const tmpl *t, const char *cmd, const char *tag)
{
    const char *argv[] = {"/bin/sh", "-c", cmd};
    const mvs_start s = {.flags = tag ? MVS_S_TAG : 0, .user = t->user, .cwd = t->workdir ? t->workdir : "",
                         .tag = tag, .argv = argv, .nargs = 3};
    mvs_buf b = {0};
    mvs_req_start(&b, &s);
    g_send(g, &b);
}

[[gnu::format(printf, 2, 3)]] static void tmpl_step_fail(sandbox *sb, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(sb->t->why, sizeof sb->t->why, fmt, ap);
    va_end(ap);
    logf_("template %s: %s", sb->t->name, sb->t->why);
    if (sb->ctl) {
        g_close(sb->ctl);
        sb->ctl = nullptr;
    }
    sb_kill_vmm(sb);
    sb->st = SB_DEAD; // its exit says the template failed: sb_vmm_exited()
}

static void ctl_ready(gconn *g)
{
    sandbox *sb = g->ctx;
    if (sb->st == SB_PAUSING) { // the connection for SNAPSHOT
        mvs_buf b = {0};
        mvs_req_empty(&b, MVS_SNAPSHOT);
        g_send(g, &b);
        return;
    }
    if (sb->is_template) { // up: pause it, and that is the template
        const tmpl *t = sb->t;
        if (sb->tphase == TP_UP) {
            VLOG("template %s: agent up in %lld ms", t->name, (long long)(now_ms() - sb->started_ms));
            if (t->start_cmd || t->ready_cmd)
                sb->give_up_at = now_ms() + READY_GIVE_UP_MS;
            sb->tphase = TP_PROBE;
            if (t->start_cmd) {
                sb->tphase = TP_STARTING;
                tmpl_cmd(g, t, t->start_cmd, "start");
                return;
            }
        }
        if (sb->tphase == TP_PROBE && t->ready_cmd) {
            sb->tphase = TP_PROBING;
            tmpl_cmd(g, t, t->ready_cmd, nullptr);
            return;
        }
        if (t->start_cmd || t->ready_cmd)
            VLOG("template %s: started and ready (%lld ms)", t->name, (long long)(now_ms() - sb->started_ms));
        sb->st = SB_PAUSING;
        mvs_buf b = {0};
        mvs_req_empty(&b, MVS_SNAPSHOT);
        g_send(g, &b);
        return;
    }
    // A new sandbox gets its environment (E2B's envVars) once: it stays in
    // the agent, and in its snapshots.
    if (sb->nenv && !sb->env_set) {
        mvs_buf b = {0};
        mvs_req_set_env(&b, (const char *const *)sb->envs, sb->nenv);
        g_send(g, &b);
        return;
    }
    VLOG("%s: running (%lld ms)", sb->id, (long long)(now_ms() - sb->started_ms));
    sb->ctl = nullptr;
    g_close(g);
    sb->st = SB_RUNNING;
    sb_waiters_wake(sb);
}

static void ctl_frame(gconn *g, const mvs_frame *f)
{
    sandbox *sb = g->ctx;
    if (sb->is_template && sb->st == SB_STARTING && (sb->tphase == TP_STARTING || sb->tphase == TP_PROBING)) {
        uint32_t ws = 0;
        if (f->type == MVS_ERROR) {
            mvs_error e = {0};
            const bool ok = mvs_dec_error(f, &e);
            char msg[128];
            snprintf(msg, sizeof msg, "%.*s", ok ? (int)e.msg.n : 0, ok ? e.msg.p : "");
            tmpl_step_fail(sb, "the %s command: %s", sb->tphase == TP_STARTING ? "start" : "ready", msg);
            return;
        }
        if (sb->tphase == TP_STARTING && f->type != MVS_P_START)
            return;
        if (sb->tphase == TP_PROBING && f->type != MVS_P_END)
            return; // its output: not kept
        if (sb->tphase == TP_STARTING) { // started: it goes on without this connection
            sb->tphase = TP_PROBE;
            sb->retry_at = now_ms();
        } else if (mvs_dec_end(f, &ws) && ws == 0) {
            sb->tphase = TP_SNAP;
            sb->retry_at = now_ms();
        } else {
            sb->tphase = TP_PROBE;
            sb->retry_at = now_ms() + READY_EVERY_MS;
        }
        sb->ctl = nullptr;
        g_close(g); // sb_tick() connects again at retry_at
        return;
    }
    if (sb->st == SB_STARTING && f->type == MVS_OK) { // SET_ENV
        sb->env_set = true;
        ctl_ready(g);
        return;
    }
    if (sb->st == SB_PAUSING && f->type == MVS_OK) // the VM went on after all: never here
        return;
    mvs_error e = {0};
    if (f->type == MVS_ERROR && mvs_dec_error(f, &e))
        logf_("%s: the agent refused: %.*s", sb->id, (int)e.msg.n, e.msg.p);
    sb->ctl = nullptr;
    g_close(g);
    sb_destroy(sb);
}

static void ctl_end(gconn *g, const char *why)
{
    sandbox *sb = g->ctx;
    if (sb->ctl == g)
        sb->ctl = nullptr;
    if (sb->st == SB_PAUSING)
        return; // the VMM is saving the VM and exiting: sb_vmm_exited()
    if (sb->st == SB_STARTING && !g->was_open) {
        // The VMM is up, the agent isn't yet: its vsock port refuses.
        sb->retry_at = now_ms() + 1;
        return;
    }
    logf_("%s: the agent's connection ended: %s", sb->id, why ? why : "closed");
    sb_destroy(sb);
}

static const gconn_ops ctl_ops = {.ready = ctl_ready, .frame = ctl_frame, .end = ctl_end};

void sb_tick(int64_t now)
{
    const int64_t unix_now = now_unix();
    pool_sweep(now);
    for (sandbox *sb = sandboxes, *next; sb; sb = next) {
        next = sb->next;
        if (sb->st == SB_STARTING && sb->pid > 0) {
            if (now >= sb->give_up_at) {
                if (sb->is_template && sb->tphase != TP_UP) {
                    tmpl_step_fail(sb, "the %s command did not succeed within %d s",
                                   sb->t->ready_cmd ? "ready" : "start", (int)(READY_GIVE_UP_MS / 1000));
                    continue;
                }
                logf_("%s: the agent never answered (see %s)", sb->id, sb->log);
                if (sb->is_template) {
                    sb_kill_vmm(sb);
                    sb->st = SB_DEAD; // sb_vmm_exited(): failed
                } else {
                    sb_destroy(sb);
                }
                continue;
            }
            if (!sb->ctl && now >= sb->retry_at) {
                bool retry;
                sb->ctl = g_open(sb, &ctl_ops, sb, &retry);
                if (!sb->ctl)
                    sb->retry_at = now + 1;
            }
            continue;
        }
        if (sb->st == SB_PAUSING && sb->pid > 0 && now >= sb->give_up_at) {
            logf_("%s: the VM did not save in time", sb->id);
            sb_destroy(sb);
            continue;
        }
        if (!sb->is_template && sb->st == SB_RUNNING && unix_now >= sb->end_unix) {
            VLOG("%s: timed out", sb->id);
            if (sb->auto_pause) {
                bool retry;
                gconn *g = g_open(sb, &ctl_ops, sb, &retry);
                if (g) {
                    sb->ctl = g;
                    sb->st = SB_PAUSING;
                    sb->give_up_at = now + START_GIVE_UP_MS;
                    continue;
                }
            }
            sb_destroy(sb);
        }
    }
}

int64_t sb_next_deadline(void)
{
    int64_t t = INT64_MAX;
    for (sandbox *sb = sandboxes; sb; sb = sb->next)
        if (sb->st == SB_STARTING && sb->pid > 0 && !sb->ctl && sb->retry_at < t)
            t = sb->retry_at;
    return t;
}

static bool file_nonempty(const char *p)
{
    struct stat st;
    return !stat(p, &st) && st.st_size > 0;
}

// The VMM saved the sandbox (snap[gen & 1]); its process is gone, or is
// a reaper's now.
static void sb_saved(sandbox *sb)
{
    unlink(sb->sock); // a new VMM binds the path again
    if (sb->ctl) {
        g_close(sb->ctl);
        sb->ctl = nullptr;
    }
    if (sb->is_template) {
        tmpl_done(sb->t, true);
        return;
    }
    // The file it started from (the other one) is free now: unlinked, the
    // exiting VMM's mapping keeps it as long as it needs.
    if (sb->restored)
        unlink(sb->snap[(sb->gen + 1) & 1]);
    sb->gen++;
    sb->st = SB_PAUSED;
    VLOG("%s: paused", sb->id);
    watchers_close(sb);
    sb_waiters_wake(sb);
}

// --- pausing without waiting for the VMM to exit ---------------------------------------
// A VMM that saved its snapshot exits, and the host kernel's teardown of
// its VM takes ~40 ms (KVM waits for an RCU barrier). The VMM writes the
// snapshot's header last, so a file with one is whole: when the VMM closes
// it (inotify's IN_CLOSE_WRITE) and the header is there, the sandbox is
// paused, and a reaper waits for the process.
typedef struct {
    int kind; // EV_REAP
    pid_t pid;
    int pidfd;
    char id[24];
    char team[68];
} reaper;

static int notify_fd = -1;

bool sb_notify_start(void)
{
    static ev_head ev = {EV_NOTIFY};
    notify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (notify_fd < 0)
        return false;
    ev_set(notify_fd, &ev, true, false);
    return true;
}

// The snapshot magic and a version: the header is there.
static bool snap_whole(const char *path)
{
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    unsigned char h[12];
    const bool ok = pread(fd, h, sizeof h, 0) == (ssize_t)sizeof h && !memcmp(h, "MVMSNAP", 8) &&
                    (h[8] == 1 || h[8] == 2) && !h[9] && !h[10] && !h[11];
    close(fd);
    return ok;
}

static void sb_saved_early(sandbox *sb)
{
    reaper *r = calloc(1, sizeof *r);
    if (!r)
        return; // then at the VMM's exit
    *r = (reaper){.kind = EV_REAP, .pid = sb->pid, .pidfd = sb->pidfd};
    snprintf(r->id, sizeof r->id, "%s", sb->id);
    snprintf(r->team, sizeof r->team, "%s", sb->team);
    ev_set(r->pidfd, r, true, false);
    sb->pid = 0;
    sb->pidfd = -1;
    sb_saved(sb);
}

void sb_notify_readable(void)
{
    alignas(struct inotify_event) char buf[4096];
    for (;;) {
        const ssize_t n = read(notify_fd, buf, sizeof buf);
        if (n <= 0)
            return;
        for (ssize_t at = 0; at + (ssize_t)sizeof(struct inotify_event) <= n;) {
            const struct inotify_event *e = (const struct inotify_event *)(buf + at);
            at += (ssize_t)sizeof *e + e->len;
            if (!(e->mask & IN_CLOSE_WRITE) || !e->len)
                continue;
            for (sandbox *sb = sandboxes; sb; sb = sb->next) {
                if (sb->wd != e->wd || sb->st != SB_PAUSING || sb->pid <= 0)
                    continue;
                const char *saved = sb->snap[sb->gen & 1], *base = strrchr(saved, '/');
                if (!strcmp(e->name, base ? base + 1 : saved) && snap_whole(saved))
                    sb_saved_early(sb);
                break;
            }
        }
    }
}

void sb_reaped(void *p)
{
    reaper *r = p;
    int st = 0;
    const pid_t w = waitpid(r->pid, &st, WNOHANG);
    if (w == 0)
        return;
    ev_del(r->pidfd);
    close(r->pidfd);
    pool_release(r->team, r->id);
    if (w < 0 || !WIFEXITED(st) || WEXITSTATUS(st))
        logf_("%s: the VMM exited after saving the sandbox (status %#x)", r->id, st);
    graveyard_add(r, free);
}

void sb_vmm_exited(sandbox *sb)
{
    // A reaper took the process (sb_saved_early) after this event was
    // fetched: it's the reaper's now, and waitpid(0) would take any child.
    if (sb->pid <= 0)
        return;
    int st = 0;
    const pid_t r = waitpid(sb->pid, &st, WNOHANG);
    if (r == 0)
        return; // not yet (spurious)
    ev_del(sb->pidfd);
    close(sb->pidfd);
    sb->pidfd = -1;
    sb->pid = 0;
    pool_release(sb->team, sb->id);
    const bool clean = r > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0;
    if (sb->st == SB_PAUSING && clean && file_nonempty(sb->snap[sb->gen & 1])) {
        sb_saved(sb);
        return;
    }
    unlink(sb->sock);
    if (sb->ctl) {
        g_close(sb->ctl);
        sb->ctl = nullptr;
    }
    if (sb->st != SB_DEAD)
        logf_("%s: the VMM exited (status %#x; console in %s)", sb->id, st, sb->log);
    if (sb->is_template) {
        sb->st = SB_DEAD;
        tmpl_done(sb->t, false);
        return;
    }
    sb_destroy(sb);
}

// --- templates -----------------------------------------------------------------------

static sandbox *sb_new(tmpl *t, const char *id)
{
    sandbox *sb = calloc(1, sizeof *sb);
    if (!sb)
        return nullptr;
    sb->kind = EV_PIDFD;
    sb->pidfd = -1;
    sb->t = t;
    snprintf(sb->id, sizeof sb->id, "%s", id);
    char d[512];
    sb_dir(sb, d, sizeof d);
    if (mkdir(d, 0700) && errno != EEXIST) {
        free(sb);
        return nullptr;
    }
    if (C.jail && geteuid() == 0 && chown(d, 65534, 65534)) {
        free(sb);
        return nullptr;
    }
    snprintf(sb->sock, sizeof sb->sock, "%s/vm.sock", d);
    snprintf(sb->log, sizeof sb->log, "%s/console.log", d);
    snprintf(sb->stats, sizeof sb->stats, "%s/stats", d);
    snprintf(sb->snap[0], sizeof sb->snap[0], "%s/a.snap", d);
    snprintf(sb->snap[1], sizeof sb->snap[1], "%s/b.snap", d);
    // Removed with the directory (IN_IGNORED).
    if (notify_fd >= 0) {
        const int wd = inotify_add_watch(notify_fd, d, IN_CLOSE_WRITE | IN_ONLYDIR);
        sb->wd = wd > 0 ? wd : 0;
    }
    sb->next = sandboxes;
    sandboxes = sb;
    return sb;
}

static tmpl *dyn_tmpls; // pushed at run time, newest first

// Boots the template once; tmpl_done() when its snapshot is saved.
static bool tmpl_boot(tmpl *t, const char *id)
{
    sandbox *sb = sb_new(t, id);
    if (!sb) {
        logf_("template %s: cannot make its directory", t->name);
        snprintf(t->why, sizeof t->why, "cannot make its directory");
        t->state = T_FAILED;
        return false;
    }
    sb->is_template = true;
    snprintf(t->snap, sizeof t->snap, "%s", sb->snap[0]);
    t->boot = sb;
    t->state = T_PREPARING;
    if (!spawn_vmm(sb, nullptr)) {
        snprintf(t->why, sizeof t->why, "cannot start its VMM");
        t->state = T_FAILED;
        return false;
    }
    logf_("template %s: booting %s", t->name, t->image);
    return true;
}

void templates_prepare(void)
{
    for (int i = 0; i < C.ntmpl; i++) {
        char id[24]; // by index: names (up to 63) don't fit a sandbox ID
        snprintf(id, sizeof id, "tmpl-%d", i);
        tmpl_boot(&C.tmpl[i], id);
    }
}

tmpl *tmpl_find(const char *name)
{
    for (int i = 0; i < C.ntmpl; i++)
        if (!strcmp(C.tmpl[i].name, name))
            return &C.tmpl[i];
    for (tmpl *t = dyn_tmpls; t; t = t->next)
        if (!t->retired && !strcmp(t->name, name))
            return t;
    return nullptr;
}

// Failed before (or without) a boot: the sandboxes waiting for it go.
static void tmpl_fail(tmpl *t)
{
    t->state = T_FAILED;
    logf_("template %s: failed: %s", t->name, t->why);
    for (sandbox *sb = sandboxes, *next; sb; sb = next) {
        next = sb->next;
        if (sb->t == t && !sb->is_template && sb->st == SB_STARTING && sb->pid <= 0)
            sb_destroy(sb);
    }
}

static void tmpl_boot_dynamic(tmpl *t)
{
    char id[24] = "t-";
    random_id(id + 2, 16, "abcdefghijklmnopqrstuvwxyz0123456789");
    if (!tmpl_boot(t, id))
        tmpl_fail(t);
}

// A file of the right size at path: fetched and checked (fetch.c renames
// it into place only then).
static bool have_file(const char *path, uint64_t size)
{
    struct stat st;
    return !lstat(path, &st) && S_ISREG(st.st_mode) && (uint64_t)st.st_size == size;
}

static bool tmpl_has(const tmpl *t, const char *sha)
{
    bool has = !strcmp(t->sha256, sha);
    for (uint32_t l = 0; l < t->nlower && !has; l++)
        has = !strcmp(t->lower[l].sha256, sha);
    return has;
}

// Some template other than `except` (not failed) has a layer `sha`.
static bool tmpl_uses(const char *sha, const tmpl *except)
{
    for (tmpl *o = dyn_tmpls; o; o = o->next)
        if (o != except && o->state != T_FAILED && tmpl_has(o, sha))
            return true;
    return false;
}

// Every layer of the template's image is here.
static bool tmpl_all_here(const tmpl *t)
{
    bool all = have_file(t->image, t->size);
    for (uint32_t l = 0; l < t->nlower && all; l++)
        all = have_file(t->lower[l].path, t->lower[l].size);
    return all;
}

void tmpl_fetched(const char *sha, bool ok, const char *why)
{
    for (tmpl *t = dyn_tmpls; t; t = t->next) {
        if (t->state != T_FETCHING || !tmpl_has(t, sha))
            continue;
        if (ok && !t->retired) {
            if (tmpl_all_here(t)) // else: more layers on their way
                tmpl_boot_dynamic(t);
            continue;
        }
        snprintf(t->why, sizeof t->why, "%s", ok ? "replaced while its image was fetched" : why);
        tmpl_fail(t);
    }
}

void tmpl_tick(void)
{
    for (tmpl **pp = &dyn_tmpls; *pp;) {
        tmpl *t = *pp;
        bool busy = !t->retired || t->state == T_PREPARING || t->state == T_FETCHING || (t->boot && t->boot->pid > 0);
        for (sandbox *sb = sandboxes; !busy && sb; sb = sb->next)
            busy = sb->t == t && !sb->is_template;
        if (busy) {
            pp = &t->next;
            continue;
        }
        *pp = t->next;
        if (t->boot)
            sb_destroy(t->boot); // its snapshot goes with its directory
        // Each of its layers' files, unless another template uses it (a
        // failed one uses none).
        for (uint32_t l = 0; l <= t->nlower; l++) {
            const char *sha = l < t->nlower ? t->lower[l].sha256 : t->sha256;
            if (!tmpl_uses(sha, t))
                unlink(l < t->nlower ? t->lower[l].path : t->image);
        }
        logf_("template %s (image %.12s): gone", t->name, t->sha256);
        free(t->start_cmd);
        free(t->ready_cmd);
        free(t->workdir);
        free(t);
    }
}

static void tmpl_done(tmpl *t, bool ok)
{
    t->state = ok ? T_READY : T_FAILED;
    if (ok) {
        struct stat st;
        stat(t->snap, &st);
        logf_("template %s: ready (%lld ms, snapshot %lld MiB on disk)", t->name,
              (long long)(now_ms() - t->boot->started_ms), (long long)(st.st_blocks * 512 / (1 << 20)));
    } else {
        logf_("template %s: failed (console in %s)", t->name, t->boot->log);
    }
    // Sandboxes that waited for it.
    for (sandbox *sb = sandboxes, *next; sb; sb = next) {
        next = sb->next;
        if (sb->t != t || sb->is_template || sb->st != SB_STARTING || sb->pid > 0)
            continue;
        if (ok)
            sb_start_from(sb);
        else
            sb_destroy(sb);
    }
}

static void sb_start_from(sandbox *sb)
{
    if (!spawn_vmm(sb, sb->t->snap))
        sb_destroy(sb);
}

// --- answers -----------------------------------------------------------------------

static void put_time(sbuf *b, int64_t t) { jw_time(b, t, 0); }

static void sandbox_json(sbuf *b, const sandbox *sb, bool detail)
{
    bool f = true;
    sb_puts(b, "{");
    jw_key(b, &f, "templateID"), jw_cstr(b, sb->t->name);
    jw_key(b, &f, "sandboxID"), jw_cstr(b, sb->id);
    jw_key(b, &f, "clientID"), jw_cstr(b, "microvm");
    jw_key(b, &f, "envdVersion"), jw_cstr(b, "0.6.4");
    if (!detail) {
        jw_key(b, &f, "envdAccessToken"), jw_cstr(b, sb->token);
        if (C.domain)
            jw_key(b, &f, "domain"), jw_cstr(b, C.domain);
        sb_puts(b, "}");
        return;
    }
    if (C.domain)
        jw_key(b, &f, "domain"), jw_cstr(b, C.domain);
    jw_key(b, &f, "startedAt"), put_time(b, sb->started_unix);
    jw_key(b, &f, "endAt"), put_time(b, sb->end_unix);
    jw_key(b, &f, "cpuCount"), sb_printf(b, "%u", sb->t->cpus);
    jw_key(b, &f, "memoryMB"), sb_printf(b, "%u", sb->t->mem_mib);
    struct stat st;
    long long disk = stat(sb->t->image, &st) ? 0LL : (long long)st.st_size;
    for (uint32_t l = 0; l < sb->t->nlower; l++)
        disk += stat(sb->t->lower[l].path, &st) ? 0LL : (long long)st.st_size;
    jw_key(b, &f, "diskSizeMB"), sb_printf(b, "%lld", (disk + (1 << 20) - 1) >> 20);
    jw_key(b, &f, "state"), jw_cstr(b, sb->st == SB_PAUSED ? "paused" : "running");
    jw_key(b, &f, "metadata"), sb_puts(b, sb->metadata ? sb->metadata : "{}");
    jw_key(b, &f, "allowInternetAccess"), sb_puts(b, sb->internet ? "true" : "false");
    sb_puts(b, "}");
}

static void answer_sandbox(hconn *h, sandbox *sb, int status)
{
    sbuf b = {0};
    sandbox_json(&b, sb, false);
    h_json(h, status, &b);
    sb_free(&b);
}

// --- waiting for a sandbox --------------------------------------------------------

static void wait_on(hconn *h, sandbox *sb, int want, int ok_status)
{
    h->rq.kind = RQ_WAIT_SB;
    h->rq.sb = sb;
    h->rq.want = want;
    h->rq.ok_status = ok_status;
    h->wnext = sb->waiters;
    sb->waiters = h;
}

void api_abort(hconn *h)
{
    sandbox *sb = h->rq.sb;
    if (!sb)
        return;
    for (hconn **pp = &sb->waiters; *pp; pp = &(*pp)->wnext)
        if (*pp == h) {
            *pp = h->wnext;
            break;
        }
    h->rq.sb = nullptr;
}

static bool sb_resume(sandbox *sb);

void sb_waiters_wake(sandbox *sb)
{
    hconn *list = sb->waiters;
    sb->waiters = nullptr;
    bool want_running = false;
    for (hconn *h = list, *next; h; h = next) {
        next = h->wnext;
        h->wnext = nullptr;
        if (sb->st == SB_DEAD) {
            h->rq.sb = nullptr;
            h->rq.kind = RQ_SIMPLE;
            h_api_error(h, 500, "the sandbox failed to start (or was killed)");
        } else if (h->rq.want == sb->st) {
            h->rq.sb = nullptr;
            h->rq.kind = RQ_SIMPLE;
            if (h->rq.ok_status == 204)
                h_respond(h, 204, "", "", 0, nullptr);
            else
                answer_sandbox(h, sb, h->rq.ok_status);
        } else {
            h->wnext = sb->waiters; // still waiting
            sb->waiters = h;
            want_running |= h->rq.want == SB_RUNNING;
        }
    }
    if (sb->st == SB_PAUSED && want_running && !sb_resume(sb)) {
        sb->st = SB_DEAD;
        sb_waiters_wake(sb);
        sb_destroy(sb);
    }
}

// --- requests --------------------------------------------------------------------

static bool ct_eq(const char *a, const char *b)
{
    const size_t n = strlen(a);
    if (n != strlen(b))
        return false;
    unsigned char d = 0;
    for (size_t i = 0; i < n; i++)
        d |= (unsigned char)(a[i] ^ b[i]);
    return d == 0;
}

static bool sb_resume(sandbox *sb)
{
    VLOG("%s: resuming", sb->id);
    return spawn_vmm(sb, sb->snap[(sb->gen + 1) & 1]);
}

static int64_t clamp_timeout(uint64_t t)
{
    const int64_t max = C.max_timeout_s ? C.max_timeout_s : NO_TIMEOUT_S;
    return t > (uint64_t)max ? max : (int64_t)t;
}

// "/sandboxes/ID[/rest]" (or with a /v2 prefix): the ID and the rest.
static bool sb_path(const char *path, char *id, size_t cap, const char **rest)
{
    if (!strncmp(path, "/v2", 3))
        path += 3;
    if (strncmp(path, "/sandboxes/", 11))
        return false;
    path += 11;
    size_t n = 0;
    while (path[n] && path[n] != '/') {
        if (n + 1 >= cap)
            return false;
        id[n] = path[n];
        n++;
    }
    id[n] = 0;
    *rest = path + n;
    return n > 0;
}

static const json_value *parse_body(hconn *h, json_doc **doc)
{
    *doc = nullptr;
    if (!h->body.len)
        return nullptr;
    const char *err;
    const json_limits lim = {1u << 20, 16, 65536};
    *doc = json_parse(h->body.p, h->body.len, &lim, &err);
    if (!*doc)
        return nullptr;
    const json_value *root = json_root(*doc);
    return root->type == JSON_OBJECT ? root : nullptr;
}

static void create(hconn *h)
{
    json_doc *doc;
    const json_value *o = parse_body(h, &doc);
    if (h->body.len && !o) {
        json_free(doc);
        h_api_error(h, 400, "the body is not a JSON object");
        return;
    }
    const char *tname = json_cstr(json_get(o, "templateID"));
    if (!tname)
        tname = "base";
    tmpl *t = tmpl_find(tname);
    if (!t && C.ntmpl == 1 && !dyn_tmpls && !strcmp(tname, "base"))
        t = &C.tmpl[0]; // the one template answers to the SDK's default
    if (!t || t->state == T_FAILED) {
        json_free(doc);
        h_api_error(h, t ? 503 : 404, t ? "the template failed to build" : "no such template");
        return;
    }
    if (sb_count() >= C.max_sandboxes) {
        json_free(doc);
        h_api_error(h, 429, "too many sandboxes");
        return;
    }
    uint64_t timeout = DEFAULT_TIMEOUT_S;
    const json_value *tv = json_get(o, "timeout");
    if (tv && !json_u64(tv, &timeout)) {
        json_free(doc);
        h_api_error(h, 400, "timeout: not a number of seconds");
        return;
    }
    // metadata: string values only; kept as JSON text.
    const json_value *md = json_get(o, "metadata");
    sbuf mb = {0};
    sb_puts(&mb, "{");
    bool first = true, bad = md && md->type != JSON_OBJECT && md->type != JSON_NULL;
    for (uint32_t i = 0; md && md->type == JSON_OBJECT && i < md->len; i++) {
        const json_value *kv = &md->kids[i];
        if (kv->type != JSON_STRING || !json_cstr(kv)) {
            bad = true;
            break;
        }
        jw_key(&mb, &first, kv->key);
        jw_str(&mb, kv->str, kv->len);
    }
    sb_puts(&mb, "}");
    const json_value *ev = json_get(o, "envVars");
    bad |= ev && ev->type != JSON_OBJECT && ev->type != JSON_NULL;
    size_t nenv = ev && ev->type == JSON_OBJECT ? ev->len : 0;
    if (nenv > MVS_MAX_STRINGS)
        bad = true;
    for (size_t i = 0; !bad && i < nenv; i++) {
        const json_value *kv = &ev->kids[i];
        bad = kv->type != JSON_STRING || !json_cstr(kv) || !kv->key[0] || strchr(kv->key, '=') ||
              strlen(kv->key) != kv->klen;
    }
    if (bad || mb.oom) {
        sb_free(&mb);
        json_free(doc);
        h_api_error(h, 400, "metadata and envVars are objects of strings");
        return;
    }
    char id[24];
    random_id(id, 20, "abcdefghijklmnopqrstuvwxyz0123456789");
    sandbox *sb = sb_new(t, id);
    if (!sb) {
        sb_free(&mb);
        json_free(doc);
        h_api_error(h, 500, "cannot make the sandbox's directory");
        return;
    }
    random_id(sb->token, 32, "abcdef0123456789");
    sb->metadata = mb.p; // owned now
    sb->started_unix = now_unix();
    sb->end_unix = sb->started_unix + clamp_timeout(timeout);
    const json_value *ai = json_get(o, "allow_internet_access");
    sb->internet = !ai || ai->type != JSON_FALSE;
    const json_value *ap = json_get(o, "autoPause");
    sb->auto_pause = ap && ap->type == JSON_TRUE;
    // E2B's "network" (egress allow and deny lists, private URLs, a proxy):
    // not done here, so refused rather than ignored, since what they'd deny
    // would go through. Public URLs, what sandboxes have, may be asked for.
    const json_value *e2 = json_get(o, "network");
    if (e2 && e2->type == JSON_OBJECT) {
        for (uint32_t i = 0; i < e2->len && !bad; i++) {
            const json_value *m = &e2->kids[i];
            bad = strcmp(m->key, "allowPublicTraffic") || (m->type != JSON_TRUE && m->type != JSON_NULL);
        }
    } else if (e2 && e2->type != JSON_NULL) {
        bad = true;
    }
    if (bad) {
        json_free(doc);
        sb_destroy(sb);
        h_api_error(h, 400, "network: egress rules (allowOut, denyOut, ...) and private URLs aren't supported here");
        return;
    }
    // "pool": {"team": NAME, "vcpus": N, "memoryMB": N}, from the control
    // plane (the numbers optional: no cap): the sandbox runs in its team's
    // cgroup, sharing the team's plan's vCPUs and memory on this node.
    const json_value *pl = json_get(o, "pool");
    if (pl && pl->type != JSON_NULL) {
        const char *tm = pl->type == JSON_OBJECT ? json_cstr(json_get(pl, "team")) : nullptr;
        bad = !C.cgroup || !tm || !tm[0] || strlen(tm) >= sizeof sb->team;
        for (const char *c = tm; !bad && *c; c++)
            bad = !((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '-');
        for (uint32_t i = 0; !bad && i < pl->len; i++) {
            const json_value *m = &pl->kids[i];
            uint64_t v;
            if (!strcmp(m->key, "team") || ((!strcmp(m->key, "vcpus") || !strcmp(m->key, "memoryMB")) && m->type == JSON_NULL))
                continue;
            if (!json_u64(m, &v))
                bad = true;
            else if (!strcmp(m->key, "vcpus") && v >= 1 && v <= 4096)
                sb->pool_cpus = (uint32_t)v;
            else if (!strcmp(m->key, "memoryMB") && v >= 64 && v <= (1ULL << 30))
                sb->pool_mem = v << 20;
            else
                bad = true;
        }
        if (bad) {
            json_free(doc);
            sb_destroy(sb);
            h_api_error(h, 400, C.cgroup ? "pool: {\"team\": a-z 0-9 -, \"vcpus\": N, \"memoryMB\": N}"
                                         : "pool: this node has no --cgroup");
            return;
        }
        snprintf(sb->team, sizeof sb->team, "%s", tm);
    }
    // "netLimits": {"txRate": BYTES, "flowRate": N, "maxDests": N}, from the
    // control plane (each optional; the daemon's defaults otherwise).
    const json_value *nw = json_get(o, "netLimits");
    if (nw && nw->type == JSON_OBJECT) {
        static const struct {
            const char *key;
            uint64_t max;
        } L[] = {{"txRate", 1000000000}, {"flowRate", 1000000}, {"maxDests", 4096}};
        uint64_t v[3] = {0};
        for (int i = 0; i < 3 && !bad; i++) {
            const json_value *x = json_get(nw, L[i].key);
            bad = x && (!json_u64(x, &v[i]) || v[i] > L[i].max);
        }
        sb->net_tx_rate = v[0], sb->net_flow_rate = (uint32_t)v[1], sb->net_max_dests = (uint32_t)v[2];
    } else if (nw && nw->type != JSON_NULL) {
        bad = true;
    }
    if (bad) {
        json_free(doc);
        sb_destroy(sb);
        h_api_error(h, 400, "netLimits: an object of txRate, flowRate and maxDests (numbers)");
        return;
    }
    if (nenv && !(sb->envs = calloc(nenv, sizeof *sb->envs)))
        bad = true;
    for (size_t i = 0; !bad && i < nenv; i++) {
        const json_value *kv = &ev->kids[i];
        const size_t l = strlen(kv->key) + 1 + kv->len + 1;
        if (!(sb->envs[i] = malloc(l))) {
            bad = true;
            break;
        }
        snprintf(sb->envs[i], l, "%s=%s", kv->key, kv->str);
        sb->nenv++;
    }
    json_free(doc);
    if (bad) {
        sb_destroy(sb);
        h_api_error(h, 500, "out of memory");
        return;
    }
    sb->st = SB_STARTING;
    if (!t->net)
        sb->internet = false;
    wait_on(h, sb, SB_RUNNING, 201);
    if (t->state == T_READY)
        sb_start_from(sb); // a failure answers the waiter
    VLOG("%s: created from %s", sb->id, t->name);
}

// The counters of each running sandbox with a network (the VMM's --stats
// file, since it last started): for the control plane, which tells abuse.
static bool read_stats(const sandbox *sb, unsigned long long v[7])
{
    const int fd = open(sb->stats, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    char b[256];
    const ssize_t n = pread(fd, b, sizeof b - 1, 0);
    close(fd);
    if (n <= 0 || b[n - 1] != '\n') // not written yet, or caught mid-write
        return false;
    b[n] = 0;
    return sscanf(b, "cpu_ns %llu tx %llu rx %llu flows %llu refused %llu denied %llu limited %llu", &v[0], &v[1],
                  &v[2], &v[3], &v[4], &v[5], &v[6]) == 7;
}

static void stats(hconn *h)
{
    sbuf b = {0};
    sb_puts(&b, "[");
    bool first = true;
    for (sandbox *sb = sandboxes; sb; sb = sb->next) {
        unsigned long long v[7];
        if (sb->is_template || sb->st != SB_RUNNING || !sb->t->net || !read_stats(sb, v))
            continue;
        sb_printf(&b,
                  "%s{\"sandboxID\":\"%s\",\"cpuCount\":%u,\"internet\":%s,\"startedAt\":%lld,\"cpuNs\":%llu,"
                  "\"txBytes\":%llu,\"rxBytes\":%llu,\"flows\":%llu,\"refused\":%llu,\"denied\":%llu,"
                  "\"limited\":%llu}",
                  first ? "" : ",", sb->id, sb->t->cpus, sb->internet ? "true" : "false",
                  (long long)sb->started_unix, v[0], v[1], v[2], v[3], v[4], v[5], v[6]);
        first = false;
    }
    sb_puts(&b, "]");
    h_json(h, 200, &b);
    sb_free(&b);
}

static void list(hconn *h)
{
    // ?state=running,paused filters; metadata filters are matched exactly.
    char state[64] = "";
    http_query(&h->req, "state", state, sizeof state);
    const bool want_run = !state[0] || strstr(state, "running"), want_pause = !state[0] || strstr(state, "paused");
    sbuf b = {0};
    sb_puts(&b, "[");
    bool first = true;
    for (sandbox *sb = sandboxes; sb; sb = sb->next) {
        if (sb->is_template || sb->st == SB_DEAD)
            continue;
        const bool paused = sb->st == SB_PAUSED;
        if ((paused && !want_pause) || (!paused && !want_run))
            continue;
        if (!first)
            sb_puts(&b, ",");
        first = false;
        sandbox_json(&b, sb, true);
    }
    sb_puts(&b, "]");
    h_json(h, 200, &b);
    sb_free(&b);
}

// --- templates pushed at run time ------------------------------------------------

enum : uint64_t { MAX_IMAGE = 16ull << 30 };
enum { MAX_DYN_TMPLS = 256 };

static bool name_ok(const char *s, size_t cap, bool dots)
{
    const size_t n = s ? strlen(s) : 0;
    if (!n || n >= cap)
        return false;
    for (const char *c = s; *c; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '-' || *c == '_' || (dots && *c == '.')))
            return false;
    return true;
}

static void tmpl_json(sbuf *b, const tmpl *t)
{
    static const char *const states[] = {"preparing", "ready", "failed", "fetching"};
    bool f = true;
    sb_puts(b, "{");
    jw_key(b, &f, "templateID"), jw_cstr(b, t->name);
    jw_key(b, &f, "sha256"), jw_cstr(b, t->sha256);
    if (t->nlower) { // the layers below it, bottom first: their sha256s
        jw_key(b, &f, "layers"), sb_puts(b, "[");
        for (uint32_t i = 0; i < t->nlower; i++)
            sb_puts(b, i ? "," : ""), jw_cstr(b, t->lower[i].sha256);
        sb_puts(b, "]");
    }
    jw_key(b, &f, "state"), jw_cstr(b, states[t->state]);
    jw_key(b, &f, "memoryMB"), sb_printf(b, "%u", t->mem_mib);
    jw_key(b, &f, "cpuCount"), sb_printf(b, "%u", t->cpus);
    jw_key(b, &f, "internet"), sb_puts(b, t->net ? "true" : "false");
    if (t->start_cmd)
        jw_key(b, &f, "startCmd"), jw_cstr(b, t->start_cmd);
    if (t->ready_cmd)
        jw_key(b, &f, "readyCmd"), jw_cstr(b, t->ready_cmd);
    if (t->workdir)
        jw_key(b, &f, "workdir"), jw_cstr(b, t->workdir);
    if (t->state == T_FAILED)
        jw_key(b, &f, "error"), jw_cstr(b, t->why[0] ? t->why : "it did not boot");
    sb_puts(b, "}");
}

// PUT /templates/NAME {"url", "sha256", "sizeBytes", "memoryMB", "cpuCount",
// "user", "internet", "startCmd", "readyCmd", "workdir", "layers"}: from the control plane. The same again is a no-op;
// anything else replaces it (sandboxes of the old one keep running).
// "layers": the layers below the image, bottom first, each {"url",
// "sha256", "sizeBytes"} (microvm-mkrootfs --lower made the image on them).
enum { CMD_MAX = 64 * 1024 };

static bool same_str(const char *a, const char *b) { return a ? b && !strcmp(a, b) : !b; }

static bool same_layers(const tmpl *t, const tmpl_layer *l, uint32_t n)
{
    bool same = t->nlower == n;
    for (uint32_t i = 0; same && i < n; i++)
        same = !strcmp(t->lower[i].sha256, l[i].sha256) && t->lower[i].size == l[i].size;
    return same;
}

static void tmpl_put(hconn *h, const char *name)
{
    if (!name_ok(name, sizeof ((tmpl *)nullptr)->name, true)) {
        h_api_error(h, 400, "a template name is 1-63 of a-z 0-9 - _ .");
        return;
    }
    json_doc *doc;
    const json_value *o = parse_body(h, &doc);
    const char *url = json_cstr(json_get(o, "url")), *sha = json_cstr(json_get(o, "sha256"));
    const char *user = json_cstr(json_get(o, "user"));
    const json_value *scv = json_get(o, "startCmd"), *rcv = json_get(o, "readyCmd"), *wdv = json_get(o, "workdir");
    const char *start = json_cstr(scv), *ready = json_cstr(rcv), *wd = json_cstr(wdv);
    uint64_t size = 0, mem = 512, cpus = 1;
    const json_value *mv = json_get(o, "memoryMB"), *cv = json_get(o, "cpuCount"), *nv = json_get(o, "internet");
    const char *bad = nullptr;
    if (!o)
        bad = "the body is not a JSON object";
    else if (!url || strlen(url) > 4096)
        bad = "url: a string";
    else if (!fetch_sha_ok(sha))
        bad = "sha256: 64 lower-case hex digits";
    else if (!json_u64(json_get(o, "sizeBytes"), &size) || !size || size > MAX_IMAGE)
        bad = "sizeBytes: 1 to 16 GiB";
    else if ((mv && !json_u64(mv, &mem)) || mem < 64 || mem > 3072)
        bad = "memoryMB: 64 to 3072";
    else if ((cv && !json_u64(cv, &cpus)) || cpus < 1 || cpus > 8)
        bad = "cpuCount: 1 to 8";
    else if (cpus > 1 && !C.kernel_smp)
        bad = "cpuCount: this node has no SMP kernel (--kernel-smp)";
    else if (user && !name_ok(user, sizeof ((tmpl *)nullptr)->user, false))
        bad = "user: 1-63 of a-z 0-9 - _";
    else if (nv && nv->type != JSON_TRUE && nv->type != JSON_FALSE)
        bad = "internet: true or false";
    else if ((scv && (!start || !start[0] || strlen(start) > CMD_MAX)) ||
             (rcv && (!ready || !ready[0] || strlen(ready) > CMD_MAX)))
        bad = "startCmd, readyCmd: commands of up to 64 KiB";
    else if (wdv && (!wd || wd[0] != '/' || strlen(wd) >= 4096))
        bad = "workdir: an absolute path";
    const json_value *lv = o ? json_get(o, "layers") : nullptr;
    tmpl_layer lower[TMPL_MAX_LOWER];
    const char *lurl[TMPL_MAX_LOWER];
    uint32_t nlower = 0;
    if (!bad && lv && (lv->type != JSON_ARRAY || lv->len > TMPL_MAX_LOWER))
        bad = "layers: an array of up to 7 {url, sha256, sizeBytes}";
    for (uint32_t i = 0; !bad && lv && i < lv->len; i++) {
        const json_value *e = &lv->kids[i];
        const char *lu = json_cstr(json_get(e, "url")), *ls = json_cstr(json_get(e, "sha256"));
        uint64_t lsz = 0;
        if (!lu || strlen(lu) > 4096 || !fetch_sha_ok(ls) || !json_u64(json_get(e, "sizeBytes"), &lsz) || !lsz ||
            lsz > MAX_IMAGE)
            bad = "layers: each {url, sha256 (64 lower-case hex digits), sizeBytes (1 to 16 GiB)}";
        else if (!strcmp(ls, sha))
            bad = "layers: the image is not one of its own layers";
        for (uint32_t k = 0; !bad && k < nlower; k++)
            if (!strcmp(lower[k].sha256, ls))
                bad = "layers: a layer twice";
        if (bad)
            break;
        lower[nlower] = (tmpl_layer){.size = lsz};
        memcpy(lower[nlower].sha256, ls, 65);
        snprintf(lower[nlower].path, sizeof lower[nlower].path, "%s/images/%s.erofs", C.dir, ls);
        lurl[nlower++] = lu;
    }
    if (bad) {
        json_free(doc);
        h_api_error(h, 400, bad);
        return;
    }
    const bool net = nv && nv->type == JSON_TRUE;
    for (int i = 0; i < C.ntmpl; i++)
        if (!strcmp(C.tmpl[i].name, name)) {
            json_free(doc);
            h_api_error(h, 409, "a template of this node's own configuration has that name");
            return;
        }
    tmpl *old = tmpl_find(name);
    if (old && old->state != T_FAILED && !strcmp(old->sha256, sha) && old->mem_mib == mem && old->cpus == cpus &&
        old->net == net && !strcmp(old->user, user ? user : "") && same_str(old->start_cmd, start) &&
        same_str(old->ready_cmd, ready) && same_str(old->workdir, wd) && same_layers(old, lower, nlower)) {
        json_free(doc);
        sbuf b = {0};
        tmpl_json(&b, old);
        h_json(h, 200, &b);
        sb_free(&b);
        return;
    }
    int n = 0;
    for (tmpl *t = dyn_tmpls; t; t = t->next)
        n += !t->retired;
    tmpl *t = n >= MAX_DYN_TMPLS ? nullptr : calloc(1, sizeof *t);
    if (!t) {
        json_free(doc);
        h_api_error(h, 507, "too many templates on this node");
        return;
    }
    if (old)
        old->retired = true;
    snprintf(t->name, sizeof t->name, "%s", name);
    snprintf(t->user, sizeof t->user, "%s", user ? user : "");
    memcpy(t->sha256, sha, 65);
    t->mem_mib = (uint32_t)mem, t->cpus = (uint32_t)cpus, t->net = net;
    t->start_cmd = start ? strdup(start) : nullptr;
    t->ready_cmd = ready ? strdup(ready) : nullptr;
    t->workdir = wd ? strdup(wd) : nullptr;
    if ((start && !t->start_cmd) || (ready && !t->ready_cmd) || (wd && !t->workdir)) {
        free(t->start_cmd), free(t->ready_cmd), free(t->workdir), free(t);
        if (old)
            old->retired = false;
        json_free(doc);
        h_api_error(h, 500, "out of memory");
        return;
    }
    t->dynamic = true;
    snprintf(t->image, sizeof t->image, "%s/images/%s.erofs", C.dir, sha);
    t->size = size;
    t->nlower = nlower;
    memcpy(t->lower, lower, nlower * sizeof lower[0]);
    t->next = dyn_tmpls;
    dyn_tmpls = t;
    if (tmpl_all_here(t)) {
        tmpl_boot_dynamic(t); // checked when they were fetched; renamed only then
    } else {
        // Each missing layer, once (fetch.c joins a fetch already going).
        const char *why = nullptr;
        t->state = T_FETCHING;
        bool ok = true;
        for (uint32_t l = 0; ok && l <= nlower; l++) {
            const bool top = l == nlower;
            const tmpl_layer *ly = top ? nullptr : &lower[l];
            if (!have_file(top ? t->image : ly->path, top ? size : ly->size))
                ok = fetch_start(top ? sha : ly->sha256, top ? url : lurl[l], top ? size : ly->size, &why);
        }
        if (!ok) {
            snprintf(t->why, sizeof t->why, "%s", why);
            tmpl_fail(t);
        }
    }
    json_free(doc);
    VLOG("template %s: pushed (image %.12s, %s)", t->name, t->sha256, old ? "a new version" : "new");
    sbuf b = {0};
    tmpl_json(&b, t);
    h_json(h, 202, &b);
    sb_free(&b);
}

static void templates_request(hconn *h, const char *m, const char *name)
{
    if (!name && !strcmp(m, "GET")) {
        sbuf b = {0};
        sb_puts(&b, "[");
        bool first = true;
        for (int i = 0; i < C.ntmpl; i++) {
            sb_puts(&b, first ? "" : ",");
            first = false;
            tmpl_json(&b, &C.tmpl[i]);
        }
        for (tmpl *t = dyn_tmpls; t; t = t->next) {
            if (t->retired)
                continue;
            sb_puts(&b, first ? "" : ",");
            first = false;
            tmpl_json(&b, t);
        }
        sb_puts(&b, "]");
        h_json(h, 200, &b);
        sb_free(&b);
    } else if (name && !strcmp(m, "PUT")) {
        tmpl_put(h, name);
    } else if (name && !strcmp(m, "DELETE")) {
        tmpl *t = tmpl_find(name);
        if (!t) {
            h_api_error(h, 404, "no such template");
        } else if (!t->dynamic) {
            h_api_error(h, 409, "a template of this node's own configuration");
        } else {
            t->retired = true; // gone once its sandboxes are (tmpl_tick)
            VLOG("template %s: deleted", t->name);
            h_respond(h, 204, "", "", 0, nullptr);
        }
    } else {
        h_api_error(h, 405, "method not allowed");
    }
}

void api_request(hconn *h)
{
    const char *m = h->req.method, *path = h->req.path;
    h->rq.kind = RQ_SIMPLE;
    if (!strcmp(path, "/health")) {
        h_respond(h, 200, "application/json", "{\"status\":\"ok\"}", 15, nullptr);
        return;
    }
    const char *key = http_header(&h->req, "x-api-key");
    if (!key || !key[0] || (C.api_key[0] && !ct_eq(key, C.api_key))) {
        h_api_error(h, 401, "invalid API key");
        return;
    }
    if (!strcmp(path, "/v2/sandboxes") || !strcmp(path, "/sandboxes")) {
        if (!strcmp(m, "POST"))
            create(h);
        else if (!strcmp(m, "GET"))
            list(h);
        else
            h_api_error(h, 405, "method not allowed");
        return;
    }
    if (!strcmp(path, "/templates") || !strncmp(path, "/templates/", 11)) {
        templates_request(h, m, path[10] ? path + 11 : nullptr);
        return;
    }
    if (!strcmp(path, "/stats") || !strcmp(path, "/pools")) {
        if (strcmp(m, "GET"))
            h_api_error(h, 405, "method not allowed");
        else if (path[1] == 's')
            stats(h);
        else
            pools(h);
        return;
    }
    char id[64];
    const char *rest;
    if (!sb_path(path, id, sizeof id, &rest)) {
        h_api_error(h, 404, "not found");
        return;
    }
    sandbox *sb = sb_find(id);
    if (!sb) {
        h_api_error(h, 404, "sandbox not found");
        return;
    }
    if (!*rest && !strcmp(m, "GET")) {
        sbuf b = {0};
        sandbox_json(&b, sb, true);
        h_json(h, 200, &b);
        sb_free(&b);
    } else if (!*rest && !strcmp(m, "DELETE")) {
        VLOG("%s: killed", sb->id);
        sb_destroy(sb);
        h_respond(h, 204, "", "", 0, nullptr);
    } else if (!strcmp(rest, "/timeout") && !strcmp(m, "POST")) {
        json_doc *doc;
        const json_value *o = parse_body(h, &doc);
        uint64_t t;
        if (!o || !json_u64(json_get(o, "timeout"), &t)) {
            json_free(doc);
            h_api_error(h, 400, "timeout: not a number of seconds");
            return;
        }
        json_free(doc);
        sb->end_unix = now_unix() + clamp_timeout(t);
        h_respond(h, 204, "", "", 0, nullptr);
    } else if ((!strcmp(rest, "/connect") || !strcmp(rest, "/resume")) && !strcmp(m, "POST")) {
        json_doc *doc;
        const json_value *o = parse_body(h, &doc);
        uint64_t t;
        if (o && json_u64(json_get(o, "timeout"), &t))
            sb->end_unix = now_unix() + clamp_timeout(t);
        json_free(doc);
        if (sb->st == SB_RUNNING) {
            answer_sandbox(h, sb, 200);
        } else if (sb->st == SB_PAUSED) {
            if (sb->end_unix < now_unix() + 10)
                sb->end_unix = now_unix() + DEFAULT_TIMEOUT_S;
            wait_on(h, sb, SB_RUNNING, 201);
            if (!sb_resume(sb)) {
                api_abort(h);
                h->rq.kind = RQ_SIMPLE;
                h_api_error(h, 500, "cannot resume the sandbox");
            }
        } else {
            wait_on(h, sb, SB_RUNNING, 201); // starting, or pausing (it resumes once paused)
        }
    } else if (!strcmp(rest, "/pause") && !strcmp(m, "POST")) {
        if (sb->st == SB_PAUSED) {
            h_api_error(h, 409, "the sandbox is already paused");
        } else if (sb->st == SB_PAUSING) {
            wait_on(h, sb, SB_PAUSED, 204);
        } else if (sb->st != SB_RUNNING) {
            h_api_error(h, 409, "the sandbox is not running yet");
        } else {
            bool retry;
            gconn *g = g_open(sb, &ctl_ops, sb, &retry);
            if (!g) {
                h_api_error(h, 500, "the sandbox is unreachable");
                return;
            }
            sb->ctl = g;
            sb->st = SB_PAUSING;
            sb->give_up_at = now_ms() + START_GIVE_UP_MS;
            wait_on(h, sb, SB_PAUSED, 204);
        }
    } else if (!strcmp(rest, "/export") && !strcmp(m, "GET")) {
        if (sb->st != SB_RUNNING)
            h_api_error(h, 409, "the sandbox is not running");
        else
            envd_export(h, sb);
    } else if (!strcmp(rest, "/metrics") && !strcmp(m, "GET")) {
        h_respond(h, 200, "application/json", "[]", 2, nullptr);
    } else {
        h_api_error(h, 404, "not found");
    }
}
