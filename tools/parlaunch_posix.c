// SPDX-License-Identifier: MIT
// Parallel cold starts (Linux): launch N microvm processes back to back,
// wait for all, report per-VM latency and the batch's throughput. The twin
// of tools/parlaunch.c (Windows), same arguments:
//
//   mvm-parlaunch N EXE "ARGS" [EXPECTED_STATUS]
//   (MVM_PAR_THREADS=T: launch from T threads; default 1)
//   (MVM_PAR_WRAP="CMD ARGS": run each VMM under a wrapper, e.g.
//    "setpriv --reuid=nobody --regid=nogroup --groups=kvm --no-new-privs";
//    "{i}" in the wrapper or ARGS becomes the VM's index, for per-VM uids,
//    cgroups or files)
//   build/mvm-parlaunch 32 build/microvm "--kernel guest/kernel/out/vmlinux --quiet --ws ws.txt"
//
// Each child gets `--trace` (prepended to ARGS, after the wrapper), /dev/null
// on stdin and a private pipe for stdout + stderr; nothing else is
// inherited (every other fd here is close-on-exec). ARGS is split on spaces.
//
// Per VM:
//   result  launch -> the VMM's MVMTRACE line arrives: the exit status is
//           known, which is when a caller has its answer
//   wall    launch -> process reaped. Later than `result`: the VM is torn
//           down in the exiting process, and KVM's teardown waits for RCU.
//   total / guest  the VMM's own MVMTRACE fields
//   pre     launch -> VMM main() (the trace's start_unix_us)
//   post    guest exit status -> process reaped
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

typedef struct {
    pid_t pid;
    int rd;          // read end of the output pipe, -1 before launch / after EOF
    double t_launch; // Unix microseconds (CLOCK_REALTIME, like start_unix_us)
    double t_result, t_exit;
    char *buf;
    size_t len, cap;
    int status;
    bool eof, reaped;
} child;

static struct {
    child *c;
    int n, step, launched, reaped;
    char **argv;
    pthread_mutex_t lock; // c[].pid / c[].rd / launched / reaped
    bool failed;
} g = {.lock = PTHREAD_MUTEX_INITIALIZER};

static double now_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (double)t.tv_sec * 1e6 + (double)t.tv_nsec / 1e3;
}

static int cmp(const void *a, const void *b)
{
    const double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void report(const char *what, double *v, int n, const char *unit)
{
    qsort(v, (size_t)n, sizeof *v, cmp);
    printf("  %-8s p50 %7.2f  p90 %7.2f  max %7.2f %s\n", what, v[n / 2],
           v[(n * 9) / 10 < n ? (n * 9) / 10 : n - 1], v[n - 1], unit);
}

static double field(const char *s, const char *name)
{
    const char *p = strstr(s, name);
    return p ? strtod(p + strlen(name), nullptr) : -1;
}

// Child i's argv: g.argv with each "{i}" replaced by i (in bufs).
static void child_argv(int i, char **out, char (*bufs)[256], int nbufs)
{
    int b = 0, k = 0;
    for (; g.argv[k]; k++) {
        const char *a = g.argv[k], *at = strstr(a, "{i}");
        if (!at || b == nbufs) {
            out[k] = g.argv[k];
            continue;
        }
        snprintf(bufs[b], sizeof bufs[b], "%.*s%d%s", (int)(at - a), a, i, at + 3);
        out[k] = bufs[b++];
    }
    out[k] = nullptr;
}

// Launcher thread t starts children t, t + step, ...
static void *launcher(void *arg)
{
    char *argv[256], bufs[16][256];
    for (int i = (int)(intptr_t)arg; i < g.n && !g.failed; i += g.step) {
        child_argv(i, argv, bufs, 16);
        int p[2];
        if (pipe2(p, O_CLOEXEC)) {
            g.failed = true;
            break;
        }
        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
        posix_spawn_file_actions_adddup2(&fa, p[1], 1);
        posix_spawn_file_actions_adddup2(&fa, p[1], 2);
        // Held across the spawn so the reaper can't see the pid before it
        // is stored.
        pthread_mutex_lock(&g.lock);
        g.c[i].t_launch = now_us();
        const int rc = posix_spawnp(&g.c[i].pid, argv[0], &fa, nullptr, argv, environ);
        if (rc) {
            fprintf(stderr, "posix_spawn %s: %s\n", g.argv[0], strerror(rc));
            g.failed = true;
            close(p[0]);
        } else {
            g.c[i].rd = p[0];
            g.launched++;
        }
        pthread_mutex_unlock(&g.lock);
        posix_spawn_file_actions_destroy(&fa);
        close(p[1]);
    }
    return nullptr;
}

static void *reaper(void *arg)
{
    (void)arg;
    for (;;) {
        int st;
        const pid_t pid = waitpid(-1, &st, 0);
        const double t = now_us();
        if (pid < 0) {
            // ECHILD: no child right now. Done once every launch happened
            // (or failed) and every launched child was reaped; otherwise
            // the next one just isn't there yet.
            pthread_mutex_lock(&g.lock);
            const bool over = (g.failed || g.launched == g.n) && g.reaped == g.launched;
            pthread_mutex_unlock(&g.lock);
            if (over)
                return nullptr;
            sched_yield();
            continue;
        }
        pthread_mutex_lock(&g.lock);
        for (int i = 0; i < g.n; i++) {
            if (g.c[i].pid == pid) {
                g.c[i].t_exit = t;
                g.c[i].status = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
                g.c[i].reaped = true;
                g.reaped++;
                break;
            }
        }
        const bool all = g.reaped == g.n;
        pthread_mutex_unlock(&g.lock);
        if (all)
            return nullptr;
    }
}

// Splits s on spaces into v (modifies s); returns the count.
static int split(char *s, char **v, int max)
{
    int n = 0;
    for (char *t = strtok(s, " "); t && n < max; t = strtok(nullptr, " "))
        v[n++] = t;
    return n;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: mvm-parlaunch N EXE \"ARGS\" [EXPECTED_STATUS]\n");
        return 2;
    }
    const int n = atoi(argv[1]);
    const int want = argc > 4 ? atoi(argv[4]) : 0;
    if (n < 1 || n > 4096)
        return 2;
    // One pipe per VM in flight.
    struct rlimit rl;
    if (!getrlimit(RLIMIT_NOFILE, &rl)) {
        rl.rlim_cur = rl.rlim_max;
        (void)setrlimit(RLIMIT_NOFILE, &rl);
    }
    char *wrap = getenv("MVM_PAR_WRAP") ? strdup(getenv("MVM_PAR_WRAP")) : nullptr;
    char *args = strdup(argv[3]);
    static char *cv[256];
    int k = wrap ? split(wrap, cv, 64) : 0;
    cv[k++] = argv[2];
    cv[k++] = "--trace";
    k += split(args, cv + k, 250 - k);
    cv[k] = nullptr;
    g.argv = cv;
    g.c = calloc((size_t)n, sizeof *g.c);
    struct pollfd *pf = calloc((size_t)n, sizeof *pf);
    int *pi = calloc((size_t)n, sizeof *pi);
    if (!g.c || !pf || !pi || !args)
        return 1;
    for (int i = 0; i < n; i++)
        g.c[i].rd = -1;
    g.n = n;
    const char *th = getenv("MVM_PAR_THREADS");
    int nth = th ? atoi(th) : 1;
    if (nth < 1 || nth > 64)
        nth = 1;
    g.step = nth;

    const double t0 = now_us();
    pthread_t ths[64], rt;
    for (int t = 0; t < nth; t++)
        pthread_create(&ths[t], nullptr, launcher, (void *)(intptr_t)t);
    pthread_create(&rt, nullptr, reaper, nullptr);

    // Read every child's output until EOF, noting when its MVMTRACE line
    // (written once the guest's exit status is known) is complete.
    int open_pipes = n;
    bool launching = true;
    while (open_pipes > 0) {
        int m = 0;
        pthread_mutex_lock(&g.lock);
        for (int i = 0; i < n; i++) {
            if (g.c[i].rd >= 0) {
                pf[m] = (struct pollfd){.fd = g.c[i].rd, .events = POLLIN};
                pi[m++] = i;
            }
        }
        const bool done_launching = g.launched == n || g.failed;
        pthread_mutex_unlock(&g.lock);
        if (launching && done_launching) {
            for (int t = 0; t < nth; t++)
                pthread_join(ths[t], nullptr);
            launching = false;
            if (g.failed)
                return 1;
        }
        if (poll(pf, (nfds_t)m, launching ? 1 : 100) <= 0)
            continue;
        const double t = now_us();
        for (int j = 0; j < m; j++) {
            if (!pf[j].revents)
                continue;
            child *c = &g.c[pi[j]];
            if (c->len + 4096 > c->cap) {
                c->cap = c->cap ? c->cap * 2 : 8192;
                c->buf = realloc(c->buf, c->cap);
                if (!c->buf)
                    return 1;
            }
            const ssize_t r = read(c->rd, c->buf + c->len, c->cap - c->len - 1);
            if (r > 0) {
                c->len += (size_t)r;
                c->buf[c->len] = 0;
                const char *tr = c->t_result ? nullptr : strstr(c->buf, "MVMTRACE");
                if (tr && strchr(tr, '\n'))
                    c->t_result = t;
                continue;
            }
            pthread_mutex_lock(&g.lock);
            close(c->rd);
            c->rd = -1;
            pthread_mutex_unlock(&g.lock);
            c->eof = true;
            open_pipes--;
        }
    }
    pthread_join(rt, nullptr);

    double last_result = 0, last_exit = 0;
    int bad = 0;
    double *res = malloc(n * sizeof *res), *tot = malloc(n * sizeof *tot), *gst = malloc(n * sizeof *gst),
           *wal = malloc(n * sizeof *wal), *pre = malloc(n * sizeof *pre), *post = malloc(n * sizeof *post);
    if (!res || !tot || !gst || !wal || !pre || !post)
        return 1;
    for (int i = 0; i < n; i++) {
        child *c = &g.c[i];
        const char *b = c->buf ? c->buf : "";
        const double total = field(b, "total_us="), start = field(b, "start_unix_us=");
        if (c->status != want || total < 0 || !c->t_result) {
            if (!bad)
                fprintf(stderr, "VM %d: status %d, output:\n%s\n", i, c->status, b);
            bad++;
        }
        if (c->t_result > last_result)
            last_result = c->t_result;
        if (c->t_exit > last_exit)
            last_exit = c->t_exit;
        res[i] = (c->t_result - c->t_launch) / 1000;
        wal[i] = (c->t_exit - c->t_launch) / 1000;
        tot[i] = total / 1000;
        gst[i] = field(b, "guest_us=") / 1000;
        pre[i] = (start - c->t_launch) / 1000;
        post[i] = (c->t_exit - start - total) / 1000;
    }
    printf("N=%d threads=%d  results in %.1f ms (%.0f VMs/s)  all reaped in %.1f ms  failed %d\n", n,
           nth, (last_result - t0) / 1000, n / ((last_result - t0) / 1e6), (last_exit - t0) / 1000,
           bad);
    report("result", res, n, "ms (launch -> exit status known)");
    report("wall", wal, n, "ms (launch -> reaped)");
    report("total", tot, n, "ms (VMM main -> guest exit status)");
    report("guest", gst, n, "ms");
    report("pre", pre, n, "ms (launch -> VMM main)");
    report("post", post, n, "ms (guest exit status -> reaped)");
    return bad ? 1 : 0;
}
