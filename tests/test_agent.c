// SPDX-License-Identifier: MIT
// End-to-end test of function invocations (Linux, KVM): the guest agent
// (`/init agent`) and the demo runtime /bin/fn-demo, driven through the
// host library (src/agent/agent.h).
//
// 1. A cold boot serves invocations: arguments, environment, payload in,
//    result, stdout, stderr and status out; a 1 MiB payload and a 3 MiB
//    result; output caps; the runtime exiting mid-invocation ends the VM.
// 2. The runtime warms up and asks for the snapshot: the VMM saves it.
// 3. N restores: each serves several invocations (warm reuse, across
//    reconnects); every restore shares the warm-up state but not the
//    random numbers, and has the host's clock.
// 4. On restored VMs: a deadline overrun, a crash, a protocol fault, and
//    the host hanging up mid-invocation each end the VM as specified.
//
//   mvm_agent_tests MICROVM VMLINUX IMAGE [--bench [N]] [--jail MICROVM-JAIL]
//
// --bench measures restore -> first response and the invocation round
// trip instead. --jail starts every VM through microvm-jail
// (tests/jail_wrap.h): the vsock socket and the snapshot live in a :rw
// bind, and the host reaches them by their host paths. Exits 77 (skipped)
// without a usable /dev/kvm.
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "agent/agent.h"
#include "jail_wrap.h"

static int fails;
static char dir[] = "/tmp/mvm-agent-XXXXXX";
static jw_cfg jw; // the VMM, directly or through microvm-jail

static void check(bool ok, const char *what)
{
    printf("  %-62s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok)
        fails++;
}

static double now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

static double unix_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (double)t.tv_sec + t.tv_nsec / 1e9;
}

typedef struct {
    pid_t pid;
    char sock[108], out[128];
} vmproc;

// Start the VMM: args after the binary, nullptr-terminated.
static void spawn(vmproc *v, const char *tag, const char *const *args)
{
    snprintf(v->sock, sizeof v->sock, "%s/%s.sock", dir, tag);
    snprintf(v->out, sizeof v->out, "%s/%s.out", dir, tag);
    unlink(v->sock);
    const char *vmm[32], *a[96];
    int n = 0;
    for (; args[n] && n < 31; n++)
        vmm[n] = strcmp(args[n], "@SOCK") ? args[n] : v->sock;
    vmm[n] = nullptr;
    if (jw_wrap(&jw, vmm, a, 96)) {
        printf("  (command line too long)\n");
        v->pid = -1;
        return;
    }
    v->pid = fork_child();
    if (v->pid == 0) {
        const int o = open(v->out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        dup2(o, 1);
        dup2(o, 2);
        execv(a[0], (char **)a);
        _exit(127);
    }
}

// Wait up to ms for the VMM to exit; kill it after that. Returns its
// exit status (or 128 + signal), and the console output in buf.
static int reap_vm(vmproc *v, double ms, char *buf, size_t cap)
{
    int st = 0;
    const double end = now_ms() + ms;
    while (v->pid > 0 && waitpid(v->pid, &st, WNOHANG) == 0) {
        if (now_ms() > end) {
            kill(v->pid, SIGKILL);
            waitpid(v->pid, &st, 0);
            break;
        }
        usleep(500);
    }
    if (v->pid < 0)
        st = 127 << 8;
    if (buf) {
        memset(buf, 0, cap);
        const int o = open(v->out, O_RDONLY);
        if (o >= 0) {
            (void)!read(o, buf, cap - 1);
            close(o);
        }
    }
    unlink(v->out);
    unlink(v->sock);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

static bool buf_is(const mva_buf *b, const char *s)
{
    return b->len == strlen(s) && (!b->len || !memcmp(b->data, s, b->len));
}

static int call(mva_client *c, mva_response *rs, const char *const *args, size_t nargs, const void *payload,
                size_t plen, uint32_t deadline_ms)
{
    mva_response_free(rs);
    const mva_request rq = {.deadline_ms = deadline_ms, .argv = args, .nargs = nargs, .payload = payload,
                            .payload_len = plen};
    const int r = mva_invoke(c, &rq, rs, 2000);
    if (r)
        printf("  (invoke: %s)\n", c->error);
    return r;
}

// "n=1 token=... random=... time=... wof=..." -> fields.
typedef struct {
    unsigned long n, token;
    char random[40];
    double time;
    int wof;
} info;

static bool parse_info(const mva_buf *b, info *in)
{
    char s[512] = {0};
    if (!b->len || b->len >= sizeof s)
        return false;
    memcpy(s, b->data, b->len);
    return sscanf(s, "n=%lu token=%lu random=%32s time=%lf wof=%d", &in->n, &in->token, in->random, &in->time,
                  &in->wof) == 5;
}

static const char *K, *IMG;

static void cold(void)
{
    printf("cold boot, no snapshot:\n");
    vmproc v;
    const char *const args[] = {"--kernel", K, "--quiet", "--rootfs", IMG, "--vsock", "@SOCK", "--append",
                                "agent", "--", "/bin/fn-demo", "nosnap", nullptr};
    spawn(&v, "cold", args);
    static mva_client c;
    mva_response rs = {0};
    check(!mva_connect(&c, v.sock, 5000) && !mva_hello(&c, 2000) && c.p.served == 0,
          "connected; HELLO (0 invocations served)");

    const char *echo[] = {"echo", "two words"}, *envp[] = {"A=1", "LANG=C.UTF-8"};
    mva_request rq = {.deadline_ms = 2000, .argv = echo, .nargs = 2, .envp = envp, .nenv = 2,
                      .payload = "hello, function", .payload_len = 15};
    check(!mva_invoke(&c, &rq, &rs, 2000) && rs.done && rs.kind == MVA_RETURNED && rs.status == 0 &&
              buf_is(&rs.result, "hello, function") && buf_is(&rs.out, "echo: payload bytes 15\n") &&
              buf_is(&rs.err, "echo: on stderr, invocation 1\n") && !c.dead,
          "echo: result, stdout, stderr, status");
    const char *env[] = {"env"};
    rq.argv = env, rq.nargs = 1, rq.payload_len = 0;
    mva_response_free(&rs);
    check(!mva_invoke(&c, &rq, &rs, 2000) && buf_is(&rs.result, "A=1\nLANG=C.UTF-8\n"), "the environment");
    const char *status[] = {"status", "7"};
    check(!call(&c, &rs, status, 2, nullptr, 0, 2000) && rs.kind == MVA_RETURNED && rs.status == 7,
          "a returned status");
    const char *upper[] = {"upper"};
    check(!call(&c, &rs, upper, 1, "MiXeD case", 10, 2000) && buf_is(&rs.result, "MIXED CASE"), "upper");
    const char *inf[] = {"info"};
    info in = {0};
    check(!call(&c, &rs, inf, 1, nullptr, 0, 2000) && parse_info(&rs.result, &in) && in.wof == 1,
          "no restore: the MADV_WIPEONFORK page keeps what warm-up wrote");
    // 1 MiB in, 1 MiB back: more than every buffer on the way.
    const size_t big = 1u << 20;
    uint8_t *pl = malloc(big);
    for (size_t i = 0; i < big; i++)
        pl[i] = (uint8_t)(i * 131 + (i >> 11));
    check(!call(&c, &rs, echo, 1, pl, big, 5000) && rs.result.len == big && !memcmp(rs.result.data, pl, big),
          "a 1 MiB payload echoed intact");
    free(pl);
    const char *bigres[] = {"big", "3000000"};
    bool ok = !call(&c, &rs, bigres, 2, nullptr, 0, 5000) && rs.result.len == 3000000 && !rs.flags;
    for (size_t i = 0; ok && i < rs.result.len; i++)
        ok = rs.result.data[i] == 'a' + i % 26;
    check(ok, "a 3 MB result");
    // Caps: the agent truncates and says so; the host holds it to them.
    rq = (mva_request){.deadline_ms = 5000, .argv = (const char *[]){"spam", "300000"}, .nargs = 2,
                       .max_output = 100000, .max_result = 10};
    mva_response_free(&rs);
    check(!mva_invoke(&c, &rq, &rs, 2000) && rs.out.len == 100000 && rs.err.len == 100000 &&
              rs.flags == (MVA_DONE_TRUNC_STDOUT | MVA_DONE_TRUNC_STDERR) && !c.dead,
          "stdout and stderr past the cap: truncated, flagged");
    rq = (mva_request){.deadline_ms = 5000, .argv = bigres, .nargs = 2, .max_result = 1000};
    mva_response_free(&rs);
    check(!mva_invoke(&c, &rq, &rs, 2000) && rs.result.len == 1000 && rs.flags == MVA_DONE_TRUNC_RESULT,
          "a result past the cap: truncated, flagged");
    const char *unknown[] = {"nosuch"};
    check(!call(&c, &rs, unknown, 1, nullptr, 0, 2000) && rs.status == 64, "the VM still serves");
    const char *ex[] = {"exit", "3"};
    check(!call(&c, &rs, ex, 2, nullptr, 0, 2000) && rs.kind == MVA_EXITED && rs.status == 3 &&
              (rs.flags & MVA_DONE_VM_ENDS) && buf_is(&rs.out, "exiting\n") && c.dead,
          "the runtime exits mid-invocation: EXITED 3, the VM ends");
    mva_response_free(&rs);
    mva_close(&c);
    char out[2048];
    const int st = reap_vm(&v, 3000, out, sizeof out);
    check(st == 3, "the VMM exits with the runtime's status");
    if (st != 3)
        printf("  status %d; console:\n%s\n", st, out);
}

static char snap[128];

static bool take_snapshot(void)
{
    printf("snapshot after warm-up:\n");
    snprintf(snap, sizeof snap, "%s/snap", dir);
    vmproc v;
    const char *const args[] = {"--kernel", K, "--quiet", "--rootfs", IMG, "--vsock", "@SOCK", "--append", "agent",
                                "--snapshot", snap, "--", "/bin/fn-demo", nullptr};
    spawn(&v, "take", args);
    char out[2048];
    const int st = reap_vm(&v, 10000, out, sizeof out);
    struct stat sb;
    const bool ok = st == 0 && !stat(snap, &sb) && sb.st_size > 0;
    check(ok, "the runtime asked; the VMM saved the VM and stopped (status 0)");
    check(strstr(out, "fn-demo: warmed up") != nullptr, "warm-up ran before the snapshot (its console output)");
    if (!ok)
        printf("  status %d; console:\n%s\n", st, out);
    return ok;
}

static void restore(vmproc *v, const char *tag)
{
    const char *const args[] = {"--restore", snap, "--rootfs", IMG, "--vsock", "@SOCK", nullptr};
    spawn(v, tag, args);
}

static void restores(int n)
{
    printf("%d restores:\n", n);
    usleep(300 * 1000); // so a clock taken from the snapshot would be visibly off
    char rnd[16][40] = {{0}};
    unsigned long token = 0;
    bool all_ok = true, tok_ok = true, time_ok = true, warm_ok = true, reconnect_ok = true, wof_ok = true;
    for (int i = 0; i < n && i < 16; i++) {
        vmproc v;
        char tag[16];
        snprintf(tag, sizeof tag, "r%d", i);
        restore(&v, tag);
        static mva_client c;
        mva_response rs = {0};
        const char *inf[] = {"info", "x", "y"};
        info a = {0}, b = {0};
        bool ok = !mva_connect(&c, v.sock, 5000) && !call(&c, &rs, inf, 3, nullptr, 0, 2000) &&
                  rs.kind == MVA_RETURNED && parse_info(&rs.result, &a) && a.n == 1;
        const double host = unix_s();
        static const char want[] = "message=from the image args=x,y";
        ok = ok && memmem(rs.result.data, rs.result.len, want, sizeof want - 1) != nullptr;
        // Warm reuse: the same runtime serves the next one.
        ok = ok && !call(&c, &rs, inf, 1, nullptr, 0, 2000) && parse_info(&rs.result, &b) && b.n == 2;
        warm_ok &= ok && b.token == a.token && strcmp(a.random, b.random);
        all_ok &= ok;
        if (!i)
            token = a.token;
        tok_ok &= a.token == token;
        time_ok &= a.time > host - 1.0 && a.time <= host + 0.1;
        wof_ok &= a.wof == 0;
        snprintf(rnd[i], sizeof rnd[i], "%s", a.random);
        // Hang up and come back: a third invocation, HELLO says 2 served.
        mva_close(&c);
        const char *echo[] = {"echo"};
        reconnect_ok &= !mva_connect(&c, v.sock, 2000) && !mva_hello(&c, 2000) && c.p.served == 2 &&
                        !call(&c, &rs, echo, 1, "again", 5, 2000) && buf_is(&rs.result, "again");
        mva_response_free(&rs);
        mva_close(&c);
        reap_vm(&v, 0, nullptr, 0);
    }
    check(all_ok, "every restore serves invocations, with the warm-up's state");
    check(tok_ok, "the same warm-up token in every restore (snapshot after warm-up)");
    check(warm_ok, "warm reuse: invocation 2 in the same runtime, fresh randomness");
    check(reconnect_ok, "a reconnect: HELLO counts 2 served, a third invocation works");
    check(time_ok, "restored guests have the host's clock");
    check(wof_ok, "the runtime's MADV_WIPEONFORK page is zeroed in every restore (RNDVMFORK)");
    bool distinct = true;
    for (int i = 0; i < n && i < 16; i++)
        for (int j = 0; j < i; j++)
            distinct &= rnd[i][0] && strcmp(rnd[i], rnd[j]);
    check(distinct, "no two restores share random numbers (reseeded at the snapshot point)");
}

// One restored VM, one invocation that ends it.
static void ending(const char *what, const char *const *args, size_t nargs, uint32_t deadline_ms, uint32_t kind,
                   int32_t status, int vm_status, bool hang_up)
{
    vmproc v;
    restore(&v, "end");
    static mva_client c;
    mva_response rs = {0};
    bool ok = !mva_connect(&c, v.sock, 5000);
    const double t0 = now_ms();
    if (ok && hang_up) {
        // Send it, then hang up mid-invocation.
        size_t len;
        uint8_t *f = mva_encode_invoke(&(mva_request){.deadline_ms = deadline_ms, .argv = args, .nargs = nargs},
                                       1, &len);
        ok = write(c.fd, f, len) == (ssize_t)len;
        free(f);
        usleep(50 * 1000);
        mva_close(&c);
    } else if (ok) {
        ok = !call(&c, &rs, args, nargs, nullptr, 0, deadline_ms) && rs.kind == kind && rs.status == status &&
             (rs.flags & MVA_DONE_VM_ENDS) && c.dead;
        if (!ok)
            printf("  (kind %u status %d flags %#x)\n", rs.kind, rs.status, rs.flags);
        mva_close(&c);
    }
    const double t_done = now_ms() - t0;
    mva_response_free(&rs);
    char out[2048];
    const int st = reap_vm(&v, 3000, out, sizeof out);
    ok = ok && st == vm_status;
    check(ok, what);
    if (!ok)
        printf("  VMM status %d (want %d) after %.0f ms; console:\n%s\n", st, vm_status, t_done, out);
}

// ---- benchmarks ------------------------------------------------------------------

static int cmp_d(const void *a, const void *b)
{
    const double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static double pct(double *v, int n, double p)
{
    qsort(v, (size_t)n, sizeof *v, cmp_d);
    return v[(int)(p * (n - 1) + 0.5)];
}

static void bench(int n)
{
    // Restore -> first response.
    double *conn = calloc((size_t)n, sizeof(double)), *first = calloc((size_t)n, sizeof(double));
    int got = 0;
    for (int i = 0; i < n; i++) {
        vmproc v;
        const double t0 = now_ms();
        restore(&v, "b");
        static mva_client c;
        mva_response rs = {0};
        const char *echo[] = {"echo"};
        if (!mva_connect(&c, v.sock, 5000)) {
            const double t1 = now_ms();
            if (!call(&c, &rs, echo, 1, "x", 1, 2000) && buf_is(&rs.result, "x")) {
                conn[got] = t1 - t0;
                first[got++] = now_ms() - t0;
            }
        }
        mva_response_free(&rs);
        mva_close(&c);
        reap_vm(&v, 0, nullptr, 0);
    }
    if (got)
        printf("restore -> connected: p50 %.2f ms, p90 %.2f ms; -> first response: p50 %.2f ms, p90 %.2f ms "
               "(%d runs)\n",
               pct(conn, got, 0.5), pct(conn, got, 0.9), pct(first, got, 0.5), pct(first, got, 0.9), got);
    free(conn);
    free(first);

    // Round trips on one warm VM.
    vmproc v;
    restore(&v, "rt");
    static mva_client c;
    mva_response rs = {0};
    if (mva_connect(&c, v.sock, 5000)) {
        printf("bench: cannot connect\n");
        return;
    }
    const char *echo[] = {"echo"};
    static const size_t sizes[] = {0, 1024, 65536, 1u << 20};
    for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
        const int iters = sizes[s] >= (1u << 20) ? 200 : 2000;
        uint8_t *pl = calloc(1, sizes[s] + 1);
        double *rt = calloc((size_t)iters, sizeof(double));
        int k = 0;
        for (int i = 0; i < iters; i++) {
            const double t0 = now_ms();
            if (call(&c, &rs, echo, 1, pl, sizes[s], 2000) || rs.result.len != sizes[s])
                break;
            rt[k++] = (now_ms() - t0) * 1000;
        }
        if (k)
            printf("invocation round trip, %7zu-byte payload and result: p50 %.1f us, p99 %.1f us (%d)\n", sizes[s],
                   pct(rt, k, 0.5), pct(rt, k, 0.99), k);
        free(pl);
        free(rt);
    }
    mva_response_free(&rs);
    mva_close(&c);
    reap_vm(&v, 0, nullptr, 0);
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s MICROVM VMLINUX IMAGE [--bench [N]]\n", argv[0]);
        return 2;
    }
    setvbuf(stdout, nullptr, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    jw.jail = jw_take_arg(&argc, argv);
    K = argv[2];
    IMG = argv[3];
    const bool do_bench = argc > 4 && !strcmp(argv[4], "--bench");
    if (access("/dev/kvm", R_OK | W_OK)) {
        printf("skipped: no usable /dev/kvm\n");
        return 77;
    }
    if (jw.jail && !jw_usable()) {
        printf("skipped: microvm-jail needs root or unprivileged user namespaces\n");
        return 77;
    }
    if (!mkdtemp(dir))
        return 1;
    jw.vmm = argv[1], jw.kernel = K, jw.rootfs = IMG, jw.dir = dir;
    if (jw.jail) {
        chmod(dir, 0777); // as root, the VM's uid is 65534
        printf("every VM through %s%s\n", jw.jail, geteuid() ? " (unprivileged)" : " (as root: VM uid 65534)");
    }
    if (!do_bench)
        cold();
    if (take_snapshot()) {
        if (do_bench) {
            bench(argc > 5 ? atoi(argv[5]) : 50);
        } else {
            restores(5);
            printf("invocations that end a restored VM:\n");
            const char *sl[] = {"sleep", "3000"}, *cr[] = {"crash"}, *bf[] = {"badframe"};
            ending("past the deadline: TIMEOUT, the VM ends (124)", sl, 2, 200, MVA_TIMEOUT, 0, 124, false);
            ending("a crash: SIGNALED 11, the VM ends (139)", cr, 1, 2000, MVA_SIGNALED, 11, 139, false);
            ending("a malformed frame from the runtime: FAULT, the VM ends (125)", bf, 1, 2000, MVA_FAULT, 0, 125,
                   false);
            ending("the host hangs up mid-invocation: the VM ends (125)", sl, 2, 5000, 0, 0, 125, true);
        }
    }
    unlink(snap);
    rmdir(dir);
    printf(fails ? "%d checks FAILED\n" : "all checks passed\n", fails);
    return fails ? 1 : 0;
}
