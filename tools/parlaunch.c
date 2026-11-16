// SPDX-License-Identifier: MIT
// Parallel cold starts: launch N microvm processes back to back, wait for
// all, report per-VM latency and the batch's throughput.
//
//   mvm-parlaunch N EXE "ARGS" [EXPECTED_STATUS]
//   (MVM_PAR_THREADS=T: launch from T threads; default 1)
//   build\mvm-parlaunch 32 build\microvm.exe "--kernel guest\kernel\out\vmlinux --quiet --ws ws.txt"
//
// Each child gets `--trace` (prepended) and a private pipe for its output,
// so nothing it prints is lost and no handle leaks into the others.
// Per VM: wall = process creation -> exit (GetProcessTimes, so it includes
// Windows process creation and teardown); total/guest = the VMM's own
// MVMTRACE fields. Batch: makespan = first CreateProcess -> last exit.
// This is the Windows build; tools/parlaunch_posix.c is the Linux one.
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    PROCESS_INFORMATION pi;
    HANDLE rd;
    double total_us, guest_us, wall_ms, pre_ms, post_ms;
    DWORD code;
} child;

static int cmp(const void *a, const void *b)
{
    const double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void report(const char *what, double *v, int n, double scale, const char *unit)
{
    qsort(v, (size_t)n, sizeof *v, cmp);
    printf("  %-8s p50 %7.2f  p90 %7.2f  max %7.2f %s\n", what, v[n / 2] * scale,
           v[(n * 9) / 10 < n ? (n * 9) / 10 : n - 1] * scale, v[n - 1] * scale, unit);
}

static double field(const char *s, const char *name)
{
    const char *p = strstr(s, name);
    return p ? strtod(p + strlen(name), nullptr) : -1;
}

static ULONGLONG ft(FILETIME f) { return (ULONGLONG)f.dwHighDateTime << 32 | f.dwLowDateTime; }

static struct {
    child *c;
    int n, step;
    const char *cmd;
    HANDLE nul;
    volatile LONG failed;
} g;

// Launcher thread t starts children t, t + step, ... Each child inherits
// exactly its own pipe's write end and NUL (an explicit handle list), so
// concurrent launches can't leak one child's pipe into another.
static DWORD WINAPI launcher(void *arg)
{
    char cmd[4096];
    for (int i = (int)(intptr_t)arg; i < g.n && !g.failed; i += g.step) {
        SECURITY_ATTRIBUTES sa = {sizeof sa, nullptr, TRUE};
        HANDLE wr;
        // 1 MiB of pipe buffer: a child never blocks on output before we read it.
        if (!CreatePipe(&g.c[i].rd, &wr, &sa, 1 << 20) ||
            !SetHandleInformation(g.c[i].rd, HANDLE_FLAG_INHERIT, 0)) {
            InterlockedExchange(&g.failed, 1);
            break;
        }
        HANDLE inherit[2] = {g.nul, wr};
        SIZE_T sz = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &sz);
        LPPROC_THREAD_ATTRIBUTE_LIST al = HeapAlloc(GetProcessHeap(), 0, sz);
        STARTUPINFOEXA si = {.StartupInfo = {.cb = sizeof si, .dwFlags = STARTF_USESTDHANDLES,
                                             .hStdInput = g.nul, .hStdOutput = wr, .hStdError = wr}};
        if (!al || !InitializeProcThreadAttributeList(al, 1, 0, &sz) ||
            !UpdateProcThreadAttribute(al, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit,
                                       sizeof inherit, nullptr, nullptr)) {
            InterlockedExchange(&g.failed, 1);
            break;
        }
        si.lpAttributeList = al;
        snprintf(cmd, sizeof cmd, "%s", g.cmd);
        if (!CreateProcessA(nullptr, cmd, nullptr, nullptr, TRUE,
                            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
                            &si.StartupInfo, &g.c[i].pi)) {
            fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError());
            InterlockedExchange(&g.failed, 1);
        }
        DeleteProcThreadAttributeList(al);
        HeapFree(GetProcessHeap(), 0, al);
        CloseHandle(wr);
        if (!g.failed)
            CloseHandle(g.c[i].pi.hThread);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: mvm-parlaunch N EXE \"ARGS\" [EXPECTED_STATUS]\n");
        return 2;
    }
    const int n = atoi(argv[1]);
    const DWORD want = argc > 4 ? (DWORD)atoi(argv[4]) : 0;
    if (n < 1 || n > 4096)
        return 2;
    child *c = calloc((size_t)n, sizeof *c);
    char *cmd = malloc(strlen(argv[2]) + strlen(argv[3]) + 32);
    if (!c || !cmd)
        return 1;
    sprintf(cmd, "\"%s\" --trace %s", argv[2], argv[3]);
    SECURITY_ATTRIBUTES sa = {sizeof sa, nullptr, TRUE};
    g.nul = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING,
                        0, nullptr);
    g.c = c;
    g.n = n;
    g.cmd = cmd;
    const char *th = getenv("MVM_PAR_THREADS");
    int nth = th ? atoi(th) : 1;
    if (nth < 1 || nth > 64)
        nth = 1;
    g.step = nth;

    FILETIME f0;
    GetSystemTimePreciseAsFileTime(&f0);
    LARGE_INTEGER q0, q1, qf;
    QueryPerformanceCounter(&q0);
    HANDLE ths[64];
    for (int t = 0; t < nth; t++)
        ths[t] = CreateThread(nullptr, 0, launcher, (void *)(intptr_t)t, 0, nullptr);
    WaitForMultipleObjects((DWORD)nth, ths, TRUE, INFINITE);
    QueryPerformanceCounter(&q1);
    QueryPerformanceFrequency(&qf);
    if (g.failed)
        return 1;
    const double launch_ms = (double)(q1.QuadPart - q0.QuadPart) * 1e3 / (double)qf.QuadPart;
    ULONGLONG last_exit = 0;
    int bad = 0;
    double *tot = malloc(n * sizeof *tot), *gst = malloc(n * sizeof *gst), *wal = malloc(n * sizeof *wal), *pre = malloc(n * sizeof *pre), *post = malloc(n * sizeof *post);
    char *buf = malloc(1 << 20);
    if (!tot || !gst || !wal || !buf)
        return 1;
    for (int i = 0; i < n; i++) {
        WaitForSingleObject(c[i].pi.hProcess, INFINITE);
        GetExitCodeProcess(c[i].pi.hProcess, &c[i].code);
        FILETIME cr, ex, k, u;
        GetProcessTimes(c[i].pi.hProcess, &cr, &ex, &k, &u);
        c[i].wall_ms = (double)(ft(ex) - ft(cr)) / 1e4;
        if (ft(ex) > last_exit)
            last_exit = ft(ex);
        DWORD got = 0, r;
        while (got < (1 << 20) - 1 && ReadFile(c[i].rd, buf + got, (1 << 20) - 1 - got, &r, nullptr) && r)
            got += r;
        buf[got] = 0;
        c[i].total_us = field(buf, "total_us=");
        c[i].guest_us = field(buf, "guest_us=");
        // FILETIME (100 ns since 1601) -> Unix microseconds
        const double cr_us = (double)(ft(cr) - 116444736000000000ull) / 10;
        const double ex_us = (double)(ft(ex) - 116444736000000000ull) / 10;
        const double st_us = field(buf, "start_unix_us=");
        c[i].pre_ms = (st_us - cr_us) / 1000;
        c[i].post_ms = (ex_us - st_us - c[i].total_us) / 1000;
        if (c[i].code != want || c[i].total_us < 0) {
            if (!bad)
                fprintf(stderr, "VM %d: status %lu, output:\n%s\n", i, c[i].code, buf);
            bad++;
        }
        tot[i] = c[i].total_us;
        gst[i] = c[i].guest_us;
        wal[i] = c[i].wall_ms;
        pre[i] = c[i].pre_ms;
        post[i] = c[i].post_ms;
        CloseHandle(c[i].rd);
        CloseHandle(c[i].pi.hProcess);
    }
    const double span_ms = (double)(last_exit - ft(f0)) / 1e4;
    printf("N=%d threads=%d  launch %.1f ms (%.2f ms/VM)  makespan %.1f ms  throughput %.0f VMs/s  failed %d\n",
           n, nth, launch_ms, launch_ms / n, span_ms, n / (span_ms / 1000), bad);
    report("wall", wal, n, 1, "ms (process created -> exited)");
    report("total", tot, n, 1e-3, "ms (VMM main -> guest exit status)");
    report("guest", gst, n, 1e-3, "ms");
    report("pre", pre, n, 1, "ms (process created -> VMM main)");
    report("post", post, n, 1, "ms (guest exit status -> process exited)");
    return bad ? 1 : 0;
}
