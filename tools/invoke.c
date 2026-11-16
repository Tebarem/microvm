// SPDX-License-Identifier: MIT
// microvm-invoke: send invocations to a VM's guest agent and print what
// comes back (Linux host).
//
//   microvm-invoke SOCK [options] [-- ARG...]
//     SOCK              the VMM's --vsock socket
//     --deadline MS     the invocation's deadline (default 3000)
//     --env K=V         an environment string for the invocation (repeatable)
//     --payload FILE    the payload ("-": stdin; default: none)
//     --count N         run the same invocation N times on one connection
//     --connect-ms MS   how long to wait for the VM (default 5000)
//
// The result goes to stdout, the function's stdout and stderr to stderr
// (prefixed), and a summary line to stderr. Exit status: the function's
// status if it returned, 128 + N if the runtime died of signal N, 124 on a
// timeout, 125 on any other failure.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "agent/agent.h"

static uint8_t *slurp(const char *path, size_t *len)
{
    FILE *f = strcmp(path, "-") ? fopen(path, "rb") : stdin;
    if (!f)
        return nullptr;
    size_t cap = 65536, n = 0;
    uint8_t *b = malloc(cap);
    for (size_t r; b && (r = fread(b + n, 1, cap - n, f)) > 0;) {
        n += r;
        if (n == cap && n <= MVA_MAX_PAYLOAD) {
            uint8_t *nb = realloc(b, cap *= 2);
            if (!nb)
                free(b);
            b = nb;
        }
    }
    if (f != stdin)
        fclose(f);
    *len = n;
    return b;
}

static void dump(const char *tag, const mva_buf *b)
{
    if (!b->len)
        return;
    fprintf(stderr, "--- %s (%zu bytes)\n", tag, b->len);
    fwrite(b->data, 1, b->len, stderr);
    if (b->data[b->len - 1] != '\n')
        fputc('\n', stderr);
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        printf("microvm-invoke %s\n", MICROVM_VERSION);
        return 0;
    }
    if (argc < 2) {
        fprintf(stderr, "usage: microvm-invoke SOCK [--deadline MS] [--env K=V]... [--payload FILE] "
                        "[--count N] [--connect-ms MS] [-- ARG...]\n"
                        "       microvm-invoke --version\n");
        return 125;
    }
    static const char *envp[MVA_MAX_STRINGS];
    size_t nenv = 0, payload_len = 0;
    uint8_t *payload = nullptr;
    unsigned long deadline = 3000, count = 1, connect_ms = 5000;
    int i = 2;
    for (; i < argc && strcmp(argv[i], "--"); i++) {
        const bool v = i + 1 < argc;
        if (!strcmp(argv[i], "--version")) {
            printf("microvm-invoke %s\n", MICROVM_VERSION);
            return 0;
        }
        if (!strcmp(argv[i], "--deadline") && v)
            deadline = strtoul(argv[++i], nullptr, 10);
        else if (!strcmp(argv[i], "--env") && v && nenv < MVA_MAX_STRINGS)
            envp[nenv++] = argv[++i];
        else if (!strcmp(argv[i], "--payload") && v) {
            if (!(payload = slurp(argv[++i], &payload_len))) {
                fprintf(stderr, "microvm-invoke: cannot read %s\n", argv[i]);
                return 125;
            }
        } else if (!strcmp(argv[i], "--count") && v)
            count = strtoul(argv[++i], nullptr, 10);
        else if (!strcmp(argv[i], "--connect-ms") && v)
            connect_ms = strtoul(argv[++i], nullptr, 10);
        else {
            fprintf(stderr, "microvm-invoke: unknown option %s\n", argv[i]);
            return 125;
        }
    }
    const char *const *args = (const char *const *)argv + (i < argc ? i + 1 : argc);
    const size_t nargs = (size_t)(argv + argc - (char **)args);
    static mva_client c;
    if (mva_connect(&c, argv[1], (int)connect_ms)) {
        fprintf(stderr, "microvm-invoke: %s\n", c.error);
        return 125;
    }
    int rc = 0;
    for (unsigned long k = 0; k < count; k++) {
        const mva_request rq = {.deadline_ms = (uint32_t)deadline, .argv = args, .nargs = nargs,
                                .envp = envp, .nenv = nenv, .payload = payload,
                                .payload_len = payload_len};
        mva_response rs = {0};
        if (mva_invoke(&c, &rq, &rs, 1000)) {
            fprintf(stderr, "microvm-invoke: %s\n", c.error);
            mva_response_free(&rs);
            return 125;
        }
        fwrite(rs.result.data ? (const void *)rs.result.data : "", 1, rs.result.len, stdout);
        fflush(stdout);
        dump("stdout", &rs.out);
        dump("stderr", &rs.err);
        static const char *const kinds[] = {"returned", "exited", "signaled", "timeout", "refused", "fault"};
        fprintf(stderr, "--- %s %d in %u us%s%s\n", kinds[rs.kind], rs.status, rs.duration_us,
                rs.flags & (MVA_DONE_TRUNC_RESULT | MVA_DONE_TRUNC_STDOUT | MVA_DONE_TRUNC_STDERR) ? ", truncated" : "",
                rs.flags & MVA_DONE_VM_ENDS ? ", the VM ended" : "");
        rc = rs.kind == MVA_RETURNED || rs.kind == MVA_EXITED ? rs.status & 0xff
             : rs.kind == MVA_SIGNALED                       ? 128 + (rs.status & 0x7f)
             : rs.kind == MVA_TIMEOUT                        ? 124
                                                             : 125;
        mva_response_free(&rs);
        if (c.dead)
            break;
    }
    mva_close(&c);
    free(payload);
    return rc;
}
