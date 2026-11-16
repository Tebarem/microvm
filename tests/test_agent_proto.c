// SPDX-License-Identifier: MIT
// Unit tests for the host side of the agent protocol (src/agent/parse.c):
// INVOKE encoding limits, and hostile guest streams the parser must refuse.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent/agent.h"
#include "common.h"

static int fails;

static void check(bool ok, const char *what)
{
    printf("  %-60s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok)
        fails++;
}

static uint8_t s[1 << 20];
static size_t n;

static void frame(uint8_t type, uint32_t id, const void *body, uint32_t len)
{
    put_le32(s + n, MVA_MAGIC);
    s[n + 4] = MVA_VERSION;
    s[n + 5] = type;
    put_le16(s + n + 6, 0);
    put_le32(s + n + 8, id);
    put_le32(s + n + 12, len);
    if (len)
        memcpy(s + n + MVA_HDR, body, len);
    n += MVA_HDR + len;
}

static void hello(void)
{
    uint8_t b[16] = {0};
    put_le32(b, MVA_VERSION);
    frame(MVA_HELLO, 0, b, 16);
}

static void done(uint32_t id, uint32_t kind, int32_t status, uint32_t flags)
{
    uint8_t b[16] = {0};
    put_le32(b, kind);
    put_le32(b + 4, (uint32_t)status);
    put_le32(b + 8, flags);
    frame(MVA_DONE, id, b, 16);
}

// Parse s[0..n) as the reply to INVOKE 1 with these caps. Returns the
// parser's error (nullptr if none) and fills rs.
static const char *parse(uint32_t max_result, uint32_t max_output, mva_response *rs, size_t *consumed)
{
    static mva_parser p;
    mva_parser_init(&p);
    mva_parser_expect(&p, 1, max_result, max_output);
    *rs = (mva_response){0};
    const size_t k = mva_parse(&p, s, n, rs);
    if (consumed)
        *consumed = k;
    return p.error;
}

static bool refused(const char *what, uint32_t max_result, uint32_t max_output)
{
    mva_response rs;
    const char *e = parse(max_result, max_output, &rs, nullptr);
    if (!e)
        printf("  (accepted: %s)\n", what);
    mva_response_free(&rs);
    return e != nullptr;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    mva_response rs;

    // A good reply.
    n = 0;
    hello();
    frame(MVA_STDOUT, 1, "out", 3);
    frame(MVA_STDERR, 1, "err", 3);
    frame(MVA_RESULT, 1, "res", 3);
    frame(MVA_RESULT, 1, "ult", 3);
    done(1, MVA_RETURNED, 7, MVA_DONE_TRUNC_STDOUT);
    size_t k = 0;
    const char *e = parse(0, 0, &rs, &k);
    check(!e && rs.done && k == n, "a well-formed reply parses to the end");
    check(rs.result.len == 6 && !memcmp(rs.result.data, "result", 6) && rs.out.len == 3 &&
              !memcmp(rs.out.data, "out", 3) && rs.err.len == 3 && rs.status == 7 &&
              rs.flags == MVA_DONE_TRUNC_STDOUT,
          "result, stdout, stderr, status and flags come through");
    mva_response_free(&rs);

    // Byte by byte gives the same.
    {
        mva_parser p;
        mva_parser_init(&p);
        mva_parser_expect(&p, 1, 0, 0);
        mva_response r = {0};
        size_t at = 0;
        while (at < n && !r.done && !p.error)
            at += mva_parse(&p, s + at, 1, &r);
        check(!p.error && r.done && at == n && r.result.len == 6, "the same reply one byte at a time");
        mva_response_free(&r);
    }

    // Data after DONE is not consumed.
    const size_t good = n;
    frame(MVA_STDOUT, 1, "late", 4);
    e = parse(0, 0, &rs, &k);
    check(!e && rs.done && k == good, "parsing stops at DONE");
    mva_response_free(&rs);

    // Hostile streams.
    uint8_t hb[16] = {0};
    put_le32(hb, MVA_VERSION);
    n = 0;
    frame(MVA_HELLO, 0, hb, 16);
    s[0] ^= 1;
    check(refused("magic", 0, 0), "bad magic");
    n = 0;
    hello();
    s[4] = 2;
    check(refused("version", 0, 0), "unknown version");
    n = 0;
    hello();
    s[6] = 1;
    check(refused("flags", 0, 0), "nonzero header flags");
    n = 0;
    frame(MVA_STDOUT, 1, "x", 1);
    check(refused("no hello", 0, 0), "data before HELLO");
    n = 0;
    hello();
    hello();
    check(refused("two hellos", 0, 0), "a second HELLO");
    n = 0;
    frame(MVA_HELLO, 0, hb, 15);
    check(refused("short hello", 0, 0), "a HELLO of the wrong size");
    n = 0;
    put_le32(hb, 9);
    frame(MVA_HELLO, 0, hb, 16);
    put_le32(hb, MVA_VERSION);
    check(refused("hello proto", 0, 0), "a HELLO with another protocol version");
    n = 0;
    hello();
    frame(MVA_STDOUT, 2, "x", 1);
    check(refused("wrong id", 0, 0), "data for another invocation");
    n = 0;
    hello();
    frame(MVA_STDOUT, 1, "", 0);
    check(refused("empty", 0, 0), "an empty data frame");
    n = 0;
    hello();
    static uint8_t big[MVA_MAX_CHUNK + 1];
    frame(MVA_RESULT, 1, big, sizeof big);
    check(refused("big chunk", 0, 0), "a data frame past 64 KiB");
    n = 0;
    hello();
    frame(MVA_STDOUT, 1, big, 60);
    frame(MVA_STDOUT, 1, big, 41);
    check(refused("output cap", 0, 100), "stdout past the invocation's cap");
    n = 0;
    hello();
    frame(MVA_STDERR, 1, big, 101);
    check(refused("stderr cap", 0, 100), "stderr past the invocation's cap");
    n = 0;
    hello();
    frame(MVA_RESULT, 1, big, 10);
    frame(MVA_RESULT, 1, big, 1);
    check(refused("result cap", 10, 0), "result past the invocation's cap");
    n = 0;
    hello();
    done(1, MVA_KIND_MAX + 1, 0, 0);
    check(refused("kind", 0, 0), "an unknown DONE kind");
    n = 0;
    hello();
    done(1, MVA_RETURNED, 0, 1u << 4);
    check(refused("flags", 0, 0), "unknown DONE flags");
    n = 0;
    hello();
    done(1, MVA_TIMEOUT, 0, 0);
    check(refused("timeout without end", 0, 0), "a dead runtime's DONE without VM_ENDS");
    n = 0;
    hello();
    frame(MVA_DONE, 1, hb, 12);
    check(refused("short done", 0, 0), "a DONE of the wrong size");
    n = 0;
    hello();
    frame(MVA_INVOKE, 1, hb, 16);
    check(refused("invoke from guest", 0, 0), "an INVOKE from the guest");
    n = 0;
    hello();
    frame(0x7f, 1, hb, 16);
    check(refused("type", 0, 0), "an unknown frame type");
    // Sticky: after an error nothing more is consumed.
    {
        mva_parser p;
        mva_parser_init(&p);
        mva_parser_expect(&p, 1, 0, 0);
        mva_response r = {0};
        n = 0;
        frame(MVA_STDOUT, 1, "x", 1);
        (void)mva_parse(&p, s, n, &r);
        n = 0;
        hello();
        check(p.error && mva_parse(&p, s, n, &r) == 0, "an error is sticky");
        mva_response_free(&r);
    }
    // While idle (no INVOKE sent), only a HELLO may come.
    {
        mva_parser p;
        mva_parser_init(&p);
        mva_response r = {0};
        n = 0;
        hello();
        const size_t h = n;
        frame(MVA_STDOUT, 1, "x", 1);
        check(mva_parse(&p, s, n, &r) == h && p.error, "data while idle after HELLO");
        mva_response_free(&r);
    }

    // Encoding.
    const char *argv[] = {"echo", "a b"}, *envp[] = {"K=V"};
    mva_request rq = {.deadline_ms = 1000, .argv = argv, .nargs = 2, .envp = envp, .nenv = 1,
                      .payload = "pay", .payload_len = 3};
    size_t len = 0;
    uint8_t *f = mva_encode_invoke(&rq, 9, &len);
    check(f && len == MVA_HDR + MVA_INVOKE_FIXED + 3 * 4 + 4 + 3 + 3 + 3 && get_le32(f + 8) == 9 &&
              get_le32(f + 12) == len - MVA_HDR && f[5] == MVA_INVOKE &&
              get_le32(f + MVA_HDR + 4) == MVA_MAX_RESULT && !memcmp(f + len - 3, "pay", 3),
          "INVOKE encodes as specified");
    free(f);
    rq.deadline_ms = 0;
    check(!mva_encode_invoke(&rq, 1, &len), "INVOKE: deadline 0 refused");
    rq.deadline_ms = 1000;
    rq.max_output = MVA_MAX_OUTPUT + 1;
    check(!mva_encode_invoke(&rq, 1, &len), "INVOKE: an output cap past the maximum refused");
    rq.max_output = 0;
    rq.payload_len = MVA_MAX_PAYLOAD + 1;
    check(!mva_encode_invoke(&rq, 1, &len), "INVOKE: a payload past 6 MiB refused");
    rq.payload_len = 3;
    static char long_arg[MVA_MAX_STRING + 2];
    memset(long_arg, 'a', MVA_MAX_STRING + 1);
    argv[1] = long_arg;
    check(!mva_encode_invoke(&rq, 1, &len), "INVOKE: a string past 4096 bytes refused");
    rq.nargs = MVA_MAX_STRINGS + 1;
    check(!mva_encode_invoke(&rq, 1, &len), "INVOKE: more than 256 arguments refused");

    printf(fails ? "%d checks FAILED\n" : "all checks passed\n", fails);
    return fails ? 1 : 0;
}
