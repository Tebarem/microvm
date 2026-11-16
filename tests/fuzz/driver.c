// SPDX-License-Identifier: MIT
// Standalone driver for the fuzz harnesses (GCC has no libFuzzer).
//
// Each harness defines LLVMFuzzerTestOneInput() and fuzz_seeds(), so the
// same file also builds with `clang -fsanitize=fuzzer` (define
// MVM_LIBFUZZER to drop this driver) or AFL++ (afl-clang-fast; pass the
// input file on the command line).
//
//   fuzz_x FILE...        run each file once (corpus replay / crash repro)
//   fuzz_x -runs=N [-seed=S] [-max_len=L]
//                         mutate the built-in seeds N times; on a crash
//                         (sanitizer abort) the input is in fuzz-crash.bin
#ifndef MVM_LIBFUZZER
#  include <stdint.h>
#  include <stdio.h>
#  include <stdlib.h>
#  include <string.h>

#  include "fuzz.h"

static uint64_t rng = 0x9e3779b97f4a7c15ull;

static uint64_t next(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

static size_t mutate(uint8_t *buf, size_t len, size_t max_len, const fuzz_seed *seeds, size_t nseeds)
{
    static const uint8_t magic8[] = {0, 1, 0x7f, 0x80, 0xff, 0x40, 0x20};
    static const uint32_t magic32[] = {0, 1, 0x7fffffff, 0x80000000u, 0xffffffffu, 0x1000, 0xfff,
                                       0x100000, 0x1000000};
    const int ops = 1 + (int)(next() % 8);
    for (int o = 0; o < ops; o++) {
        const size_t pos = len ? (size_t)(next() % len) : 0;
        switch (next() % 9) {
        case 0: // flip a bit
            if (len)
                buf[pos] ^= (uint8_t)(1u << (next() % 8));
            break;
        case 1: // random byte
            if (len)
                buf[pos] = (uint8_t)next();
            break;
        case 2: // interesting byte
            if (len)
                buf[pos] = magic8[next() % sizeof magic8];
            break;
        case 3: // interesting 32-bit value
            if (len >= 4) {
                const uint32_t v = magic32[next() % (sizeof magic32 / 4)];
                const size_t p = (size_t)(next() % (len - 3));
                memcpy(buf + p, &v, 4);
            }
            break;
        case 4: // interesting 64-bit value (sign-extended 32-bit or huge)
            if (len >= 8) {
                const uint64_t v = next() % 2 ? UINT64_MAX - (next() % 4096) : next() % 0x4000000;
                const size_t p = (size_t)(next() % (len - 7));
                memcpy(buf + p, &v, 8);
            }
            break;
        case 5: // delete a chunk
            if (len > 1) {
                const size_t n = 1 + (size_t)(next() % (len - pos < 64 ? len - pos : 64));
                memmove(buf + pos, buf + pos + n, len - pos - n);
                len -= n;
            }
            break;
        case 6: // insert random bytes
            if (len < max_len) {
                size_t n = 1 + (size_t)(next() % 32);
                if (n > max_len - len)
                    n = max_len - len;
                memmove(buf + pos + n, buf + pos, len - pos);
                for (size_t i = 0; i < n; i++)
                    buf[pos + i] = (uint8_t)next();
                len += n;
            }
            break;
        case 7: // overwrite with a chunk of another seed
            if (nseeds && len) {
                const fuzz_seed *s = &seeds[next() % nseeds];
                if (s->len) {
                    const size_t from = (size_t)(next() % s->len);
                    size_t n = 1 + (size_t)(next() % 64);
                    if (n > s->len - from)
                        n = s->len - from;
                    if (n > len - pos)
                        n = len - pos;
                    memcpy(buf + pos, s->data + from, n);
                }
            }
            break;
        default: // duplicate a chunk
            if (len && len < max_len) {
                size_t n = 1 + (size_t)(next() % 16);
                if (n > len - pos)
                    n = len - pos;
                if (n > max_len - len)
                    n = max_len - len;
                memmove(buf + pos + n, buf + pos, len - pos);
                len += n;
            }
            break;
        }
    }
    return len;
}

static int run_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return 1;
    }
    static uint8_t buf[1 << 20];
    const size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    LLVMFuzzerTestOneInput(buf, n);
    return 0;
}

int main(int argc, char **argv)
{
    unsigned long long runs = 100000;
    size_t max_len = 4096;
    bool files = false;
    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "-runs=", 6))
            runs = strtoull(argv[i] + 6, nullptr, 10);
        else if (!strncmp(argv[i], "-seed=", 6))
            rng = strtoull(argv[i] + 6, nullptr, 10) | 1;
        else if (!strncmp(argv[i], "-max_len=", 9))
            max_len = (size_t)strtoull(argv[i] + 9, nullptr, 10);
        else
            files = true;
    }
    if (files) {
        int rc = 0;
        for (int i = 1; i < argc; i++)
            if (argv[i][0] != '-')
                rc |= run_file(argv[i]);
        return rc;
    }

    size_t nseeds = 0;
    const fuzz_seed *seeds = fuzz_seeds(&nseeds);
    if (max_len < 64)
        max_len = 64;
    uint8_t *buf = malloc(max_len);
    if (!buf)
        return 1;
    for (size_t i = 0; i < nseeds; i++) // seeds as-is first
        LLVMFuzzerTestOneInput(seeds[i].data, seeds[i].len);
    for (unsigned long long r = 0; r < runs; r++) {
        size_t len = 0;
        if (nseeds) {
            const fuzz_seed *s = &seeds[next() % nseeds];
            len = s->len < max_len ? s->len : max_len;
            memcpy(buf, s->data, len);
        }
        len = mutate(buf, len, max_len, seeds, nseeds);
        // Keep the current input on disk only when asked: writing it every
        // iteration would dominate the run time.
        if (getenv("MVM_FUZZ_SAVE")) {
            FILE *f = fopen("fuzz-crash.bin", "wb");
            if (f) {
                fwrite(buf, 1, len, f);
                fclose(f);
            }
        }
        // The harness must not keep a pointer to the input.
        uint8_t *copy = malloc(len ? len : 1);
        if (!copy)
            return 1;
        memcpy(copy, buf, len);
        LLVMFuzzerTestOneInput(copy, len);
        free(copy);
    }
    free(buf);
    printf("%llu runs ok\n", runs);
    return 0;
}
#endif
