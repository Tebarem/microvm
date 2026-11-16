// SPDX-License-Identifier: MIT
// Interface between a fuzz harness and tests/fuzz/driver.c.
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *data;
    size_t len;
} fuzz_seed;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
// Starting inputs for the standalone driver's mutator.
const fuzz_seed *fuzz_seeds(size_t *n);

// Harness invariant check: abort (so sanitizers/AFL see a crash) if false.
#define FUZZ_ASSERT(cond)                                                                    \
    do {                                                                                     \
        if (!(cond)) {                                                                       \
            fprintf(stderr, "%s:%d: fuzz invariant failed: %s\n", __FILE__, __LINE__, #cond); \
            abort();                                                                         \
        }                                                                                    \
    } while (0)
