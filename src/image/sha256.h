// SPDX-License-Identifier: MIT
// SHA-256 (FIPS 180-4): OCI blob digests and layer diff_ids.
#pragma once

#include "../common.h"

typedef struct {
    uint32_t h[8];
    uint64_t len; // bytes hashed so far
    uint8_t buf[64];
    size_t n;     // bytes in buf
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const void *data, size_t len, uint8_t out[32]);
// Lowercase hex, NUL-terminated.
void sha256_hex(const uint8_t d[32], char out[65]);
// Which implementation runs: "sha-ni" or "portable".
const char *sha256_impl(void);
// Tests: force the portable code (true) or pick by CPU again (false).
void sha256_force_portable(bool on);
