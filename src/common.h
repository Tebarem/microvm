// SPDX-License-Identifier: MIT
// Shared helpers: fixed-width types, checked arithmetic, logging.
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if __has_include(<stdckdint.h>)
#  include <stdckdint.h>
#else // GCC 13: same semantics via builtins
#  define ckd_add(r, a, b) __builtin_add_overflow((a), (b), (r))
#  define ckd_sub(r, a, b) __builtin_sub_overflow((a), (b), (r))
#  define ckd_mul(r, a, b) __builtin_mul_overflow((a), (b), (r))
#endif

#define MVM_LIKELY(x)   __builtin_expect(!!(x), 1)
#define MVM_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define MVM_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

constexpr uint64_t KiB = 1024;
constexpr uint64_t MiB = 1024 * KiB;
constexpr uint64_t GiB = 1024 * MiB;

// vCPUs per VM (--cpus). The guest sees one package with this many cores,
// one thread each, of which the VM's are present: its CPUID is the same
// whatever the count (a fixed CPU view for pre-patched kernels, patch 0026).
constexpr uint32_t MVM_MAX_VCPUS = 8;

// Unbuffered logging straight to stderr (no stdio buffers in the VMM).
[[gnu::format(printf, 1, 2)]] void mvm_log(const char *fmt, ...);
[[noreturn, gnu::format(printf, 1, 2)]] void mvm_die(const char *fmt, ...);
// Raw write of bytes to stdout / stderr.
void mvm_write_out(const void *buf, size_t len);
void mvm_write_err(const void *buf, size_t len);

static inline void put_le16(uint8_t *p, uint16_t v) { memcpy(p, &v, sizeof v); }
static inline void put_le32(uint8_t *p, uint32_t v) { memcpy(p, &v, sizeof v); }
static inline void put_le64(uint8_t *p, uint64_t v) { memcpy(p, &v, sizeof v); }
static inline uint16_t get_le16(const uint8_t *p) { uint16_t v; memcpy(&v, p, sizeof v); return v; }
static inline uint32_t get_le32(const uint8_t *p) { uint32_t v; memcpy(&v, p, sizeof v); return v; }
static inline uint64_t get_le64(const uint8_t *p) { uint64_t v; memcpy(&v, p, sizeof v); return v; }
