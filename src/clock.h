// SPDX-License-Identifier: MIT
// Monotonic nanosecond clock for phase timing.
#pragma once

#include <stdint.h>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
static inline uint64_t mvm_now_ns(void)
{
    static uint64_t freq;
    LARGE_INTEGER c;
    if (!freq) {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        freq = (uint64_t)f.QuadPart;
    }
    QueryPerformanceCounter(&c);
    uint64_t t = (uint64_t)c.QuadPart;
    return (t / freq) * 1000000000ull + (t % freq) * 1000000000ull / freq;
}
#else
#  include <time.h>
static inline uint64_t mvm_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
#endif
