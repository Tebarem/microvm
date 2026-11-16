// SPDX-License-Identifier: MIT
// Guest physical memory. One contiguous region at GPA 0 for now.
//
// Every access to guest memory from the VMM goes through guest_slice():
// it is the single place where guest-controlled addresses become host
// pointers, so it is the single place that has to get bounds right.
#pragma once

#include "common.h"

typedef struct {
    uint8_t *base;
    uint64_t size;
} guest_mem;

[[nodiscard]] static inline uint8_t *guest_slice(const guest_mem *m, uint64_t gpa, uint64_t len)
{
    uint64_t end;
    if (ckd_add(&end, gpa, len) || end > m->size)
        return nullptr;
    return m->base + gpa;
}
