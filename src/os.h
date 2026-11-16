// SPDX-License-Identifier: MIT
// Thin OS layer: files and guest-memory reservation.
#pragma once

#include "common.h"

typedef struct {
    intptr_t h; // fd on POSIX, HANDLE on Windows
} os_file;

[[nodiscard]] int os_file_open_ro(const char *path, os_file *out);
[[nodiscard]] int os_file_size(os_file f, uint64_t *size);
// Read exactly len bytes at off; returns 0 on success.
[[nodiscard]] int os_file_pread(os_file f, void *buf, size_t len, uint64_t off);
void os_file_close(os_file f);
// Create (or truncate) a file only we can read and write.
[[nodiscard]] int os_file_create(const char *path, os_file *out);
// Write exactly len bytes at off; returns 0 on success.
[[nodiscard]] int os_file_pwrite(os_file f, const void *buf, size_t len, uint64_t off);
// Fill buf from the OS's random number generator; returns 0 on success.
[[nodiscard]] int os_random(void *buf, size_t len);
// The wall clock: seconds since the Unix epoch and the nanoseconds within that
// second. Returns 0, or -1 with *sec and *nsec untouched.
[[nodiscard]] int os_wall_clock(int64_t *sec, uint32_t *nsec);
// Map the first `size` bytes of a file read-only and shared: every mapping of
// the file, in any process, uses the same page-cache pages. size must be a
// multiple of 4096 and at most the file's size.
[[nodiscard]] int os_file_map_ro(os_file f, uint64_t size, void **out);
void os_file_unmap(void *p, uint64_t size);
// Map n files the same way into one reservation of span bytes: file i's
// first size[i] bytes at *out + off[i] (page-aligned, ascending, apart,
// inside span); the rest of the span can't be touched. Undo with
// os_file_unmap(*out, span). Windows: one file, at offset 0, span its size.
[[nodiscard]] int os_files_map_ro(const os_file *f, const uint64_t *size, const uint64_t *off, uint32_t n,
                                  uint64_t span, void **out);

// Start a detached thread.
[[nodiscard]] int os_thread_start(void (*fn)(void *), void *arg);
// Start a joinable thread; os_thread_join() waits for it and frees it.
typedef struct {
    intptr_t h;
} os_thread;
[[nodiscard]] int os_thread_run(os_thread *t, void (*fn)(void *), void *arg);
void os_thread_join(os_thread t);
// Sleep while *addr holds val: returns once another thread changed it and
// called os_wake_all(addr), or spuriously (check again). Linux: a futex.
void os_wait_u32(_Atomic uint32_t *addr, uint32_t val);
void os_wake_all(_Atomic uint32_t *addr);
// Give up the CPU to another thread, if one is waiting.
void os_yield(void);

// Reserve zero-filled, demand-paged memory. Nothing is pre-faulted.
[[nodiscard]] void *os_mem_reserve(size_t size);
void os_mem_release(void *p, size_t size);
// Drop the contents of [p, p+len) (page-aligned) inside memory from
// os_mem_reserve or guest RAM: anonymous pages read as zero again, pages
// of a copy-on-write file view as the file's. Nothing on Windows.
void os_mem_discard(void *p, size_t len);

// Per-page residency of [base, base+size) (size page-aligned): map[i] gets
// OS_PAGE_RESIDENT if page i is in our working set, plus OS_PAGE_SHARED if
// it is still the unmodified, shareable file page of a copy-on-write view.
// Returns the number of resident pages, or SIZE_MAX on error.
constexpr uint8_t OS_PAGE_RESIDENT = 1;
constexpr uint8_t OS_PAGE_SHARED = 2;
size_t os_mem_resident(void *base, size_t size, uint8_t *map);
// Open whatever os_mem_resident() and os_mem_private() need, so they still
// work once the process is sandboxed.
void os_mem_resident_prepare(void);
// The pages of [base, base+size) that are private copies: map[i] = 1 for a
// page of a copy-on-write file view that something wrote since it was
// mapped, or a page of anonymous memory ever touched (resident or swapped
// out); 0 for one still the file's (or never touched). Returns 0, or -1
// where that can't be known (Windows; no /proc).
[[nodiscard]] int os_mem_private(void *base, size_t size, uint8_t *map);

// ---- guest RAM ---------------------------------------------------------
// Built in three steps so parts of it can be copy-on-write views of a file,
// shared with every other VM through the host page cache until written:
//   os_ram_reserve(&r, size)            address space only
//   os_ram_map_file(&r, off, len, ...)  any number of non-overlapping views
//   os_ram_commit(&r)                   everything else: demand-zero memory
// Only after os_ram_commit may the unmapped parts be touched.
constexpr uint64_t OS_FILE_MAP_ALIGN = 64 * 1024; // file offsets (Windows granularity)
constexpr size_t OS_RAM_MAX_VIEWS = 8;

typedef struct {
    size_t off, len;
} os_ram_view;

typedef struct {
    uint8_t *base;
    size_t size;
    size_t nviews;
    os_ram_view views[OS_RAM_MAX_VIEWS]; // sorted by off
    bool committed;
} os_ram;

[[nodiscard]] int os_ram_reserve(os_ram *r, size_t size);
// Map file bytes [foff, foff + len) copy-on-write at r->base + off. off and
// len must be page-aligned and foff a multiple of OS_FILE_MAP_ALIGN; the
// range must lie inside the file. On failure nothing changed: copy the
// bytes after os_ram_commit instead.
[[nodiscard]] int os_ram_map_file(os_ram *r, size_t off, size_t len, os_file f, uint64_t foff);
// Map len bytes of f at foff over [off, off+len) of a file view already
// mapped, copy-on-write (Linux; page-aligned; before os_ram_commit). It stays
// part of that view. Fails only on bad arguments: past that, a failure
// would leave a hole in guest RAM, and the process dies instead.
[[nodiscard]] int os_ram_overlay_file(os_ram *r, size_t off, size_t len, os_file f, uint64_t foff);
[[nodiscard]] int os_ram_commit(os_ram *r);
void os_ram_release(os_ram *r);
