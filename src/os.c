// SPDX-License-Identifier: MIT
#if defined(_WIN32)
#  define _CRT_RAND_S // rand_s()
#endif
#include "os.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>

static void write_handle(DWORD which, const void *buf, size_t len)
{
    HANDLE h = GetStdHandle(which);
    const char *p = buf;
    while (len) {
        DWORD n = 0;
        if (!WriteFile(h, p, len > 0x7fffffff ? 0x7fffffff : (DWORD)len, &n, nullptr) || !n)
            return;
        p += n;
        len -= n;
    }
}
void mvm_write_out(const void *buf, size_t len) { write_handle(STD_OUTPUT_HANDLE, buf, len); }
void mvm_write_err(const void *buf, size_t len) { write_handle(STD_ERROR_HANDLE, buf, len); }

int os_file_open_ro(const char *path, os_file *out)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    out->h = (intptr_t)h;
    return 0;
}

int os_file_size(os_file f, uint64_t *size)
{
    LARGE_INTEGER s;
    if (!GetFileSizeEx((HANDLE)f.h, &s))
        return -1;
    *size = (uint64_t)s.QuadPart;
    return 0;
}

int os_file_pread(os_file f, void *buf, size_t len, uint64_t off)
{
    char *p = buf;
    while (len) {
        OVERLAPPED ov = {0};
        ov.Offset = (DWORD)off;
        ov.OffsetHigh = (DWORD)(off >> 32);
        DWORD chunk = len > (1u << 30) ? (1u << 30) : (DWORD)len, n = 0;
        if (!ReadFile((HANDLE)f.h, p, chunk, &n, &ov) || n == 0)
            return -1;
        p += n;
        off += n;
        len -= n;
    }
    return 0;
}

void os_file_close(os_file f) { CloseHandle((HANDLE)f.h); }

int os_file_create(const char *path, os_file *out)
{
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    out->h = (intptr_t)h;
    return 0;
}

int os_file_pwrite(os_file f, const void *buf, size_t len, uint64_t off)
{
    const char *p = buf;
    while (len) {
        OVERLAPPED ov = {0};
        ov.Offset = (DWORD)off;
        ov.OffsetHigh = (DWORD)(off >> 32);
        DWORD chunk = len > (1u << 30) ? (1u << 30) : (DWORD)len, n = 0;
        if (!WriteFile((HANDLE)f.h, p, chunk, &n, &ov) || n == 0)
            return -1;
        p += n;
        off += n;
        len -= n;
    }
    return 0;
}

int os_random(void *buf, size_t len)
{
    uint8_t *p = buf;
    for (size_t i = 0; i < len; i += sizeof(unsigned int)) {
        unsigned int r;
        if (rand_s(&r))
            return -1;
        memcpy(p + i, &r, len - i < sizeof r ? len - i : sizeof r);
    }
    return 0;
}

int os_wall_clock(int64_t *sec, uint32_t *nsec)
{
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft); // 100 ns ticks since 1601-01-01 UTC
    const uint64_t ticks = ((uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime) - 116444736000000000ull;
    *sec = (int64_t)(ticks / 10000000);
    *nsec = (uint32_t)(ticks % 10000000) * 100;
    return 0;
}

int os_file_map_ro(os_file f, uint64_t size, void **out)
{
    uint64_t fsize;
    if (!size || size % 4096 || size > SIZE_MAX || os_file_size(f, &fsize) || size > fsize)
        return -1;
    HANDLE sec = CreateFileMappingA((HANDLE)f.h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!sec)
        return -1;
    void *p = MapViewOfFile(sec, FILE_MAP_READ, 0, 0, (SIZE_T)size);
    CloseHandle(sec); // the view keeps the section alive
    if (!p)
        return -1;
    *out = p;
    return 0;
}

void os_file_unmap(void *p, uint64_t size)
{
    (void)size;
    if (p)
        UnmapViewOfFile(p);
}

int os_files_map_ro(const os_file *f, const uint64_t *size, const uint64_t *off, uint32_t n, uint64_t span,
                    void **out)
{
    // Placeholders could stitch several views together; one is all the
    // Windows build needs (sbxd, which uses layers, is Linux-only).
    if (n != 1 || off[0] || span != size[0])
        return -1;
    return os_file_map_ro(f[0], size[0], out);
}

typedef struct {
    void (*fn)(void *);
    void *arg;
} thread_start;

static DWORD WINAPI thread_trampoline(LPVOID p)
{
    thread_start t = *(thread_start *)p;
    free(p);
    t.fn(t.arg);
    return 0;
}

int os_thread_start(void (*fn)(void *), void *arg)
{
    thread_start *t = malloc(sizeof *t);
    if (!t)
        return -1;
    *t = (thread_start){fn, arg};
    HANDLE h = CreateThread(nullptr, 64 * 1024, thread_trampoline, t, 0, nullptr);
    if (!h) {
        free(t);
        return -1;
    }
    CloseHandle(h);
    return 0;
}

int os_thread_run(os_thread *out, void (*fn)(void *), void *arg)
{
    thread_start *t = malloc(sizeof *t);
    if (!t)
        return -1;
    *t = (thread_start){fn, arg};
    HANDLE h = CreateThread(nullptr, 64 * 1024, thread_trampoline, t, 0, nullptr);
    if (!h) {
        free(t);
        return -1;
    }
    out->h = (intptr_t)h;
    return 0;
}

void os_thread_join(os_thread t)
{
    WaitForSingleObject((HANDLE)t.h, INFINITE);
    CloseHandle((HANDLE)t.h);
}

void os_wait_u32(_Atomic uint32_t *addr, uint32_t val)
{
    (void)WaitOnAddress((volatile void *)addr, &val, sizeof val, INFINITE);
}

void os_wake_all(_Atomic uint32_t *addr) { WakeByAddressAll((void *)addr); }

void os_yield(void) { SwitchToThread(); }

void *os_mem_reserve(size_t size)
{
    // WHvMapGpaRange needs committed memory, but commit only charges the
    // pagefile; physical pages are still demand-zeroed on first touch.
    return VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

void os_mem_discard(void *p, size_t len) { (void)p, (void)len; }

void os_mem_release(void *p, size_t size)
{
    (void)size;
    VirtualFree(p, 0, MEM_RELEASE);
}

typedef struct {
    void *va;
    ULONG_PTR attrs; // bit 0: Valid (resident in our working set)
} ws_ex_info;
BOOL WINAPI K32QueryWorkingSetEx(HANDLE process, PVOID info, DWORD size);

size_t os_mem_resident(void *base, size_t size, uint8_t *map)
{
    const size_t pages = size / 4096;
    ws_ex_info *info = calloc(pages, sizeof *info);
    if (!info)
        return SIZE_MAX;
    for (size_t i = 0; i < pages; i++)
        info[i].va = (uint8_t *)base + i * 4096;
    size_t n = 0;
    if (!K32QueryWorkingSetEx(GetCurrentProcess(), info, (DWORD)(pages * sizeof *info))) {
        free(info);
        return SIZE_MAX;
    }
    for (size_t i = 0; i < pages; i++) {
        const bool valid = info[i].attrs & 1, shared = (info[i].attrs >> 15) & 1;
        map[i] = (valid ? OS_PAGE_RESIDENT : 0) | (valid && shared ? OS_PAGE_SHARED : 0);
        n += valid;
    }
    free(info);
    return n;
}

void os_mem_resident_prepare(void) {}

int os_mem_private(void *base, size_t size, uint8_t *map)
{
    (void)base, (void)size, (void)map;
    return -1;
}

// ---- guest RAM: shared bookkeeping --------------------------------------
static bool ram_view_slot(const os_ram *r, size_t off, size_t len, size_t *slot)
{
    size_t end;
    if (r->committed || r->nviews == OS_RAM_MAX_VIEWS || !len || (off | len) & 4095 ||
        ckd_add(&end, off, len) || end > r->size)
        return false;
    size_t i = 0;
    while (i < r->nviews && r->views[i].off < off)
        i++;
    if (i > 0 && r->views[i - 1].off + r->views[i - 1].len > off)
        return false;
    if (i < r->nviews && end > r->views[i].off)
        return false;
    *slot = i;
    return true;
}

static void ram_view_insert(os_ram *r, size_t i, size_t off, size_t len)
{
    memmove(&r->views[i + 1], &r->views[i], (r->nviews - i) * sizeof r->views[0]);
    r->views[i] = (os_ram_view){off, len};
    r->nviews++;
}

static bool ram_file_range_ok(os_file f, uint64_t foff, size_t len)
{
    uint64_t fsize, fend;
    return foff % OS_FILE_MAP_ALIGN == 0 && !os_file_size(f, &fsize) &&
           !ckd_add(&fend, foff, (uint64_t)len) && fend <= fsize;
}

// MapViewOfFile3 and VirtualAlloc2 (Windows 10 1803) are hidden by the headers
// at the default NTDDI_VERSION, and not every import library exports them.
// They live in kernelbase.dll, so look them up there: without them, the
// placeholder calls fail with -1.
#  ifndef MEM_PRESERVE_PLACEHOLDER
#    define MEM_PRESERVE_PLACEHOLDER 0x00000002
#  endif
#  ifndef MEM_REPLACE_PLACEHOLDER
#    define MEM_REPLACE_PLACEHOLDER 0x00004000
#  endif
#  ifndef MEM_RESERVE_PLACEHOLDER
#    define MEM_RESERVE_PLACEHOLDER 0x00040000
#  endif
typedef PVOID(WINAPI *virtual_alloc2_fn)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, void *, ULONG);
typedef PVOID(WINAPI *map_view_of_file3_fn)(HANDLE, HANDLE, PVOID, ULONG64, SIZE_T, ULONG, ULONG,
                                            void *, ULONG);

static FARPROC kernelbase_proc(const char *name)
{
    HMODULE m = GetModuleHandleA("kernelbase.dll");
    return m ? GetProcAddress(m, name) : nullptr;
}

static virtual_alloc2_fn get_virtual_alloc2(void)
{
    union {
        FARPROC p;
        virtual_alloc2_fn f;
    } u = {.p = kernelbase_proc("VirtualAlloc2")};
    return u.f;
}

static map_view_of_file3_fn get_map_view_of_file3(void)
{
    union {
        FARPROC p;
        map_view_of_file3_fn f;
    } u = {.p = kernelbase_proc("MapViewOfFile3")};
    return u.f;
}

// Windows: placeholders let file views and anonymous memory be stitched
// together inside one contiguous reservation.
int os_ram_reserve(os_ram *r, size_t size)
{
    *r = (os_ram){.size = size};
    const virtual_alloc2_fn va2 = get_virtual_alloc2();
    if (!va2)
        return -1;
    r->base = va2(nullptr, nullptr, size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS,
                  nullptr, 0);
    return r->base ? 0 : -1;
}

int os_ram_map_file(os_ram *r, size_t off, size_t len, os_file f, uint64_t foff)
{
    size_t slot;
    if (!ram_view_slot(r, off, len, &slot) || !ram_file_range_ok(f, foff, len))
        return -1;
    const map_view_of_file3_fn mv3 = get_map_view_of_file3();
    if (!mv3)
        return -1; // before any placeholder is carved out
    HANDLE sec = CreateFileMappingA((HANDLE)f.h, nullptr, PAGE_WRITECOPY, 0, 0, nullptr);
    if (!sec)
        return -1;
    // Carve [off, off + len) out of the placeholder that contains it, unless
    // it already is exactly one placeholder.
    MEMORY_BASIC_INFORMATION mbi;
    const bool whole = VirtualQuery(r->base + off, &mbi, sizeof mbi) &&
                       (uint8_t *)mbi.BaseAddress == r->base + off && mbi.RegionSize == len;
    if (!whole && !VirtualFree(r->base + off, len, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)) {
        CloseHandle(sec);
        return -1;
    }
    void *v = mv3(sec, GetCurrentProcess(), r->base + off, foff, len, MEM_REPLACE_PLACEHOLDER,
                  PAGE_WRITECOPY, nullptr, 0);
    CloseHandle(sec); // the view keeps the section alive
    if (!v)
        return -1; // the carved-out placeholder stays; os_ram_commit fills it
    ram_view_insert(r, slot, off, len);
    return 0;
}

int os_ram_overlay_file(os_ram *r, size_t off, size_t len, os_file f, uint64_t foff)
{
    (void)r, (void)off, (void)len, (void)f, (void)foff;
    return -1; // snapshots are KVM's
}

int os_ram_commit(os_ram *r)
{
    // Fill every gap between views, placeholder by placeholder: a gap can
    // hold several adjacent placeholders (splits, failed maps).
    const virtual_alloc2_fn va2 = get_virtual_alloc2();
    if (!va2)
        return -1;
    for (size_t i = 0; i <= r->nviews; i++) {
        size_t lo = i ? r->views[i - 1].off + r->views[i - 1].len : 0;
        const size_t hi = i < r->nviews ? r->views[i].off : r->size;
        while (lo < hi) {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery(r->base + lo, &mbi, sizeof mbi))
                return -1;
            size_t n = (size_t)((uint8_t *)mbi.BaseAddress + mbi.RegionSize - (r->base + lo));
            if (n > hi - lo)
                n = hi - lo;
            // Commit only charges the pagefile; pages are still demand-zeroed.
            if (!va2(nullptr, r->base + lo, n, MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER,
                     PAGE_READWRITE, nullptr, 0))
                return -1;
            lo += n;
        }
    }
    r->committed = true;
    return 0;
}

void os_ram_release(os_ram *r)
{
    for (size_t off = 0; r->base && off < r->size;) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(r->base + off, &mbi, sizeof mbi) || !mbi.RegionSize)
            break;
        if (mbi.Type == MEM_MAPPED)
            UnmapViewOfFile(mbi.BaseAddress);
        else
            VirtualFree(mbi.BaseAddress, 0, MEM_RELEASE);
        off = (size_t)((uint8_t *)mbi.BaseAddress + mbi.RegionSize - r->base);
    }
    *r = (os_ram){0};
}

#else
#  include <errno.h>
#  include <fcntl.h>
#  include <linux/futex.h>
#  include <pthread.h>
#  include <sched.h>
#  include <stdatomic.h>
#  include <sys/mman.h>
#  include <sys/random.h>
#  include <sys/stat.h>
#  include <sys/syscall.h>
#  include <time.h>
#  include <unistd.h>

static void write_fd(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return;
        p += n;
        len -= (size_t)n;
    }
}
void mvm_write_out(const void *buf, size_t len) { write_fd(1, buf, len); }
void mvm_write_err(const void *buf, size_t len) { write_fd(2, buf, len); }

int os_file_open_ro(const char *path, os_file *out)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    out->h = fd;
    return 0;
}

int os_file_size(os_file f, uint64_t *size)
{
    struct stat st;
    if (fstat((int)f.h, &st) != 0)
        return -1;
    *size = (uint64_t)st.st_size;
    return 0;
}

int os_file_pread(os_file f, void *buf, size_t len, uint64_t off)
{
    char *p = buf;
    while (len) {
        ssize_t n = pread((int)f.h, p, len, (off_t)off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        off += (uint64_t)n;
        len -= (size_t)n;
    }
    return 0;
}

void os_file_close(os_file f) { close((int)f.h); }

int os_file_create(const char *path, os_file *out)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    out->h = fd;
    return 0;
}

int os_file_pwrite(os_file f, const void *buf, size_t len, uint64_t off)
{
    const char *p = buf;
    while (len) {
        ssize_t n = pwrite((int)f.h, p, len, (off_t)off);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        off += (uint64_t)n;
        len -= (size_t)n;
    }
    return 0;
}

int os_random(void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len) {
        const ssize_t n = getrandom(p, len, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int os_wall_clock(int64_t *sec, uint32_t *nsec)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts))
        return -1;
    *sec = (int64_t)ts.tv_sec;
    *nsec = (uint32_t)ts.tv_nsec;
    return 0;
}

int os_file_map_ro(os_file f, uint64_t size, void **out)
{
    uint64_t fsize;
    if (!size || size % 4096 || size > SIZE_MAX || os_file_size(f, &fsize) || size > fsize)
        return -1;
    void *p = mmap(nullptr, (size_t)size, PROT_READ, MAP_SHARED, (int)f.h, 0);
    if (p == MAP_FAILED)
        return -1;
    *out = p;
    return 0;
}

void os_file_unmap(void *p, uint64_t size)
{
    if (p)
        munmap(p, (size_t)size);
}

int os_files_map_ro(const os_file *f, const uint64_t *size, const uint64_t *off, uint32_t n, uint64_t span,
                    void **out)
{
    if (!n || !span || span % 4096 || span > SIZE_MAX)
        return -1;
    uint64_t prev_end = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t fsize, end;
        if (!size[i] || size[i] % 4096 || off[i] % 4096 || off[i] < prev_end || (i && off[i] == prev_end) ||
            ckd_add(&end, off[i], size[i]) || end > span || os_file_size(f[i], &fsize) || size[i] > fsize)
            return -1;
        prev_end = end;
    }
    uint8_t *base = mmap(nullptr, (size_t)span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (base == MAP_FAILED)
        return -1;
    for (uint32_t i = 0; i < n; i++)
        if (mmap(base + off[i], (size_t)size[i], PROT_READ, MAP_SHARED | MAP_FIXED, (int)f[i].h, 0) == MAP_FAILED) {
            munmap(base, (size_t)span);
            return -1;
        }
    *out = base;
    return 0;
}

typedef struct {
    void (*fn)(void *);
    void *arg;
} thread_start;

static void *thread_trampoline(void *p)
{
    thread_start t = *(thread_start *)p;
    free(p);
    t.fn(t.arg);
    return nullptr;
}

// os_thread_start()'s: tells the creator the thread is running its own code.
typedef struct {
    void (*fn)(void *);
    void *arg;
    atomic_bool running;
} thread_handshake;

static void *started_trampoline(void *p)
{
    thread_handshake *h = p;
    void (*fn)(void *) = h->fn;
    void *arg = h->arg;
    atomic_store_explicit(&h->running, true, memory_order_release); // h belongs to the creator now
    fn(arg);
    return nullptr;
}

// Returns once the thread runs fn: glibc's own start-up in the new thread
// (rseq registration, signal mask) is done by then. The sandbox starts
// device threads right before it installs seccomp, which would otherwise
// race that start-up and kill the process for its rseq() call.
int os_thread_start(void (*fn)(void *), void *arg)
{
    thread_handshake h = {.fn = fn, .arg = arg};
    atomic_init(&h.running, false);
    // Device threads are small: a 64 KiB stack, not glibc's 8 MiB default
    // (only touched pages cost memory, but the reservation counts against
    // the sandbox's address-space limit).
    pthread_attr_t at;
    pthread_t th;
    if (pthread_attr_init(&at))
        return -1;
    (void)pthread_attr_setstacksize(&at, 64 * 1024);
    const int err = pthread_create(&th, &at, started_trampoline, &h);
    pthread_attr_destroy(&at);
    if (err)
        return -1;
    pthread_detach(th);
    while (!atomic_load_explicit(&h.running, memory_order_acquire))
        sched_yield();
    return 0;
}

int os_thread_run(os_thread *out, void (*fn)(void *), void *arg)
{
    thread_start *t = malloc(sizeof *t);
    if (!t)
        return -1;
    *t = (thread_start){fn, arg};
    pthread_t th;
    if (pthread_create(&th, nullptr, thread_trampoline, t) != 0) {
        free(t);
        return -1;
    }
    out->h = (intptr_t)th;
    return 0;
}

void os_thread_join(os_thread t) { pthread_join((pthread_t)t.h, nullptr); }

void os_wait_u32(_Atomic uint32_t *addr, uint32_t val)
{
    (void)syscall(SYS_futex, addr, FUTEX_WAIT_PRIVATE, val, nullptr, nullptr, 0);
}

void os_wake_all(_Atomic uint32_t *addr)
{
    (void)syscall(SYS_futex, addr, FUTEX_WAKE_PRIVATE, INT32_MAX, nullptr, nullptr, 0);
}

void os_yield(void) { sched_yield(); }

void *os_mem_reserve(size_t size)
{
    void *p = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    return p == MAP_FAILED ? nullptr : p;
}

void os_mem_release(void *p, size_t size) { munmap(p, size); }

void os_mem_discard(void *p, size_t len) { (void)madvise(p, len, MADV_DONTNEED); }

// /proc/self/pagemap knows per-PTE presence and whether a page is still a
// (shared) file page; it is readable without privileges (PFNs read as 0,
// which we don't need).
static int pagemap_fd = -1;

void os_mem_resident_prepare(void)
{
    if (pagemap_fd < 0)
        pagemap_fd = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
}

// One byte per page from /proc/self/pagemap: os_mem_private()'s 0/1, or
// os_mem_resident()'s flags. Returns the resident pages, or SIZE_MAX.
static size_t read_pagemap(void *base, size_t pages, uint8_t *map, bool private)
{
    const int fd = pagemap_fd >= 0 ? pagemap_fd : open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return SIZE_MAX;
    uint64_t buf[512];
    const uint64_t first = (uintptr_t)base / 4096;
    size_t n = 0;
    for (size_t i = 0; i < pages;) {
        const size_t k = pages - i < 512 ? pages - i : 512;
        if (pread(fd, buf, k * 8, (off_t)((first + i) * 8)) != (ssize_t)(k * 8)) {
            if (fd != pagemap_fd)
                close(fd);
            return SIZE_MAX;
        }
        for (size_t j = 0; j < k; j++) {
            const bool present = buf[j] >> 63 & 1, swapped = buf[j] >> 62 & 1, file = buf[j] >> 61 & 1;
            if (private)
                map[i + j] = (present && !file) || swapped;
            else
                map[i + j] = (present ? OS_PAGE_RESIDENT : 0) | (present && file ? OS_PAGE_SHARED : 0);
            n += present;
        }
        i += k;
    }
    if (fd != pagemap_fd)
        close(fd);
    return n;
}

int os_mem_private(void *base, size_t size, uint8_t *map)
{
    return read_pagemap(base, size / 4096, map, true) == SIZE_MAX ? -1 : 0;
}

size_t os_mem_resident(void *base, size_t size, uint8_t *map)
{
    const size_t pages = size / 4096;
    size_t n = read_pagemap(base, pages, map, false);
    if (n != SIZE_MAX)
        return n;
    if (mincore(base, size, map) != 0)
        return SIZE_MAX;
    n = 0;
    for (size_t i = 0; i < pages; i++) {
        map[i] &= 1;
        n += map[i];
    }
    return n;
}

// ---- guest RAM: shared bookkeeping --------------------------------------
static bool ram_view_slot(const os_ram *r, size_t off, size_t len, size_t *slot)
{
    size_t end;
    if (r->committed || r->nviews == OS_RAM_MAX_VIEWS || !len || (off | len) & 4095 ||
        ckd_add(&end, off, len) || end > r->size)
        return false;
    size_t i = 0;
    while (i < r->nviews && r->views[i].off < off)
        i++;
    if (i > 0 && r->views[i - 1].off + r->views[i - 1].len > off)
        return false;
    if (i < r->nviews && end > r->views[i].off)
        return false;
    *slot = i;
    return true;
}

static void ram_view_insert(os_ram *r, size_t i, size_t off, size_t len)
{
    memmove(&r->views[i + 1], &r->views[i], (r->nviews - i) * sizeof r->views[0]);
    r->views[i] = (os_ram_view){off, len};
    r->nviews++;
}

static bool ram_file_range_ok(os_file f, uint64_t foff, size_t len)
{
    uint64_t fsize, fend;
    return foff % OS_FILE_MAP_ALIGN == 0 && !os_file_size(f, &fsize) &&
           !ckd_add(&fend, foff, (uint64_t)len) && fend <= fsize;
}

int os_ram_reserve(os_ram *r, size_t size)
{
    *r = (os_ram){.size = size};
    void *p = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED)
        return -1;
    // 4 KiB pages: with transparent huge pages on "always" (Debian's
    // default), each first touch would fault in 2 MiB, and a boot that
    // touches ~5 MB would cost ~17 MB per VM. Failure is harmless.
    (void)madvise(p, size, MADV_NOHUGEPAGE);
    r->base = p;
    return 0;
}

int os_ram_map_file(os_ram *r, size_t off, size_t len, os_file f, uint64_t foff)
{
    size_t slot;
    if (!ram_view_slot(r, off, len, &slot) || !ram_file_range_ok(f, foff, len))
        return -1;
    void *p = mmap(r->base + off, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, (int)f.h,
                   (off_t)foff);
    if (p == MAP_FAILED) {
        // MAP_FIXED may already have dropped the old mapping: put it back.
        if (mmap(r->base + off, len, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1, 0) == MAP_FAILED)
            mvm_die("cannot restore guest memory after a failed file mapping");
        return -1;
    }
    ram_view_insert(r, slot, off, len);
    return 0;
}

int os_ram_overlay_file(os_ram *r, size_t off, size_t len, os_file f, uint64_t foff)
{
    size_t end;
    uint64_t fsize, fend;
    if (r->committed || !len || (off | len | foff) & 4095 || ckd_add(&end, off, len) || end > r->size ||
        os_file_size(f, &fsize) || ckd_add(&fend, foff, (uint64_t)len) || fend > fsize)
        return -1;
    // Only over a file view: the bookkeeping then stays right as it is.
    bool inside = false;
    for (size_t i = 0; i < r->nviews; i++)
        inside |= r->views[i].off <= off && end - r->views[i].off <= r->views[i].len;
    if (!inside)
        return -1;
    if (mmap(r->base + off, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, (int)f.h, (off_t)foff) ==
        MAP_FAILED)
        mvm_die("cannot map a snapshot's pages over guest memory"); // the old view is gone
    return 0;
}

int os_ram_commit(os_ram *r)
{
    r->committed = true; // the anonymous mapping is usable from the start
    return 0;
}

void os_ram_release(os_ram *r)
{
    if (r->base)
        munmap(r->base, r->size);
    *r = (os_ram){0};
}
#endif

void mvm_log(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf - 1, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if ((size_t)n > sizeof buf - 2)
        n = sizeof buf - 2;
    buf[n++] = '\n';
    mvm_write_err(buf, (size_t)n);
}

void mvm_die(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf - 1, fmt, ap);
    va_end(ap);
    if (n > 0) {
        if ((size_t)n > sizeof buf - 2)
            n = sizeof buf - 2;
        buf[n++] = '\n';
        mvm_write_err("microvm: ", 9);
        mvm_write_err(buf, (size_t)n);
    }
    // _Exit, not exit: other threads (the kernel loader, the profiler) may
    // still be running, and atexit handlers racing them can deadlock.
    _Exit(1);
}
