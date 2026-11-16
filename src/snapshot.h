// SPDX-License-Identifier: MIT
// Snapshots: a VM saved at a point the guest chose (control port 0x706),
// restored by later VMMs, any number of times.
//
// File layout (little-endian):
//   0       header page (snap_header)
//   4096    state: each vCPU's blob (u32 length, hv_vcpu_save()), then
//           each device's state
//   runs_off  a diff's page runs (below)
//   mem_off guest RAM, mem_size bytes, sparse: zero pages are holes
//
// A restore maps the RAM copy-on-write straight from the file, so every VM
// restored from one snapshot shares its pages through the host page cache
// until it writes them. The file is input like any other: the header and
// every device's state are checked as strictly as a guest's register
// writes, and the vCPU state goes through the hypervisor's own checks.
//
// A diff (version 2) holds only the pages that differ from a full snapshot,
// its base: the one the saved VM's RAM was mapped from. Its runs say which
// pages it has, each stored where a full snapshot keeps it (mem_off + the
// page's address); every other page is the base's. A restore maps the base,
// then the diff's runs over it. A VM restored from a diff saves another
// diff of the same base (its pages and the ones it changed), so there is
// never a chain. Every snapshot has a random id; a diff names its base's.
#pragma once

#include "common.h"

constexpr uint64_t SNAP_STATE_OFF = 4096;
constexpr uint64_t SNAP_MEM_ALIGN = 64 * 1024; // OS_FILE_MAP_ALIGN
constexpr uint64_t SNAP_STATE_MAX = 1024 * 1024;
constexpr uint32_t SNAP_VERSION = 1;      // a full snapshot
constexpr uint32_t SNAP_VERSION_DIFF = 2; // a diff: older VMMs refuse it
constexpr uint32_t SNAP_MAX_RUNS = 16384; // each is a mapping: kept well under vm.max_map_count
constexpr uint32_t SNAP_MAX_DEVICES = 3; // VIRTIO_MAX_DEVICES
constexpr uint32_t SNAP_MAX_LAYERS = 8;  // X86_PMEM_MAX

typedef struct {
    uint64_t mem_size;   // guest RAM, a multiple of 1 MiB
    uint64_t mem_off;    // where it starts in the file
    uint64_t state_len;  // bytes of state at SNAP_STATE_OFF
    uint64_t rootfs_size; // 0: none; else the span of the images (one: its size)
    // The root filesystem's layers, bottom first: the restore needs images
    // of these sizes. 0 in files from before layers: one, rootfs_size bytes.
    uint32_t nlayers;
    uint64_t layer_size[SNAP_MAX_LAYERS];
    uint64_t tsc_khz;    // the guest's TSC rate: the restore's must match
    uint64_t cpuid_hash; // hv_vcpu_cpuid_hash(): the same CPU model
    uint32_t ncpus;      // vCPUs, 1..MVM_MAX_VCPUS (0 in files from before: 1)
    uint32_t ndev;       // virtio devices, in MMIO slot order
    uint32_t dev_id[SNAP_MAX_DEVICES];
    uint64_t id[2];      // random; 0 in files from before ids
    // A diff: its base's id (nonzero), and nruns runs at runs_off.
    bool diff;
    uint64_t base_id[2];
    uint64_t runs_off;
    uint32_t nruns;
} snap_header;

// A run of pages a diff has: pages first .. first + count - 1.
typedef struct {
    uint32_t first, count;
} snap_run;

void snap_header_encode(const snap_header *h, uint8_t page[4096]);
// Checks the magic, version and that every region lies inside a file of
// file_size bytes. Returns 0 or -1.
// For a diff, the RAM region is checked by snap_runs_decode (it ends at
// the last run).
[[nodiscard]] int snap_header_decode(const uint8_t page[4096], uint64_t file_size, snap_header *h);

// A diff's runs: 8 bytes each (u32 first page, u32 count). Decoding checks
// they are in order, apart (a page in two runs, or runs that touch, are
// refused), nonempty, inside RAM and inside a file of file_size bytes.
void snap_runs_encode(const snap_run *runs, uint32_t n, uint8_t *out);
[[nodiscard]] int snap_runs_decode(const uint8_t *in, const snap_header *h, uint64_t file_size, snap_run *runs);

// ---- state serialization ------------------------------------------------------
// Writers stop at the buffer's end and remember it; readers return zeros
// past the end of the input and remember that. Check .bad once at the end.
typedef struct {
    uint8_t *p;
    size_t len, cap;
    bool bad;
} snap_w;

typedef struct {
    const uint8_t *p;
    size_t len, at;
    bool bad;
} snap_r;

static inline void sw_bytes(snap_w *w, const void *src, size_t n)
{
    if (w->bad || w->cap - w->len < n) {
        w->bad = true;
        return;
    }
    memcpy(w->p + w->len, src, n);
    w->len += n;
}
static inline void sw_u8(snap_w *w, uint8_t v) { sw_bytes(w, &v, 1); }
static inline void sw_u16(snap_w *w, uint16_t v) { sw_bytes(w, &v, 2); }
static inline void sw_u32(snap_w *w, uint32_t v) { sw_bytes(w, &v, 4); }
static inline void sw_u64(snap_w *w, uint64_t v) { sw_bytes(w, &v, 8); }

static inline bool sr_bytes(snap_r *r, void *dst, size_t n)
{
    if (r->bad || r->len - r->at < n) {
        r->bad = true;
        memset(dst, 0, n);
        return false;
    }
    memcpy(dst, r->p + r->at, n);
    r->at += n;
    return true;
}
static inline uint8_t sr_u8(snap_r *r) { uint8_t v; sr_bytes(r, &v, 1); return v; }
static inline uint16_t sr_u16(snap_r *r) { uint16_t v; sr_bytes(r, &v, 2); return v; }
static inline uint32_t sr_u32(snap_r *r) { uint32_t v; sr_bytes(r, &v, 4); return v; }
static inline uint64_t sr_u64(snap_r *r) { uint64_t v; sr_bytes(r, &v, 8); return v; }
// A bool must be 0 or 1.
static inline bool sr_bool(snap_r *r)
{
    const uint8_t v = sr_u8(r);
    if (v > 1)
        r->bad = true;
    return v == 1;
}
