// SPDX-License-Identifier: MIT
// Snapshot file header (see snapshot.h).
#include "snapshot.h"

static const char MAGIC[8] = "MVMSNAP";

enum : size_t {
    H_MAGIC = 0, H_VERSION = 8, H_NDEV = 12, H_MEM_SIZE = 16, H_MEM_OFF = 24, H_STATE_LEN = 32,
    H_ROOTFS = 40, H_TSC = 48, H_CPUID = 56, H_DEV = 64, H_ID = 80, H_BASE_ID = 96, H_RUNS_OFF = 112,
    H_NRUNS = 120, H_NCPUS = 124, H_NLAYERS = 128, H_LAYERS = 136, // .. 200
};

void snap_header_encode(const snap_header *h, uint8_t page[4096])
{
    memset(page, 0, 4096);
    memcpy(page + H_MAGIC, MAGIC, sizeof MAGIC);
    put_le32(page + H_VERSION, h->diff ? SNAP_VERSION_DIFF : SNAP_VERSION);
    put_le32(page + H_NDEV, h->ndev);
    put_le32(page + H_NCPUS, h->ncpus);
    put_le64(page + H_MEM_SIZE, h->mem_size);
    put_le64(page + H_MEM_OFF, h->mem_off);
    put_le64(page + H_STATE_LEN, h->state_len);
    put_le64(page + H_ROOTFS, h->rootfs_size);
    put_le32(page + H_NLAYERS, h->nlayers);
    for (uint32_t i = 0; i < h->nlayers && i < SNAP_MAX_LAYERS; i++)
        put_le64(page + H_LAYERS + 8 * i, h->layer_size[i]);
    put_le64(page + H_TSC, h->tsc_khz);
    put_le64(page + H_CPUID, h->cpuid_hash);
    for (uint32_t i = 0; i < h->ndev && i < SNAP_MAX_DEVICES; i++)
        put_le32(page + H_DEV + 4 * i, h->dev_id[i]);
    put_le64(page + H_ID, h->id[0]);
    put_le64(page + H_ID + 8, h->id[1]);
    if (h->diff) {
        put_le64(page + H_BASE_ID, h->base_id[0]);
        put_le64(page + H_BASE_ID + 8, h->base_id[1]);
        put_le64(page + H_RUNS_OFF, h->runs_off);
        put_le32(page + H_NRUNS, h->nruns);
    }
}

int snap_header_decode(const uint8_t page[4096], uint64_t file_size, snap_header *h)
{
    memset(h, 0, sizeof *h);
    const uint32_t version = get_le32(page + H_VERSION);
    if (memcmp(page + H_MAGIC, MAGIC, sizeof MAGIC) || (version != SNAP_VERSION && version != SNAP_VERSION_DIFF))
        return -1;
    h->diff = version == SNAP_VERSION_DIFF;
    h->ndev = get_le32(page + H_NDEV);
    h->ncpus = get_le32(page + H_NCPUS);
    if (h->ncpus == 0)
        h->ncpus = 1;
    h->mem_size = get_le64(page + H_MEM_SIZE);
    h->mem_off = get_le64(page + H_MEM_OFF);
    h->state_len = get_le64(page + H_STATE_LEN);
    h->rootfs_size = get_le64(page + H_ROOTFS);
    h->nlayers = get_le32(page + H_NLAYERS);
    if (h->nlayers > SNAP_MAX_LAYERS || (h->nlayers && !h->rootfs_size))
        return -1;
    for (uint32_t i = 0; i < h->nlayers; i++) {
        h->layer_size[i] = get_le64(page + H_LAYERS + 8 * i);
        if (!h->layer_size[i] || h->layer_size[i] % 4096 || h->layer_size[i] > h->rootfs_size)
            return -1;
    }
    h->tsc_khz = get_le64(page + H_TSC);
    h->cpuid_hash = get_le64(page + H_CPUID);
    h->id[0] = get_le64(page + H_ID);
    h->id[1] = get_le64(page + H_ID + 8);
    if (h->ndev > SNAP_MAX_DEVICES || h->ncpus > MVM_MAX_VCPUS)
        return -1;
    for (uint32_t i = 0; i < h->ndev; i++)
        h->dev_id[i] = get_le32(page + H_DEV + 4 * i);
    uint64_t end;
    if (h->mem_size < 2 * MiB || h->mem_size > 3072 * MiB || h->mem_size % MiB ||
        h->state_len > SNAP_STATE_MAX || h->mem_off % SNAP_MEM_ALIGN ||
        h->mem_off < SNAP_STATE_OFF + h->state_len || h->rootfs_size % 4096 || h->rootfs_size > 64 * GiB)
        return -1;
    if (!h->diff)
        return ckd_add(&end, h->mem_off, h->mem_size) || end > file_size ? -1 : 0;
    h->base_id[0] = get_le64(page + H_BASE_ID);
    h->base_id[1] = get_le64(page + H_BASE_ID + 8);
    h->runs_off = get_le64(page + H_RUNS_OFF);
    h->nruns = get_le32(page + H_NRUNS);
    // The runs lie between the state and RAM, and RAM starts in the file
    // (snap_runs_decode checks where each run's pages end).
    if (!(h->base_id[0] | h->base_id[1]) || !h->nruns || h->nruns > SNAP_MAX_RUNS || h->runs_off % 8 ||
        h->runs_off < SNAP_STATE_OFF + h->state_len || ckd_add(&end, h->runs_off, 8ull * h->nruns) ||
        end > h->mem_off || h->mem_off > file_size)
        return -1;
    return 0;
}

void snap_runs_encode(const snap_run *runs, uint32_t n, uint8_t *out)
{
    for (uint32_t i = 0; i < n; i++) {
        put_le32(out + 8 * i, runs[i].first);
        put_le32(out + 8 * i + 4, runs[i].count);
    }
}

int snap_runs_decode(const uint8_t *in, const snap_header *h, uint64_t file_size, snap_run *runs)
{
    const uint64_t pages = h->mem_size / 4096;
    uint64_t next = 0; // the first page the next run may start at
    for (uint32_t i = 0; i < h->nruns; i++) {
        const uint64_t first = get_le32(in + 8 * i), count = get_le32(in + 8 * i + 4);
        // u32 + u32 can't wrap a u64; mem_off + pages * 4096 can't either
        // (mem_off <= file_size was checked, and pages <= 3 GiB / 4 KiB).
        if (!count || first < next || first + count > pages || h->mem_off > UINT64_MAX - pages * 4096 ||
            h->mem_off + (first + count) * 4096 > file_size)
            return -1;
        runs[i] = (snap_run){(uint32_t)first, (uint32_t)count};
        next = first + count + 1;
    }
    return 0;
}
