// SPDX-License-Identifier: MIT
#pragma once

#include <stdatomic.h>
#include <stdio.h>

#include "dev/devices.h"
#include "dev/virtio.h"
#include "hv.h"
#include "mem.h"
#include "os.h"
#include "snapshot.h"

// VMM exit codes when the guest didn't report its own status.
enum : int {
    MVM_EXIT_VMM_ERROR = 1,
    MVM_EXIT_RESET = 3,     // guest reset without reporting a status (e.g. panic)
    MVM_EXIT_TRIPLE = 4,    // triple fault
    MVM_EXIT_DEAD_HLT = 5,  // HLT with interrupts disabled
    MVM_EXIT_NO_HV = 77,    // no usable hypervisor on this host (ctest: skipped)
};

constexpr size_t MVM_MAX_MARKS = 32;
constexpr size_t MVM_PROF_DEPTH = 6;

typedef struct {
    hv_vm *hv;
    hv_vcpu *vcpu; // vcpus[0]: it boots the guest, on the main thread
    hv_vcpu *vcpus[MVM_MAX_VCPUS];
    uint32_t ncpus; // --cpus; each vCPU past the first runs on its own thread
    guest_mem mem;
    uart8250 com1;
    cmos_rtc cmos;
    ioapic ioapic;
    virtio_dev *virtio[VIRTIO_MAX_DEVICES]; // device i at VIRTIO_MMIO_BASE + i * VIRTIO_MMIO_SIZE
    int nvirtio;

    // Port I/O and MSR exits are handled one at a time (MMIO goes to
    // devices that lock themselves).
    atomic_flag io_lock;
    atomic_bool stop, stopping;
    int exit_status;
    bool trace;
    // vCPU threads (vm_start_cpus): they wait for `go`; `cpus_running`
    // counts those still in their run loop. A snapshot parks every vCPU but
    // the one saving: each saves its own state, then waits for the stop.
    // park_word: parked vCPUs, plus PARK_STOP once the VM stops.
    _Atomic uint32_t go, cpus_attached, cpus_running, park_word;
    atomic_bool park;

    // phase timestamps (ns, monotonic)
    uint64_t t_start, t_mem, t_vm, t_vcpu, t_prefault, t_load, t_boot, t_sandbox, t_run, t_end;
    uint64_t t_load_begin, t_load_end; // kernel copy, on the loader thread
    int64_t start_unix_us; // wall clock at main() entry, for tools that also see process times
    uint64_t mark_t[MVM_MAX_MARKS];
    uint8_t mark_id[MVM_MAX_MARKS];
    uint32_t nmarks;

    // guest RIP profiler (--profile): per sample the RIP, then up to
    // MVM_PROF_DEPTH kernel-text addresses found on the stack (0-padded)
    uint64_t *prof;
    uint32_t nprof, prof_cap;
    uint32_t prof_interval_us;
    atomic_bool prof_stop;

    uint64_t touched_kib;  // guest RAM actually resident after the run
    uint64_t shared_kib;   // ...of which still shared file pages (not copied)
    uint8_t *touched;      // per guest page: touched by the guest (traced recording)
    uint64_t mapped_bytes; // kernel bytes mapped copy-on-write instead of read

    struct balloon *balloon; // --balloon, or nullptr

    // snapshots
    bool snap_on;          // --snapshot: port 0x706 saves to snap_f and stops
    atomic_bool snap_req;
    os_file snap_f;
    bool restored;         // started from a snapshot (--restore)
    // --snapshot-diff: a VM restored from a snapshot saves only the pages
    // that differ from base_id, the full snapshot its RAM was mapped from
    // (snapshot.h). snap_map: a byte per page for the save (reserved, so
    // untouched until then); from_diff: the pages a diff restored (1), or
    // nullptr. snap_runs/snap_bytes: the last save's, for --trace.
    bool snap_diff;
    uint64_t base_id[2];
    uint8_t *snap_map, *from_diff;
    uint32_t snap_runs;
    uint64_t snap_bytes;
    uint64_t rootfs_size, tsc_khz;
    uint32_t nlayers;      // --rootfs images, bottom first (a snapshot records their sizes)
    uint64_t layer_size[SNAP_MAX_LAYERS];
    uint8_t seed[32];      // fresh randomness for the guest (port 0x707)
    uint8_t resume[MVM_RESUME_LEN];
    const uint8_t *env;    // --env: the blob /init reads (port 0x707), or nullptr
    uint32_t env_len;
    const uint8_t *rd;     // the record port 0x707 reads return: resume or env
    uint32_t rd_len, rd_at;
    uint64_t t_snap_begin, t_snap_end;

    // exit statistics, all vCPUs'
    _Atomic uint64_t n_exits, n_io, n_unknown_io, n_retry, n_mmio, n_mmio_queued, n_msr;
} vm;

// The I/O APIC's way out (ctx: the hv_vm).
void vm_send_msi(void *ctx, uint64_t addr, uint32_t data);

// Device handlers (hv_handlers callbacks); opaque is the vm.
void vm_pio(void *opaque, uint16_t port, uint8_t size, bool write, uint32_t *val);
void vm_mmio(void *opaque, uint64_t gpa, uint8_t size, bool write, uint64_t *val);
void vm_mmio_queued(void *opaque, uint64_t gpa, uint8_t size, uint64_t val);
bool vm_msr(void *opaque, uint32_t index, bool write, uint64_t *val);

// Start the RIP sampler thread (call right before vm_run).
[[nodiscard]] int vm_profile_start(vm *v, uint32_t interval_us, uint32_t max_samples);
// Write samples one per line: hex RIP, then the stack addresses.
[[nodiscard]] int vm_profile_write(const vm *v, FILE *f); // closes f

// Save the VM to v->snap_f: on the thread of vCPU `self`, which the guest
// asked on, with every other vCPU parked.
[[nodiscard]] int vm_snapshot(vm *v, uint32_t self);
// Load the vCPUs' and devices' state of a snapshot (its state section) into
// a VM built like the one saved: RAM mapped, vCPUs and devices created.
[[nodiscard]] int vm_restore(vm *v, const uint8_t *state, size_t len);

// Start the threads of vCPUs 1.. (they wait for vm_run). Before the
// sandbox, which refuses new threads.
[[nodiscard]] int vm_start_cpus(vm *v);
// Run vCPU 0 here, and the others on their threads, until the guest stops;
// returns the exit status.
int vm_run(vm *v);
void vm_print_trace(const vm *v);
