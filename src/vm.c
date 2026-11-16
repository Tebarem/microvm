// SPDX-License-Identifier: MIT
// vCPU run loops and port-I/O dispatch.
//
// vCPU 0 runs on the main thread, every other vCPU on a thread of its own
// (vm_start_cpus). Exits are handled on the thread that took them: port
// I/O under io_lock (the UART, CMOS, control ports), MMIO by devices that
// lock themselves. The first stop wins and kicks every vCPU out of the
// guest; a snapshot parks every vCPU but the one saving.
#include "vm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include "clock.h"
#include "dev/balloon.h"
#include "os.h"
#include "snapshot.h"

enum : uint32_t { PARK_STOP = 1u << 31 }; // park_word: the VM stopped

static void stop(vm *v, int status)
{
    bool was = false;
    if (!atomic_compare_exchange_strong(&v->stopping, &was, true))
        return;
    v->exit_status = status;
    v->t_end = mvm_now_ns();
    atomic_store(&v->stop, true);
    if (v->ncpus > 1) { // the others may be halted in the guest: wake them
        atomic_fetch_or(&v->park_word, PARK_STOP);
        os_wake_all(&v->park_word);
        for (uint32_t i = 0; i < v->ncpus; i++)
            hv_vcpu_kick(v->vcpus[i]);
    }
}

static void io_lock(vm *v)
{
    for (unsigned spins = 0; atomic_flag_test_and_set_explicit(&v->io_lock, memory_order_acquire);)
        if (++spins > 64) // the holder may be writing the console: don't burn the core
            os_yield();
}

static void io_unlock(vm *v) { atomic_flag_clear_explicit(&v->io_lock, memory_order_release); }

static void note_unknown(vm *v, uint16_t port, bool write)
{
    v->n_unknown_io++;
    if (v->trace && v->n_unknown_io <= 16)
        mvm_log("unknown port %s 0x%x", write ? "write" : "read", port);
}

static void latch_resume(vm *v)
{
    struct timespec ts = {0};
    (void)timespec_get(&ts, TIME_UTC);
    memset(v->resume, 0, sizeof v->resume);
    put_le64(v->resume, (uint64_t)(int64_t)ts.tv_sec);
    put_le32(v->resume + 8, (uint32_t)ts.tv_nsec);
    put_le32(v->resume + 12, v->restored ? 1 : 0);
    memcpy(v->resume + 16, v->seed, sizeof v->seed);
    v->rd = v->resume, v->rd_len = MVM_RESUME_LEN, v->rd_at = 0;
}

static const uint8_t NO_ENV[4]; // length 0

// Returns the value for reads; ignored for writes.
static uint32_t port_access(vm *v, uint16_t port, bool write, uint32_t val)
{
    if (port >= COM1_BASE && port < COM1_BASE + 8) {
        if (write) {
            uart_write(&v->com1, port - COM1_BASE, (uint8_t)val);
            return 0;
        }
        return uart_read(&v->com1, port - COM1_BASE);
    }
    switch (port) {
    case 0x70:
    case 0x71:
        if (write) {
            cmos_write(&v->cmos, port, (uint8_t)val);
            return 0;
        }
        return cmos_read(&v->cmos, port);
    case 0x64: // i8042 status / command
        if (write && (val & 0xff) == 0xfe)
            stop(v, MVM_EXIT_RESET);
        return 0;
    case 0x60:
    case 0x61:
        return 0;
    case 0x20:
    case 0x21:
    case 0xa0:
    case 0xa1:
        return 0; // reads back 0, so Linux picks the NULL legacy PIC
    case 0x80: // POST / io_delay
        return 0;
    case MVM_PORT_MARK:
        if (write && v->nmarks < MVM_MAX_MARKS) {
            v->mark_t[v->nmarks] = mvm_now_ns();
            v->mark_id[v->nmarks++] = (uint8_t)val;
        }
        return 0;
    case MVM_PORT_EXIT:
        if (write)
            stop(v, val & 0xff);
        return 0;
    case MVM_PORT_CONSOLE: // handled in vm_pio (needs the access size)
        return 0;
    case MVM_PORT_SNAPSHOT:
        if (write && v->snap_on)
            v->snap_req = true; // vm_run saves once this exit is handled
        return 0;
    case MVM_PORT_RESUME:
        if (write && (val & 0xff) == 1) {
            v->rd = v->env ? v->env : NO_ENV, v->rd_len = v->env ? v->env_len : sizeof NO_ENV, v->rd_at = 0;
            return 0;
        }
        if (write) {
            latch_resume(v);
            return 0;
        }
        return v->rd && v->rd_at < v->rd_len ? v->rd[v->rd_at++] : 0;
    default:
        note_unknown(v, port, write);
        return 0xffffffffu;
    }
}

void vm_pio(void *opaque, uint16_t port, uint8_t size, bool write, uint32_t *val)
{
    vm *v = opaque;
    v->n_io++;
    io_lock(v);
    if (write && port == MVM_PORT_CONSOLE) {
        for (uint8_t i = 0; i < size && i < 4; i++) // as many bytes as the access is wide
            uart_emit(&v->com1, (uint8_t)(*val >> (8 * i)));
    } else if (write) {
        (void)port_access(v, port, true, *val);
    } else {
        const uint32_t r = port_access(v, port, false, 0);
        *val = size == 4 ? r : (r & ((1u << (size * 8)) - 1));
    }
    io_unlock(v);
}

void vm_send_msi(void *ctx, uint64_t addr, uint32_t data) { (void)hv_vm_signal_msi(ctx, addr, data); }

static void mmio_access(vm *v, uint64_t gpa, uint8_t size, bool write, uint64_t *val)
{
    if (gpa >= VIRTIO_MMIO_BASE && gpa - VIRTIO_MMIO_BASE < (uint64_t)v->nvirtio * VIRTIO_MMIO_SIZE) {
        const uint64_t i = (gpa - VIRTIO_MMIO_BASE) / VIRTIO_MMIO_SIZE;
        virtio_mmio_access(v->virtio[i], gpa - VIRTIO_MMIO_BASE - i * VIRTIO_MMIO_SIZE, size, write, val);
        return;
    }
    if (gpa >= IOAPIC_BASE && gpa - IOAPIC_BASE < IOAPIC_SIZE && v->nvirtio) {
        ioapic_mmio(&v->ioapic, gpa - IOAPIC_BASE, size, write, val);
        return;
    }
    if (v->trace && v->n_mmio <= 16)
        mvm_log("unknown MMIO %s 0x%llx (%u bytes)", write ? "write" : "read",
                (unsigned long long)gpa, size);
    if (!write)
        *val = ~0ull; // nothing there: floating bus
}

void vm_mmio(void *opaque, uint64_t gpa, uint8_t size, bool write, uint64_t *val)
{
    vm *v = opaque;
    v->n_mmio++;
    mmio_access(v, gpa, size, write, val);
}

void vm_mmio_queued(void *opaque, uint64_t gpa, uint8_t size, uint64_t val)
{
    vm *v = opaque;
    v->n_mmio_queued++;
    mmio_access(v, gpa, size, true, &val);
}

// AMD performance counters (legacy and core-extension ranges). There is no
// PMU to give the guest, so the counters don't exist: #GP, which Linux's
// probe takes as "no PMU" after one access instead of seven.
static bool amd_pmu_msr(uint32_t index)
{
    return (index >= 0xc0010000 && index <= 0xc0010007) ||
           (index >= 0xc0010200 && index <= 0xc001020b);
}

bool vm_msr(void *opaque, uint32_t index, bool write, uint64_t *val)
{
    vm *v = opaque;
    v->n_msr++;
    if (v->trace && v->n_msr <= 16)
        mvm_log("unknown MSR %s 0x%x", write ? "write" : "read", index);
    if (amd_pmu_msr(index))
        return false;
    if (write)
        return true;
    switch (index) {
    case 0xc0010015: // AMD HWCR: TscFreqSel, so the TSC "counts at P0"
        *val = 1ull << 24;
        break;
    default:
        *val = 0;
        break;
    }
    return true;
}

// ---- snapshots ------------------------------------------------------------------
// State section: each vCPU's blob (u32 length, then the blob), I/O APIC,
// UART, CMOS, u8 device count, each virtio device.
static uint8_t snap_state[SNAP_STATE_MAX]; // bss: touched only when used
// Each vCPU's blob, saved on its own thread (KVM wants a vCPU's ioctls
// there: moving KVM_RUN to another thread costs an RCU grace period).
static uint8_t cpu_state[MVM_MAX_VCPUS][HV_STATE_MAX];
static int64_t cpu_state_len[MVM_MAX_VCPUS];

// A vCPU asked to park: save its state, then wait for the VM to stop.
static void park(vm *v, uint32_t i)
{
    cpu_state_len[i] = hv_vcpu_save(v->vcpus[i], cpu_state[i], HV_STATE_MAX);
    atomic_fetch_add(&v->park_word, 1);
    os_wake_all(&v->park_word);
    for (uint32_t w; !((w = atomic_load(&v->park_word)) & PARK_STOP);)
        os_wait_u32(&v->park_word, w);
}

// Every vCPU but `self` out of the guest and parked. false: the VM
// stopped first.
static bool park_others(vm *v, uint32_t self)
{
    if (v->ncpus < 2)
        return true;
    atomic_store(&v->park, true);
    for (uint32_t i = 0; i < v->ncpus; i++)
        if (i != self)
            hv_vcpu_kick(v->vcpus[i]);
    for (uint32_t w;;) {
        w = atomic_load(&v->park_word);
        if (w & PARK_STOP)
            return false;
        if (w == v->ncpus - 1)
            return true;
        os_wait_u32(&v->park_word, w);
    }
}

static bool page_zero(const uint8_t *p)
{
    uint64_t acc = 0;
    for (size_t i = 0; i < 4096; i += 8) {
        uint64_t x;
        memcpy(&x, p + i, 8);
        acc |= x;
    }
    return acc == 0;
}

// Guest pages [i, j) to the file at mem_off, the zero ones left as holes.
static int write_pages(vm *v, uint64_t mem_off, size_t i, size_t j)
{
    while (i < j) {
        if (page_zero(v->mem.base + i * 4096)) {
            i++;
            continue;
        }
        size_t k = i + 1;
        while (k < j && !page_zero(v->mem.base + k * 4096))
            k++;
        if (os_file_pwrite(v->snap_f, v->mem.base + i * 4096, (k - i) * 4096, mem_off + i * 4096))
            return -1;
        v->snap_bytes += (k - i) * 4096;
        i = k;
    }
    return 0;
}

// A diff's runs from map (1: a page the diff must have). Gaps of up to gap
// pages are bridged with the base's pages: a run less to map at restore.
static uint32_t diff_runs(const uint8_t *map, size_t pages, size_t gap, snap_run *runs)
{
    uint32_t n = 0;
    for (size_t i = 0; i < pages;) {
        if (!map[i]) {
            i++;
            continue;
        }
        if (n && i - (runs[n - 1].first + runs[n - 1].count) <= gap)
            runs[n - 1].count = (uint32_t)(i + 1 - runs[n - 1].first);
        else if (n == SNAP_MAX_RUNS)
            return UINT32_MAX;
        else
            runs[n++] = (snap_run){(uint32_t)i, 1};
        i++;
    }
    return n;
}

int vm_snapshot(vm *v, uint32_t self)
{
    v->t_snap_begin = mvm_now_ns();
    if (!park_others(v, self)) {
        os_file_close(v->snap_f);
        mvm_log("the VM stopped while the snapshot was being taken");
        return -1;
    }
    uart_flush(&v->com1);
    // The devices stay locked to the end: their I/O threads must not
    // change rings or buffers in guest memory while it is being copied.
    for (int i = 0; i < v->nvirtio; i++)
        virtio_lock(v->virtio[i]);
    int rc = -1;
    v->snap_bytes = 0;
    v->snap_runs = 0;
    snap_w w = {.p = snap_state, .cap = sizeof snap_state};
    cpu_state_len[self] = hv_vcpu_save(v->vcpus[self], cpu_state[self], HV_STATE_MAX);
    for (uint32_t i = 0; i < v->ncpus; i++) {
        if (cpu_state_len[i] < 0)
            goto out;
        sw_u32(&w, (uint32_t)cpu_state_len[i]);
        sw_bytes(&w, cpu_state[i], (size_t)cpu_state_len[i]);
    }
    ioapic_save(&v->ioapic, &w);
    uart_save(&v->com1, &w);
    cmos_save(&v->cmos, &w);
    sw_u8(&w, (uint8_t)v->nvirtio);
    snap_header h = {.mem_size = v->mem.size, .state_len = w.len, .rootfs_size = v->rootfs_size,
                     .tsc_khz = v->tsc_khz, .cpuid_hash = hv_vcpu_cpuid_hash(v->vcpu),
                     .ncpus = v->ncpus, .ndev = (uint32_t)v->nvirtio, .nlayers = v->nlayers};
    memcpy(h.layer_size, v->layer_size, sizeof h.layer_size);
    for (int i = 0; i < v->nvirtio; i++) {
        virtio_save(v->virtio[i], &w);
        h.dev_id[i] = v->virtio[i]->ops->device_id;
    }
    if (w.bad || os_random(h.id, sizeof h.id))
        goto out;
    h.state_len = w.len;
    const size_t pages = v->mem.size / 4096;
    // A diff: the pages written since the restore, and those a diff
    // restored. Without pagemap (no /proc), a full snapshot instead.
    static snap_run runs[SNAP_MAX_RUNS];
    if (v->snap_diff && (v->base_id[0] | v->base_id[1]) && v->snap_map &&
        !os_mem_private(v->mem.base, v->mem.size, v->snap_map)) {
        if (v->from_diff)
            for (size_t i = 0; i < pages; i++)
                v->snap_map[i] |= v->from_diff[i];
        uint32_t nr = UINT32_MAX;
        for (size_t gap = 8; nr == UINT32_MAX; gap *= 4)
            nr = diff_runs(v->snap_map, pages, gap, runs);
        if (!nr) // nothing changed: a diff has at least one run
            runs[nr++] = (snap_run){0, 1};
        h.diff = true;
        h.base_id[0] = v->base_id[0], h.base_id[1] = v->base_id[1];
        h.nruns = v->snap_runs = nr;
        h.runs_off = (SNAP_STATE_OFF + w.len + 7) / 8 * 8;
    }
    const uint64_t meta_end = h.diff ? h.runs_off + 8ull * h.nruns : SNAP_STATE_OFF + w.len;
    h.mem_off = (meta_end + SNAP_MEM_ALIGN - 1) / SNAP_MEM_ALIGN * SNAP_MEM_ALIGN;
    if (os_file_pwrite(v->snap_f, snap_state, w.len, SNAP_STATE_OFF))
        goto out;
    // RAM, sparse: the file ends where RAM (a diff: its last run) does.
    size_t end = pages;
    if (h.diff) {
        static uint8_t enc[8 * SNAP_MAX_RUNS];
        snap_runs_encode(runs, h.nruns, enc);
        if (os_file_pwrite(v->snap_f, enc, 8ull * h.nruns, h.runs_off))
            goto out;
        for (uint32_t i = 0; i < h.nruns; i++)
            if (write_pages(v, h.mem_off, runs[i].first, runs[i].first + runs[i].count))
                goto out;
        end = runs[h.nruns - 1].first + runs[h.nruns - 1].count;
    } else if (write_pages(v, h.mem_off, 0, pages))
        goto out;
    static const uint8_t zero = 0;
    if (page_zero(v->mem.base + (end - 1) * 4096) &&
        os_file_pwrite(v->snap_f, &zero, 1, h.mem_off + end * 4096 - 1))
        goto out;
    // The header last: a file that has one is whole (the file was empty,
    // and on any failure it gets none). microvm-sbxd counts on that to
    // learn a sandbox is paused without waiting for this process to exit.
    static uint8_t page[4096];
    snap_header_encode(&h, page);
    if (os_file_pwrite(v->snap_f, page, sizeof page, 0))
        goto out;
    rc = 0;
out:
    for (int i = 0; i < v->nvirtio; i++)
        virtio_unlock(v->virtio[i]);
    os_file_close(v->snap_f);
    v->t_snap_end = mvm_now_ns();
    if (rc)
        mvm_log("cannot write the snapshot");
    return rc;
}

int vm_restore(vm *v, const uint8_t *state, size_t len)
{
    snap_r r = {.p = state, .len = len};
    for (uint32_t i = 0; i < v->ncpus; i++) {
        const uint32_t n = sr_u32(&r);
        if (r.bad || n > HV_STATE_MAX || n > r.len - r.at || hv_vcpu_restore(v->vcpus[i], state + r.at, n))
            return -1;
        r.at += n;
    }
    ioapic_load(&v->ioapic, &r);
    uart_load(&v->com1, &r);
    cmos_load(&v->cmos, &r);
    if (sr_u8(&r) != (uint8_t)v->nvirtio)
        return -1;
    for (int i = 0; i < v->nvirtio; i++)
        if (!virtio_load(v->virtio[i], &r))
            return -1;
    if (r.bad || r.at != r.len)
        return -1;
    v->restored = true;
    return 0;
}

static void prof_sample(vm *v, const hv_exit *ex);

static void cpu_loop(vm *v, uint32_t i)
{
    hv_exit ex;
    while (!v->stop) {
        if (MVM_UNLIKELY(atomic_load_explicit(&v->park, memory_order_relaxed))) {
            park(v, i);
            break;
        }
        if (hv_vcpu_run(v->vcpus[i], &ex)) {
            stop(v, MVM_EXIT_VMM_ERROR);
            break;
        }
        v->n_exits++;
        switch (ex.kind) {
        case HV_EXIT_HANDLED:
            // The guest's snapshot request: this vCPU saves the VM.
            if (MVM_UNLIKELY(atomic_load_explicit(&v->snap_req, memory_order_relaxed)) &&
                atomic_exchange(&v->snap_req, false))
                stop(v, vm_snapshot(v, i) ? MVM_EXIT_VMM_ERROR : 0);
            break;
        case HV_EXIT_RETRY: // a kick: the loop looks at why
            v->n_retry++;
            if (ex.sampled && i == 0 && v->nprof < v->prof_cap)
                prof_sample(v, &ex);
            break;
        case HV_EXIT_HLT:
            stop(v, MVM_EXIT_DEAD_HLT);
            break;
        case HV_EXIT_SHUTDOWN:
            stop(v, MVM_EXIT_TRIPLE);
            break;
        case HV_EXIT_FAIL:
            stop(v, MVM_EXIT_VMM_ERROR);
            break;
        }
    }
}

typedef struct {
    vm *v;
    uint32_t i;
} cpu_thread;

static void cpu_main(void *arg)
{
    const cpu_thread *t = arg;
    vm *v = t->v;
    hv_vcpu_attach(v->vcpus[t->i]);
    atomic_fetch_add(&v->cpus_attached, 1);
    os_wake_all(&v->cpus_attached);
    for (uint32_t g; !(g = atomic_load(&v->go));)
        os_wait_u32(&v->go, g);
    cpu_loop(v, t->i);
    if (atomic_fetch_sub(&v->cpus_running, 1) == 1)
        os_wake_all(&v->cpus_running);
}

int vm_start_cpus(vm *v)
{
    static cpu_thread threads[MVM_MAX_VCPUS];
    atomic_store(&v->cpus_running, v->ncpus - 1);
    for (uint32_t i = 1; i < v->ncpus; i++) {
        threads[i] = (cpu_thread){v, i};
        if (os_thread_start(cpu_main, &threads[i]))
            return -1;
    }
    // Attached: a kick from now on reaches the vCPU's own thread.
    for (uint32_t n; (n = atomic_load(&v->cpus_attached)) < v->ncpus - 1;)
        os_wait_u32(&v->cpus_attached, n);
    return 0;
}

int vm_run(vm *v)
{
    v->t_run = mvm_now_ns();
    if (v->ncpus > 1) {
        atomic_store(&v->go, 1);
        os_wake_all(&v->go);
    }
    cpu_loop(v, 0);
    // stop() kicked the others out of the guest: wait for them to leave.
    for (uint32_t n; v->ncpus > 1 && (n = atomic_load(&v->cpus_running)) > 0;)
        os_wait_u32(&v->cpus_running, n);
    uart_flush(&v->com1);
    atomic_store(&v->prof_stop, true);
    return v->exit_status;
}

// Translate a guest virtual address through the guest's 4-level page
// tables. Profiling only: the guest controls these tables, so every read
// goes through guest_slice() like any other guest data.
static bool gva_to_gpa(const guest_mem *m, uint64_t cr3, uint64_t gva, uint64_t *gpa)
{
    constexpr uint64_t ADDR = 0x000ffffffffff000ull;
    uint64_t table = cr3 & ADDR;
    for (int level = 3; level >= 0; level--) {
        const uint8_t *p = guest_slice(m, table + ((gva >> (12 + 9 * level)) & 511) * 8, 8);
        if (!p)
            return false;
        uint64_t e;
        memcpy(&e, p, sizeof e);
        if (!(e & 1))
            return false;
        if ((level == 1 || level == 2) && (e & 0x80)) { // 2 MiB / 1 GiB page
            const uint64_t mask = (1ull << (12 + 9 * level)) - 1;
            *gpa = ((e & ADDR) & ~mask) | (gva & mask);
            return true;
        }
        table = e & ADDR;
    }
    *gpa = table | (gva & 0xfff);
    return true;
}

// Record the RIP plus kernel-text addresses on the stack: likely return
// addresses (a heuristic: stale slots show up too), enough to attribute
// time to callers without frame pointers.
static void prof_sample(vm *v, const hv_exit *ex)
{
    uint64_t *out = v->prof + (size_t)v->nprof++ * (MVM_PROF_DEPTH + 1);
    out[0] = ex->rip;
    size_t n = 0;
    for (uint64_t sp = ex->rsp; ex->cr3 && n < MVM_PROF_DEPTH && sp - ex->rsp < 1024; sp += 8) {
        uint64_t gpa, val;
        const uint8_t *p;
        if (!gva_to_gpa(&v->mem, ex->cr3, sp, &gpa) || !(p = guest_slice(&v->mem, gpa, 8)))
            break;
        memcpy(&val, p, sizeof val);
        if (val >= 0xffffffff80000000ull && val < 0xffffffffc0000000ull)
            out[++n] = val;
    }
}

// Busy-waits between kicks: sleep granularity (1 ms on Windows) is far too
// coarse, and profiling runs can afford to burn one host core.
static void sampler(void *arg)
{
    vm *v = arg;
    const uint64_t step = (uint64_t)v->prof_interval_us * 1000;
    uint64_t next = mvm_now_ns() + step;
    while (!atomic_load(&v->prof_stop)) {
        if (mvm_now_ns() >= next) {
            hv_vcpu_kick(v->vcpu);
            next += step;
        }
    }
}

int vm_profile_start(vm *v, uint32_t interval_us, uint32_t max_samples)
{
    v->prof = calloc((size_t)max_samples * (MVM_PROF_DEPTH + 1), sizeof *v->prof);
    if (!v->prof)
        return -1;
    v->prof_cap = max_samples;
    v->prof_interval_us = interval_us ? interval_us : 1;
    atomic_store(&v->prof_stop, false);
    hv_vcpu_set_profiling(v->vcpu, true);
    return os_thread_start(sampler, v);
}

int vm_profile_write(const vm *v, FILE *f)
{
    for (uint32_t i = 0; i < v->nprof; i++) {
        const uint64_t *s = v->prof + (size_t)i * (MVM_PROF_DEPTH + 1);
        fprintf(f, "%llx", (unsigned long long)s[0]);
        for (size_t d = 1; d <= MVM_PROF_DEPTH && s[d]; d++)
            fprintf(f, " %llx", (unsigned long long)s[d]);
        fputc('\n', f);
    }
    return fclose(f);
}

static double us(uint64_t a, uint64_t b) { return b > a ? (double)(b - a) / 1000.0 : 0.0; }

void vm_print_trace(const vm *v)
{
    char buf[1024];
    int n = snprintf(buf, sizeof buf,
                     "MVMTRACE hv=%s status=%d mem_us=%.1f vm_us=%.1f vcpu_us=%.1f prefault_us=%.1f "
                     "wait_us=%.1f boot_us=%.1f sandbox_us=%.1f load_us=%.1f setup_us=%.1f guest_us=%.1f "
                     "total_us=%.1f exits=%llu io=%llu "
                     "unknown_io=%llu mmio=%llu mmio_queued=%llu msr=%llu retry=%llu touched_kib=%llu shared_kib=%llu "
                     "mapped_kib=%llu start_unix_us=%lld",
                     hv_name(), v->exit_status, us(v->t_start, v->t_mem), us(v->t_mem, v->t_vm),
                     us(v->t_vm, v->t_vcpu), us(v->t_vcpu, v->t_prefault),
                     us(v->t_prefault, v->t_load), us(v->t_load, v->t_boot), us(v->t_boot, v->t_sandbox),
                     us(v->t_load_begin, v->t_load_end),
                     us(v->t_start, v->t_run), us(v->t_run, v->t_end), us(v->t_start, v->t_end),
                     (unsigned long long)v->n_exits, (unsigned long long)v->n_io,
                     (unsigned long long)v->n_unknown_io, (unsigned long long)v->n_mmio,
                     (unsigned long long)v->n_mmio_queued,
                     (unsigned long long)v->n_msr, (unsigned long long)v->n_retry,
                     (unsigned long long)v->touched_kib, (unsigned long long)v->shared_kib,
                     (unsigned long long)(v->mapped_bytes / 1024), (long long)v->start_unix_us);
    for (uint32_t i = 0; i < v->nmarks && n > 0 && (size_t)n < sizeof buf - 32; i++)
        n += snprintf(buf + n, sizeof buf - (size_t)n, " mark%u_us=%.1f", v->mark_id[i],
                      us(v->t_start, v->mark_t[i]));
    if (v->balloon && n > 0 && (size_t)n < sizeof buf - 48)
        n += snprintf(buf + n, sizeof buf - (size_t)n, " balloon_discarded_kib=%llu",
                      (unsigned long long)(balloon_discarded(v->balloon) / 1024));
    if (v->t_snap_end && n > 0 && (size_t)n < sizeof buf - 96)
        n += snprintf(buf + n, sizeof buf - (size_t)n, " snapshot_us=%.1f snapshot_kib=%llu snapshot_runs=%u",
                      us(v->t_snap_begin, v->t_snap_end), (unsigned long long)(v->snap_bytes / 1024),
                      v->snap_runs);
    if (n > 0 && (size_t)n < sizeof buf - 1) {
        buf[n++] = '\n';
        mvm_write_err(buf, (size_t)n);
    }
}
