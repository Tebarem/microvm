// SPDX-License-Identifier: MIT
// Hypervisor backend interface. Exactly one backend is compiled in:
// hv_kvm.c on Linux, hv_whp.c on Windows. No vtable, no indirection.
//
// Device accesses (port I/O, MMIO, unknown MSRs) are dispatched by the
// backend straight into the handlers below, from inside hv_vcpu_run(). That
// is the only way WHP's instruction emulator can work (it calls back
// synchronously), and it keeps the KVM fast path free of extra round trips.
#pragma once

#include "common.h"

typedef struct hv_vm hv_vm;
typedef struct hv_vcpu hv_vcpu;

typedef struct {
    uint64_t base;
    uint32_t limit;
    uint16_t selector;
    uint8_t type, present, dpl, db, s, l, g, avl;
} hv_segment;

typedef struct {
    uint64_t base;
    uint16_t limit;
} hv_dtable;

typedef struct {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip, rflags;
} hv_regs;

typedef struct {
    hv_segment cs, ds, es, fs, gs, ss, tr, ldt;
    hv_dtable gdt, idt;
    uint64_t cr0, cr3, cr4, efer;
} hv_sregs;

typedef struct {
    void *opaque;
    // Port I/O. For reads, store the result in *val (low `size` bytes).
    void (*pio)(void *opaque, uint16_t port, uint8_t size, bool write, uint32_t *val);
    // Guest-physical access outside RAM.
    void (*mmio)(void *opaque, uint64_t gpa, uint8_t size, bool write, uint64_t *val);
    // A write the hypervisor queued instead of exiting (hv_vm_queue_writes).
    // Called on the vCPU's thread, in order, before the next exit is handled.
    void (*mmio_queued)(void *opaque, uint64_t gpa, uint8_t size, uint64_t val);
    // MSR the hypervisor doesn't implement. Return false to fail the access
    // with #GP, as hardware does for an MSR that doesn't exist.
    bool (*msr)(void *opaque, uint32_t index, bool write, uint64_t *val);
} hv_handlers;

typedef enum : uint8_t {
    HV_EXIT_HANDLED,  // a device access was dispatched; check for stop
    HV_EXIT_RETRY,    // spurious / interrupted / halted-with-IF; run again
    HV_EXIT_HLT,      // HLT with interrupts disabled: guest is dead
    HV_EXIT_SHUTDOWN, // triple fault / unrecoverable exception
    HV_EXIT_FAIL,     // backend error; see hw_reason
} hv_exit_kind;

typedef enum : uint8_t {
    HV_ACCESS_NONE,
    HV_ACCESS_PIO,
    HV_ACCESS_MMIO,
    HV_ACCESS_MSR,
} hv_access_kind;

typedef struct {
    hv_exit_kind kind;
    hv_access_kind access; // what HV_EXIT_HANDLED dispatched (for stats)
    bool sampled;          // exit was caused by hv_vcpu_kick() while profiling
    uint64_t rip;          // guest RIP, valid when sampled
    uint64_t rsp, cr3;     // guest RSP and CR3 when sampled; cr3 0 if unknown
    uint64_t hw_reason;
} hv_exit;

typedef struct {
    uint64_t tsc_khz; // guest TSC frequency, 0 if unknown
} hv_info;

// Returns 0, HV_UNAVAILABLE if this host has no usable hypervisor (no
// /dev/kvm, Windows Hypervisor Platform off), or -1 on other errors.
constexpr int HV_UNAVAILABLE = -2;

// CPUID bits to hide from the guest on top of the backend's CPU template:
// in leaf `leaf` (subleaf `subleaf`, or every subleaf if `any_subleaf`),
// register `reg` (0 eax, 1 ebx, 2 ecx, 3 edx) reads with the bits in `mask`
// clear. Presents an older CPU (a common view across a fleet, or a test of
// a kernel pre-patched for this one). Set before hv_vm_create(); the list
// is copied.
typedef struct {
    uint32_t leaf, subleaf;
    bool any_subleaf;
    uint8_t reg;
    uint32_t mask;
} hv_cpuid_hide;
constexpr size_t HV_CPUID_HIDE_MAX = 8;
void hv_set_cpuid_hide(const hv_cpuid_hide *hide, size_t n);

[[nodiscard]] int hv_vm_create(hv_vm **out);
void hv_vm_destroy(hv_vm *vm);
[[nodiscard]] int hv_vm_map_mem(hv_vm *vm, uint64_t gpa, void *hva, uint64_t size);
// Map memory the guest may only read, e.g. a read-only file view. A guest
// write never reaches it: it exits and is dropped like a write to nothing.
[[nodiscard]] int hv_vm_map_mem_ro(hv_vm *vm, uint64_t gpa, void *hva, uint64_t size);
// vCPUs a VM may have on this backend (at most MVM_MAX_VCPUS). vCPU 0
// boots; the others wait for the guest to start them (INIT, SIPI).
uint32_t hv_max_vcpus(void);
[[nodiscard]] int hv_vcpu_create(hv_vm *vm, uint32_t id, const hv_handlers *h, hv_vcpu **out);
// Call on the thread that will run the vCPU, before it does: kicks go
// there. (A vCPU starts out attached to the thread that created it.)
void hv_vcpu_attach(hv_vcpu *vcpu);
// Apply CPUID policy (backend-specific base, then common fix-ups).
[[nodiscard]] int hv_vcpu_setup_cpuid(hv_vcpu *vcpu);
[[nodiscard]] int hv_vcpu_set_state(hv_vcpu *vcpu, const hv_regs *regs, const hv_sregs *sregs);
[[nodiscard]] int hv_vcpu_run(hv_vcpu *vcpu, hv_exit *exit);
void hv_get_info(hv_vm *vm, hv_vcpu *vcpu, hv_info *info);
typedef struct {
    uint64_t gpa, size;
} hv_range;

// hv_vm_map_mem(), but only the `now` ranges (page-aligned, any order,
// may overlap) are mapped before returning. The rest of the region is mapped
// on a background thread while the guest runs; a guest access that gets
// there first waits for it. Worth it where mapping costs per page (WHP:
// ~11 us/MB, serialized in the hypervisor); elsewhere the same as mapping
// everything now.
[[nodiscard]] int hv_vm_map_mem_split(hv_vm *vm, uint64_t gpa, void *hva, uint64_t size,
                                      const hv_range *now, size_t n_now);

// For recording a working set: map the region one page at a time as the
// guest first touches it, setting touched[page index] for each page, so
// the record holds what the guest used rather than what the host wrote
// (the whole kernel image). Slow; HV_UNAVAILABLE where the backend can't
// (KVM), and the caller maps normally.
[[nodiscard]] int hv_vm_map_mem_traced(hv_vm *vm, uint64_t gpa, void *hva, uint64_t size,
                                       uint8_t *touched);

// Ask the hypervisor to build second-level page-table entries for these GPA
// ranges now, in one batch, instead of one fault per first-touched page.
// write=false maps pages for reading only, so copy-on-write file pages stay
// shared until the guest really writes them.
[[nodiscard]] int hv_vcpu_prefault(hv_vcpu *vcpu, const hv_range *ranges, size_t n, bool write);
// hv_vcpu_kick() (callable from any thread) makes the vCPU's current or
// next hv_vcpu_run() return HV_EXIT_RETRY soon: it leaves the guest, or
// doesn't enter it. A kick is never lost: one that lands while the vCPU is
// outside the guest makes its next run return at once. So a thread that
// sets a flag and then kicks gets the vCPU's thread to look at the flag.
// Profiling: the RETRY exit a kick causes also reports the guest RIP.
void hv_vcpu_set_profiling(hv_vcpu *vcpu, bool on);
void hv_vcpu_kick(hv_vcpu *vcpu);
// Deliver an MSI (x86 format: address 0xfeeXXXXX, data = vector | mode) to
// the guest's local APIC. Callable from any thread; wakes a halted vCPU.
[[nodiscard]] int hv_vm_signal_msi(hv_vm *vm, uint64_t addr, uint32_t data);
// Let the guest's writes to [gpa, gpa + len) queue up in the hypervisor
// instead of each one exiting; they reach handlers.mmio_queued before the
// vCPU's next exit is handled. Only for registers whose writes can wait
// until then. Reads still exit. HV_UNAVAILABLE where the backend can't.
[[nodiscard]] int hv_vm_queue_writes(hv_vm *vm, uint64_t gpa, uint32_t len);
// Linux: have guest writes to [gpa, gpa + len) signal eventfd `fd` in the
// kernel instead of exiting. The write's value is lost, so only for
// doorbells whose reader checks everything. HV_UNAVAILABLE where the
// backend can't.
[[nodiscard]] int hv_vm_doorbell(hv_vm *vm, uint64_t gpa, uint32_t len, int fd);

// ---- snapshots (KVM; HV_UNAVAILABLE elsewhere) ------------------------------
// The vCPU's architectural state as one backend-specific blob, at most
// HV_STATE_MAX bytes.
constexpr size_t HV_STATE_MAX = 64 * 1024;
// Before the sandbox: find out what there is to save, allocate for it.
[[nodiscard]] int hv_vcpu_save_prepare(hv_vcpu *vcpu);
// Finish the exit just handled without running the guest any further, then
// save. Returns the blob's length, or -1.
[[nodiscard]] int64_t hv_vcpu_save(hv_vcpu *vcpu, uint8_t *buf, size_t cap);
// Load a blob from hv_vcpu_save() into a new vCPU whose CPUID is set up.
// The blob comes from a file: every record's type and length is checked,
// and the hypervisor checks the values as for any state it is given.
[[nodiscard]] int hv_vcpu_restore(hv_vcpu *vcpu, const uint8_t *buf, size_t len);
// A hash of the CPUID the vCPU was given: a snapshot restores only onto
// the same CPU model.
uint64_t hv_vcpu_cpuid_hash(const hv_vcpu *vcpu);
// The ioctls hv_vcpu_save() issues, for the sandbox's allowlist.
size_t hv_save_ioctls(hv_vcpu *vcpu, int *fds, unsigned long *requests, size_t max);

const char *hv_name(void);
// Linux: the (fd, request) ioctl pairs the backend still issues once the
// guest runs, for the sandbox's allowlist. Returns how many were written.
size_t hv_runtime_ioctls(hv_vcpu *vcpu, int *fds, unsigned long *requests, size_t max);
