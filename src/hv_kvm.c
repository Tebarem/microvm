// SPDX-License-Identifier: MIT
// Linux KVM backend.
//
// Interrupt model: KVM_CAP_SPLIT_IRQCHIP, so only the local APIC lives in
// the kernel. That matches WHP's LAPIC emulation exactly; PIC/IOAPIC/PIT
// are deliberately absent (the guest kernel is configured not to need them).
#include "hv.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <linux/kvm_para.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef KVM_PRE_FAULT_MEMORY // Linux 6.10+; older uapi headers lack it
struct kvm_pre_fault_memory {
    __u64 gpa;
    __u64 size;
    __u64 flags;
    __u64 padding[5];
};
#  define KVM_PRE_FAULT_MEMORY _IOWR(KVMIO, 0xd5, struct kvm_pre_fault_memory)
#endif

#ifndef MADV_POPULATE_READ // Linux 5.14+
#  define MADV_POPULATE_READ 22
#  define MADV_POPULATE_WRITE 23
#endif

constexpr uint64_t KVM_TSS_ADDR = 0xfffbd000;
constexpr int KVM_MAX_SLOTS = 8;
constexpr int KVM_SPLIT_IRQCHIP_ROUTES = 24;
// The kernel's PAGE_SIZE on x86, which sizes the coalesced-MMIO ring.
constexpr int KVM_PAGE = 4096;
constexpr uint32_t KVM_RING_MAX =
    (KVM_PAGE - sizeof(struct kvm_coalesced_mmio_ring)) / sizeof(struct kvm_coalesced_mmio);

struct hv_vm {
    int kvm_fd;
    int vm_fd;
    int run_size;
    uint32_t next_slot;
    bool tsc_deadline;
    int coalesced_page; // KVM_CAP_COALESCED_MMIO: the ring's page in the vCPU mapping, 0 if none
    struct {
        uint64_t gpa, size;
        uint8_t *hva;
    } slots[KVM_MAX_SLOTS]; // for prefault: guest-physical -> host address
};

struct hv_vcpu {
    hv_vm *vm;
    int fd;
    uint32_t id;
    struct kvm_run *run;
    struct kvm_coalesced_mmio_ring *ring; // writes KVM queued (hv_vm_queue_writes)
    hv_handlers h;
    uint64_t cpuid_hash;
    // snapshots (hv_vcpu_save_prepare)
    struct kvm_msrs *msrs; // the MSRs KVM says to save, and that read back
    struct kvm_xsave *xsave;
    size_t xsave_size;
    pthread_t thread; // the thread that runs this vCPU (target of kicks)
    bool profiling;
    uint32_t eagain; // KVM_RUN's EAGAINs in a row
};

static void kick_handler(int sig) { (void)sig; }

static hv_cpuid_hide cpuid_hide[HV_CPUID_HIDE_MAX];
static size_t n_cpuid_hide;

void hv_set_cpuid_hide(const hv_cpuid_hide *hide, size_t n)
{
    n_cpuid_hide = n < HV_CPUID_HIDE_MAX ? n : HV_CPUID_HIDE_MAX;
    memcpy(cpuid_hide, hide, n_cpuid_hide * sizeof *hide);
}

const char *hv_name(void) { return "kvm"; }

int hv_vm_create(hv_vm **out)
{
    hv_vm *vm = calloc(1, sizeof *vm);
    if (!vm)
        return -1;
    vm->kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (vm->kvm_fd < 0) {
        const int e = errno;
        mvm_log("open /dev/kvm: %s", strerror(e));
        free(vm);
        return e == ENOENT || e == ENXIO || e == ENODEV ? HV_UNAVAILABLE : -1;
    }
    if (ioctl(vm->kvm_fd, KVM_GET_API_VERSION, 0) != KVM_API_VERSION) {
        mvm_log("unsupported KVM API version");
        goto fail;
    }
    vm->vm_fd = ioctl(vm->kvm_fd, KVM_CREATE_VM, 0);
    if (vm->vm_fd < 0) {
        mvm_log("KVM_CREATE_VM: %s", strerror(errno));
        goto fail;
    }
    // Only needed on Intel; harmless (no-op) on AMD.
    if (ioctl(vm->vm_fd, KVM_SET_TSS_ADDR, KVM_TSS_ADDR) < 0) {
        mvm_log("KVM_SET_TSS_ADDR: %s", strerror(errno));
        goto fail;
    }
    struct kvm_enable_cap cap = {.cap = KVM_CAP_SPLIT_IRQCHIP};
    cap.args[0] = KVM_SPLIT_IRQCHIP_ROUTES;
    if (ioctl(vm->vm_fd, KVM_ENABLE_CAP, &cap) < 0) {
        mvm_log("KVM_CAP_SPLIT_IRQCHIP: %s", strerror(errno));
        goto fail;
    }
    // Unknown MSRs come to us instead of becoming #GP in the guest.
    // Optional: older kernels just keep the #GP behaviour.
    struct kvm_enable_cap msr_cap = {.cap = KVM_CAP_X86_USER_SPACE_MSR};
    msr_cap.args[0] = KVM_MSR_EXIT_REASON_UNKNOWN;
    (void)ioctl(vm->vm_fd, KVM_ENABLE_CAP, &msr_cap);
    // No virtual PMU: counters are a cross-tenant side channel and the
    // guest's perf probe costs boot time. Must precede vCPU creation.
    // Older kernels (< 5.18) lack the cap; CPUID still hides the PMU.
    struct kvm_enable_cap pmu_cap = {.cap = KVM_CAP_PMU_CAPABILITY};
    pmu_cap.args[0] = KVM_PMU_CAP_DISABLE;
    (void)ioctl(vm->vm_fd, KVM_ENABLE_CAP, &pmu_cap);
    vm->run_size = ioctl(vm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (vm->run_size <= 0)
        goto fail;
    vm->tsc_deadline = ioctl(vm->kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_TSC_DEADLINE_TIMER) > 0;
    const int cpage = ioctl(vm->kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_COALESCED_MMIO);
    if (cpage > 0 && vm->run_size > 0 && (int64_t)cpage * KVM_PAGE < vm->run_size)
        vm->coalesced_page = cpage;
    *out = vm;
    return 0;
fail:
    hv_vm_destroy(vm);
    return -1;
}

void hv_vm_destroy(hv_vm *vm)
{
    if (!vm)
        return;
    if (vm->vm_fd > 0)
        close(vm->vm_fd);
    if (vm->kvm_fd > 0)
        close(vm->kvm_fd);
    free(vm);
}

static int set_region(hv_vm *vm, uint64_t gpa, void *hva, uint64_t size, uint32_t flags)
{
    if (vm->next_slot >= KVM_MAX_SLOTS)
        return -1;
    struct kvm_userspace_memory_region r = {
        .slot = vm->next_slot,
        .flags = flags,
        .guest_phys_addr = gpa,
        .memory_size = size,
        .userspace_addr = (uint64_t)(uintptr_t)hva,
    };
    if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &r) < 0) {
        mvm_log("KVM_SET_USER_MEMORY_REGION%s: %s", flags ? " (read-only)" : "", strerror(errno));
        return -1;
    }
    vm->slots[vm->next_slot].gpa = gpa;
    vm->slots[vm->next_slot].size = size;
    vm->slots[vm->next_slot++].hva = hva;
    return 0;
}

int hv_vm_map_mem(hv_vm *vm, uint64_t gpa, void *hva, uint64_t size)
{
    return set_region(vm, gpa, hva, size, 0);
}

int hv_vm_map_mem_ro(hv_vm *vm, uint64_t gpa, void *hva, uint64_t size)
{
    // Guest writes to a read-only slot exit as MMIO writes (ignored).
    return set_region(vm, gpa, hva, size, KVM_MEM_READONLY);
}

// A KVM memslot costs the same at any size (SPTEs are built on fault).
int hv_vm_map_mem_split(hv_vm *vm, uint64_t gpa, void *hva, uint64_t size, const hv_range *now,
                        size_t n_now)
{
    (void)now;
    (void)n_now;
    return hv_vm_map_mem(vm, gpa, hva, size);
}

int hv_vm_map_mem_traced(hv_vm *vm, uint64_t gpa, void *hva, uint64_t size, uint8_t *touched)
{
    (void)vm;
    (void)gpa;
    (void)hva;
    (void)size;
    (void)touched;
    return HV_UNAVAILABLE;
}

uint32_t hv_max_vcpus(void) { return MVM_MAX_VCPUS; }

// SIGUSR1 interrupts KVM_RUN (hv_vcpu_kick). No SA_RESTART: KVM_RUN must
// return EINTR. Installed before the sandbox, which has no sigaction.
static void kick_prepare(void)
{
    static bool done;
    if (done)
        return;
    struct sigaction sa = {.sa_handler = kick_handler};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, nullptr);
    done = true;
}

int hv_vcpu_create(hv_vm *vm, uint32_t id, const hv_handlers *h, hv_vcpu **out)
{
    hv_vcpu *v = calloc(1, sizeof *v);
    if (!v)
        return -1;
    if (id > 0) // another thread will kick it, or be kicked by it
        kick_prepare();
    v->vm = vm;
    v->id = id;
    v->h = *h;
    v->thread = pthread_self();
    v->fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, (unsigned long)id);
    if (v->fd < 0) {
        mvm_log("KVM_CREATE_VCPU: %s", strerror(errno));
        free(v);
        return -1;
    }
    v->run = mmap(nullptr, (size_t)vm->run_size, PROT_READ | PROT_WRITE, MAP_SHARED, v->fd, 0);
    if (v->run == MAP_FAILED) {
        close(v->fd);
        free(v);
        return -1;
    }
    if (vm->coalesced_page)
        v->ring = (void *)((uint8_t *)v->run + (size_t)vm->coalesced_page * KVM_PAGE);
    *out = v;
    return 0;
}

void hv_vcpu_attach(hv_vcpu *v) { v->thread = pthread_self(); }

// The guest's topology: one package of MVM_MAX_VCPUS cores, a thread each
// (common.h). TOPO_SHIFT: the APIC ID bits that number the cores.
constexpr uint32_t TOPO_SHIFT = 3;
static_assert(1u << TOPO_SHIFT == MVM_MAX_VCPUS);

int hv_vcpu_setup_cpuid(hv_vcpu *v)
{
    constexpr uint32_t max_ent = 256;
    size_t sz = sizeof(struct kvm_cpuid2) + max_ent * sizeof(struct kvm_cpuid_entry2);
    struct kvm_cpuid2 *c = calloc(1, sz);
    if (!c)
        return -1;
    c->nent = max_ent;
    if (ioctl(v->vm->kvm_fd, KVM_GET_SUPPORTED_CPUID, c) < 0) {
        mvm_log("KVM_GET_SUPPORTED_CPUID: %s", strerror(errno));
        free(c);
        return -1;
    }
    // Leaves 0xb and 0x1f: KVM reports no topology (subleaf 0, zeroed, on
    // AMD), so ours replaces them: 0xb, subleaves 0 (threads), 1 (cores)
    // and 2 (the end). Without 0x1f, Linux reads 0xb.
    uint32_t max_basic = 0, n = 0;
    for (uint32_t i = 0; i < c->nent; i++) {
        if (c->entries[i].function == 0)
            max_basic = c->entries[i].eax;
        if (c->entries[i].function != 0xb && c->entries[i].function != 0x1f)
            c->entries[n++] = c->entries[i];
    }
    for (uint32_t sub = 0; max_basic >= 0xb && sub < 3 && n < max_ent; sub++)
        c->entries[n++] = (struct kvm_cpuid_entry2){
            .function = 0xb, .index = sub, .flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX};
    c->nent = n;
    // The CPU template: the host's features, minus what a microVM doesn't
    // use. A fixed view also lets one pre-patched kernel image (patch 0026)
    // match on every host of the same CPU model.
    for (uint32_t i = 0; i < c->nent; i++) {
        struct kvm_cpuid_entry2 *e = &c->entries[i];
        switch (e->function) {
        case 1:
            e->ecx |= 1u << 31; // hypervisor present
            if (v->vm->tsc_deadline)
                e->ecx |= 1u << 24; // TSC-deadline LAPIC timer (KVM emulates it)
            // APIC ID, and the package's logical processors (HTT: valid).
            e->ebx = (e->ebx & 0xffffu) | (MVM_MAX_VCPUS << 16) | (v->id << 24);
            e->edx |= 1u << 28;
            break;
        case 4: // Intel caches: L1 and L2 per core, L3 shared by the package
        case 0x8000001d: // AMD's
            if (e->eax & 0x1f) {
                const uint32_t level = (e->eax >> 5) & 7;
                e->eax &= ~(0xfffu << 14);
                if (level >= 3)
                    e->eax |= (MVM_MAX_VCPUS - 1) << 14;
                if (e->function == 4)
                    e->eax = (e->eax & ~(0x3fu << 26)) | ((MVM_MAX_VCPUS - 1) << 26);
            }
            break;
        case 6:
            e->eax |= 1u << 2; // ARAT: LAPIC timer keeps running in C-states
            break;
        case 0xa: // Intel architectural PMU: none
            e->eax = e->ebx = e->ecx = e->edx = 0;
            break;
        case 0xb:
            // Level 0: threads (one per core), level 1: cores, no more.
            if (e->index == 0)
                e->eax = 0, e->ebx = 1, e->ecx = 1u << 8;
            else if (e->index == 1)
                e->eax = TOPO_SHIFT, e->ebx = MVM_MAX_VCPUS, e->ecx = 2u << 8 | 1;
            else
                e->eax = e->ebx = 0, e->ecx = e->index;
            e->edx = v->id;
            break;
        case 0x8000001e: // AMD: extended APIC ID, core ID, one thread per core
            e->eax = v->id;
            e->ebx = v->id;
            e->ecx = 0;
            break;
        case KVM_CPUID_FEATURES:
            // Paravirt features: only PV EOI (an EOI without an APIC exit).
            // No kvmclock (the guest runs on the TSC, its frequency on the
            // command line), no async page faults (they also tell the guest
            // when the host is paging), no steal time, nothing for SMP.
            // Each of these would also swap pv_ops at boot, which keeps the
            // alternatives pre-patch (0026) from matching.
            e->eax &= 1u << KVM_FEATURE_PV_EOI;
            e->edx = 0; // no hints (KVM_HINTS_REALTIME)
            break;
        case 0x80000008: // AMD: cores in the package, APIC ID bits for them
            e->ecx = (e->ecx & ~0xf0ffu) | (TOPO_SHIFT << 12) | (MVM_MAX_VCPUS - 1);
            break;
        case 0x80000001:
            // AMD core / northbridge / L2 performance counter extensions
            e->ecx &= ~((1u << 23) | (1u << 24) | (1u << 28));
            break;
        case 0x80000022: // AMD PerfMonV2
            e->eax = e->ebx = e->ecx = e->edx = 0;
            break;
        default:
            break;
        }
        uint32_t *regs[4] = {&e->eax, &e->ebx, &e->ecx, &e->edx};
        for (size_t j = 0; j < n_cpuid_hide; j++) {
            const hv_cpuid_hide *h = &cpuid_hide[j];
            if (e->function == h->leaf && (h->any_subleaf || e->index == h->subleaf))
                *regs[h->reg] &= ~h->mask;
        }
    }
    int rc = ioctl(v->fd, KVM_SET_CPUID2, c);
    if (rc < 0)
        mvm_log("KVM_SET_CPUID2: %s", strerror(errno));
    uint64_t h = 0xcbf29ce484222325ull; // FNV-1a over the entries we set
    for (const uint8_t *b = (const uint8_t *)c->entries, *e = b + c->nent * sizeof c->entries[0]; b < e; b++)
        h = (h ^ *b) * 0x100000001b3ull;
    v->cpuid_hash = h;
    free(c);
    if (rc < 0)
        return -1;
    // AMD HWCR.TscFreqSel: the TSC counts at the P0 frequency, so Linux
    // trusts it without a "Firmware Bug" warning. KVM accepts the bit from
    // the host since 6.5; older kernels refuse it, which is harmless.
    struct {
        struct kvm_msrs h;
        struct kvm_msr_entry e;
    } m = {.h = {.nmsrs = 1}, .e = {.index = 0xc0010015, .data = 1ull << 24}};
    (void)ioctl(v->fd, KVM_SET_MSRS, &m);
    return 0;
}

static struct kvm_segment seg_to_kvm(const hv_segment *s)
{
    return (struct kvm_segment){
        .base = s->base, .limit = s->limit, .selector = s->selector,
        .type = s->type, .present = s->present, .dpl = s->dpl, .db = s->db,
        .s = s->s, .l = s->l, .g = s->g, .avl = s->avl,
        .unusable = s->present ? 0 : 1,
    };
}

int hv_vcpu_set_state(hv_vcpu *v, const hv_regs *r, const hv_sregs *s)
{
    struct kvm_sregs ks;
    if (ioctl(v->fd, KVM_GET_SREGS, &ks) < 0)
        return -1;
    ks.cs = seg_to_kvm(&s->cs);
    ks.ds = seg_to_kvm(&s->ds);
    ks.es = seg_to_kvm(&s->es);
    ks.fs = seg_to_kvm(&s->fs);
    ks.gs = seg_to_kvm(&s->gs);
    ks.ss = seg_to_kvm(&s->ss);
    ks.tr = seg_to_kvm(&s->tr);
    ks.ldt = seg_to_kvm(&s->ldt);
    ks.gdt.base = s->gdt.base;
    ks.gdt.limit = s->gdt.limit;
    ks.idt.base = s->idt.base;
    ks.idt.limit = s->idt.limit;
    ks.cr0 = s->cr0;
    ks.cr3 = s->cr3;
    ks.cr4 = s->cr4;
    ks.efer = s->efer;
    if (ioctl(v->fd, KVM_SET_SREGS, &ks) < 0) {
        mvm_log("KVM_SET_SREGS: %s", strerror(errno));
        return -1;
    }
    struct kvm_regs kr = {
        .rax = r->rax, .rbx = r->rbx, .rcx = r->rcx, .rdx = r->rdx,
        .rsi = r->rsi, .rdi = r->rdi, .rsp = r->rsp, .rbp = r->rbp,
        .r8 = r->r8, .r9 = r->r9, .r10 = r->r10, .r11 = r->r11,
        .r12 = r->r12, .r13 = r->r13, .r14 = r->r14, .r15 = r->r15,
        .rip = r->rip, .rflags = r->rflags,
    };
    if (ioctl(v->fd, KVM_SET_REGS, &kr) < 0) {
        mvm_log("KVM_SET_REGS: %s", strerror(errno));
        return -1;
    }
    return 0;
}

// ---- snapshots ------------------------------------------------------------------
// The blob is a list of records: u32 type, u32 length, the ioctl's struct.
enum : uint32_t {
    ST_MP = 1, ST_REGS, ST_SREGS, ST_XSAVE, ST_XCRS, ST_DEBUG, ST_LAPIC, ST_MSRS, ST_EVENTS,
};
constexpr uint32_t MAX_SAVED_MSRS = 512;
enum : uint32_t { MSR_IA32_TSC = 0x10, MSR_IA32_TSC_DEADLINE = 0x6e0 };

static void drain_queued(hv_vcpu *v);

uint64_t hv_vcpu_cpuid_hash(const hv_vcpu *v) { return v->cpuid_hash; }

int hv_vcpu_save_prepare(hv_vcpu *v)
{
    if (v->msrs)
        return 0;
    struct kvm_msr_list probe = {.nmsrs = 0};
    if (ioctl(v->vm->kvm_fd, KVM_GET_MSR_INDEX_LIST, &probe) < 0 && errno != E2BIG)
        return -1;
    const uint32_t n = probe.nmsrs;
    if (n == 0 || n > MAX_SAVED_MSRS)
        return -1;
    struct kvm_msr_list *list = calloc(1, sizeof *list + n * sizeof list->indices[0]);
    v->msrs = calloc(1, sizeof *v->msrs + n * sizeof v->msrs->entries[0]);
    if (!list || !v->msrs) {
        free(list);
        return -1;
    }
    list->nmsrs = n;
    if (ioctl(v->vm->kvm_fd, KVM_GET_MSR_INDEX_LIST, list) < 0) {
        free(list);
        return -1;
    }
    // Restored in this order: the TSC first (the deadline and the TSC
    // adjust are relative to it), the TSC deadline last.
    uint32_t k = 0;
    for (uint32_t i = 0; i < list->nmsrs && i < n; i++)
        if (list->indices[i] == MSR_IA32_TSC)
            v->msrs->entries[k++].index = MSR_IA32_TSC;
    for (uint32_t i = 0; i < list->nmsrs && i < n; i++)
        if (list->indices[i] != MSR_IA32_TSC && list->indices[i] != MSR_IA32_TSC_DEADLINE)
            v->msrs->entries[k++].index = list->indices[i];
    for (uint32_t i = 0; i < list->nmsrs && i < n; i++)
        if (list->indices[i] == MSR_IA32_TSC_DEADLINE)
            v->msrs->entries[k++].index = MSR_IA32_TSC_DEADLINE;
    free(list);
    // Keep the ones that read back: KVM lists some this CPU doesn't have,
    // and KVM_GET_MSRS stops at the first it can't read.
    v->msrs->nmsrs = k;
    for (;;) {
        const int got = ioctl(v->fd, KVM_GET_MSRS, v->msrs);
        if (got < 0)
            return -1;
        if ((uint32_t)got >= v->msrs->nmsrs)
            break;
        memmove(&v->msrs->entries[got], &v->msrs->entries[got + 1],
                (v->msrs->nmsrs - (uint32_t)got - 1) * sizeof v->msrs->entries[0]);
        v->msrs->nmsrs--;
    }
    const int xs = ioctl(v->vm->vm_fd, KVM_CHECK_EXTENSION, KVM_CAP_XSAVE2);
    v->xsave_size = xs > (int)sizeof(struct kvm_xsave) ? (size_t)xs : sizeof(struct kvm_xsave);
    if (v->xsave_size > HV_STATE_MAX / 2 || !(v->xsave = calloc(1, v->xsave_size)))
        return -1;
    return 0;
}

size_t hv_save_ioctls(hv_vcpu *v, int *fds, unsigned long *requests, size_t max)
{
    static const unsigned long REQ[] = {
        KVM_GET_MP_STATE, KVM_GET_SREGS, KVM_GET_XSAVE, KVM_GET_XSAVE2, KVM_GET_XCRS,
        KVM_GET_DEBUGREGS, KVM_GET_LAPIC, KVM_GET_MSRS, KVM_GET_VCPU_EVENTS,
    };
    size_t n = 0;
    for (size_t i = 0; i < sizeof REQ / sizeof REQ[0] && n < max; i++, n++) {
        fds[n] = v->fd;
        requests[n] = REQ[i];
    }
    return n;
}

static bool put_rec(uint8_t *buf, size_t cap, size_t *at, uint32_t type, const void *p, size_t len)
{
    if (cap - *at < 8 || cap - *at - 8 < len)
        return false;
    put_le32(buf + *at, type);
    put_le32(buf + *at + 4, (uint32_t)len);
    memcpy(buf + *at + 8, p, len);
    *at += 8 + len;
    return true;
}

int64_t hv_vcpu_save(hv_vcpu *v, uint8_t *buf, size_t cap)
{
    if (!v->msrs)
        return -1;
    // KVM finishes the instruction that exited (port I/O, MMIO) on the next
    // KVM_RUN; with immediate_exit set, that is all it does.
    v->run->immediate_exit = 1;
    const int rc = ioctl(v->fd, KVM_RUN, 0);
    v->run->immediate_exit = 0;
    if (rc == 0 || errno != EINTR) {
        mvm_log("KVM_RUN (immediate exit): %s", rc ? strerror(errno) : "it ran");
        return -1;
    }
    drain_queued(v);

    // The order QEMU and Firecracker use: the MP state first, as getting it
    // may move pending interrupts into the local APIC.
    struct kvm_mp_state mp;
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    struct kvm_xcrs xcrs;
    struct kvm_debugregs dbg;
    struct kvm_lapic_state lapic;
    struct kvm_vcpu_events ev;
    const unsigned long get_xsave = v->xsave_size > sizeof(struct kvm_xsave) ? KVM_GET_XSAVE2 : KVM_GET_XSAVE;
    const uint32_t want = v->msrs->nmsrs;
    size_t at = 0;
    if (ioctl(v->fd, KVM_GET_MP_STATE, &mp) < 0 || !put_rec(buf, cap, &at, ST_MP, &mp, sizeof mp) ||
        ioctl(v->fd, KVM_GET_REGS, &regs) < 0 || !put_rec(buf, cap, &at, ST_REGS, &regs, sizeof regs) ||
        ioctl(v->fd, KVM_GET_SREGS, &sregs) < 0 || !put_rec(buf, cap, &at, ST_SREGS, &sregs, sizeof sregs) ||
        ioctl(v->fd, get_xsave, v->xsave) < 0 ||
        !put_rec(buf, cap, &at, ST_XSAVE, v->xsave, v->xsave_size) ||
        ioctl(v->fd, KVM_GET_XCRS, &xcrs) < 0 || !put_rec(buf, cap, &at, ST_XCRS, &xcrs, sizeof xcrs) ||
        ioctl(v->fd, KVM_GET_DEBUGREGS, &dbg) < 0 || !put_rec(buf, cap, &at, ST_DEBUG, &dbg, sizeof dbg) ||
        ioctl(v->fd, KVM_GET_LAPIC, &lapic) < 0 || !put_rec(buf, cap, &at, ST_LAPIC, &lapic, sizeof lapic) ||
        ioctl(v->fd, KVM_GET_MSRS, v->msrs) != (int)want ||
        !put_rec(buf, cap, &at, ST_MSRS, v->msrs->entries, want * sizeof v->msrs->entries[0]) ||
        ioctl(v->fd, KVM_GET_VCPU_EVENTS, &ev) < 0 || !put_rec(buf, cap, &at, ST_EVENTS, &ev, sizeof ev)) {
        mvm_log("saving the vCPU failed: %s", strerror(errno));
        return -1;
    }
    return (int64_t)at;
}

int hv_vcpu_restore(hv_vcpu *v, const uint8_t *buf, size_t len)
{
    // Every record exactly once, each the size this kernel's struct is.
    const void *rec[ST_EVENTS + 1] = {0};
    uint32_t rlen[ST_EVENTS + 1] = {0};
    for (size_t at = 0; at < len;) {
        if (len - at < 8)
            return -1;
        const uint32_t type = get_le32(buf + at), n = get_le32(buf + at + 4);
        if (type < ST_MP || type > ST_EVENTS || rec[type] || n > len - at - 8)
            return -1;
        rec[type] = buf + at + 8;
        rlen[type] = n;
        at += 8 + (size_t)n;
    }
    static const size_t SIZE[ST_EVENTS + 1] = {
        [ST_MP] = sizeof(struct kvm_mp_state), [ST_REGS] = sizeof(struct kvm_regs),
        [ST_SREGS] = sizeof(struct kvm_sregs), [ST_XCRS] = sizeof(struct kvm_xcrs),
        [ST_DEBUG] = sizeof(struct kvm_debugregs), [ST_LAPIC] = sizeof(struct kvm_lapic_state),
        [ST_EVENTS] = sizeof(struct kvm_vcpu_events),
    };
    for (uint32_t t = ST_MP; t <= ST_EVENTS; t++) {
        if (!rec[t])
            return -1;
        if (SIZE[t] && rlen[t] != SIZE[t])
            return -1;
    }
    const int xs = ioctl(v->vm->vm_fd, KVM_CHECK_EXTENSION, KVM_CAP_XSAVE2);
    const size_t xsave_size = xs > (int)sizeof(struct kvm_xsave) ? (size_t)xs : sizeof(struct kvm_xsave);
    const uint32_t nmsr = rlen[ST_MSRS] / sizeof(struct kvm_msr_entry);
    if (rlen[ST_XSAVE] != xsave_size || rlen[ST_MSRS] % sizeof(struct kvm_msr_entry) ||
        nmsr == 0 || nmsr > MAX_SAVED_MSRS)
        return -1;
    // Copies: the ioctls want aligned structs, the blob is packed.
    struct kvm_mp_state mp;
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    struct kvm_xcrs xcrs;
    struct kvm_debugregs dbg;
    struct kvm_lapic_state lapic;
    struct kvm_vcpu_events ev;
    memcpy(&mp, rec[ST_MP], sizeof mp);
    memcpy(&regs, rec[ST_REGS], sizeof regs);
    memcpy(&sregs, rec[ST_SREGS], sizeof sregs);
    memcpy(&xcrs, rec[ST_XCRS], sizeof xcrs);
    memcpy(&dbg, rec[ST_DEBUG], sizeof dbg);
    memcpy(&lapic, rec[ST_LAPIC], sizeof lapic);
    memcpy(&ev, rec[ST_EVENTS], sizeof ev);
    struct kvm_xsave *xsave = calloc(1, xsave_size);
    struct kvm_msrs *msrs = calloc(1, sizeof *msrs + nmsr * sizeof msrs->entries[0]);
    int rc = -1;
    if (!xsave || !msrs)
        goto out;
    memcpy(xsave, rec[ST_XSAVE], xsave_size);
    msrs->nmsrs = nmsr;
    memcpy(msrs->entries, rec[ST_MSRS], rlen[ST_MSRS]);
    // Firecracker's order: the local APIC before the MSRs (the TSC deadline
    // needs the timer in deadline mode), the events last.
    const char *what = nullptr;
    if (ioctl(v->fd, KVM_SET_MP_STATE, &mp) < 0) what = "KVM_SET_MP_STATE";
    else if (ioctl(v->fd, KVM_SET_REGS, &regs) < 0) what = "KVM_SET_REGS";
    else if (ioctl(v->fd, KVM_SET_SREGS, &sregs) < 0) what = "KVM_SET_SREGS";
    else if (ioctl(v->fd, KVM_SET_XSAVE, xsave) < 0) what = "KVM_SET_XSAVE";
    else if (ioctl(v->fd, KVM_SET_XCRS, &xcrs) < 0) what = "KVM_SET_XCRS";
    else if (ioctl(v->fd, KVM_SET_DEBUGREGS, &dbg) < 0) what = "KVM_SET_DEBUGREGS";
    else if (ioctl(v->fd, KVM_SET_LAPIC, &lapic) < 0) what = "KVM_SET_LAPIC";
    else if (ioctl(v->fd, KVM_SET_MSRS, msrs) != (int)nmsr) what = "KVM_SET_MSRS";
    else if (ioctl(v->fd, KVM_SET_VCPU_EVENTS, &ev) < 0) what = "KVM_SET_VCPU_EVENTS";
    if (what)
        mvm_log("restoring the vCPU: %s: %s", what, strerror(errno));
    else
        rc = 0;
out:
    free(xsave);
    free(msrs);
    return rc;
}

static void do_pio(hv_vcpu *v, struct kvm_run *run)
{
    const uint8_t sz = run->io.size;
    const bool write = run->io.direction == KVM_EXIT_IO_OUT;
    uint8_t *data = (uint8_t *)run + run->io.data_offset;
    for (uint32_t i = 0; i < run->io.count; i++, data += sz) {
        uint32_t val = 0;
        if (write)
            memcpy(&val, data, sz);
        v->h.pio(v->h.opaque, run->io.port, sz, write, &val);
        if (!write)
            memcpy(data, &val, sz); // KVM picks IN results up from the run page
    }
}

int hv_vm_queue_writes(hv_vm *vm, uint64_t gpa, uint32_t len)
{
    if (!vm->coalesced_page)
        return HV_UNAVAILABLE;
    struct kvm_coalesced_mmio_zone z = {.addr = gpa, .size = len};
    if (ioctl(vm->vm_fd, KVM_REGISTER_COALESCED_MMIO, &z) < 0) {
        mvm_log("KVM_REGISTER_COALESCED_MMIO: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int hv_vm_doorbell(hv_vm *vm, uint64_t gpa, uint32_t len, int fd)
{
    struct kvm_ioeventfd e = {.addr = gpa, .len = len, .fd = fd};
    if (ioctl(vm->vm_fd, KVM_IOEVENTFD, &e) < 0) {
        mvm_log("KVM_IOEVENTFD: %s", strerror(errno));
        return errno == ENOSYS || errno == EINVAL ? HV_UNAVAILABLE : -1;
    }
    return 0;
}

// Hand the writes KVM queued to the handler, oldest first. KVM fills the
// ring (from `last`) and we empty it (from `first`); a write that finds it
// full exits as usual, so nothing is lost or reordered.
static void drain_queued(hv_vcpu *v)
{
    struct kvm_coalesced_mmio_ring *r = v->ring;
    if (!r)
        return;
    uint32_t first = r->first;
    while (first < KVM_RING_MAX && first != __atomic_load_n(&r->last, __ATOMIC_ACQUIRE)) {
        const struct kvm_coalesced_mmio *e = &r->coalesced_mmio[first];
        uint64_t val = 0;
        const uint8_t len = (uint8_t)(e->len > 8 ? 8 : e->len);
        memcpy(&val, e->data, len);
        if (!e->pio && v->h.mmio_queued)
            v->h.mmio_queued(v->h.opaque, e->phys_addr, len, val);
        first = (first + 1) % KVM_RING_MAX;
        __atomic_store_n(&r->first, first, __ATOMIC_RELEASE);
    }
}

int hv_vcpu_run(hv_vcpu *v, hv_exit *ex)
{
    ex->access = HV_ACCESS_NONE;
    ex->sampled = false;
    const int rc = ioctl(v->fd, KVM_RUN, 0);
    drain_queued(v); // they come before whatever made the vCPU exit
    if (rc < 0) {
        // EAGAIN: a vCPU the guest just started (INIT, SIPI) is to run
        // again. But KVM also returns it on every call when it can't start
        // its per-VM worker (e.g. RLIMIT_NPROC): retrying that would spin.
        if (errno == EAGAIN && ++v->eagain < 1000) {
            ex->kind = HV_EXIT_RETRY;
            return 0;
        }
        if (errno == EINTR) {
            // A kick (hv_vcpu_kick): the next run enters the guest again.
            // Cleared before the caller looks at why it was kicked.
            __atomic_store_n(&v->run->immediate_exit, 0, __ATOMIC_SEQ_CST);
            ex->kind = HV_EXIT_RETRY;
            struct kvm_regs r;
            if (v->profiling && ioctl(v->fd, KVM_GET_REGS, &r) == 0) {
                ex->sampled = true;
                ex->rip = r.rip;
                ex->rsp = r.rsp;
                ex->cr3 = 0; // KVM_GET_SREGS isn't allowed by the sandbox

            }
            return 0;
        }
        mvm_log("KVM_RUN: %s", strerror(errno));
        return -1;
    }
    v->eagain = 0;
    struct kvm_run *run = v->run;
    ex->hw_reason = run->exit_reason;
    switch (run->exit_reason) {
    case KVM_EXIT_IO:
        do_pio(v, run);
        ex->kind = HV_EXIT_HANDLED;
        ex->access = HV_ACCESS_PIO;
        return 0;
    case KVM_EXIT_MMIO: {
        uint64_t val = 0;
        const uint8_t len = (uint8_t)(run->mmio.len > 8 ? 8 : run->mmio.len);
        if (run->mmio.is_write)
            memcpy(&val, run->mmio.data, len);
        v->h.mmio(v->h.opaque, run->mmio.phys_addr, len, run->mmio.is_write, &val);
        if (!run->mmio.is_write)
            memcpy(run->mmio.data, &val, len);
        ex->kind = HV_EXIT_HANDLED;
        ex->access = HV_ACCESS_MMIO;
        return 0;
    }
    case KVM_EXIT_X86_RDMSR:
    case KVM_EXIT_X86_WRMSR: {
        const bool write = run->exit_reason == KVM_EXIT_X86_WRMSR;
        uint64_t val = write ? run->msr.data : 0;
        const bool ok = v->h.msr(v->h.opaque, run->msr.index, write, &val);
        if (!write && ok)
            run->msr.data = val;
        run->msr.error = ok ? 0 : 1; // KVM injects #GP

        ex->kind = HV_EXIT_HANDLED;
        ex->access = HV_ACCESS_MSR;
        return 0;
    }
    case KVM_EXIT_HLT:
        ex->kind = HV_EXIT_HLT;
        return 0;
    case KVM_EXIT_SHUTDOWN:
    case KVM_EXIT_SYSTEM_EVENT:
        ex->kind = HV_EXIT_SHUTDOWN;
        return 0;
    case KVM_EXIT_INTR:
    case KVM_EXIT_IOAPIC_EOI:
        ex->kind = HV_EXIT_RETRY;
        return 0;
    case KVM_EXIT_FAIL_ENTRY:
        ex->kind = HV_EXIT_FAIL;
        ex->hw_reason = run->fail_entry.hardware_entry_failure_reason;
        mvm_log("KVM_EXIT_FAIL_ENTRY reason=0x%llx",
                (unsigned long long)run->fail_entry.hardware_entry_failure_reason);
        return 0;
    case KVM_EXIT_INTERNAL_ERROR:
        ex->kind = HV_EXIT_FAIL;
        mvm_log("KVM_EXIT_INTERNAL_ERROR suberror=%u", run->internal.suberror);
        return 0;
    default:
        ex->kind = HV_EXIT_FAIL;
        mvm_log("unhandled KVM exit %u", run->exit_reason);
        return 0;
    }
}

void hv_get_info(hv_vm *vm, hv_vcpu *v, hv_info *info)
{
    (void)vm;
    int khz = ioctl(v->fd, KVM_GET_TSC_KHZ, 0);
    info->tsc_khz = khz > 0 ? (uint64_t)khz : 0;
}

void hv_vcpu_set_profiling(hv_vcpu *v, bool on)
{
    if (on)
        kick_prepare();
    v->profiling = on;
}

// immediate_exit catches the vCPU outside KVM_RUN (KVM checks it on entry,
// after finishing the exit just handled); the signal, inside it.
void hv_vcpu_kick(hv_vcpu *v)
{
    __atomic_store_n(&v->run->immediate_exit, 1, __ATOMIC_SEQ_CST);
    pthread_kill(v->thread, SIGUSR1);
}

int hv_vm_signal_msi(hv_vm *vm, uint64_t addr, uint32_t data)
{
    struct kvm_msi m = {.address_lo = (uint32_t)addr, .address_hi = (uint32_t)(addr >> 32), .data = data};
    // > 0 delivered, 0 blocked by the guest (e.g. its APIC is off): fine.
    return ioctl(vm->vm_fd, KVM_SIGNAL_MSI, &m) < 0 ? -1 : 0;
}

// The host pages first (allocated, or read in from the file), then KVM's
// stage-2 entries for them. KVM_PRE_FAULT_MEMORY alone faults like a guest
// read: on anonymous memory nothing has touched yet it maps the shared zero
// page read-only, and the guest's first write (or the loader's, which runs
// concurrently) throws that entry away again.
int hv_vcpu_prefault(hv_vcpu *v, const hv_range *ranges, size_t n, bool write)
{
    const hv_vm *vm = v->vm;
    for (size_t i = 0; i < n; i++) {
        const hv_range *g = &ranges[i];
        for (uint32_t s = 0; s < vm->next_slot; s++) {
            const uint64_t lo = vm->slots[s].gpa, hi = lo + vm->slots[s].size;
            if (g->gpa < lo || g->gpa >= hi || g->size > hi - g->gpa)
                continue;
            if (madvise(vm->slots[s].hva + (g->gpa - lo), g->size,
                        write ? MADV_POPULATE_WRITE : MADV_POPULATE_READ) < 0) {
                mvm_log("madvise(MADV_POPULATE_%s): %s", write ? "WRITE" : "READ", strerror(errno));
                return -1;
            }
            break;
        }
        struct kvm_pre_fault_memory r = {.gpa = g->gpa, .size = g->size};
        while (r.size) {
            if (ioctl(v->fd, KVM_PRE_FAULT_MEMORY, &r) < 0) {
                if (errno == EINTR || errno == EAGAIN)
                    continue; // r.gpa / r.size were advanced
                mvm_log("KVM_PRE_FAULT_MEMORY: %s", strerror(errno));
                return -1;
            }
        }
    }
    return 0;
}

size_t hv_runtime_ioctls(hv_vcpu *v, int *fds, unsigned long *requests, size_t max)
{
    // KVM_RUN, plus KVM_GET_REGS for the profiler's RIP samples. Port I/O,
    // MMIO and MSR exits are completed through the shared kvm_run page.
    // KVM_SIGNAL_MSI on the VM: device interrupts (hv_vm_signal_msi).
    static const unsigned long REQ[] = {KVM_RUN, KVM_GET_REGS};
    size_t n = 0;
    for (size_t i = 0; i < sizeof REQ / sizeof REQ[0] && n < max; i++, n++) {
        fds[n] = v->fd;
        requests[n] = REQ[i];
    }
    if (n < max) {
        fds[n] = v->vm->vm_fd;
        requests[n++] = KVM_SIGNAL_MSI;
    }
    return n;
}
