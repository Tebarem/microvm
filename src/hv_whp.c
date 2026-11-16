// SPDX-License-Identifier: MIT
// Windows Hypervisor Platform backend.
//
// Interrupt model mirrors the KVM split irqchip: WHP's xAPIC emulation only.
//
// Mapping guest RAM costs ~11 us per MB and is serialized in the hypervisor,
// so hv_vm_map_mem_split() maps the working set up front and the rest on a
// thread that starts with the guest.
// Hyper-V synthetic frequency MSRs are exposed so the guest learns the TSC
// and LAPIC-timer frequencies without PIT calibration.
//
// Plain IN/OUT is decoded straight from the exit context (one register
// write to finish it). String I/O and MMIO need operand decoding, which is
// done by the WHP instruction emulator (winhvemulation.dll).
#include "hv.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhvemulation.h>
#include <winhvplatform.h>
#include <cpuid.h>
#include <stdlib.h>

constexpr size_t MAX_RAM_REGIONS = 8;

struct hv_vm {
    WHV_PARTITION_HANDLE part;
    struct {
        uint64_t gpa, size;
        uint8_t *hva;
        bool ro; // hv_vm_map_mem_ro(): the guest only reads it
    } ram[MAX_RAM_REGIONS];
    size_t nram;
    // hv_vm_map_mem_split(): the ranges the background thread maps, and
    // the region they belong to. Only the vCPU thread waits on `mapper`.
    HANDLE mapper;
    hv_range *later;
    size_t nlater;
    uint8_t *later_hva;
    uint64_t later_gpa;
    HRESULT mapper_hr;
    // hv_vm_map_mem_traced(): pages of ram[traced] the guest has touched.
    uint8_t *touched;
    size_t traced;
};

struct hv_vcpu {
    hv_vm *vm;
    uint32_t id;
    hv_handlers h;
    WHV_EMULATOR_HANDLE emu;
    bool profiling;
};

const char *hv_name(void) { return "whp"; }

static int set_prop(WHV_PARTITION_HANDLE p, WHV_PARTITION_PROPERTY_CODE code, const void *prop,
                    UINT32 size, const char *what)
{
    HRESULT hr = WHvSetPartitionProperty(p, code, prop, size);
    if (FAILED(hr)) {
        mvm_log("WHvSetPartitionProperty(%s): 0x%08lx", what, (unsigned long)hr);
        return -1;
    }
    return 0;
}

// CPUID changes on top of what the hypervisor would report. Each entry sets
// the bits in `mask` of one register to `val`; everything else keeps the
// hypervisor's (already filtered) default.
typedef struct {
    uint32_t leaf, subleaf;
    bool subleaf_specific;
    uint8_t reg; // 0 eax, 1 ebx, 2 ecx, 3 edx
    uint32_t mask, val;
} cpuid_tweak;

static const cpuid_tweak CPUID_TWEAKS[] = {
    // ARAT: the LAPIC timer keeps running in deep C-states, so Linux needs
    // no PIT/HPET broadcast timer.
    {.leaf = 6, .reg = 0, .mask = 1u << 2, .val = 1u << 2},
    // Invariant TSC: with patch 0001 Linux keeps the TSC clocksource.
    {.leaf = 0x80000007, .reg = 3, .mask = 1u << 8, .val = 1u << 8},
    // Hide RDSEED: the guest seeds its CRNG from RDRAND instead (also a
    // hardware DRBG); RDSEED is slow enough under WHP to cost ~0.2 ms of
    // boot. Guest-internal only, the host is unaffected.
    {.leaf = 7, .subleaf = 0, .subleaf_specific = true, .reg = 1, .mask = 1u << 18, .val = 0},
};

static cpuid_tweak cpuid_hide[HV_CPUID_HIDE_MAX];
static size_t n_cpuid_hide;

void hv_set_cpuid_hide(const hv_cpuid_hide *hide, size_t n)
{
    n_cpuid_hide = n < HV_CPUID_HIDE_MAX ? n : HV_CPUID_HIDE_MAX;
    for (size_t i = 0; i < n_cpuid_hide; i++)
        cpuid_hide[i] = (cpuid_tweak){.leaf = hide[i].leaf, .subleaf = hide[i].subleaf,
                                      .subleaf_specific = !hide[i].any_subleaf,
                                      .reg = hide[i].reg, .mask = hide[i].mask, .val = 0};
}

static int setup_cpuid2(WHV_PARTITION_HANDLE p)
{
    constexpr size_t N = sizeof CPUID_TWEAKS / sizeof CPUID_TWEAKS[0];
    WHV_X64_CPUID_RESULT2 res[N + HV_CPUID_HIDE_MAX];
    size_t n = 0;
    memset(res, 0, sizeof res);
    for (size_t i = 0; i < N + n_cpuid_hide; i++) {
        const cpuid_tweak *t = i < N ? &CPUID_TWEAKS[i] : &cpuid_hide[i - N];
        WHV_X64_CPUID_RESULT2_FLAGS flags = t->subleaf_specific
                                                ? WHvX64CpuidResult2FlagSubleafSpecific
                                                : (WHV_X64_CPUID_RESULT2_FLAGS)0;
        // One entry per leaf and subleaf: merge into an earlier one.
        size_t j = 0;
        while (j < n && !(res[j].Function == t->leaf && res[j].Flags == flags &&
                          (!t->subleaf_specific || res[j].Index == t->subleaf)))
            j++;
        if (j == n) {
            res[n].Function = t->leaf;
            res[n].Index = t->subleaf_specific ? t->subleaf : 0;
            res[n].Flags = flags;
            n++;
        }
        uint32_t *out = &res[j].Output.Eax, *mask = &res[j].Mask.Eax;
        out[t->reg] = (out[t->reg] & ~t->mask) | (t->val & t->mask);
        mask[t->reg] |= t->mask;
    }
    HRESULT hr = WHvSetPartitionProperty(p, WHvPartitionPropertyCodeCpuidResultList2, res,
                                         (UINT32)(n * sizeof res[0]));
    return FAILED(hr) ? -1 : 0;
}

static int setup_cpuid(WHV_PARTITION_HANDLE p)
{
    if (setup_cpuid2(p) == 0)
        return 0;
    if (n_cpuid_hide) {
        mvm_log("--cpuid-hide needs a newer Windows (WHvPartitionPropertyCodeCpuidResultList2)");
        return -1;
    }
    // Older Windows: whole-leaf overrides only, built from host CPUID. Leaf
    // 7 is left alone here (its subleaves can't be overridden separately).
    WHV_X64_CPUID_RESULT res[2] = {0};
    unsigned a, b, c, d;
    __cpuid(6, a, b, c, d);
    res[0] = (WHV_X64_CPUID_RESULT){.Function = 6, .Eax = a | (1u << 2) /* ARAT */,
                                    .Ebx = b, .Ecx = c, .Edx = d};
    __cpuid(0x80000007, a, b, c, d);
    res[1] = (WHV_X64_CPUID_RESULT){.Function = 0x80000007, .Eax = a, .Ebx = b, .Ecx = c,
                                    .Edx = d | (1u << 8) /* invariant TSC */};
    return set_prop(p, WHvPartitionPropertyCodeCpuidResultList, res, sizeof res, "CpuidResultList");
}

int hv_vm_create(hv_vm **out)
{
    WHV_CAPABILITY cap = {0};
    UINT32 cap_len = 0;
    if (FAILED(WHvGetCapability(WHvCapabilityCodeHypervisorPresent, &cap, sizeof cap, &cap_len)) ||
        !cap.HypervisorPresent) {
        mvm_log("no hypervisor: enable the Windows Hypervisor Platform feature");
        return HV_UNAVAILABLE;
    }
    hv_vm *vm = calloc(1, sizeof *vm);
    if (!vm)
        return -1;
    HRESULT hr = WHvCreatePartition(&vm->part);
    if (FAILED(hr)) {
        mvm_log("WHvCreatePartition: 0x%08lx (is Windows Hypervisor Platform enabled?)",
                (unsigned long)hr);
        free(vm);
        return -1;
    }
    WHV_PARTITION_PROPERTY prop = {0};
    prop.ProcessorCount = 1;
    if (set_prop(vm->part, WHvPartitionPropertyCodeProcessorCount, &prop, sizeof prop,
                 "ProcessorCount"))
        goto fail;

    memset(&prop, 0, sizeof prop);
    prop.LocalApicEmulationMode = WHvX64LocalApicEmulationModeXApic;
    if (set_prop(vm->part, WHvPartitionPropertyCodeLocalApicEmulationMode, &prop, sizeof prop,
                 "LocalApic"))
        goto fail;

    memset(&prop, 0, sizeof prop);
    prop.SyntheticProcessorFeaturesBanks.BanksCount = 1;
    WHV_SYNTHETIC_PROCESSOR_FEATURES *f = &prop.SyntheticProcessorFeaturesBanks.Bank0;
    f->HypervisorPresent = 1;
    f->Hv1 = 1;
    f->AccessFrequencyRegs = 1;
    f->AccessHypercallRegs = 1; // Linux only treats us as Hyper-V if this is set
    f->AccessVpIndex = 1;
    f->AccessPartitionReferenceCounter = 1;
    // Non-fatal: without it the guest falls back to slower calibration.
    (void)set_prop(vm->part, WHvPartitionPropertyCodeSyntheticProcessorFeaturesBanks, &prop,
                   sizeof prop, "SyntheticProcessorFeatures");

    // MSRs the hypervisor doesn't implement exit to us instead of #GP.
    memset(&prop, 0, sizeof prop);
    prop.ExtendedVmExits.X64MsrExit = 1;
    if (set_prop(vm->part, WHvPartitionPropertyCodeExtendedVmExits, &prop, sizeof prop,
                 "ExtendedVmExits"))
        goto fail;
    memset(&prop, 0, sizeof prop);
    prop.X64MsrExitBitmap.UnhandledMsrs = 1;
    if (set_prop(vm->part, WHvPartitionPropertyCodeX64MsrExitBitmap, &prop, sizeof prop,
                 "X64MsrExitBitmap"))
        goto fail;

    if (setup_cpuid(vm->part))
        goto fail;

    hr = WHvSetupPartition(vm->part);
    if (FAILED(hr)) {
        mvm_log("WHvSetupPartition: 0x%08lx", (unsigned long)hr);
        goto fail;
    }
    *out = vm;
    return 0;
fail:
    hv_vm_destroy(vm);
    return -1;
}

static HRESULT map_range(hv_vm *vm, void *hva, uint64_t gpa, uint64_t size)
{
    return WHvMapGpaRange(vm->part, hva, gpa, size,
                          WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite |
                              WHvMapGpaRangeFlagExecute);
}

static DWORD WINAPI mapper_main(void *arg)
{
    hv_vm *vm = arg;
    HRESULT hr = S_OK;
    for (size_t i = 0; i < vm->nlater && SUCCEEDED(hr); i++) {
        const hv_range *r = &vm->later[i];
        hr = map_range(vm, vm->later_hva + (r->gpa - vm->later_gpa), r->gpa, r->size);
    }
    vm->mapper_hr = hr;
    return 0;
}

// Wait for the background mapper, if one is running.
static int mapper_wait(hv_vm *vm)
{
    if (!vm->mapper)
        return 0;
    WaitForSingleObject(vm->mapper, INFINITE);
    CloseHandle(vm->mapper);
    vm->mapper = nullptr;
    free(vm->later);
    vm->later = nullptr;
    if (FAILED(vm->mapper_hr)) {
        mvm_log("WHvMapGpaRange (background): 0x%08lx", (unsigned long)vm->mapper_hr);
        return -1;
    }
    return 0;
}

void hv_vm_destroy(hv_vm *vm)
{
    if (!vm)
        return;
    (void)mapper_wait(vm);
    free(vm->later); // set if the guest never ran
    if (vm->part)
        WHvDeletePartition(vm->part);
    free(vm);
}

int hv_vm_map_mem(hv_vm *vm, uint64_t gpa, void *hva, uint64_t size)
{
    if (vm->nram == MAX_RAM_REGIONS)
        return -1;
    HRESULT hr = map_range(vm, hva, gpa, size);
    if (FAILED(hr)) {
        mvm_log("WHvMapGpaRange: 0x%08lx", (unsigned long)hr);
        return -1;
    }
    vm->ram[vm->nram].gpa = gpa;
    vm->ram[vm->nram].size = size;
    vm->ram[vm->nram].hva = hva;
    vm->nram++;
    return 0;
}

int hv_vm_map_mem_ro(hv_vm *vm, uint64_t gpa, void *hva, uint64_t size)
{
    if (vm->nram == MAX_RAM_REGIONS)
        return -1;
    HRESULT hr = WHvMapGpaRange(vm->part, hva, gpa, size, WHvMapGpaRangeFlagRead);
    if (FAILED(hr)) {
        mvm_log("WHvMapGpaRange (read-only): 0x%08lx", (unsigned long)hr);
        return -1;
    }
    vm->ram[vm->nram].gpa = gpa;
    vm->ram[vm->nram].size = size;
    vm->ram[vm->nram].hva = hva;
    vm->ram[vm->nram].ro = true;
    vm->nram++;
    return 0;
}

int hv_vm_map_mem_traced(hv_vm *vm, uint64_t gpa, void *hva, uint64_t size, uint8_t *touched)
{
    if (vm->nram == MAX_RAM_REGIONS || vm->touched || gpa % 4096 || size % 4096)
        return -1;
    // Nothing is mapped: each first touch exits as a memory access to RAM,
    // which maps that page (hv_vcpu_run).
    vm->ram[vm->nram].gpa = gpa;
    vm->ram[vm->nram].size = size;
    vm->ram[vm->nram].hva = hva;
    vm->traced = vm->nram++;
    vm->touched = touched;
    return 0;
}

// A traced region's page the guest touched for the first time: map it.
// Returns false if gpa isn't in it, or was mapped already (then the exit
// is something else).
static bool trace_touch(hv_vm *vm, uint64_t gpa)
{
    if (!vm->touched || gpa < vm->ram[vm->traced].gpa ||
        gpa - vm->ram[vm->traced].gpa >= vm->ram[vm->traced].size)
        return false;
    const uint64_t page = (gpa - vm->ram[vm->traced].gpa) / 4096;
    if (vm->touched[page])
        return false;
    HRESULT hr = map_range(vm, vm->ram[vm->traced].hva + page * 4096,
                           vm->ram[vm->traced].gpa + page * 4096, 4096);
    if (FAILED(hr)) {
        mvm_log("WHvMapGpaRange (traced): 0x%08lx", (unsigned long)hr);
        return false;
    }
    vm->touched[page] = 1;
    return true;
}

static int range_cmp(const void *a, const void *b)
{
    const hv_range *x = a, *y = b;
    return (x->gpa > y->gpa) - (x->gpa < y->gpa);
}

int hv_vm_map_mem_split(hv_vm *vm, uint64_t gpa, void *hva, uint64_t size, const hv_range *now,
                        size_t n_now)
{
    uint64_t end;
    if (!n_now || vm->mapper || ckd_add(&end, gpa, size))
        return hv_vm_map_mem(vm, gpa, hva, size);
    if (vm->nram == MAX_RAM_REGIONS)
        return -1;
    // `now`, clipped to the region, page-aligned outwards, sorted, merged.
    hv_range *r = malloc(n_now * sizeof *r);
    hv_range *later = malloc((n_now + 1) * sizeof *later);
    if (!r || !later) {
        free(r);
        free(later);
        return -1;
    }
    size_t n = 0;
    for (size_t i = 0; i < n_now; i++) {
        uint64_t lo = now[i].gpa, hi;
        if (ckd_add(&hi, lo, now[i].size))
            hi = UINT64_MAX;
        lo = (lo < gpa ? gpa : lo) & ~0xfffull;
        const uint64_t up = (hi > end ? end : hi) | 0xfff; // round up, capped at end
        hi = up >= end ? end : up + 1;
        if (lo < hi)
            r[n++] = (hv_range){lo, hi - lo};
    }
    qsort(r, n, sizeof *r, range_cmp);
    size_t m = 0;
    for (size_t i = 0; i < n; i++) {
        if (m && r[i].gpa <= r[m - 1].gpa + r[m - 1].size) {
            const uint64_t e = r[i].gpa + r[i].size;
            if (e > r[m - 1].gpa + r[m - 1].size)
                r[m - 1].size = e - r[m - 1].gpa;
        } else
            r[m++] = r[i];
    }
    // The rest of the region, for the background thread.
    size_t nl = 0;
    uint64_t cur = gpa;
    for (size_t i = 0; i < m; i++) {
        if (r[i].gpa > cur)
            later[nl++] = (hv_range){cur, r[i].gpa - cur};
        cur = r[i].gpa + r[i].size;
    }
    if (cur < end)
        later[nl++] = (hv_range){cur, end - cur};

    HRESULT hr = S_OK;
    for (size_t i = 0; i < m && SUCCEEDED(hr); i++)
        hr = map_range(vm, (uint8_t *)hva + (r[i].gpa - gpa), r[i].gpa, r[i].size);
    free(r);
    if (FAILED(hr)) {
        free(later);
        mvm_log("WHvMapGpaRange: 0x%08lx", (unsigned long)hr);
        return -1;
    }
    vm->ram[vm->nram].gpa = gpa;
    vm->ram[vm->nram].size = size;
    vm->ram[vm->nram].hva = hva;
    vm->nram++;
    if (!nl) {
        free(later);
        return 0;
    }
    // The thread starts with the guest (mapper_start), not now: it would
    // contend with the working-set prefault for the hypervisor's lock.
    vm->later = later;
    vm->nlater = nl;
    vm->later_hva = hva;
    vm->later_gpa = gpa;
    return 0;
}

// Start mapping the rest of RAM in the background, on the first vCPU run.
static int mapper_start(hv_vm *vm)
{
    if (!vm->later || vm->mapper)
        return 0;
    vm->mapper = CreateThread(nullptr, 64 * 1024, mapper_main, vm,
                              STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
    if (vm->mapper)
        return 0;
    mapper_main(vm); // no thread: map it all now
    free(vm->later);
    vm->later = nullptr;
    if (FAILED(vm->mapper_hr)) {
        mvm_log("WHvMapGpaRange: 0x%08lx", (unsigned long)vm->mapper_hr);
        return -1;
    }
    return 0;
}

// Host address of guest RAM [gpa, gpa + len), for reading or, if `write`,
// for writing (never a read-only region: that host memory is read-only).
static uint8_t *ram_ptr(hv_vm *vm, uint64_t gpa, uint64_t len, bool write)
{
    for (size_t i = 0; i < vm->nram; i++) {
        uint64_t off, end;
        if ((write && vm->ram[i].ro) || ckd_sub(&off, gpa, vm->ram[i].gpa))
            continue;
        if (ckd_add(&end, off, len) || end > vm->ram[i].size)
            continue;
        return vm->ram[i].hva + off;
    }
    return nullptr;
}

// ---- instruction emulator callbacks ------------------------------------
static HRESULT CALLBACK emu_io(void *ctx, WHV_EMULATOR_IO_ACCESS_INFO *io)
{
    hv_vcpu *v = ctx;
    uint32_t val = io->Data;
    const bool write = io->Direction == 1;
    v->h.pio(v->h.opaque, io->Port, (uint8_t)io->AccessSize, write, &val);
    if (!write)
        io->Data = val;
    return S_OK;
}

static HRESULT CALLBACK emu_mem(void *ctx, WHV_EMULATOR_MEMORY_ACCESS_INFO *m)
{
    hv_vcpu *v = ctx;
    const uint8_t sz = m->AccessSize > 8 ? 8 : m->AccessSize;
    const bool write = m->Direction == 1;
    uint8_t *p = ram_ptr(v->vm, m->GpaAddress, sz, write);
    if (p) {
        if (write)
            memcpy(p, m->Data, sz);
        else
            memcpy(m->Data, p, sz);
        return S_OK;
    }
    uint64_t val = 0;
    if (write)
        memcpy(&val, m->Data, sz);
    v->h.mmio(v->h.opaque, m->GpaAddress, sz, write, &val);
    if (!write)
        memcpy(m->Data, &val, sz);
    return S_OK;
}

static HRESULT CALLBACK emu_get_regs(void *ctx, const WHV_REGISTER_NAME *names, UINT32 n,
                                     WHV_REGISTER_VALUE *vals)
{
    hv_vcpu *v = ctx;
    return WHvGetVirtualProcessorRegisters(v->vm->part, v->id, names, n, vals);
}

static HRESULT CALLBACK emu_set_regs(void *ctx, const WHV_REGISTER_NAME *names, UINT32 n,
                                     const WHV_REGISTER_VALUE *vals)
{
    hv_vcpu *v = ctx;
    return WHvSetVirtualProcessorRegisters(v->vm->part, v->id, names, n, vals);
}

static HRESULT CALLBACK emu_translate(void *ctx, WHV_GUEST_VIRTUAL_ADDRESS gva,
                                      WHV_TRANSLATE_GVA_FLAGS flags,
                                      WHV_TRANSLATE_GVA_RESULT_CODE *result,
                                      WHV_GUEST_PHYSICAL_ADDRESS *gpa)
{
    hv_vcpu *v = ctx;
    WHV_TRANSLATE_GVA_RESULT r;
    HRESULT hr = WHvTranslateGva(v->vm->part, v->id, gva, flags, &r, gpa);
    if (SUCCEEDED(hr))
        *result = r.ResultCode;
    return hr;
}

static const WHV_EMULATOR_CALLBACKS EMU_CALLBACKS = {
    .Size = sizeof(WHV_EMULATOR_CALLBACKS),
    .WHvEmulatorIoPortCallback = emu_io,
    .WHvEmulatorMemoryCallback = emu_mem,
    .WHvEmulatorGetVirtualProcessorRegisters = emu_get_regs,
    .WHvEmulatorSetVirtualProcessorRegisters = emu_set_regs,
    .WHvEmulatorTranslateGvaPage = emu_translate,
};

// One: the partition is created with ProcessorCount 1, and WHP is for
// development only (KVM is the production backend).
uint32_t hv_max_vcpus(void) { return 1; }

void hv_vcpu_attach(hv_vcpu *v) { (void)v; }

int hv_vcpu_create(hv_vm *vm, uint32_t id, const hv_handlers *h, hv_vcpu **out)
{
    hv_vcpu *v = calloc(1, sizeof *v);
    if (!v)
        return -1;
    v->vm = vm;
    v->id = id;
    v->h = *h;
    HRESULT hr = WHvCreateVirtualProcessor(vm->part, id, 0);
    if (FAILED(hr)) {
        mvm_log("WHvCreateVirtualProcessor: 0x%08lx", (unsigned long)hr);
        free(v);
        return -1;
    }
    hr = WHvEmulatorCreateEmulator(&EMU_CALLBACKS, &v->emu);
    if (FAILED(hr)) {
        mvm_log("WHvEmulatorCreateEmulator: 0x%08lx", (unsigned long)hr);
        free(v);
        return -1;
    }
    *out = v;
    return 0;
}

int hv_vcpu_setup_cpuid(hv_vcpu *v)
{
    // CPUID overrides are partition-wide on WHP; see setup_cpuid().
    (void)v;
    return 0;
}

static WHV_X64_SEGMENT_REGISTER seg_to_whp(const hv_segment *s)
{
    WHV_X64_SEGMENT_REGISTER r = {0};
    r.Base = s->base;
    r.Limit = s->limit;
    r.Selector = s->selector;
    r.SegmentType = s->type;
    r.NonSystemSegment = s->s;
    r.DescriptorPrivilegeLevel = s->dpl;
    r.Present = s->present;
    r.Available = s->avl;
    r.Long = s->l;
    r.Default = s->db;
    r.Granularity = s->g;
    return r;
}

int hv_vcpu_set_state(hv_vcpu *v, const hv_regs *r, const hv_sregs *s)
{
    static const WHV_REGISTER_NAME names[] = {
        WHvX64RegisterRax, WHvX64RegisterRcx, WHvX64RegisterRdx, WHvX64RegisterRbx,
        WHvX64RegisterRsp, WHvX64RegisterRbp, WHvX64RegisterRsi, WHvX64RegisterRdi,
        WHvX64RegisterR8,  WHvX64RegisterR9,  WHvX64RegisterR10, WHvX64RegisterR11,
        WHvX64RegisterR12, WHvX64RegisterR13, WHvX64RegisterR14, WHvX64RegisterR15,
        WHvX64RegisterRip, WHvX64RegisterRflags,
        WHvX64RegisterEs, WHvX64RegisterCs, WHvX64RegisterSs, WHvX64RegisterDs,
        WHvX64RegisterFs, WHvX64RegisterGs, WHvX64RegisterLdtr, WHvX64RegisterTr,
        WHvX64RegisterIdtr, WHvX64RegisterGdtr,
        WHvX64RegisterCr0, WHvX64RegisterCr3, WHvX64RegisterCr4, WHvX64RegisterEfer,
    };
    WHV_REGISTER_VALUE vals[MVM_ARRAY_LEN(names)];
    memset(vals, 0, sizeof vals);
    const uint64_t gp[] = {r->rax, r->rcx, r->rdx, r->rbx, r->rsp, r->rbp, r->rsi, r->rdi,
                           r->r8,  r->r9,  r->r10, r->r11, r->r12, r->r13, r->r14, r->r15,
                           r->rip, r->rflags};
    size_t i = 0;
    for (; i < MVM_ARRAY_LEN(gp); i++)
        vals[i].Reg64 = gp[i];
    vals[i++].Segment = seg_to_whp(&s->es);
    vals[i++].Segment = seg_to_whp(&s->cs);
    vals[i++].Segment = seg_to_whp(&s->ss);
    vals[i++].Segment = seg_to_whp(&s->ds);
    vals[i++].Segment = seg_to_whp(&s->fs);
    vals[i++].Segment = seg_to_whp(&s->gs);
    vals[i++].Segment = seg_to_whp(&s->ldt);
    vals[i++].Segment = seg_to_whp(&s->tr);
    vals[i].Table.Base = s->idt.base;
    vals[i++].Table.Limit = s->idt.limit;
    vals[i].Table.Base = s->gdt.base;
    vals[i++].Table.Limit = s->gdt.limit;
    vals[i++].Reg64 = s->cr0;
    vals[i++].Reg64 = s->cr3;
    vals[i++].Reg64 = s->cr4;
    vals[i++].Reg64 = s->efer;
    static_assert(MVM_ARRAY_LEN(names) == 32);

    HRESULT hr = WHvSetVirtualProcessorRegisters(v->vm->part, v->id, names,
                                                 (UINT32)MVM_ARRAY_LEN(names), vals);
    if (FAILED(hr)) {
        mvm_log("WHvSetVirtualProcessorRegisters: 0x%08lx", (unsigned long)hr);
        return -1;
    }
    return 0;
}

// Finish an exit we handled ourselves: RIP past the instruction, plus
// optional RAX/RDX results.
static int finish(hv_vcpu *v, const WHV_VP_EXIT_CONTEXT *vp, int nres, uint64_t rax, uint64_t rdx)
{
    static const WHV_REGISTER_NAME names[3] = {WHvX64RegisterRip, WHvX64RegisterRax,
                                               WHvX64RegisterRdx};
    WHV_REGISTER_VALUE vals[3] = {0};
    vals[0].Reg64 = vp->Rip + vp->InstructionLength;
    vals[1].Reg64 = rax;
    vals[2].Reg64 = rdx;
    HRESULT hr = WHvSetVirtualProcessorRegisters(v->vm->part, v->id, names, (UINT32)(1 + nres), vals);
    if (FAILED(hr)) {
        mvm_log("WHvSetVirtualProcessorRegisters(finish): 0x%08lx", (unsigned long)hr);
        return -1;
    }
    return 0;
}

// Fail the exiting instruction with #GP(0): RIP stays on it.
static int inject_gp(hv_vcpu *v)
{
    static const WHV_REGISTER_NAME name = WHvRegisterPendingEvent;
    WHV_REGISTER_VALUE val = {0};
    val.ExceptionEvent.EventPending = 1;
    val.ExceptionEvent.EventType = WHvX64PendingEventException;
    val.ExceptionEvent.DeliverErrorCode = 1;
    val.ExceptionEvent.Vector = 13;
    val.ExceptionEvent.ErrorCode = 0;
    HRESULT hr = WHvSetVirtualProcessorRegisters(v->vm->part, v->id, &name, 1, &val);
    if (FAILED(hr)) {
        mvm_log("WHvSetVirtualProcessorRegisters(#GP): 0x%08lx", (unsigned long)hr);
        return -1;
    }
    return 0;
}

// Fault the exiting instruction with #PF on gva: RIP stays on it.
static int inject_pf(hv_vcpu *v, uint64_t gva, uint32_t err)
{
    static const WHV_REGISTER_NAME name = WHvRegisterPendingEvent;
    WHV_REGISTER_VALUE val = {0};
    val.ExceptionEvent.EventPending = 1;
    val.ExceptionEvent.EventType = WHvX64PendingEventException;
    val.ExceptionEvent.DeliverErrorCode = 1;
    val.ExceptionEvent.Vector = 14;
    val.ExceptionEvent.ErrorCode = err;
    val.ExceptionEvent.ExceptionParameter = gva; // CR2
    HRESULT hr = WHvSetVirtualProcessorRegisters(v->vm->part, v->id, &name, 1, &val);
    if (FAILED(hr)) {
        mvm_log("WHvSetVirtualProcessorRegisters(#PF): 0x%08lx", (unsigned long)hr);
        return -1;
    }
    return 0;
}

// INS / OUTS (and REP) in 64-bit mode, done here: the WHP emulator fails on
// them from user mode, and it would cost more anyway. One exit moves at most
// the rest of the memory page; a longer REP re-executes with RSI or RDI and
// RCX advanced and RIP unchanged, as when the CPU takes an interrupt in the
// middle of one.
// The I/O permission check happened in hardware before the exit, and the
// translation below honours the guest's CPL and page protections (and, for
// INS, marks the page dirty).
// A page the guest hasn't mapped (or may not read, or write for INS) gets a
// #PF, which the guest resolves and re-executes, like a hardware fault on
// the access.
// Returns 1 for anything unusual (prefixes, DF/TF, other translation
// results, an element that straddles pages, memory that isn't RAM): the
// caller hands those to the emulator.
static int string_io(hv_vcpu *v, const WHV_VP_EXIT_CONTEXT *vp,
                     const WHV_X64_IO_PORT_ACCESS_CONTEXT *io)
{
    const bool out = io->AccessInfo.IsWrite;
    const uint8_t sz = (uint8_t)io->AccessInfo.AccessSize;
    const uint8_t len = (uint8_t)vp->InstructionLength;
    if (!vp->ExecutionState.EferLma || !vp->Cs.Long || (vp->Rflags & (1u << 10 | 1u << 8)) ||
        (sz != 1 && sz != 2 && sz != 4) || len == 0 || io->InstructionByteCount < len)
        return 1;
    // Only [F3] [66] [REX] 6C/6D (INS) or 6E/6F (OUTS): no segment or
    // address-size override.
    for (uint8_t i = 0; i + 1 < len; i++) {
        const uint8_t b = io->InstructionBytes[i];
        if (b != 0xf3 && b != 0x66 && (b & 0xf0) != 0x40)
            return 1;
    }
    if ((io->InstructionBytes[len - 1] & 0xfe) != (out ? 0x6e : 0x6c))
        return 1;

    const bool rep = io->AccessInfo.RepPrefix;
    uint64_t count = rep ? io->Rcx : 1;
    uint64_t at = out ? io->Rsi : io->Rdi; // OUTS reads DS:RSI, INS writes ES:RDI
    if (count) {
        WHV_TRANSLATE_GVA_RESULT r;
        WHV_GUEST_PHYSICAL_ADDRESS gpa;
        const WHV_TRANSLATE_GVA_FLAGS how =
            out ? WHvTranslateGvaFlagValidateRead
                : WHvTranslateGvaFlagValidateWrite | WHvTranslateGvaFlagSetPageTableBits;
        HRESULT hr = WHvTranslateGva(v->vm->part, v->id, at, how, &r, &gpa);
        if (FAILED(hr))
            return 1;
        if (r.ResultCode == WHvTranslateGvaResultPageNotPresent ||
            r.ResultCode == WHvTranslateGvaResultPrivilegeViolation) {
            // #PF: P set for a protection fault, W for a write, U for CPL 3.
            const uint32_t err = (r.ResultCode == WHvTranslateGvaResultPrivilegeViolation ? 1u : 0u) |
                                 (out ? 0u : 2u) | (vp->ExecutionState.Cpl == 3 ? 4u : 0u);
            return inject_pf(v, at, err);
        }
        if (r.ResultCode != WHvTranslateGvaResultSuccess)
            return 1;
        const uint64_t room = (4096 - (at & 4095)) / sz; // whole elements left in the page
        if (room == 0)
            return 1;
        const uint64_t k = count < room ? count : room;
        uint8_t *p = ram_ptr(v->vm, (gpa & ~4095ull) | (at & 4095), k * sz, !out);
        if (!p)
            return 1;
        for (uint64_t i = 0; i < k; i++) {
            uint32_t val = 0;
            if (out)
                memcpy(&val, p + i * sz, sz);
            v->h.pio(v->h.opaque, io->PortNumber, sz, out, &val);
            if (!out)
                memcpy(p + i * sz, &val, sz);
        }
        at += k * sz;
        count -= k;
    }
    const WHV_REGISTER_NAME names[3] = {WHvX64RegisterRip,
                                        out ? WHvX64RegisterRsi : WHvX64RegisterRdi,
                                        WHvX64RegisterRcx};
    WHV_REGISTER_VALUE vals[3] = {0};
    vals[0].Reg64 = count ? vp->Rip : vp->Rip + len;
    vals[1].Reg64 = at;
    vals[2].Reg64 = count;
    HRESULT hr = WHvSetVirtualProcessorRegisters(v->vm->part, v->id, names, rep ? 3 : 2, vals);
    if (FAILED(hr)) {
        mvm_log("WHvSetVirtualProcessorRegisters(string I/O): 0x%08lx", (unsigned long)hr);
        return -1;
    }
    return 0;
}

static int emulated(const char *what, HRESULT hr, WHV_EMULATOR_STATUS st)
{
    if (FAILED(hr) || !st.EmulationSuccessful) {
        mvm_log("WHP %s emulation failed: hr=0x%08lx status=0x%x", what, (unsigned long)hr,
                (unsigned)st.AsUINT32);
        return -1;
    }
    return 0;
}

int hv_vcpu_run(hv_vcpu *v, hv_exit *ex)
{
    WHV_RUN_VP_EXIT_CONTEXT ctx;
    ex->access = HV_ACCESS_NONE;
    ex->sampled = false;
    if (mapper_start(v->vm))
        return -1;
    HRESULT hr = WHvRunVirtualProcessor(v->vm->part, v->id, &ctx, sizeof ctx);
    if (FAILED(hr)) {
        mvm_log("WHvRunVirtualProcessor: 0x%08lx", (unsigned long)hr);
        return -1;
    }
    ex->hw_reason = ctx.ExitReason;
    ex->kind = HV_EXIT_HANDLED;
    switch (ctx.ExitReason) {
    case WHvRunVpExitReasonX64IoPortAccess: {
        const WHV_X64_IO_PORT_ACCESS_CONTEXT *io = &ctx.IoPortAccess;
        ex->access = HV_ACCESS_PIO;
        if (io->AccessInfo.StringOp || io->AccessInfo.RepPrefix) {
            if (io->AccessInfo.StringOp) {
                const int r = string_io(v, &ctx.VpContext, io);
                if (r <= 0)
                    return r;
            }
            WHV_EMULATOR_STATUS st = {0};
            hr = WHvEmulatorTryIoEmulation(v->emu, v, &ctx.VpContext, io, &st);
            return emulated("string I/O", hr, st);
        }
        const uint8_t sz = (uint8_t)io->AccessInfo.AccessSize;
        const bool write = io->AccessInfo.IsWrite;
        uint32_t val = (uint32_t)io->Rax;
        v->h.pio(v->h.opaque, io->PortNumber, sz, write, &val);
        if (write)
            return finish(v, &ctx.VpContext, 0, 0, 0);
        uint64_t rax = io->Rax;
        switch (sz) {
        case 1: rax = (rax & ~0xffull) | (val & 0xff); break;
        case 2: rax = (rax & ~0xffffull) | (val & 0xffff); break;
        default: rax = val; break; // 32-bit results zero-extend
        }
        return finish(v, &ctx.VpContext, 1, rax, 0);
    }
    case WHvRunVpExitReasonMemoryAccess: {
        if (v->vm->mapper && ram_ptr(v->vm, ctx.MemoryAccess.Gpa, 1, false)) {
            // RAM the background mapper hasn't reached yet: wait for it and
            // rerun the instruction.
            if (mapper_wait(v->vm))
                return -1;
            ex->kind = HV_EXIT_RETRY;
            return 0;
        }
        if (trace_touch(v->vm, ctx.MemoryAccess.Gpa)) {
            ex->kind = HV_EXIT_RETRY;
            return 0;
        }
        ex->access = HV_ACCESS_MMIO;
        WHV_EMULATOR_STATUS st = {0};
        hr = WHvEmulatorTryMmioEmulation(v->emu, v, &ctx.VpContext, &ctx.MemoryAccess, &st);
        return emulated("MMIO", hr, st);
    }
    case WHvRunVpExitReasonX64MsrAccess: {
        const WHV_X64_MSR_ACCESS_CONTEXT *m = &ctx.MsrAccess;
        ex->access = HV_ACCESS_MSR;
        const bool write = m->AccessInfo.IsWrite;
        uint64_t val = write ? ((m->Rdx << 32) | (m->Rax & 0xffffffffull)) : 0;
        if (!v->h.msr(v->h.opaque, m->MsrNumber, write, &val))
            return inject_gp(v);
        if (write)
            return finish(v, &ctx.VpContext, 0, 0, 0);
        return finish(v, &ctx.VpContext, 2, val & 0xffffffffull, val >> 32);
    }
    case WHvRunVpExitReasonX64Halt:
        // HLT with IF=0 can never wake up. With IF=1 the emulated LAPIC
        // timer will fire; re-entering lets the hypervisor deliver it.
        ex->kind = (ctx.VpContext.Rflags & (1u << 9)) ? HV_EXIT_RETRY : HV_EXIT_HLT;
        return 0;
    case WHvRunVpExitReasonUnrecoverableException:
        ex->kind = HV_EXIT_SHUTDOWN;
        return 0;
    case WHvRunVpExitReasonCanceled:
        ex->kind = HV_EXIT_RETRY;
        ex->sampled = v->profiling;
        ex->rip = ctx.VpContext.Rip;
        ex->rsp = ex->cr3 = 0;
        if (v->profiling) {
            static const WHV_REGISTER_NAME names[] = {WHvX64RegisterRsp, WHvX64RegisterCr3};
            WHV_REGISTER_VALUE vals[2];
            if (SUCCEEDED(WHvGetVirtualProcessorRegisters(v->vm->part, v->id, names, 2, vals))) {
                ex->rsp = vals[0].Reg64;
                ex->cr3 = vals[1].Reg64;
            }
        }
        return 0;
    case WHvRunVpExitReasonX64InterruptWindow:
    case WHvRunVpExitReasonX64ApicEoi:
        ex->kind = HV_EXIT_RETRY;
        return 0;
    default:
        mvm_log("unhandled WHP exit 0x%x at rip=0x%llx", (unsigned)ctx.ExitReason,
                (unsigned long long)ctx.VpContext.Rip);
        ex->kind = HV_EXIT_FAIL;
        return 0;
    }
}

void hv_get_info(hv_vm *vm, hv_vcpu *v, hv_info *info)
{
    (void)vm;
    (void)v;
    WHV_CAPABILITY cap;
    UINT32 sz = 0;
    info->tsc_khz = 0;
    if (SUCCEEDED(WHvGetCapability(WHvCapabilityCodeProcessorClockFrequency, &cap, sizeof cap, &sz)))
        info->tsc_khz = cap.ProcessorClockFrequency / 1000;
}

void hv_vcpu_set_profiling(hv_vcpu *v, bool on) { v->profiling = on; }

void hv_vcpu_kick(hv_vcpu *v) { (void)WHvCancelRunVirtualProcessor(v->vm->part, v->id, 0); }

int hv_vm_queue_writes(hv_vm *vm, uint64_t gpa, uint32_t len)
{
    (void)vm, (void)gpa, (void)len;
    return HV_UNAVAILABLE; // WHP exits for every access
}

int hv_vcpu_save_prepare(hv_vcpu *v) { (void)v; return HV_UNAVAILABLE; }
int64_t hv_vcpu_save(hv_vcpu *v, uint8_t *buf, size_t cap) { (void)v, (void)buf, (void)cap; return -1; }
int hv_vcpu_restore(hv_vcpu *v, const uint8_t *buf, size_t len)
{
    (void)v, (void)buf, (void)len;
    return HV_UNAVAILABLE;
}
uint64_t hv_vcpu_cpuid_hash(const hv_vcpu *v) { (void)v; return 0; }
size_t hv_save_ioctls(hv_vcpu *v, int *fds, unsigned long *requests, size_t max)
{
    (void)v, (void)fds, (void)requests, (void)max;
    return 0;
}

int hv_vm_doorbell(hv_vm *vm, uint64_t gpa, uint32_t len, int fd)
{
    (void)vm, (void)gpa, (void)len, (void)fd;
    return HV_UNAVAILABLE;
}

int hv_vm_signal_msi(hv_vm *vm, uint64_t addr, uint32_t data)
{
    // The APIC delivery modes a device may use have the same numbers as
    // WHV_INTERRUPT_TYPE: fixed 0, lowest priority 1, NMI 4.
    const uint32_t mode = (data >> 8) & 7;
    if (mode != 0 && mode != 1 && mode != 4)
        return -1;
    WHV_INTERRUPT_CONTROL c = {0};
    c.Type = mode;
    c.DestinationMode = (addr >> 2) & 1 ? WHvX64InterruptDestinationModeLogical
                                        : WHvX64InterruptDestinationModePhysical;
    c.TriggerMode = WHvX64InterruptTriggerModeEdge;
    c.Destination = (uint32_t)(addr >> 12) & 0xff;
    c.Vector = data & 0xff;
    return FAILED(WHvRequestInterrupt(vm->part, &c, sizeof c)) ? -1 : 0;
}

int hv_vcpu_prefault(hv_vcpu *v, const hv_range *ranges, size_t n, bool write)
{
    static_assert(sizeof(hv_range) == sizeof(WHV_MEMORY_RANGE_ENTRY));
    WHV_ADVISE_GPA_RANGE_POPULATE pop = {0};
    pop.Flags.Prefetch = 1;
    pop.AccessType = write ? WHvMemoryAccessWrite : WHvMemoryAccessRead;
    for (size_t done = 0; done < n;) {
        const UINT32 chunk = n - done > 4096 ? 4096 : (UINT32)(n - done);
        HRESULT hr = WHvAdviseGpaRange(v->vm->part, (const WHV_MEMORY_RANGE_ENTRY *)(ranges + done),
                                       chunk, WHvAdviseGpaRangeCodePopulate, &pop, sizeof pop);
        if (FAILED(hr)) {
            mvm_log("WHvAdviseGpaRange(populate): 0x%08lx", (unsigned long)hr);
            return -1;
        }
        done += chunk;
    }
    return 0;
}

size_t hv_runtime_ioctls(hv_vcpu *v, int *fds, unsigned long *requests, size_t max)
{
    (void)v, (void)fds, (void)requests, (void)max;
    return 0; // no ioctl filtering on Windows
}
