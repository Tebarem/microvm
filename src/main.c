// SPDX-License-Identifier: MIT
// microvm: a minimal, cold-start-optimized VMM.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "boot/elf.h"
#include "boot/x86.h"
#include "clock.h"
#include "dev/balloon.h"
#include "dev/net.h"
#include "dev/vsock.h"
#include "net_helper.h"
#include "os.h"
#include "sandbox.h"
#include "snapshot.h"
#include "vm.h"

// 64-bit smoke-test guest: prints "OK\n" on COM1, drops a marker, exits 0.
static const uint8_t HELLO_GUEST[] = {
    0x66, 0xba, 0xf8, 0x03, // mov dx, 0x3f8
    0xb0, 'O', 0xee,        // mov al, 'O'; out dx, al
    0xb0, 'K', 0xee,        // mov al, 'K'; out dx, al
    0xb0, '\n', 0xee,       // mov al, '\n'; out dx, al
    0x66, 0xba, 0x00, 0x07, // mov dx, 0x700
    0xb0, 0x01, 0xee,       // mov al, 1; out dx, al     (marker 1)
    0x66, 0xba, 0x01, 0x07, // mov dx, 0x701
    0xb0, 0x00, 0xee,       // mov al, 0; out dx, al     (exit 0)
    0xf4,                   // hlt
    0xeb, 0xfe,             // jmp $
};

// reduced_hw (kernel patch 0025): there is no PIT or PIC to stop or probe.
static const char DEFAULT_CMDLINE[] =
    "earlyprintk=microvm,keep console=ttyS0 reboot=k panic=-1 tsc=reliable no_timer_check noroms "
    "io_delay=none keep_image_gaps reduced_hw";

static void usage(void)
{
    static const char msg[] =
        "usage: microvm (--kernel VMLINUX | --hello | --restore FILE) [options] [-- COMMAND [ARG...]]\n"
        "  --kernel PATH     uncompressed x86-64 vmlinux (ELF)\n"
        "  --hello           run the built-in smoke-test guest\n"
        "  --snapshot FILE   when the guest asks (control port 0x706; /init's 'snapshot'),\n"
        "                    save the VM to FILE and stop with status 0 (KVM)\n"
        "  --snapshot-diff   with --snapshot, in a VM restored from a snapshot: save only\n"
        "                    the pages that differ from the full snapshot its memory came\n"
        "                    from (its base); restore that with --base\n"
        "  --restore FILE    start from a snapshot instead of booting: same --rootfs images\n"
        "                    and devices as when it was taken, no COMMAND (it was saved)\n"
        "  --base FILE       the full snapshot a --restore diff was saved against\n"
        "  --mem MIB         guest RAM ceiling in MiB (default 64; pages are lazily touched)\n"
        "  --cpus N          vCPUs (default 1, at most 8; KVM only). A kernel built with\n"
        "                    SMP (guest/kernel/out/vmlinux-smp) starts the others. With\n"
        "                    --restore, the snapshot's count (give it or leave it out)\n"
        "  --rootfs IMAGE    EROFS root filesystem (microvm-mkrootfs): /init enters it and\n"
        "                    runs what the image's config says (Entrypoint, Cmd, Env,\n"
        "                    WorkingDir, User), COMMAND replacing Cmd as in 'docker run';\n"
        "                    the exit status becomes the VMM's. The image is never written:\n"
        "                    the guest's changes go to a tmpfs over it. Given more than\n"
        "                    once (at most 8, Linux): layers, bottom first, each its own\n"
        "                    image (microvm-mkrootfs --lower), stacked by /init\n"
        "  -e, --env NAME[=VALUE]\n"
        "                    set NAME in the command's environment, over the image's Env;\n"
        "                    a bare NAME takes this process's NAME, or unsets NAME if it\n"
        "                    has none (repeatable; as 'docker run -e')\n"
        "  --env-file FILE   NAME=VALUE or NAME lines, as 'docker run --env-file': blank\n"
        "                    lines and # comments skipped; applied before -e (repeatable)\n"
        "  --vsock PATH      a virtio-vsock device; the host reaches the guest's port P by\n"
        "                    connecting to the new Unix socket PATH and sending\n"
        "                    \"CONNECT P\\n\" (answer: \"OK N\\n\"); for the guest to reach\n"
        "                    the host's port P, connect and send \"LISTEN P\\n\" ahead of time\n"
        "                    (answer when the guest connects: \"OK N\\n\"); the caller removes PATH\n"
        "  --balloon         a virtio-balloon device that takes the guest's free page\n"
        "                    reports: memory the guest frees goes back to the host (and\n"
        "                    out of --snapshot-diff files); it never inflates\n"
        "  --net             a virtio-net device: the guest is 10.0.2.15/24, its TCP and UDP\n"
        "                    flows become host sockets (opened by a sandboxed helper process);\n"
        "                    10.0.2.3:53 is the host's resolver, 10.0.2.2 the host's loopback\n"
        "  --net-allow CIDR[,PORT]\n"
        "                    let the guest reach a range the egress policy refuses (loopback,\n"
        "                    private, link-local, CGNAT, the host's own addresses...); repeatable\n"
        "  --net-dns ADDR    the resolver for 10.0.2.3 (default: the host's /etc/resolv.conf)\n"
        "  --net-deny-all    refuse every flow, DNS too (a network device with nowhere to go)\n"
        "  --net-only        refuse everything outside the --net-allow ranges, DNS too\n"
        "  --net-deny-port P refuse port P everywhere, TCP and UDP (mail: 25); repeatable\n"
        "  --net-flow-rate N at most N new flows a second (bursts of 5 s worth)\n"
        "  --net-max-dests N at most N different addresses a minute\n"
        "  --net-tx-rate B   at most B bytes a second out, all flows together\n"
        "  --net-fd FD       --net with a helper already running on socket FD (microvm-jail)\n"
        "  --stats FILE      every 2 s, the network counters and the VMM's CPU time in FILE\n"
        "  --cmdline STR     replace the default kernel command line\n"
        "  --append STR      append to the kernel command line\n"
        "  --quiet           add 'quiet printk_drop_suppressed' to the command line:\n"
        "                    the console shows errors only, and the kernel doesn't\n"
        "                    log the messages it hides either\n"
        "  --map-kernel      map read-only kernel segments copy-on-write, shared across VMs\n"
        "  --cpuid-hide LEAF[.SUB]:REG:MASK\n"
        "                    hide CPUID bits from the guest, e.g. 7.0:ecx:0x8 (PKU); REG is\n"
        "                    eax..edx, no .SUB means every subleaf; repeatable, up to 8\n"
        "  --trace           print a MVMTRACE timing line to stderr\n"
        "  --timestamps      prefix guest console lines with host time since VMM start\n"
        "  --profile FILE    sample the guest RIP every --profile-us (default 50) into FILE\n"
        "  --prefault MIB    pre-build stage-2 mappings for the first MIB of guest RAM\n"
        "  --ws-record FILE  after the run, save the guest pages that were touched\n"
        "  --ws FILE         prefault exactly the pages saved by --ws-record\n"
        "  --dump-mem FILE   after the run, write all of guest RAM to FILE (debugging)\n"
        "  --no-sandbox      don't sandbox the VMM process (debugging only)\n"
        "  --version         print the version and exit\n";
    mvm_write_err(msg, sizeof msg - 1);
    exit(2);
}

// "LEAF[.SUBLEAF]:REG:MASK", numbers in C syntax (0x...).
static bool parse_cpuid_hide(const char *s, hv_cpuid_hide *h)
{
    static const char *const regs[] = {"eax", "ebx", "ecx", "edx"};
    char *e;
    unsigned long long leaf = strtoull(s, &e, 0), sub = 0;
    const bool any = *e != '.';
    if (e == s)
        return false;
    if (!any)
        sub = strtoull(e + 1, &e, 0);
    if (*e != ':' || leaf > UINT32_MAX || sub > UINT32_MAX)
        return false;
    s = e + 1;
    uint8_t reg = 0;
    while (reg < 4 && strncmp(s, regs[reg], 3))
        reg++;
    if (reg == 4 || s[3] != ':')
        return false;
    const unsigned long long mask = strtoull(s + 4, &e, 0);
    if (*e || e == s + 4 || !mask || mask > UINT32_MAX)
        return false;
    *h = (hv_cpuid_hide){.leaf = (uint32_t)leaf, .subleaf = (uint32_t)sub, .any_subleaf = any,
                         .reg = reg, .mask = (uint32_t)mask};
    return true;
}

// ---- --env / --env-file ------------------------------------------------
// The command's environment on top of the image's, as `docker run -e` and
// `--env-file` give it: NAME=VALUE sets NAME; a bare NAME takes the host's
// NAME, or removes NAME when the host has none. The files come first, then
// the -e strings, each in order; a later NAME wins.
//
// /init reads the strings from port 0x707 (vm.c), not from the kernel
// command line, which every guest process can read (/proc/cmdline) and the
// console prints. Blob: u32 length, then that many bytes of NUL-terminated
// strings.
typedef struct {
    uint8_t *b;
    size_t len, cap, n;
} env_blob;

static void env_push(env_blob *e, const char *s, size_t n)
{
    if (!n || s[0] == '=')
        mvm_die("--env '%.*s': no variable name", (int)(n < 64 ? n : 64), s);
    if (memchr(s, 0, n) || e->n == MVM_ENV_MAX_STRINGS || n + 1 > MVM_ENV_MAX - e->len)
        mvm_die("--env: at most %d strings and %d bytes in all, no NUL bytes", MVM_ENV_MAX_STRINGS,
                MVM_ENV_MAX);
    if (e->len + n + 1 > e->cap) {
        e->cap = e->cap ? e->cap : 4096;
        while (e->len + n + 1 > e->cap)
            e->cap *= 2;
        if (!(e->b = realloc(e->b, e->cap)))
            mvm_die("out of memory");
    }
    memcpy(e->b + e->len, s, n);
    e->b[e->len + n] = 0;
    e->len += n + 1;
    e->n++;
}

// One -e string, or one line of a file: a bare NAME looks up the host's.
static void env_add(env_blob *e, const char *s, size_t n)
{
    if (memchr(s, '=', n)) {
        env_push(e, s, n);
        return;
    }
    char name[256];
    if (n && n < sizeof name) {
        memcpy(name, s, n);
        name[n] = 0;
        const char *v = getenv(name);
        if (v) {
            const size_t vl = strlen(v);
            char *kv = malloc(n + 1 + vl);
            if (!kv)
                mvm_die("out of memory");
            memcpy(kv, s, n);
            kv[n] = '=';
            memcpy(kv + n + 1, v, vl);
            env_push(e, kv, n + 1 + vl);
            free(kv);
            return;
        }
    }
    env_push(e, s, n); // the guest removes NAME
}

// Docker's format: a line is NAME=VALUE (VALUE verbatim, quotes and all) or
// a bare NAME; leading blanks are dropped, and blank lines and lines that
// start with # are skipped. A NAME has no blanks.
static void env_file(env_blob *e, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        mvm_die("--env-file '%s': cannot open it", path);
    char *buf = malloc(MVM_ENV_MAX + 1);
    if (!buf)
        mvm_die("out of memory");
    const size_t n = fread(buf, 1, MVM_ENV_MAX + 1, f);
    if (ferror(f) || n > MVM_ENV_MAX)
        mvm_die("--env-file '%s': cannot read it, or longer than %d bytes", path, MVM_ENV_MAX);
    fclose(f);
    unsigned line_no = 0;
    for (size_t at = 0; at < n;) {
        line_no++;
        const char *nl = memchr(buf + at, '\n', n - at);
        size_t end = nl ? (size_t)(nl - buf) : n, next = nl ? end + 1 : n;
        if (end > at && buf[end - 1] == '\r')
            end--;
        while (at < end && (buf[at] == ' ' || buf[at] == '\t'))
            at++;
        if (at < end && buf[at] != '#') {
            const char *s = buf + at, *eq = memchr(s, '=', end - at);
            const size_t name_len = eq ? (size_t)(eq - s) : end - at;
            for (size_t i = 0; i < name_len; i++)
                if (s[i] == ' ' || s[i] == '\t' || !s[i])
                    mvm_die("--env-file '%s' line %u: a variable name with a blank in it", path, line_no);
            env_add(e, s, end - at);
        }
        at = next;
    }
    free(buf);
}

// ---- guest working set -------------------------------------------------
// The pages a boot touches are nearly identical every time. Recording them
// once and prefaulting exactly that set turns ~1 hypervisor fault per page
// into one batched call, without touching (= paying memory for) anything
// the guest wouldn't have touched anyway. Where the backend can trace the
// guest's first touches (WHP), the record holds only those: text the guest
// never runs is copied in but not prefaulted (~0.3 us a page).
//
// File format, one run per line: "<first page> <count> [r]" in hex. "r"
// marks pages the guest only read from a copy-on-write file view; those are
// prefaulted read-only so they stay shared with every other VM.
static int ws_measure(vm *v, FILE *record, const void *pmem, uint64_t pmem_size)
{
    const size_t pages = v->mem.size / 4096;
    uint8_t *map = calloc(pages, 1);
    if (!map)
        return -1;
    size_t n = os_mem_resident(v->mem.base, v->mem.size, map);
    if (n == SIZE_MAX) {
        free(map);
        return -1;
    }
    size_t shared = 0;
    for (size_t i = 0; i < pages; i++)
        shared += (map[i] & OS_PAGE_SHARED) != 0;
    v->touched_kib = (uint64_t)n * 4;
    v->shared_kib = (uint64_t)shared * 4;
    int rc = 0;
    // Traced: leave out what the host wrote but the guest never touched,
    // in holes of 64 KiB or more (the kernel's 2 MiB of int3 padding, cold
    // code). Smaller holes stay: each extra run costs a map and a prefault
    // call, and a page one boot skips, the next may touch (~3 us a fault).
    constexpr size_t MIN_HOLE = 16;
    for (size_t i = 0; v->touched && i < pages;) {
        size_t j = i;
        while (j < pages && !v->touched[j])
            j++;
        if (j - i >= MIN_HOLE)
            memset(map + i, 0, j - i);
        i = j > i ? j : i + 1;
    }
    if (record) {
        FILE *f = record;
        for (size_t i = 0; i < pages;) {
            if (!map[i]) {
                i++;
                continue;
            }
            size_t j = i;
            while (j < pages && map[j] == map[i])
                j++;
            fprintf(f, "%zx %zx%s\n", i, j - i, map[i] & OS_PAGE_SHARED ? " r" : "");
            i = j;
        }
        // The root filesystem image: the pages the guest read (it can't
        // write them), at their guest-physical page numbers.
        const size_t ppages = (size_t)(pmem_size / 4096);
        uint8_t *pmap = ppages ? calloc(ppages, 1) : nullptr;
        if (ppages && (!pmap || os_mem_resident((void *)pmem, pmem_size, pmap) == SIZE_MAX))
            rc = -1;
        for (size_t i = 0; pmap && rc == 0 && i < ppages;) {
            if (!pmap[i]) {
                i++;
                continue;
            }
            size_t j = i;
            while (j < ppages && pmap[j])
                j++;
            fprintf(f, "%llx %zx r\n", (unsigned long long)(X86_PMEM_GPA / 4096 + i), j - i);
            i = j;
        }
        free(pmap);
        if (fclose(f))
            rc = -1;
    }
    free(map);
    return rc;
}

typedef struct {
    hv_range *r;
    size_t n, cap;
} range_list;

static bool range_push(range_list *l, hv_range r)
{
    if (l->n == l->cap) {
        const size_t cap = l->cap ? l->cap * 2 : 256;
        hv_range *nr = realloc(l->r, cap * sizeof *nr);
        if (!nr)
            return false;
        l->r = nr;
        l->cap = cap;
    }
    l->r[l->n++] = r;
    return true;
}

// Read a recorded working set (if any): pages the guest wrote into `rw`,
// pages it only read into `ro`, pages of the root filesystem image into
// `pm` (checked against the image's size once it's open: ws_prefault()).
static int ws_load(const char *path, uint64_t mem_size, range_list *rw, range_list *ro,
                   range_list *pm)
{
    bool ok = true;
    FILE *f = path ? fopen(path, "r") : nullptr;
    if (path && !f)
        ok = false;
    char line[128];
    while (ok && f && fgets(line, sizeof line, f)) {
        unsigned long long first, count;
        char flag[4] = "";
        if (sscanf(line, "%llx %llx %3s", &first, &count, flag) < 2)
            continue;
        uint64_t gpa, size, end;
        if (ckd_mul(&gpa, (uint64_t)first, 4096) || ckd_mul(&size, (uint64_t)count, 4096) ||
            ckd_add(&end, gpa, size))
            continue;
        if (gpa >= X86_PMEM_GPA)
            ok = range_push(pm, (hv_range){gpa, size});
        else if (end <= mem_size) // else: stale entry from a bigger --mem
            ok = range_push(flag[0] == 'r' ? ro : rw, (hv_range){gpa, size});
    }
    if (f)
        fclose(f);
    return ok ? 0 : -1;
}

// Prefault the working set, then free the lists. Image pages (always read
// only) are kept to those inside one of the images mapped now (n of them,
// at gpa[i], size[i] bytes): a record made with other images may name
// pages past their ends, or in the holes between them.
static int ws_prefault(vm *v, range_list *rw, range_list *ro, range_list *pm, uint32_t n, const uint64_t *gpa,
                       const uint64_t *size)
{
    bool ok = true;
    size_t k = 0;
    for (size_t i = 0; i < pm->n; i++)
        for (uint32_t l = 0; l < n; l++) {
            const uint64_t off = pm->r[i].gpa - gpa[l];
            if (pm->r[i].gpa >= gpa[l] && off < size[l] && pm->r[i].size <= size[l] - off) {
                pm->r[k++] = pm->r[i];
                break;
            }
        }
    pm->n = k;
    // Overlapping ranges are fine: populating a present page is a no-op.
    if (rw->n && hv_vcpu_prefault(v->vcpu, rw->r, rw->n, true))
        ok = false;
    if (ok && ro->n && hv_vcpu_prefault(v->vcpu, ro->r, ro->n, false))
        ok = false;
    if (ok && pm->n && hv_vcpu_prefault(v->vcpu, pm->r, pm->n, false))
        ok = false;
    free(rw->r);
    free(ro->r);
    free(pm->r);
    *rw = *ro = *pm = (range_list){0};
    return ok ? 0 : -1;
}

static int file_reader(void *ctx, void *buf, size_t len, uint64_t off)
{
    return os_file_pread(*(os_file *)ctx, buf, len, off);
}

// Loading a vmlinux is split in two: kernel_open() parses the image and
// (with --map-kernel) turns aligned read-only segments into copy-on-write
// file views,
// which must happen before guest RAM is committed; kernel_copy() copies the
// remaining segments once RAM is usable.
//
// --map-kernel saves memory (untouched kernel pages are never copied, and
// read-only ones stay shared across VMs: with pre-patched return sites the
// guest writes only ~120 of ~800 text pages) but is slower on WHP today:
// populating file-backed pages costs more than anonymous ones.
//
// Without --map-kernel but with a working set, the read-only parts the guest
// doesn't touch (64 KiB chunks with no working-set page: the 2 MiB of int3
// padding before the main text, cold code) become file views too: shared
// with every VM and never faulted in, instead of a private copy each.
constexpr size_t MAX_COLD_VIEWS = 16;
typedef struct {
    os_file f;
    elf_info info;
    bool mapped[ELF_MAX_SEGMENTS];
    uint64_t mapped_bytes;
    struct {
        uint64_t gpa, len;
    } cold[MAX_COLD_VIEWS];
    size_t ncold;
} kernel_image;

static bool ws_has_page_in(const range_list *l, uint64_t gpa, uint64_t len)
{
    for (size_t i = 0; i < l->n; i++)
        if (l->r[i].gpa < gpa + len && gpa < l->r[i].gpa + l->r[i].size)
            return true;
    return false;
}

static void map_cold(kernel_image *k, os_ram *ram, const elf_segment *s, const range_list *ws_rw,
                     const range_list *ws_ro)
{
    constexpr uint64_t C = OS_FILE_MAP_ALIGN;
    if (s->writable || (s->off - s->gpa) % C)
        return;
    const uint64_t lo = (s->gpa + C - 1) / C * C, hi = (s->gpa + s->filesz) / C * C;
    for (uint64_t c = lo; c < hi && k->ncold < MAX_COLD_VIEWS;) {
        uint64_t e = c;
        while (e < hi && !ws_has_page_in(ws_rw, e, C) && !ws_has_page_in(ws_ro, e, C))
            e += C;
        if (e - c >= 4 * C && // a view costs more than copying a few pages
            !os_ram_map_file(ram, (size_t)c, (size_t)(e - c), k->f, s->off + (c - s->gpa))) {
            k->cold[k->ncold].gpa = c;
            k->cold[k->ncold].len = e - c;
            k->ncold++;
            k->mapped_bytes += e - c;
        }
        c = e > c ? e : c + C;
    }
}

static int kernel_open(kernel_image *k, os_ram *ram, const char *path, bool map,
                       const range_list *ws_rw, const range_list *ws_ro)
{
    uint64_t fsize;
    *k = (kernel_image){0};
    if (os_file_open_ro(path, &k->f))
        return -1;
    if (os_file_size(k->f, &fsize) ||
        elf_parse(file_reader, &k->f, fsize, ram->size, X86_HIMEM_START, &k->info)) {
        os_file_close(k->f);
        return -1;
    }
    for (uint16_t i = 0; map && i < k->info.nseg; i++) {
        const elf_segment *s = &k->info.seg[i];
        // Map whole pages of file data; the partial last page is fixed up in
        // kernel_copy(). Never map past the segment's last page.
        const uint64_t len = (s->filesz + 4095) & ~(uint64_t)4095;
        bool clash = false; // another segment sharing the view's last page
        for (uint16_t j = 0; j < k->info.nseg; j++)
            clash |= j != i && k->info.seg[j].gpa < s->gpa + len &&
                     s->gpa < k->info.seg[j].gpa + k->info.seg[j].memsz;
        // Writable segments (data, bss) are copied: the guest writes nearly
        // all of them, and each written page of a file view is a slower
        // copy-on-write fault than part of one bulk read.
        if (clash || s->gpa % 4096 || s->off % OS_FILE_MAP_ALIGN || !s->filesz || s->writable)
            continue;
        if (!os_ram_map_file(ram, (size_t)s->gpa, (size_t)len, k->f, s->off)) {
            k->mapped[i] = true;
            k->mapped_bytes += len;
        }
    }
    for (uint16_t i = 0; !map && (ws_rw->n || ws_ro->n) && i < k->info.nseg; i++)
        map_cold(k, ram, &k->info.seg[i], ws_rw, ws_ro);
    return 0;
}

// The copy runs on a second thread while the main thread creates the
// partition: both take about a millisecond and don't depend on each other.
typedef struct {
    kernel_image *k; // nullptr: built-in hello guest
    guest_mem *m;
    int rc;
    uint64_t t0, t1;
} loader_job;

static int kernel_copy(kernel_image *k, guest_mem *m);

static void loader_main(void *arg)
{
    loader_job *j = arg;
    j->t0 = mvm_now_ns();
    if (j->k) {
        j->rc = kernel_copy(j->k, j->m);
    } else {
        uint8_t *dst = guest_slice(j->m, X86_HIMEM_START, sizeof HELLO_GUEST);
        if (dst)
            memcpy(dst, HELLO_GUEST, sizeof HELLO_GUEST);
        j->rc = dst ? 0 : -1;
    }
    j->t1 = mvm_now_ns();
}

static bool all_zero(const uint8_t *p, size_t n)
{
    return n == 0 || (p[0] == 0 && memcmp(p, p + 1, n - 1) == 0);
}

// Copy file data into guest RAM through a bounce buffer, skipping guest
// pages that would only receive zeros: guest RAM is already zero, and a page
// nobody writes costs the host nothing. A vmlinux is ~40% zero pages
// (alignment padding, zero-initialised page tables and buffers in .data).
static int copy_sparse(os_file f, uint8_t *dst, uint64_t len, uint64_t off, uint8_t *buf,
                       size_t bufsz)
{
    for (uint64_t done = 0; done < len;) {
        const size_t n = (size_t)(len - done < bufsz ? len - done : bufsz);
        if (os_file_pread(f, buf, n, off + done))
            return -1;
        for (size_t p = 0; p < n;) {
            // Chunks follow guest page boundaries, not file offsets.
            const size_t to_page = 4096 - (size_t)((uintptr_t)(dst + done + p) & 4095);
            const size_t c = to_page < n - p ? to_page : n - p;
            if (!all_zero(buf + p, c))
                memcpy(dst + done + p, buf + p, c);
            p += c;
        }
        done += n;
    }
    return 0;
}

static int kernel_copy(kernel_image *k, guest_mem *m)
{
    constexpr size_t BOUNCE = 256u << 10;
    uint8_t *buf = nullptr;
    int rc = 0;
    for (uint16_t i = 0; !rc && i < k->info.nseg; i++) {
        const elf_segment *s = &k->info.seg[i];
        uint8_t *dst = guest_slice(m, s->gpa, s->memsz);
        if (!dst) {
            rc = -1;
        } else if (k->mapped[i]) {
            // The view's last page continues with whatever follows in the
            // file; guest RAM must hold zeros there (bss), as after a copy.
            const uint64_t page_end = (s->filesz + 4095) & ~(uint64_t)4095;
            memset(dst + s->filesz, 0, (size_t)(page_end - s->filesz));
        } else if (s->filesz) {
            if (!buf && !(buf = malloc(BOUNCE))) {
                rc = -1;
                break;
            }
            // Copy around the cold views (kept in address order).
            uint64_t at = s->gpa;
            const uint64_t end = s->gpa + s->filesz;
            for (size_t c = 0; !rc && c <= k->ncold; c++) {
                uint64_t to = end, skip = end;
                if (c < k->ncold) {
                    if (k->cold[c].gpa < at || k->cold[c].gpa >= end)
                        continue;
                    to = k->cold[c].gpa;
                    skip = to + k->cold[c].len;
                }
                if (to > at)
                    rc = copy_sparse(k->f, dst + (at - s->gpa), to - at, s->off + (at - s->gpa),
                                     buf, BOUNCE);
                at = skip;
            }
        }
    }
    free(buf); // large enough to come straight from (and go back to) the OS
    os_file_close(k->f);
    return rc;
}

// Device I/O threads and the threads of vCPUs 1.., started inside the
// sandbox's Landlock domain, before seccomp (which refuses new threads).
typedef struct {
    vsock *vs;
    net *nd;
    vm *v;
} devices;

static void start_devices(void *ctx)
{
    const devices *d = ctx;
    if (d->vs && vsock_start(d->vs))
        mvm_die("cannot start the vsock I/O thread");
    if (d->nd && net_start(d->nd))
        mvm_die("cannot start the network I/O thread");
    if (d->v->ncpus > 1 && vm_start_cpus(d->v))
        mvm_die("cannot start the vCPU threads");
}

int main(int argc, char **argv)
{
    static vm v; // zero-initialized, off the stack
    v.t_start = mvm_now_ns();
    struct timespec t0;
    if (timespec_get(&t0, TIME_UTC) == TIME_UTC)
        v.start_unix_us = (int64_t)t0.tv_sec * 1000000 + t0.tv_nsec / 1000;

    const char *kernel = nullptr, *cmdline = DEFAULT_CMDLINE, *append = nullptr;
    bool hello = false, quiet = false, timestamps = false, map_kernel = false, serial_load = false;
    bool sandbox = true;
    const char *profile = nullptr;
    uint32_t profile_us = 50;
    uint64_t prefault_mib = 0;
    const char *ws_record = nullptr, *ws_replay = nullptr, *dump_mem = nullptr;
    uint64_t mem_mib = 64;
    uint32_t cpus = 0; // --cpus; 0: not given
    const char *rootfs = nullptr, *vsock_path = nullptr; // rootfs: the first layer, if any
    const char *layer_path[X86_PMEM_MAX];
    uint32_t nlayers = 0;
    const char *snapshot = nullptr, *restore = nullptr, *base = nullptr;
    bool snapshot_diff = false;
    bool net_on = false, balloon_on = false;
    int net_fd = -1;
    bool net_policy_set = false;
    static net_policy npol;
    const char *stats_path = nullptr;
    hv_cpuid_hide cpuid_hide[HV_CPUID_HIDE_MAX];
    size_t n_cpuid_hide = 0;
    int cmd_at = argc; // argv[cmd_at..]: the command to run in the rootfs
    // --env-file and -e/--env values, in order (files go first: env_file).
    const char **env_files = calloc((size_t)argc, sizeof *env_files);
    const char **env_strs = calloc((size_t)argc, sizeof *env_strs);
    size_t n_env_files = 0, n_env_strs = 0;
    if (!env_files || !env_strs)
        mvm_die("out of memory");
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--")) {
            cmd_at = i + 1;
            break;
        }
        if (!strcmp(a, "--version")) {
            printf("microvm %s\n", MICROVM_VERSION);
            return 0;
        }
        const bool has_val = i + 1 < argc;
        if (!strcmp(a, "--kernel") && has_val) kernel = argv[++i];
        else if (!strcmp(a, "--hello")) hello = true;
        else if (!strcmp(a, "--mem") && has_val) mem_mib = strtoull(argv[++i], nullptr, 10);
        else if (!strcmp(a, "--cpus") && has_val) {
            char *end;
            const unsigned long n = strtoul(argv[++i], &end, 10);
            if (*end || n < 1 || n > MVM_MAX_VCPUS)
                mvm_die("--cpus must be between 1 and %u", MVM_MAX_VCPUS);
            cpus = (uint32_t)n;
        }
        else if (!strcmp(a, "--rootfs") && has_val) {
            if (nlayers == X86_PMEM_MAX)
                mvm_die("at most %u --rootfs layers", X86_PMEM_MAX);
            layer_path[nlayers++] = argv[++i];
            rootfs = layer_path[0];
        }
        else if (!strcmp(a, "--vsock") && has_val) vsock_path = argv[++i];
        else if (!strcmp(a, "--net")) net_on = true;
        else if (!strcmp(a, "--balloon")) balloon_on = true;
        else if (!strcmp(a, "--net-fd") && has_val) {
            char *end;
            const long fd = strtol(argv[++i], &end, 10);
            if (*end || end == argv[i] || fd < 3 || fd > 1023 || net_helper_check_fd((int)fd))
                mvm_die("--net-fd '%s': not an open helper channel (a SOCK_SEQPACKET socket, fd 3 or more)",
                        argv[i]);
            net_on = true, net_fd = (int)fd;
        } else if (!strcmp(a, "--net-allow") && has_val) {
            net_policy_set = true;
            if (net_policy_allow(&npol, argv[++i]))
                mvm_die("--net-allow '%s': not ADDR[/BITS][,PORT], or more than %d", argv[i], NET_MAX_ALLOW);
        } else if (!strcmp(a, "--net-deny-all")) {
            net_policy_set = true;
            npol.deny_all = true;
        } else if (!strcmp(a, "--net-only")) {
            net_policy_set = true;
            npol.allow_only = true;
        } else if (!strcmp(a, "--net-dns") && has_val) {
            net_policy_set = true;
            if (net_policy_dns(&npol, argv[++i]))
                mvm_die("--net-dns '%s': not an address, or more than %d", argv[i], NET_MAX_DNS);
        } else if (!strcmp(a, "--net-deny-port") && has_val) {
            net_policy_set = true;
            if (net_policy_deny_port(&npol, argv[++i]))
                mvm_die("--net-deny-port '%s': not a port, or more than %d", argv[i], NET_MAX_DENY_PORTS);
        } else if ((!strcmp(a, "--net-flow-rate") || !strcmp(a, "--net-max-dests")) && has_val) {
            net_policy_set = true;
            const bool rate = a[6] == 'f';
            uint64_t num;
            if (net_policy_number(argv[++i], rate ? 1000000 : NET_MAX_DESTS, &num))
                mvm_die("%s '%s': not a number from 1 to %u", a, argv[i], rate ? 1000000u : NET_MAX_DESTS);
            *(rate ? &npol.flow_rate : &npol.max_dests) = (uint32_t)num;
        } else if (!strcmp(a, "--net-tx-rate") && has_val) {
            // The device's cap, and its own helper's pacing (with --net-fd,
            // the jail's helper paces its sockets).
            if (net_policy_number(argv[++i], NET_MAX_TX_RATE, &npol.tx_rate))
                mvm_die("--net-tx-rate '%s': not a number of bytes from 1 to %llu", argv[i],
                        (unsigned long long)NET_MAX_TX_RATE);
        } else if (!strcmp(a, "--stats") && has_val) {
            stats_path = argv[++i];
        }
        else if ((!strcmp(a, "--env") || !strcmp(a, "-e")) && has_val) env_strs[n_env_strs++] = argv[++i];
        else if (!strcmp(a, "--env-file") && has_val) env_files[n_env_files++] = argv[++i];
        else if (!strcmp(a, "--snapshot") && has_val) snapshot = argv[++i];
        else if (!strcmp(a, "--restore") && has_val) restore = argv[++i];
        else if (!strcmp(a, "--base") && has_val) base = argv[++i];
        else if (!strcmp(a, "--snapshot-diff")) snapshot_diff = true;
        else if (!strcmp(a, "--cmdline") && has_val) cmdline = argv[++i];
        else if (!strcmp(a, "--append") && has_val) append = argv[++i];
        else if (!strcmp(a, "--quiet")) quiet = true;
        else if (!strcmp(a, "--map-kernel")) map_kernel = true;
        else if (!strcmp(a, "--cpuid-hide") && has_val) {
            const char *val = argv[++i];
            if (n_cpuid_hide == HV_CPUID_HIDE_MAX || !parse_cpuid_hide(val, &cpuid_hide[n_cpuid_hide]))
                mvm_die("--cpuid-hide '%s': not LEAF[.SUBLEAF]:REG:MASK (REG eax..edx), or more than %d",
                        val, (int)HV_CPUID_HIDE_MAX);
            n_cpuid_hide++;
        }
        else if (!strcmp(a, "--serial-load")) serial_load = true;
        else if (!strcmp(a, "--no-sandbox")) sandbox = false;
        else if (!strcmp(a, "--trace")) v.trace = true;
        else if (!strcmp(a, "--timestamps")) timestamps = true;
        else if (!strcmp(a, "--profile") && has_val) profile = argv[++i];
        else if (!strcmp(a, "--ws-record") && has_val) ws_record = argv[++i];
        else if (!strcmp(a, "--dump-mem") && has_val) dump_mem = argv[++i];
        else if (!strcmp(a, "--ws") && has_val) ws_replay = argv[++i];
        else if (!strcmp(a, "--prefault") && has_val)
            prefault_mib = strtoull(argv[++i], nullptr, 10);
        else if (!strcmp(a, "--profile-us") && has_val)
            profile_us = (uint32_t)strtoul(argv[++i], nullptr, 10);
        else usage();
    }
    if (!!kernel + hello + !!restore != 1 || (rootfs && hello) || (vsock_path && hello) || (net_on && hello) ||
        (balloon_on && hello) ||
        (restore ? cmd_at < argc || prefault_mib : cmd_at < argc && !rootfs) || (base && !restore) ||
        (snapshot_diff && !snapshot))
        usage();
    // The environment: read now (the files, the host's variables), served
    // to /init from memory (vm.c), with its length in front.
    static env_blob envb;
    if (n_env_files + n_env_strs) {
        if (!rootfs || restore)
            mvm_die("--env and --env-file need --rootfs, and don't apply to --restore (the snapshot's "
                    "command has its environment: give an invocation's with microvm-invoke --env)");
        if (!(envb.b = malloc(envb.cap = 4096)))
            mvm_die("out of memory");
        envb.len = 4; // the length goes first
        for (size_t k = 0; k < n_env_files; k++)
            env_file(&envb, env_files[k]);
        for (size_t k = 0; k < n_env_strs; k++)
            env_add(&envb, env_strs[k], strlen(env_strs[k]));
        put_le32(envb.b, (uint32_t)(envb.len - 4));
        v.env = envb.b, v.env_len = (uint32_t)envb.len;
    }
    free(env_files);
    free(env_strs);
    // With --net-fd the policy is the running helper's (microvm-jail's
    // --net-allow and --net-dns): one given here would be ignored.
    if (net_fd >= 0 && net_policy_set)
        mvm_die("--net-allow, --net-dns and the network limits don't apply with --net-fd: the helper on the fd "
                "has its policy");
    if (stats_path && !net_on)
        mvm_die("--stats needs --net");
    // The network helper: forked now, while this process is small and has
    // one thread. It holds the only sockets that reach out (net_helper.h).
    if (net_on && net_fd < 0 && (net_fd = net_helper_start(&npol)) < 0)
        mvm_die("cannot start the network helper");
    // A snapshot: its header and state now, its RAM in step 1.
    // A diff: its base's header, and its runs.
    static snap_header sh, bh;
    os_file snap_in = {0}, base_in = {0};
    uint8_t *snap_state = nullptr;
    snap_run *runs = nullptr;
    if (restore) {
        static uint8_t page[4096];
        uint64_t fsize = 0;
        if (os_file_open_ro(restore, &snap_in) || os_file_size(snap_in, &fsize) || fsize < sizeof page ||
            os_file_pread(snap_in, page, sizeof page, 0) || snap_header_decode(page, fsize, &sh))
            mvm_die("'%s' is not a snapshot this VMM can restore", restore);
        mem_mib = sh.mem_size / MiB;
        if (!(snap_state = malloc(sh.state_len ? sh.state_len : 1)) ||
            os_file_pread(snap_in, snap_state, sh.state_len, SNAP_STATE_OFF))
            mvm_die("cannot read '%s'", restore);
        if (sh.diff) {
            uint64_t bsize = 0;
            if (!base)
                mvm_die("'%s' is a diff: give the snapshot it was saved against (--base)", restore);
            if (os_file_open_ro(base, &base_in) || os_file_size(base_in, &bsize) || bsize < sizeof page ||
                os_file_pread(base_in, page, sizeof page, 0) || snap_header_decode(page, bsize, &bh) ||
                bh.diff)
                mvm_die("'%s' is not a full snapshot this VMM can restore", base);
            if (memcmp(bh.id, sh.base_id, sizeof bh.id) || bh.mem_size != sh.mem_size)
                mvm_die("'%s' is not the snapshot '%s' was saved against", base, restore);
            uint8_t *enc = malloc(8ull * sh.nruns);
            if (!enc || !(runs = malloc(sh.nruns * sizeof *runs)) ||
                os_file_pread(snap_in, enc, 8ull * sh.nruns, sh.runs_off) ||
                snap_runs_decode(enc, &sh, fsize, runs))
                mvm_die("'%s' is not a snapshot this VMM can restore", restore);
            free(enc);
        }
    }
    if (restore && cpus && cpus != sh.ncpus)
        mvm_die("the snapshot has %u vCPUs: --cpus can't change that", sh.ncpus);
    v.ncpus = restore ? sh.ncpus : cpus ? cpus : 1;
    if (v.ncpus > hv_max_vcpus())
        mvm_die("this hypervisor (%s) runs at most %u vCPUs here", hv_name(), hv_max_vcpus());
    if (v.ncpus > 1 && hello)
        mvm_die("--hello runs one vCPU");
    const uint64_t min_mib = hello ? 2 : 32;
    if (mem_mib < min_mib || mem_mib > 3072)
        mvm_die("--mem must be between %llu and 3072 MiB", (unsigned long long)min_mib);

    // 1. guest RAM: reserved, never pre-faulted. Kernel segments may become
    //    copy-on-write file views before the rest is committed.
    static os_ram ram;
    if (os_ram_reserve(&ram, (size_t)(mem_mib * MiB)))
        mvm_die("cannot reserve %llu MiB of guest memory", (unsigned long long)mem_mib);
    v.mem = (guest_mem){.base = ram.base, .size = ram.size};
    // The working set to replay (none while recording one): it also decides
    // which read-only kernel chunks need no private copy.
    range_list ws_rw = {0}, ws_ro = {0}, ws_pm = {0}, now = {0};
    if (ws_record)
        ws_replay = nullptr;
    if (ws_load(ws_replay, v.mem.size, &ws_rw, &ws_ro, &ws_pm))
        mvm_die("cannot read working set '%s'", ws_replay);
    static kernel_image kimg;
    // Restored RAM is the snapshot file itself, copy-on-write: shared with
    // every VM restored from it until written.
    // A diff: its base, then its pages over it.
    if (restore && !sh.diff && os_ram_map_file(&ram, 0, ram.size, snap_in, sh.mem_off))
        mvm_die("cannot map '%s' as guest memory", restore);
    if (restore && sh.diff) {
        if (os_ram_map_file(&ram, 0, ram.size, base_in, bh.mem_off))
            mvm_die("cannot map '%s' as guest memory", base);
        if (!(v.from_diff = os_mem_reserve(ram.size / 4096)))
            mvm_die("out of memory");
        for (uint32_t i = 0; i < sh.nruns; i++) {
            const size_t off = (size_t)runs[i].first * 4096, len = (size_t)runs[i].count * 4096;
            if (os_ram_overlay_file(&ram, off, len, snap_in, sh.mem_off + off))
                mvm_die("cannot map '%s' as guest memory", restore);
            memset(v.from_diff + runs[i].first, 1, runs[i].count);
        }
        free(runs);
        os_file_close(base_in); // the mapping keeps the file
    }
    if (restore)
        memcpy(v.base_id, sh.diff ? sh.base_id : sh.id, sizeof v.base_id);
    if (kernel && kernel_open(&kimg, &ram, kernel, map_kernel, &ws_rw, &ws_ro))
        mvm_die("cannot load '%s': not an x86-64 vmlinux, or doesn't fit in %llu MiB", kernel,
                (unsigned long long)mem_mib);
    if (os_ram_commit(&ram))
        mvm_die("cannot commit %llu MiB of guest memory", (unsigned long long)mem_mib);
    v.mapped_bytes = kernel ? kimg.mapped_bytes : 0;
    v.t_mem = mvm_now_ns();

    // 2. copy the guest in on a second thread, overlapping steps 3-5
    loader_job job = {.k = kernel ? &kimg : nullptr, .m = &v.mem};
    os_thread loader;
    const bool threaded = !restore && !serial_load && os_thread_run(&loader, loader_main, &job) == 0;
    if (!threaded && !restore)
        loader_main(&job);

    // 3. VM + memory
    hv_set_cpuid_hide(cpuid_hide, n_cpuid_hide);
    const int hv_rc = hv_vm_create(&v.hv);
    if (hv_rc == HV_UNAVAILABLE) {
        mvm_log("microvm: no usable hypervisor (%s) on this host", hv_name());
        if (threaded) // exit() must not race the loader (it deadlocked under ASan)
            os_thread_join(loader);
        return MVM_EXIT_NO_HV;
    }
    if (hv_rc)
        mvm_die("failed to create VM (%s)", hv_name());
    // With a recorded working set, only its pages (and any --prefault range)
    // are mapped before the guest starts: WHP's mapping cost is per page
    // and serialized, so the rest is mapped while the guest boots.
    // Recording a working set maps pages as the guest touches them, where
    // the backend can: nothing is prefaulted then.
    uint8_t *touched = ws_record ? calloc(v.mem.size / 4096, 1) : nullptr;
    if (ws_record && !touched)
        mvm_die("out of memory");
    int traced = touched ? hv_vm_map_mem_traced(v.hv, 0, v.mem.base, v.mem.size, touched)
                         : HV_UNAVAILABLE;
    if (traced != HV_UNAVAILABLE && traced)
        mvm_die("failed to map guest memory");
    if (!traced) {
        prefault_mib = 0;
    } else {
        free(touched);
        touched = nullptr;
    }
    bool now_ok = true;
    for (size_t i = 0; now_ok && i < ws_rw.n; i++)
        now_ok = range_push(&now, ws_rw.r[i]);
    for (size_t i = 0; now_ok && i < ws_ro.n; i++)
        now_ok = range_push(&now, ws_ro.r[i]);
    if (now_ok && now.n && prefault_mib)
        now_ok = range_push(&now, (hv_range){0, (prefault_mib < mem_mib ? prefault_mib : mem_mib) * MiB});
    if (!now_ok || (traced && hv_vm_map_mem_split(v.hv, 0, v.mem.base, v.mem.size, now.r, now.n)))
        mvm_die("failed to map guest memory");
    v.touched = touched;
    free(now.r);
    // The root filesystem: the image files themselves, read-only and shared
    // with every VM through the host page cache. The guest sees persistent
    // memory: one range per layer (x86_pmem_layout), mapped from one host
    // reservation, so the working-set code sees one span.
    os_file layer_f[X86_PMEM_MAX];
    uint64_t layer_size[X86_PMEM_MAX] = {0}, layer_gpa[X86_PMEM_MAX] = {0}, layer_off[X86_PMEM_MAX];
    void *rootfs_p = nullptr;
    uint64_t rootfs_size = 0; // the span: from X86_PMEM_GPA to the end of the last layer
    for (uint32_t i = 0; i < nlayers; i++) {
        if (os_file_open_ro(layer_path[i], &layer_f[i]) || os_file_size(layer_f[i], &layer_size[i]))
            mvm_die("cannot open '%s'", layer_path[i]);
        if (!layer_size[i] || layer_size[i] % 4096 || layer_size[i] > X86_PMEM_SPAN_MAX)
            mvm_die("'%s': a root filesystem image is a nonzero multiple of 4 KiB, at most 64 GiB",
                    layer_path[i]);
    }
    if (nlayers) {
        if (x86_pmem_layout(nlayers, layer_size, layer_gpa, &rootfs_size))
            mvm_die("the --rootfs layers take more than 64 GiB together");
        for (uint32_t i = 0; i < nlayers; i++)
            layer_off[i] = layer_gpa[i] - X86_PMEM_GPA;
        if (os_files_map_ro(layer_f, layer_size, layer_off, nlayers, rootfs_size, &rootfs_p))
            mvm_die("cannot map the --rootfs images (more than one needs Linux)");
        for (uint32_t i = 0; i < nlayers; i++)
            if (hv_vm_map_mem_ro(v.hv, layer_gpa[i], (uint8_t *)rootfs_p + layer_off[i], layer_size[i]))
                mvm_die("cannot map '%s' into the guest", layer_path[i]);
    }
    if (restore) {
        // Before layers, a snapshot recorded one image's size.
        const uint32_t sn = sh.nlayers ? sh.nlayers : sh.rootfs_size ? 1 : 0;
        bool same = sn == nlayers;
        for (uint32_t i = 0; same && i < sn; i++)
            same = layer_size[i] == (sh.nlayers ? sh.layer_size[i] : sh.rootfs_size);
        if (!same)
            mvm_die("the snapshot was taken with %u root filesystem layer%s of other sizes: give the same "
                    "--rootfs images, in the same order",
                    sn, sn == 1 ? "" : "s");
    }
    v.rootfs_size = rootfs_size;
    v.nlayers = nlayers;
    memcpy(v.layer_size, layer_size, sizeof v.layer_size);
    v.t_vm = mvm_now_ns();

    // 4. vCPUs
    const hv_handlers handlers = {.opaque = &v, .pio = vm_pio, .mmio = vm_mmio,
                                 .mmio_queued = vm_mmio_queued, .msr = vm_msr};
    for (uint32_t i = 0; i < v.ncpus; i++)
        if (hv_vcpu_create(v.hv, i, &handlers, &v.vcpus[i]) || hv_vcpu_setup_cpuid(v.vcpus[i]))
            mvm_die("failed to create vCPU %u", i);
    v.vcpu = v.vcpus[0];
    hv_info hinfo;
    hv_get_info(v.hv, v.vcpu, &hinfo);
    v.tsc_khz = hinfo.tsc_khz;
    if (restore && (sh.cpuid_hash != hv_vcpu_cpuid_hash(v.vcpu) || sh.tsc_khz != hinfo.tsc_khz))
        mvm_die("the snapshot was taken on another CPU model or TSC rate");
    // Devices with interrupts: the I/O APIC routes them to the local APIC.
    ioapic_init(&v.ioapic, (uint8_t)v.ncpus /* after the local APICs */, vm_send_msi, v.hv);
    vsock *vs = nullptr;
    if (vsock_path) {
        vs = vsock_create(vsock_path, &v.mem, &v.ioapic, VIRTIO_IRQ_FIRST + (unsigned)v.nvirtio);
        if (!vs)
            mvm_die("cannot create the vsock device");
        v.virtio[v.nvirtio++] = vsock_dev(vs);
        const int rc = hv_vm_doorbell(v.hv, VIRTIO_MMIO_BASE + (uint64_t)(v.nvirtio - 1) * VIRTIO_MMIO_SIZE +
                                                VIRTIO_MMIO_QUEUE_NOTIFY, 4, vsock_doorbell_fd(vs));
        if (rc && rc != HV_UNAVAILABLE)
            mvm_die("cannot set up the vsock device");
    }
    net *nd = nullptr;
    if (net_on) {
        nd = v.nvirtio < VIRTIO_MAX_DEVICES
                 ? net_create(net_helper_open, (void *)(intptr_t)net_fd, &v.mem, &v.ioapic,
                              VIRTIO_IRQ_FIRST + (unsigned)v.nvirtio)
                 : nullptr;
        if (!nd)
            mvm_die("cannot create the network device");
        net_set_tx_rate(nd, npol.tx_rate);
        if (stats_path) {
            os_file sf;
            if (os_file_create(stats_path, &sf))
                mvm_die("--stats: cannot create '%s'", stats_path);
            net_set_stats_fd(nd, sf.h);
        }
        v.virtio[v.nvirtio++] = net_dev(nd);
        const int rc = hv_vm_doorbell(v.hv, VIRTIO_MMIO_BASE + (uint64_t)(v.nvirtio - 1) * VIRTIO_MMIO_SIZE +
                                                VIRTIO_MMIO_QUEUE_NOTIFY, 4, net_doorbell_fd(nd));
        if (rc && rc != HV_UNAVAILABLE)
            mvm_die("cannot set up the network device");
    }
    // Last, so the other devices keep their slots with or without it.
    if (balloon_on) {
        balloon *bd = v.nvirtio < VIRTIO_MAX_DEVICES
                          ? balloon_create(&v.mem, &v.ioapic, VIRTIO_IRQ_FIRST + (unsigned)v.nvirtio)
                          : nullptr;
        if (!bd)
            mvm_die("cannot create the balloon device");
        v.balloon = bd;
        v.virtio[v.nvirtio++] = balloon_dev(bd);
    }
    // Interrupt acknowledgements needn't exit: the device applies them
    // when the vCPU next exits (virtio_mmio.c explains why that's safe).
    for (int i = 0; i < v.nvirtio; i++) {
        const int rc = hv_vm_queue_writes(v.hv, VIRTIO_MMIO_BASE + (uint64_t)i * VIRTIO_MMIO_SIZE +
                                                    VIRTIO_MMIO_INT_ACK, 4);
        if (rc && rc != HV_UNAVAILABLE)
            mvm_die("cannot set up the virtio devices");
    }
    if (restore) {
        bool same = sh.ndev == (uint32_t)v.nvirtio;
        for (int i = 0; same && i < v.nvirtio; i++)
            same = sh.dev_id[i] == v.virtio[i]->ops->device_id;
        if (!same)
            mvm_die("the snapshot has other devices (%u virtio, first id %u): give the same "
                    "--vsock, --net and --balloon as when it was taken", sh.ndev, sh.ndev ? sh.dev_id[0] : 0);
    }
    v.t_vcpu = mvm_now_ns();

    // 5. populate second-level page tables for the recorded working set in
    //    one batch. (Populating the kernel's pages before copying it in was
    //    measured too: slower, the copy cost is ReadFile itself.)
    if (prefault_mib) {
        const hv_range r = {0, (prefault_mib < mem_mib ? prefault_mib : mem_mib) * MiB};
        if (hv_vcpu_prefault(v.vcpu, &r, 1, true))
            mvm_die("prefault failed");
    }
    if (ws_prefault(&v, &ws_rw, &ws_ro, &ws_pm, nlayers, layer_gpa, layer_size))
        mvm_die("cannot replay working set '%s'", ws_replay ? ws_replay : "");
    v.t_prefault = mvm_now_ns();

    if (threaded)
        os_thread_join(loader);
    if (job.rc)
        mvm_die("cannot read '%s'", kernel ? kernel : "hello guest");
    const uint64_t entry = kernel ? kimg.info.entry : X86_HIMEM_START;
    if (os_random(v.seed, sizeof v.seed))
        mvm_die("no randomness from the OS");
    v.t_load_begin = job.t0;
    v.t_load_end = job.t1;
    v.t_load = mvm_now_ns();

    // 6. boot structures + initial register state, or the snapshot's state
    uart_init(&v.com1);
    if (restore) {
        if (vm_restore(&v, snap_state, sh.state_len))
            mvm_die("cannot restore '%s': its state doesn't fit this VM", restore);
        free(snap_state);
        os_file_close(snap_in); // the RAM mapping keeps the file
    } else {
    char cl[X86_CMDLINE_MAX];
    // "quiet" goes first: early params are parsed in order, and an early
    // console registered before it would replay the whole log so far.
    // printk_drop_suppressed (patch 0028) skips formatting the messages
    // "quiet" hides: ~0.1 ms of boot.
    int n = snprintf(cl, sizeof cl, "%s%s", quiet ? "quiet printk_drop_suppressed " : "",
                     cmdline);
    if (hinfo.tsc_khz && n > 0 && (size_t)n < sizeof cl)
        n += snprintf(cl + n, sizeof cl - (size_t)n, " tsc_early_khz=%llu",
                      (unsigned long long)hinfo.tsc_khz);
    // The wall clock, so the guest needn't read the CMOS RTC (~22 exits),
    // with kernel patch 0012. A stock kernel hands it to init as a variable.
    struct timespec wall;
    if (kernel && timespec_get(&wall, TIME_UTC) == TIME_UTC && n > 0 && (size_t)n < sizeof cl)
        n += snprintf(cl + n, sizeof cl - (size_t)n, " wallclock=%lld.%09ld",
                      (long long)wall.tv_sec, (long)wall.tv_nsec);
    uint32_t irq_pins = 0;
    for (int i = 0; i < v.nvirtio && n > 0 && (size_t)n + 1 < sizeof cl; i++) {
        cl[n++] = ' ';
        n += virtio_cmdline(cl + n, sizeof cl - (size_t)n, i);
        irq_pins |= 1u << (VIRTIO_IRQ_FIRST + (unsigned)i);
    }
    // Free page reporting in blocks of 2^ORDER pages (the kernel's default
    // is 2 MiB, 9): see BALLOON_REPORT_ORDER.
    if (v.balloon && n > 0 && (size_t)n < sizeof cl)
        n += snprintf(cl + n, sizeof cl - (size_t)n, " page_reporting.page_reporting_order=%d",
                      BALLOON_REPORT_ORDER);
    if (nd && n > 0 && (size_t)n + 1 < sizeof cl) { // the guest's static address
        cl[n++] = ' ';
        n += net_cmdline(cl + n, sizeof cl - (size_t)n);
    }
    if (append && n > 0 && (size_t)n < sizeof cl)
        n += snprintf(cl + n, sizeof cl - (size_t)n, " %s", append);
    // Words after "--" are /init's arguments: "run COMMAND...". The kernel
    // splits on spaces and strips double quotes, so each word is quoted and
    // may not contain a double quote or a control character itself.
    // "env": /init reads --env from port 0x707 first.
    // "layersN": the image is in N layers (/init stacks /dev/pmem0..N-1).
    char lw[24] = "";
    if (nlayers > 1)
        snprintf(lw, sizeof lw, " layers%u", nlayers);
    if (rootfs && n > 0 && (size_t)n < sizeof cl)
        n += snprintf(cl + n, sizeof cl - (size_t)n, " --%s%s run", lw, v.env ? " env" : "");
    for (int i = cmd_at; rootfs && i < argc && n > 0 && (size_t)n < sizeof cl; i++) {
        for (const char *c = argv[i]; *c; c++)
            if (*c == '"' || (unsigned char)*c < 0x20 || *c == 0x7f)
                mvm_die("command words may not contain '\"' or control characters");
        n += snprintf(cl + n, sizeof cl - (size_t)n, " \"%s\"", argv[i]);
    }
    if (n < 0 || (size_t)n >= sizeof cl)
        mvm_die("kernel command line too long (max %llu bytes)",
                (unsigned long long)X86_CMDLINE_MAX - 1);

    x86_boot_cfg cfg = {.cmdline = cl, .entry = entry, .npmem = nlayers, .ncpus = v.ncpus, .irq_pins = irq_pins};
    memcpy(cfg.pmem_gpa, layer_gpa, sizeof cfg.pmem_gpa);
    memcpy(cfg.pmem_size, layer_size, sizeof cfg.pmem_size);
    hv_regs regs;
    hv_sregs sregs;
    if (x86_setup_boot(&v.mem, &cfg, &regs, &sregs) || hv_vcpu_set_state(v.vcpu, &regs, &sregs))
        mvm_die("failed to set up boot state");
    }
    if (timestamps)
        v.com1.ts_base = v.t_start;
    v.t_boot = mvm_now_ns();

    // 7. sandbox: open everything the rest of the run needs, then give up
    //    the right to open anything else (see sandbox.h).
    FILE *ws_out = ws_record ? fopen(ws_record, "w") : nullptr;
    FILE *prof_out = profile ? fopen(profile, "w") : nullptr;
    FILE *dump_out = dump_mem ? fopen(dump_mem, "wb") : nullptr;
    if ((ws_record && !ws_out) || (profile && !prof_out))
        mvm_die("cannot open '%s' for writing", ws_record && !ws_out ? ws_record : profile);
    if (dump_mem && !dump_out)
        mvm_die("cannot open '%s' for writing", dump_mem);
    if (snapshot) {
        for (uint32_t i = 0; i < v.ncpus; i++)
            if (hv_vcpu_save_prepare(v.vcpus[i]))
                mvm_die("--snapshot: this hypervisor (%s) can't save a VM", hv_name());
        if (os_file_create(snapshot, &v.snap_f))
            mvm_die("cannot open '%s' for writing", snapshot);
        v.snap_on = true;
        // A diff needs pagemap; its map is reserved now, touched only when
        // saving.
        if (snapshot_diff && restore) {
            v.snap_diff = true;
            if (!(v.snap_map = os_mem_reserve(v.mem.size / 4096)))
                mvm_die("out of memory");
            os_mem_resident_prepare();
        }
    }
    // Give the files their buffers now: stdio would otherwise fstat() them
    // on first write, and some glibc versions do that with newfstatat() - a
    // path-based call the sandbox forbids.
    static char ws_buf[16384], prof_buf[16384];
    if ((ws_out && setvbuf(ws_out, ws_buf, _IOFBF, sizeof ws_buf)) ||
        (prof_out && setvbuf(prof_out, prof_buf, _IOFBF, sizeof prof_buf)))
        mvm_die("setvbuf failed");
    if (v.trace || ws_record)
        os_mem_resident_prepare();
    if (profile && vm_profile_start(&v, profile_us, 1u << 20))
        mvm_die("failed to start profiler");
    static devices devs;
    devs = (devices){vs, nd, &v};
    const bool threads = vs || nd || v.ncpus > 1;
    if (sandbox) {
        constexpr size_t MAX_IOCTLS = 16 * MVM_MAX_VCPUS;
        static int fds[MAX_IOCTLS];
        static unsigned long reqs[MAX_IOCTLS];
        static sandbox_ioctl allow[MAX_IOCTLS];
        size_t nio = 0;
        for (uint32_t c = 0; c < v.ncpus; c++) {
            nio += hv_runtime_ioctls(v.vcpus[c], fds + nio, reqs + nio, MAX_IOCTLS - nio);
            if (snapshot)
                nio += hv_save_ioctls(v.vcpus[c], fds + nio, reqs + nio, MAX_IOCTLS - nio);
        }
        for (size_t i = 0; i < nio; i++)
            allow[i] = (sandbox_ioctl){fds[i], reqs[i]};
        // Headroom for the rest of the run: trace/working-set buffers and
        // the profiler's sample array are allocated already or are small.
        const sandbox_cfg sc = {.ioctls = allow,
                                .nioctls = nio,
                                .mem_headroom = 64 * MiB,
                                .device_io = vs || nd,
                                .accept_fd = vs ? vsock_listen_fd(vs) : -1,
                                .recvmsg_fd = nd ? net_fd : 0,
                                .nofile = 64 + vsock_max_fds() + (nd ? net_max_fds() : 0),
                                .start_threads = threads ? start_devices : nullptr,
                                .ctx = &devs};
        char report[160] = "";
        if (sandbox_enter(&sc, report, sizeof report))
            mvm_die("cannot sandbox the VMM: %s (--no-sandbox to run without)",
                    report[0] ? report : "a sandbox layer failed");
        if (v.trace)
            mvm_log("%s", report);
    }
    else if (threads)
        start_devices(&devs);
    v.t_sandbox = mvm_now_ns();

    // 8. run
    int status = vm_run(&v);
    if (prof_out && vm_profile_write(&v, prof_out))
        mvm_die("failed to write profile to '%s'", profile);
    // Unbuffered, straight from guest RAM: a buffered stream would fstat()
    // on first write (see setvbuf above).
    if (dump_out && (setvbuf(dump_out, nullptr, _IONBF, 0) ||
                     fwrite(v.mem.base, 1, v.mem.size, dump_out) != v.mem.size || fclose(dump_out)))
        mvm_die("failed to write guest RAM to '%s'", dump_mem);
    if (v.trace || ws_out) {
        if (ws_measure(&v, ws_out, rootfs_p, rootfs_size))
            mvm_log("working-set measurement failed");
    }
    if (v.trace)
        vm_print_trace(&v);
    return status;
}
