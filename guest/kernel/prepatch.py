#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Do boot-time work on a vmlinux at build time (kernel patches 0019, 0021, 0026).

Static call sites: the kernel heapsorts .static_call_sites by key on every
boot. They are sorted here, and patch 0021 skips the sort when it finds the
table already in order. This needs no guess about the CPU and is always done.

Return sites: every function return in a mitigated x86 kernel is compiled as
`jmp __x86_return_thunk`, and the kernel rewrites all ~10k of them at boot
to jump to the thunk the CPU needs. That is a fifth of a microVM's boot,
and it dirties nearly every text page, so a kernel image mapped
copy-on-write into many VMs can't stay shared.

This rewrites them in the image instead, to THUNK, and records THUNK in
`prepatched_return_thunk`. At boot, patch 0019 skips the rewrite if the
kernel picked that same thunk. If it picked another (a different CPU), it
patches the sites as usual: a wrong guess costs time, never correctness.

  prepatch.py VMLINUX [THUNK|auto|none]

THUNK applies to the return sites only.

`auto` picks the thunk the kernel's default SRSO mitigation uses on this
build host's CPU: srso_alias_return_thunk on AMD family 19h (Zen 3/4),
srso_return_thunk on 17h (Zen 1/2), none elsewhere.

All other alternative patching (patch 0026) needs the VM's exact CPU
features, so it is taken from two snapshot boots instead of guessed:

  prepatch.py --alternatives VMLINUX BEFORE AFTER

See prepatch_alternatives() and tools/prepatch-alternatives.ps1.
"""
import struct
import sys


def auto_thunk():
    vendor = family = None
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                key, _, val = line.partition(":")
                key, val = key.strip(), val.strip()
                if key == "vendor_id" and vendor is None:
                    vendor = val
                elif key == "cpu family" and family is None:
                    family = int(val)
    except OSError:
        return None
    if vendor != "AuthenticAMD":
        return None
    return {0x19: "srso_alias_return_thunk", 0x17: "srso_return_thunk"}.get(family)


class Elf:
    def __init__(self, data):
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            sys.exit("prepatch: not a little-endian ELF64 file")
        self.d = data
        phoff, shoff = struct.unpack_from("<QQ", data, 0x20)
        phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", data, 0x36)
        self.loads = []
        for i in range(phnum):
            p_type, _, p_offset, p_vaddr, _, p_filesz = struct.unpack_from(
                "<IIQQQQ", data, phoff + i * phentsize)
            if p_type == 1:  # PT_LOAD
                self.loads.append((p_vaddr, p_offset, p_filesz))
        secs = [struct.unpack_from("<IIQQQQII", data, shoff + i * shentsize) for i in range(shnum)]
        symtab = next((s for s in secs if s[1] == 2), None)  # SHT_SYMTAB
        if symtab is None:
            sys.exit("prepatch: no symbol table (stripped vmlinux?)")
        strtab = secs[symtab[6]]
        self.syms, self.sizes = {}, {}
        for off in range(symtab[4], symtab[4] + symtab[5], 24):
            st_name, _, _, _, st_value, st_size = struct.unpack_from("<IBBHQQ", data, off)
            end = data.index(b"\0", strtab[4] + st_name)
            name = data[strtab[4] + st_name:end].decode()
            self.syms.setdefault(name, st_value)
            self.sizes.setdefault(name, st_size)

    def sym(self, name):
        if name not in self.syms:
            sys.exit(f"prepatch: no symbol {name}")
        return self.syms[name]

    def file_backed(self, va, n):
        return any(vaddr <= va and va + n <= vaddr + filesz
                   for vaddr, _, filesz in self.loads)

    def off(self, va, n):
        for vaddr, offset, filesz in self.loads:
            if vaddr <= va and va + n <= vaddr + filesz:
                return offset + va - vaddr
        sys.exit(f"prepatch: {va:#x} is not file-backed")


def sort_static_calls(elf, data):
    """Sort struct static_call_site { s32 addr; s32 key; } by key.

    Both fields are relative to their own address, and the key's low two
    bits are flags (TAIL, INIT), so moving an entry re-bases both fields.
    Returns the number of sites moved into order, 0 if already sorted.
    """
    if "__start_static_call_sites" not in elf.syms:
        return 0
    lo, hi = elf.sym("__start_static_call_sites"), elf.sym("__stop_static_call_sites")
    if (hi - lo) % 8:
        sys.exit("prepatch: .static_call_sites size is not a multiple of 8")
    ents = []
    for va in range(lo, hi, 8):
        a, k = struct.unpack_from("<ii", data, elf.off(va, 8))
        ents.append((va + a, va + 4 + k))  # absolute; the key keeps its flag bits
    keys = [k & ~3 for _, k in ents]
    if all(keys[i] <= keys[i + 1] for i in range(len(keys) - 1)):
        return 0
    ents.sort(key=lambda e: (e[1] & ~3, e[0]))
    for i, (a, k) in enumerate(ents):
        va = lo + 8 * i
        struct.pack_into("<ii", data, elf.off(va, 8), a - va, k - (va + 4))
    return len(ents)


ALT_MAGIC = 0x3148435441505041  # "APPATCH1", kernel patch 0026
ALT_INPUTS_MAX = 1024
ALT_UNDO_MAX = 64 << 10
KERNEL_MAP = 0xffffffff80000000  # kernel virtual = physical + this


def prepatch_alternatives(path, before_path, after_path):
    """Copy the text alternative_instructions() writes into the image (0026).

    BEFORE and AFTER are --dump-mem snapshots of two boots of this image,
    with "alt_snapshot=before" and "alt_snapshot": the kernel stops just
    before and just after the rewrite. The text that differs between them is
    what the rewrite wrote. Each such byte must lie in an alternative,
    retpoline, return or ENDBR-seal site and still hold its compiled value in
    BEFORE, else this refuses. Text other boot code rewrites (static calls,
    runtime constants) is the same in both, and stays as compiled.

    Those bytes go into the image, with an undo table of (compiled,
    pre-patched) pairs so a boot with different inputs can restore them.
    """
    data = bytearray(open(path, "rb").read())
    before = open(before_path, "rb").read()
    after = open(after_path, "rb").read()
    elf = Elf(data)
    ap = elf.sym("alt_prepatch")
    hdr = elf.off(ap, 16 + ALT_INPUTS_MAX + ALT_UNDO_MAX)
    if struct.unpack_from("<Q", data, hdr)[0] != 0:
        sys.exit("prepatch: image is already pre-patched; snapshot a freshly built one")
    sp = ap - KERNEL_MAP
    text = elf.sym("_text")
    ranges = ((text, elf.sym("_etext")), (elf.sym("_sinittext"), elf.sym("_einittext")))
    need = max(sp + 16 + ALT_INPUTS_MAX, max(e for _, e in ranges) - KERNEL_MAP)
    if min(len(before), len(after)) < need:
        sys.exit("prepatch: a snapshot is smaller than the guest image")
    inputs_len = struct.unpack_from("<I", after, sp + 8)[0]
    if not 0 < inputs_len <= ALT_INPUTS_MAX:
        sys.exit("prepatch: the snapshot boot can't be pre-patched (or didn't reach the "
                 "snapshot point: was it booted with alt_snapshot?)")
    if struct.unpack_from("<I", before, sp + 8)[0] != 0:
        sys.exit("prepatch: BEFORE is not an alt_snapshot=before boot")
    # Pre-patched paravirt sites call the final pv_ops targets from the first
    # instruction on, where a fresh kernel goes through pv_ops: the same only
    # if no pv op was changed during boot.
    if "pv_ops" in elf.syms:
        va, n = elf.sym("pv_ops"), elf.sizes["pv_ops"]
        if data[elf.off(va, n):elf.off(va, n) + n] != after[va - KERNEL_MAP:va - KERNEL_MAP + n]:
            sys.exit("prepatch: pv_ops changed during boot; early code would call the "
                     "new ops before their setup, refusing")

    sites = set()

    def rel_sites(start_sym, end_sym):
        if start_sym not in elf.syms:
            return []
        lo, hi = elf.sym(start_sym), elf.sym(end_sym)
        return [va + struct.unpack_from("<i", data, elf.off(va, 4))[0] for va in range(lo, hi, 4)]

    lo, hi = elf.sym("__alt_instructions"), elf.sym("__alt_instructions_end")
    for va in range(lo, hi, 14):  # struct alt_instr: s32, s32, u32, u8 instrlen, u8
        o = elf.off(va, 14)
        site = va + struct.unpack_from("<i", data, o)[0]
        sites.update(range(site, site + data[o + 12]))
    for site in rel_sites("__retpoline_sites", "__retpoline_sites_end"):
        # call/jmp rel32 (5 bytes) or Jcc rel32 (6), plus a CS prefix when
        # built with -mindirect-branch-cs-prefix (room for the kernel to
        # write a 6-byte indirect call / jmp in place of the thunk call).
        o = elf.off(site, 2)
        cs = data[o] == 0x2E
        n = 6 if data[o + cs] == 0x0F else 5
        sites.update(range(site, site + cs + n))
    for site in rel_sites("__return_sites", "__return_sites_end"):
        sites.update(range(site, site + 5))
    for site in rel_sites("__ibt_endbr_seal", "__ibt_endbr_seal_end"):
        sites.update(range(site, site + 4))

    undo = bytearray()
    changed = runs = 0
    for start, end in ranges:
        fo = elf.off(start, end - start)
        img = data[fo:fo + end - start]
        x = before[start - KERNEL_MAP:end - KERNEL_MAP]
        y = after[start - KERNEL_MAP:end - KERNEL_MAP]
        i = 0
        while i < len(x):
            if x[i:i + 4096] == y[i:i + 4096]:
                i += 4096
                continue
            stop = min(i + 4096, len(x))
            while i < stop:
                if x[i] == y[i]:
                    i += 1
                    continue
                j = i
                while j < len(x) and x[j] != y[j] and j - i < 0xffff:
                    j += 1
                for k in range(i, j):
                    if start + k not in sites:
                        sys.exit(f"prepatch: {start + k:#x} changed during alternative "
                                 "patching but is in no patch site; refusing")
                if x[i:j] != img[i:j]:
                    sys.exit(f"prepatch: {start + i:#x} was rewritten before alternative "
                             "patching too; refusing")
                undo += struct.pack("<iH", start + i - text, j - i) + img[i:j] + y[i:j]
                data[fo + i:fo + j] = y[i:j]
                changed += j - i
                runs += 1
                i = j

    # Static call sites: static_call_init() rewrites every one (before the
    # patch point) unless it already holds the instruction it computes, so a
    # wrong guess here only costs that write. Only sites whose key still has
    # its compiled target in BEFORE are written: then they call what their
    # trampoline would even before static_call_init() runs. A key updated
    # earlier (a paravirt clock, say) keeps its sites as compiled.
    # A key BEFORE shows as changed was set after static_call_init() (the APIC
    # driver's calls, NULL until the driver is installed; nothing may update
    # a key before static_call_init()). For its plain call sites, write what
    # static_call_init() computes from the compiled target: a 5-byte NOP for
    # NULL (its trampoline only returns, so the same no-op before init), else
    # a direct call.
    NOP5 = bytes((0x0F, 0x1F, 0x44, 0x00, 0x00))
    ret0 = elf.syms.get("__static_call_return0")
    scs = 0
    lo, hi = elf.sym("__start_static_call_sites"), elf.sym("__stop_static_call_sites")
    for va in range(lo, hi, 8):
        a, k = struct.unpack_from("<ii", data, elf.off(va, 8))
        site, key = va + a, (va + 4 + k) & ~3
        tail = (va + 4 + k) & 1
        func = struct.unpack_from("<Q", data, elf.off(key, 8))[0] if elf.file_backed(key, 8) else 0
        if before[key - KERNEL_MAP:key - KERNEL_MAP + 8] != struct.pack("<Q", func):
            o = elf.off(site, 5)
            if tail or data[o] != 0xE8 or func == ret0:
                continue
            if before[site - KERNEL_MAP:site - KERNEL_MAP + 5] != after[site - KERNEL_MAP:site - KERNEL_MAP + 5]:
                sys.exit(f"prepatch: static call site {site:#x} changed during alternative patching")
            want = NOP5 if func == 0 else b"\xe8" + struct.pack("<i", func - (site + 5))
            if want != data[o:o + 5]:
                data[o:o + 5] = want
                scs += 1
            continue
        o = elf.off(site, 6)
        n = 6 if data[o] == 0x0F else 5  # Jcc rel32 tail call, else call/jmp rel32
        snapb = before[site - KERNEL_MAP:site - KERNEL_MAP + n]
        if snapb != after[site - KERNEL_MAP:site - KERNEL_MAP + n]:
            sys.exit(f"prepatch: static call site {site:#x} changed during alternative patching")
        if snapb != data[o:o + n]:
            data[o:o + n] = snapb
            scs += 1

    if len(undo) > ALT_UNDO_MAX:
        sys.exit(f"prepatch: undo table needs {len(undo)} bytes, the kernel has {ALT_UNDO_MAX}")
    struct.pack_into("<QII", data, hdr, ALT_MAGIC, inputs_len, len(undo))
    data[hdr + 16:hdr + 16 + inputs_len] = after[sp + 16:sp + 16 + inputs_len]
    data[hdr + 16 + ALT_INPUTS_MAX:hdr + 16 + ALT_INPUTS_MAX + len(undo)] = undo
    with open(path, "wb") as f:
        f.write(data)
    print(f"prepatch: {changed} text bytes pre-patched in {runs} runs, undo table "
          f"{len(undo)} bytes, {inputs_len} bytes of inputs; {scs} static call sites "
          f"written as static_call_init() would")


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--alternatives":
        prepatch_alternatives(sys.argv[2], sys.argv[3], sys.argv[4])
        return
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    path = sys.argv[1]
    thunk_name = sys.argv[2] if len(sys.argv) == 3 else "auto"
    if thunk_name == "auto":
        thunk_name = auto_thunk()

    data = bytearray(open(path, "rb").read())
    elf = Elf(data)
    n = sort_static_calls(elf, data)
    print(f"prepatch: {n} static call sites sorted" if n else
          "prepatch: static call sites already in order")
    if not thunk_name or thunk_name == "none":
        print("prepatch: no return thunk for this CPU; return sites left as compiled")
    else:
        patch_returns(elf, data, thunk_name)
    keep = [(elf.sym(s), 8) for s in ("prepatched_return_thunk",) if s in elf.syms]
    if "alt_prepatch" in elf.syms:
        keep.append((elf.sym("alt_prepatch"), 16 + ALT_INPUTS_MAX + ALT_UNDO_MAX))
    n, saved = split_zero_runs(data, keep)
    if n:
        print(f"prepatch: {saved >> 10} KiB of zero pages in {n} runs left to the loader to zero")
    with open(path, "wb") as f:
        f.write(data)


def split_zero_runs(data, keep, min_pages=16):
    """Let the loader zero-fill long runs of zero pages instead of reading them.

    ELF can only say "zeros" at a segment's end (memsz > filesz), so each
    PT_LOAD is split where a run of at least MIN_PAGES zero pages starts:
    the part before it ends with the run as its zero tail. The kernel's
    alignment padding and .bss are a third of what a loader reads. KEEP
    lists (va, size) ranges later build steps write, which stay in the file.
    Returns the number of runs and the bytes no longer read.
    """
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    phdrs = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize) for i in range(phnum)]
    out, runs, saved = [], 0, 0
    for ph in phdrs:
        p_type, flags, off, va, pa, fs, ms, al = ph
        if p_type != 1 or off % 4096 or va % 4096:
            out.append(ph)
            continue

        def zero(p):
            if any(kv < va + p + 4096 and va + p < kv + kn for kv, kn in keep):
                return False
            return not any(data[off + p:off + min(p + 4096, fs)])

        def piece(s, file_end, mem_end):
            out.append((1, flags, off + s, va + s, pa + s, file_end - s, mem_end - s, al))

        start, p = 0, 0
        while p < fs:
            if not zero(p):
                p += 4096
                continue
            q = p
            while q < fs and zero(q):
                q += 4096
            if q >= fs:  # zeros up to the end of the file data: a longer tail
                piece(start, p, ms)
                runs, saved, start = runs + 1, saved + fs - p, None
                break
            if q - p >= min_pages * 4096:
                piece(start, p, q)
                runs, saved, start = runs + 1, saved + q - p, q
            p = q
        if start is not None:
            piece(start, fs, ms)
    if runs == 0:
        return 0, 0
    first = min(ph[2] for ph in phdrs if ph[0] == 1)
    if phoff + len(out) * phentsize > first or any(
            data[phoff + phnum * phentsize:phoff + len(out) * phentsize]):
        print("prepatch: no room for more program headers; zero runs left in the file")
        return 0, 0
    for i, ph in enumerate(out):
        struct.pack_into("<IIQQQQQQ", data, phoff + i * phentsize, *ph)
    struct.pack_into("<H", data, 0x38, len(out))
    return runs, saved


def patch_returns(elf, data, thunk_name):
    """Exits without writing the file if any site isn't as compiled."""
    default = elf.sym("__x86_return_thunk")
    thunk = elf.sym(thunk_name)
    marker = elf.off(elf.sym("prepatched_return_thunk"), 8)
    start, end = elf.sym("__return_sites"), elf.sym("__return_sites_end")
    if struct.unpack_from("<Q", data, marker)[0] not in (0, thunk):
        sys.exit("prepatch: image already pre-patched for another thunk")

    patched = already = 0
    for site in range(start, end, 4):
        addr = site + struct.unpack_from("<i", data, elf.off(site, 4))[0]
        o = elf.off(addr, 5)
        if data[o] != 0xE9:
            sys.exit(f"prepatch: return site {addr:#x} is not a JMP rel32; image left as compiled")
        dest = addr + 5 + struct.unpack_from("<i", data, o + 1)[0]
        if dest == thunk:
            already += 1
            continue
        if dest != default:
            sys.exit(f"prepatch: return site {addr:#x} jumps to {dest:#x}; image left as compiled")
        struct.pack_into("<i", data, o + 1, thunk - (addr + 5))
        patched += 1
    struct.pack_into("<Q", data, marker, thunk)
    print(f"prepatch: {patched + already} return sites -> {thunk_name} ({already} already)")


if __name__ == "__main__":
    main()
