#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Aggregate microvm --profile samples into a per-symbol guest profile.

    microvm --kernel vmlinux --quiet --profile p1.txt   (repeat for more samples)
    python3 tools/profile.py [--inclusive | --callers SYM] guest/kernel/out/System.map p*.txt

Each sample line is the guest RIP followed by kernel-text addresses found on
the stack. Those are likely return addresses, but the scan is heuristic:
stale stack slots show up too, so caller numbers are approximate.

  (default)      self time per symbol
  --inclusive    samples with the symbol anywhere in RIP + stack
  --callers SYM  for samples whose RIP is in SYM: which symbols are on the stack
"""
import bisect
import collections
import sys


def load_map(path):
    syms, marks = [], {}
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3:
                if parts[2] in ("_stext", "_etext", "_sinittext", "_einittext"):
                    marks[parts[2]] = int(parts[0], 16)
                if parts[1].lower() in "tw":
                    syms.append((int(parts[0], 16), parts[2]))
    syms.sort()
    text = [(marks["_stext"], marks["_etext"]), (marks["_sinittext"], marks["_einittext"])]
    return [a for a, _ in syms], [n for _, n in syms], text


def main():
    args = sys.argv[1:]
    mode, target = "self", None
    if args and args[0] == "--inclusive":
        mode, args = "inclusive", args[1:]
    elif len(args) > 1 and args[0] == "--callers":
        mode, target, args = "callers", args[1], args[2:]
    if len(args) < 2:
        sys.exit(__doc__)
    addrs, names, text = load_map(args[0])

    def in_text(addr):
        return any(lo <= addr < hi for lo, hi in text)

    def sym(addr):
        if addr < 0xFFFF800000000000:
            return "[user]" if addr < 0x800000000000 else "[phys/early]"
        i = bisect.bisect_right(addrs, addr) - 1
        return names[i] if i >= 0 else "[unknown]"

    hits = collections.Counter()
    total = 0
    for path in args[1:]:
        with open(path) as f:
            for line in f:
                words = line.split()
                if not words:
                    continue
                vals = [int(w, 16) for w in words]
                # Stack words that aren't code addresses (pointers to rodata,
                # data) are noise.
                frames = [sym(vals[0])] + [sym(a) for a in vals[1:] if in_text(a)]
                if mode == "self":
                    total += 1
                    hits[frames[0]] += 1
                elif mode == "inclusive":
                    total += 1
                    for name in set(frames):
                        hits[name] += 1
                elif frames[0] == target:
                    total += 1
                    for name in set(frames[1:]) - {target}:
                        hits[name] += 1
    if not total:
        sys.exit("no samples")
    print(f"{total} samples" + (f" in {target}" if target else ""))
    acc = 0.0
    for name, n in hits.most_common(40):
        pct = 100.0 * n / total
        acc += pct
        cum = f"{acc:6.2f}%" if mode == "self" else "       "
        print(f"{pct:6.2f}% {cum}  {n:6d}  {name}")


if __name__ == "__main__":
    main()
