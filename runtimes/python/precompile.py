# SPDX-License-Identifier: MIT
# Compile a Python image's modules to bytecode, inside the image, and write
# the .pyc files as a tar layer to stdout (base64, between marker lines):
#
#   python3 /opt/microvm/precompile.py [--unchecked] [DIR...]
#
# The official Python images ship no .pyc files, and a function's image is
# read-only, so every cold start compiled every module it imported, every
# time. tools/pyc-layer.sh boots the image with this, and the layer it gets
# back goes on top (microvm-mkrootfs --add-layer): imports then load the
# bytecode. Run by the image's own interpreter, so the bytecode is its
# version's, for exactly the sources the image has.
#
# Compiles every directory on sys.path, and each DIR (a function's code),
# at the default optimization level. The .pyc files are hash-based (PEP
# 552), so they don't depend on file times and the layer is the same every
# time for the same image:
# - default, checked: each import reads the source and checks its hash,
#   and compiles it as before if it changed (a layer under this one
#   changed and this one wasn't rebuilt). On the KVM box that cost nothing
#   measurable for `import json, ssl`, and 4 of 80 ms for asyncio, email
#   and http.client (BENCH.md);
# - --unchecked: the source is never looked at again. A stale layer then
#   runs the old code.
import base64
import compileall
import io
import os
import py_compile
import sys
import tarfile

BEGIN, END = b"-----BEGIN MICROVM PYC LAYER-----\n", b"-----END MICROVM PYC LAYER-----\n"


def main():
    args = sys.argv[1:]
    checked = "--unchecked" not in args
    dirs = [a for a in args if a != "--unchecked"]
    mode = py_compile.PycInvalidationMode.CHECKED_HASH if checked else py_compile.PycInvalidationMode.UNCHECKED_HASH
    here = os.path.dirname(os.path.abspath(__file__))
    roots = []
    for d in [p for p in sys.path if p and os.path.abspath(p) != here] + dirs + [here]:
        d = os.path.realpath(d)
        if os.path.isdir(d) and not any(d == r or d.startswith(r + "/") for r in roots):
            roots = [r for r in roots if not r.startswith(d + "/")] + [d]
    failed = 0
    for d in roots:
        if not compileall.compile_dir(d, quiet=2, workers=1, invalidation_mode=mode):
            failed += 1
    tag = sys.implementation.cache_tag
    buf = io.BytesIO()
    n = size = 0
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        for d in roots:
            for top, subdirs, files in os.walk(d):
                subdirs.sort()
                if os.path.basename(top) != "__pycache__":
                    continue
                pycs = sorted(f for f in files if f.endswith(".pyc") and f".{tag}" in f)
                if not pycs:
                    continue
                info = tarfile.TarInfo(top.lstrip("/"))
                info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, 0
                t.addfile(info)
                for f in pycs:
                    p = os.path.join(top, f)
                    data = open(p, "rb").read()
                    info = tarfile.TarInfo(p.lstrip("/"))
                    info.size, info.mode, info.mtime = len(data), 0o644, 0
                    t.addfile(info, io.BytesIO(data))
                    n += 1
                    size += len(data)
    out = sys.stdout.buffer
    out.write(BEGIN)
    out.write(base64.encodebytes(buf.getvalue()))
    out.write(END)
    out.flush()
    print(f"precompile: {n} .pyc files, {size} bytes, {'checked' if checked else 'unchecked'} hashes, "
          f"from {' '.join(roots)}" + (f"; {failed} directories had files that don't compile" if failed else ""),
          file=sys.stderr)


main()
