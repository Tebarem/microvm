#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Writes tests/zstd_vectors.h: inputs made here (deterministic), compressed
# by the zstd CLI (1.5.5 made the checked-in ones) with the options that make
# the decoder take each path: raw, RLE and compressed blocks; raw, RLE and
# Huffman literals (1 and 4 streams, with trees reused across blocks);
# predefined, RLE, FSE and repeated sequence tables; repeat offsets; small
# windows that slide; frames with and without a content size and a checksum;
# concatenated and skippable frames. The test checks each output's length
# and SHA-256.
#
#   python3 tests/gen_zstd_vectors.py > tests/zstd_vectors.h
import hashlib
import random
import struct
import subprocess
import sys


def zstd(data, *opts):
    return subprocess.run(["zstd", "-q", "-c", *opts], input=data, check=True,
                          stdout=subprocess.PIPE).stdout


def zstd_file(data, *opts):  # from a file, so the frame records its size
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
    try:
        return subprocess.run(["zstd", "-q", "-c", *opts, f.name], check=True,
                              stdout=subprocess.PIPE).stdout
    finally:
        os.unlink(f.name)


rng = random.Random(8878)
words = ("the quick brown fox jumps over lazy dog microvm erofs layer image "
         "kernel guest offset literal sequence huffman window frame block").split()
text = "".join("line %d: %s %d\n" % (i, " ".join(rng.choice(words) for _ in range(rng.randint(3, 12))),
                                       i * i % 997) for i in range(500)).encode()
small = text[:6000]
bits = bytes(rng.choice(b"ac") for _ in range(135_000))                      # 2 blocks, 1 bit/byte
noise = bytes(rng.getrandbits(8) for _ in range(3000))
period = text[:20_000] * 40                                            # 800 KB
short_period = bytes(rng.choice(b"0123456789") for _ in range(600)) * 500    # 300 KB
mixed = b"".join(text[i * 2500:(i + 1) * 2500] + noise[:200 * (i % 3)] + bytes(3000 * (i % 2))
                 for i in range(12))

vectors = [
    ("empty", b"", zstd_file(b"", "-3")),
    ("empty_nocheck", b"", zstd(b"", "--no-check")),
    ("one", b"x", zstd_file(b"x", "-3")),
    ("text_l1", text, zstd_file(text, "-1")),
    ("text_l19", text, zstd_file(text, "-19")),
    ("text_fast", text, zstd_file(text, "--fast=4")),
    ("small_l22", small, zstd_file(small, "--ultra", "-22")),
    ("small_stream", small, zstd(small, "-3")),             # no content size
    ("small_nocheck", small, zstd_file(small, "-3", "--no-check")),
    ("bits_l19", bits, zstd(bits, "-19")),
    ("noise", noise, zstd_file(noise, "-3")),               # a raw block
    ("zeros", bytes(1_000_000), zstd(bytes(1_000_000), "-3")),  # RLE blocks
    ("period_wlog17", period, zstd(period, "-3", "--zstd=wlog=17")),
    ("short_period_wlog10", short_period, zstd(short_period, "-5", "--zstd=wlog=10")),
    ("mixed_l7", mixed, zstd(mixed, "-7")),
]
# Concatenated frames with skippable frames around them.
skip1 = struct.pack("<II", 0x184D2A50, 5) + b"hello"
skip2 = struct.pack("<II", 0x184D2A5F, 0)
cat = skip1 + zstd_file(text[:5000], "-3") + skip2 + zstd(bits[:20000], "-1") + zstd_file(b"", "-3") + skip1
vectors.append(("concatenated", text[:5000] + bits[:20000], cat))


# A tar+zstd image layer (test_oci.c checks these files).
def layer_tar():
    import io, tarfile
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=tarfile.USTAR_FORMAT) as t:
        def add(name, data=None, mode=0o644):
            ti = tarfile.TarInfo(name)
            ti.mtime, ti.mode, ti.uname, ti.gname = 0, mode, "", ""
            if data is None:
                ti.type, ti.mode = tarfile.DIRTYPE, 0o755
                t.addfile(ti)
            else:
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
        add("zst/")
        add("zst/hello", b"hello from a zstd layer\n")
        add("zst/text", text)
        add("zst/bits", bits[:50000])
    return b.getvalue()


tar = layer_tar()
vectors.append(("layer_tar", tar, zstd(tar, "-3")))

out = sys.stdout
out.write("// SPDX-License-Identifier: MIT\n")
out.write("// Made by tests/gen_zstd_vectors.py with the zstd CLI (%s): see there.\n"
          % subprocess.run(["zstd", "-V"], stdout=subprocess.PIPE, text=True).stdout.split(",")[0]
          .replace("*** ", "").strip())
out.write("#pragma once\n#include <stddef.h>\n#include <stdint.h>\n\n")
for name, plain, comp in vectors:
    out.write("static const uint8_t zv_%s[%d] = {" % (name, max(len(comp), 1)))
    for i, b in enumerate(comp):
        out.write(("\n    " if i % 20 == 0 else " ") + "%d," % b)
    out.write("\n};\n")
out.write("\ntypedef struct {\n    const char *name;\n    const uint8_t *z;\n    size_t zn;\n"
          "    size_t n;          // decompressed bytes\n    const char *sha256; // of them\n} zstd_vector;\n\n")
out.write("static const zstd_vector zstd_vectors[] = {\n")
for name, plain, comp in vectors:
    out.write('    {"%s", zv_%s, %d, %d, "%s"},\n' % (name, name, len(comp), len(plain),
                                                     hashlib.sha256(plain).hexdigest()))
out.write("};\n")
total = sum(len(c) for _, _, c in vectors)
print("%d vectors, %d compressed bytes" % (len(vectors), total), file=sys.stderr)
