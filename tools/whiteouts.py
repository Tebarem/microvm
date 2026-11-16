#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Hide paths of an image from a layer that goes on top of it, as a
# Dockerfile's `RUN rm -rf` would: writes OCI whiteouts (.wh.NAME) into a
# layer directory for every path of the image that matches a pattern.
#
#   python3 -I tools/whiteouts.py OCI_DIR LAYER_DIR PATTERN...
#
# A pattern is a path without the leading /, matched one segment at a time
# with shell wildcards (* never crosses a /): usr/local/lib/python3.*/
# site-packages/pip-*.dist-info. A match hides the whole subtree, and paths
# under a hidden one aren't listed again. Prints each hidden path.
#
# Reads the image's own layers (OCI layout, first manifest, tar or
# tar+gzip) only for their file names. The whiteouts are empty files, and
# the directories leading to them are created in LAYER_DIR. Tar LAYER_DIR
# with them and give it to microvm-mkrootfs --add-layer, as fn-images.sh does.
import fnmatch
import json
import os
import sys
import tarfile


def layers(oci):
    def blob(digest):
        algo, hexd = digest.split(":", 1)
        if algo != "sha256" or len(hexd) != 64 or not all(c in "0123456789abcdef" for c in hexd):
            sys.exit(f"bad digest {digest!r}")
        return os.path.join(oci, "blobs", "sha256", hexd)

    index = json.load(open(os.path.join(oci, "index.json")))
    manifest = json.load(open(blob(index["manifests"][0]["digest"])))
    if "layers" not in manifest:
        sys.exit("the first manifest is an index: give a single-platform layout")
    return [blob(layer["digest"]) for layer in manifest["layers"]]


def matches(pattern, path):
    p, s = pattern.split("/"), path.split("/")
    return len(p) == len(s) and all(fnmatch.fnmatchcase(b, a) for a, b in zip(p, s))


def main():
    if len(sys.argv) < 4:
        sys.exit("usage: whiteouts.py OCI_DIR LAYER_DIR PATTERN...")
    oci, out, patterns = sys.argv[1], sys.argv[2], [p.strip("/") for p in sys.argv[3:]]
    names = set()
    for path in layers(oci):
        with tarfile.open(path, "r:*") as t:
            for e in t:
                name = os.path.normpath(e.name).lstrip("/")
                if name in (".", "") or name.startswith("../"):
                    continue
                base = os.path.basename(name)
                if base.startswith(".wh."):
                    continue
                names.add(name)
    hide = sorted(n for n in names if any(matches(p, n) for p in patterns))
    done = []
    for n in hide:
        if any(n.startswith(d + "/") for d in done):
            continue
        parent, base = os.path.split(n)
        os.makedirs(os.path.join(out, parent), exist_ok=True)
        open(os.path.join(out, parent, ".wh." + base), "w").close()
        done.append(n)
        print("hidden: /" + n)
    if not done:
        sys.exit("no path of the image matches")


main()
