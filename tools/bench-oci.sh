#!/bin/sh
# SPDX-License-Identifier: MIT
# A realistic multi-layer test image, built from this machine's own files
# with GNU tar and gzip -6 (so: real tars, real dynamic-Huffman gzip), and
# what converting it costs. No docker, no network.
#
#   tools/bench-oci.sh BUILD_DIR WORK_DIR [EXTRA_LAYER.tar]
#
# Layers (~600 MB decompressed): a base (/etc, /usr/bin, /usr/sbin), a
# runtime (Python's stdlib), packages (Perl, docs), an app (headers, plus
# EXTRA_LAYER.tar, e.g. the test layer with /bin/probe), and a clean-up
# layer that whites out /usr/share/doc and a file. Writes WORK_DIR/layout
# (OCI, gzip layers) and WORK_DIR/docker.tar (docker-archive, plain layers),
# converts both, and prints the times.
set -eu
B=$1
W=$2
EXTRA=${3:-}
mkdir -p "$W"
cd "$W"
T="tar --create --numeric-owner --ignore-failed-read --warning=no-file-ignored -C /"
if [ ! -f l1.tar ]; then
    $T -f l1.tar etc usr/bin usr/sbin 2>/dev/null || true
    $T -f l2.tar usr/lib/python3 usr/lib/python3.12 2>/dev/null || true
    $T -f l3.tar usr/share/perl usr/share/perl5 usr/share/doc 2>/dev/null || true
    $T -f l4.tar usr/include 2>/dev/null || true
    if [ -n "$EXTRA" ]; then
        tar --concatenate -f l4.tar "$EXTRA"
    fi
    rm -rf wh && mkdir -p wh/usr/share wh/etc
    : > wh/usr/share/.wh.doc
    : > wh/etc/.wh.motd
    mkdir -p wh/usr/include && : > wh/usr/include/.wh..wh..opq
    echo "only this is left" > wh/usr/include/README
    tar --create --numeric-owner -f l5.tar -C wh usr etc
    for i in 1 2 3 4 5; do gzip -6 -k -f l$i.tar; done
fi
# zstd -3 is what `docker buildx --output compression=zstd` and
# `podman push --compression-format zstd` use by default.
if command -v zstd > /dev/null && [ ! -f l5.tar.zst ]; then
    for i in 1 2 3 4 5; do zstd -q -3 -k -f l$i.tar; done
fi
ls -l l*.tar l*.tar.gz l*.tar.zst 2>/dev/null || true
CFG='{"Entrypoint":["/bin/probe"],"Cmd":["from","the","image"],"Env":["PATH=/usr/bin:/bin"],"WorkingDir":"/usr","User":"0:0"}'
rm -rf layout docker.tar
"$B/mvm-mkoci" --config "$CFG" layout l1.tar.gz l2.tar.gz l3.tar.gz l4.tar.gz l5.tar.gz
"$B/mvm-mkoci" --docker-archive --config "$CFG" docker.tar l1.tar l2.tar l3.tar l4.tar l5.tar
du -sh layout docker.tar
for run in 1 2 3; do
    "$B/microvm-mkrootfs" --stats --config layout.cfg --oci layout layout.erofs
done
for run in 1 2 3; do
    "$B/microvm-mkrootfs" --stats --docker-archive docker.tar docker.erofs
done
ls -l layout.erofs
"$B/mvm-mkoci" --bench l1.tar.gz
if [ -f l5.tar.zst ]; then
    rm -rf layout-zstd
    "$B/mvm-mkoci" --config "$CFG" layout-zstd l1.tar.zst l2.tar.zst l3.tar.zst l4.tar.zst l5.tar.zst
    du -sh layout-zstd
    for run in 1 2 3; do
        "$B/microvm-mkrootfs" --stats --oci layout-zstd layout-zstd.erofs
    done
    # The same files; only the config file's manifest-digest (64 hex digits)
    # differs, since the layer blobs do.
    n=$(cmp -l layout.erofs layout-zstd.erofs | wc -l)
    if [ "$n" -le 64 ]; then
        echo "zstd and gzip layouts make the same image but for the manifest digest ($n bytes differ)"
    else
        echo "zstd and gzip layouts differ in $n bytes"
    fi
    "$B/mvm-mkoci" --bench l1.tar.zst
    "$B/mvm-mkoci" --bench l2.tar.zst
    for t in "gzip -d -c l1.tar.gz" "zstd -d -c l1.tar.zst"; do
        s=$(date +%s.%N); $t > /dev/null; e=$(date +%s.%N)
        echo "$t: $(awk "BEGIN { print $e - $s }") s"
    done
fi
