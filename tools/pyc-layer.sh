#!/bin/bash
# SPDX-License-Identifier: MIT
# A layer of Python bytecode for an image, compiled by the image's own
# interpreter in a VM (runtimes/python/precompile.py):
#
#   tools/pyc-layer.sh BUILD_DIR KERNEL IMAGE OUT.tar [ARG...]
#
# IMAGE (an EROFS image from microvm-mkrootfs) must have python3 on its PATH
# and /opt/microvm/precompile.py (fn-images.sh puts it in the function
# layer). ARGs go to precompile.py: --unchecked, and directories of the
# function's own code. The VM's console carries the layer back, base64
# between marker lines; OUT.tar is then a plain tar to give microvm-mkrootfs
# as the last --add-layer, after everything it was compiled from. Like any
# layer, it is parsed as untrusted input there. WRAP: a command prefix for
# the VMM (e.g. setpriv ... to run as nobody); MEM: guest MiB (default 512:
# the .pyc files are written to the guest's tmpfs first).
set -eu
B=$1 K=$2 IMG=$3 OUT=$4
shift 4
WRAP=${WRAP:-}
log=$OUT.log
$WRAP "$B/microvm" --kernel "$K" --quiet --mem "${MEM:-512}" --rootfs "$IMG" \
    -- python3 /opt/microvm/precompile.py "$@" > "$log" 2>&1 ||
    { echo "pyc-layer: the VM failed:" >&2; grep -v '^[A-Za-z0-9+/=]*$' "$log" | tail -20 >&2; exit 1; }
sed -n '/^-----BEGIN MICROVM PYC LAYER-----$/,/^-----END MICROVM PYC LAYER-----$/p' "$log" |
    sed '1d;$d' | base64 -d > "$OUT"
tar -tf "$OUT" > /dev/null
grep '^precompile: ' "$log" || true
rm -f "$log"
