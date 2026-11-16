#!/bin/bash
# SPDX-License-Identifier: MIT
# Functions on public runtime images (Linux/KVM): put the runtime adapter
# and an example function on top of the image (--add-layer), snapshot it
# after warm-up, and check and time what restores do.
#
#   tools/fn-images.sh BUILD_DIR KERNEL WORK_DIR KIND OCI_DIR [MEM_MIB]
#
# KIND is python, bun or node; OCI_DIR an OCI layout of that image (skopeo
# copy docker://...@sha256:... oci:DIR). WRAP is a command prefix (e.g.
# setpriv ... to run as nobody); N the timed runs (default 20). Step 4
# reads the VMMs' smaps_rollup, which only root can (they are
# non-dumpable): run the script as root, the VMMs through WRAP.
#
# 1. The function image: the OCI image plus runtimes/ (with reseed.node,
#    built here with CC, default cc) and the example, as one added layer.
#    The layer also hides the package managers (tools/whiteouts.py): npm
#    and npx, pip and ensurepip. A function doesn't run them, and they
#    carry most of the image's fixable vulnerabilities (IMAGES.md).
#    Python's then gets its bytecode as one more layer (tools/pyc-layer.sh:
#    compiled in a VM by the image's own interpreter); PYC=0 leaves it out.
# 2. A snapshot after warm-up (runtimes/examples/rng.*, which uses every
#    random source it has before the snapshot).
# 3. Two VMs restored from it, two invocations each: every random value must
#    differ between the two VMs. Values that repeat are state the snapshot
#    shares (SECURITY.md): the script fails, except for Python's hash()
#    seed, which is fixed at interpreter start and listed as known.
# 4. Memory: 8 restored VMs held after one invocation each.
# 5. p50 of N runs: restore -> first response, and cold boot -> first
#    response (the same function, no snapshot), wall clock from launching
#    the VMM to the response printed, as a client sees it.
# 6. With --no-snapshot the runtime serves and takes no snapshot.
set -eu
B=$1 K=$2 W=$3 KIND=$4 OCI=$5 MEM=${6:-256}
N=${N:-20}
WRAP=${WRAP:-}
SRC=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$W"
[ -z "$WRAP" ] || chmod 777 "$W" # WRAP's user writes the image, sockets and snapshots here
L=$W/layer
rm -rf "$L" && mkdir -p "$L/opt/microvm" "$L/app"
cp "$SRC/runtimes/python/microvm_runtime.py" "$L/opt/microvm/runtime.py"
cp "$SRC/runtimes/python/precompile.py" "$L/opt/microvm/precompile.py"
cp "$SRC/runtimes/js/microvm_runtime.mjs" "$L/opt/microvm/runtime.mjs"
${CC:-cc} -std=c2x -O2 -shared -fPIC -nostdlib -fno-stack-protector -Wall -Wextra -Werror \
    -o "$L/opt/microvm/reseed.node" "$SRC/runtimes/js/reseed.c"
cp "$SRC/runtimes/examples/rng.py" "$SRC/runtimes/examples/rng.mjs" "$L/app/"
# SNAP: the runtime's arguments that ask for the snapshot; COLD: that don't.
# STRIP: what the layer hides (none for Bun: bunx is the bun binary).
case $KIND in
python)
    RT=(python3 /opt/microvm/runtime.py) FN=/app/rng.py SNAP=() COLD=(--no-snapshot)
    STRIP=('usr/local/lib/python3.*/site-packages/pip' 'usr/local/lib/python3.*/site-packages/pip-*.dist-info'
           'usr/local/lib/python3.*/ensurepip' 'usr/local/bin/pip' 'usr/local/bin/pip3*') ;;
bun | node)
    RT=("$KIND" /opt/microvm/runtime.mjs) FN=/app/rng.mjs SNAP=() COLD=(--no-snapshot)
    STRIP=()
    [ "$KIND" = bun ] || STRIP=('usr/local/lib/node_modules/npm' 'usr/local/bin/npm' 'usr/local/bin/npx') ;;
*) echo "KIND: python, bun or node" >&2; exit 2 ;;
esac
TOP=(opt app)
if [ ${#STRIP[@]} -gt 0 ]; then
    python3 -I "$SRC/tools/whiteouts.py" "$OCI" "$L" "${STRIP[@]}"
    TOP+=(usr)
fi
tar --create --numeric-owner --owner=0 --group=0 --mode=a+rX,go-w --mtime=@0 --sort=name \
    -f "$W/fn-layer.tar" -C "$L" "${TOP[@]}"
CMD=("${RT[@]}" "${SNAP[@]}" "$FN")
CMD_COLD=("${RT[@]}" "${COLD[@]}" "$FN")
IMG=$W/$KIND-fn.erofs SNAPFILE=$W/$KIND.snap
$WRAP "$B/microvm-mkrootfs" --stats --oci "$OCI" --add-layer "$W/fn-layer.tar" "$IMG" 2>&1 | head -2
if [ ${#STRIP[@]} -gt 0 ]; then # the guest's shell expands the patterns: nothing may match
    left=$($WRAP "$B/microvm" --kernel "$K" --quiet --mem "$MEM" --rootfs "$IMG" -- /bin/sh -c \
        "for p in $(printf '/%s ' "${STRIP[@]}"); do [ -e \$p ] && echo \$p; done; echo end" 2>&1) || true
    [ "$left" = end ] || { echo "FAILED: still in the image: $left"; exit 1; }
    echo "stripped: nothing left of ${STRIP[*]}"
fi
if [ "$KIND" = python ] && [ "${PYC:-1}" != 0 ]; then # bytecode, built from the image above, goes last
    WRAP="$WRAP" MEM=512 bash "$SRC/tools/pyc-layer.sh" "$B" "$K" "$IMG" "$W/pyc-layer.tar" /app
    $WRAP "$B/microvm-mkrootfs" --stats --oci "$OCI" --add-layer "$W/fn-layer.tar" \
        --add-layer "$W/pyc-layer.tar" "$IMG" 2>&1 | head -1
fi

ms() { awk -v a="$1" -v b="$(date +%s%N)" 'BEGIN { printf "%.1f\n", (b - a) / 1e6 }'; }
t0=$(date +%s%N)
rm -f "$SNAPFILE" "$W/s.sock"
$WRAP "$B/microvm" --kernel "$K" --quiet --map-kernel --mem "$MEM" --rootfs "$IMG" --vsock "$W/s.sock" \
    --append agent --snapshot "$SNAPFILE" -- "${CMD[@]}" > "$W/snap.log" 2>&1 || { cat "$W/snap.log"; exit 1; }
echo "snapshot after warm-up: $(ms $t0) ms; file $(du -k "$SNAPFILE" | cut -f1) KiB on disk for $MEM MiB of RAM"

vm=() # pids of the VMMs we started
stop_vms() { for p in "${vm[@]}"; do kill "$p" 2> /dev/null || true; done; wait 2> /dev/null || true; vm=(); }
trap stop_vms EXIT
invoke() { # SOCK PAYLOAD
    echo "$2" | $WRAP "$B/microvm-invoke" "$1" --payload - --connect-ms 10000 2> "$W/invoke.err" ||
        { echo "invoke failed: $(cat "$W/invoke.err")" >&2; return 1; }
}

echo "== two VMs restored from the snapshot, two invocations each"
for v in a b; do
    rm -f "$W/$v.sock"
    $WRAP "$B/microvm" --restore "$SNAPFILE" --rootfs "$IMG" --vsock "$W/$v.sock" > "$W/$v.log" 2>&1 &
    vm+=($!)
done
for v in a b; do
    for k in 1 2; do
        invoke "$W/$v.sock" "$v$k" > "$W/$v$k.json"
        echo; cat "$W/$v$k.json"
        # what the function printed came back with its own invocation
        grep -qx "stdout of $v$k" "$W/invoke.err" && grep -qx "stderr of $v$k" "$W/invoke.err" ||
            { echo "FAILED: output of $v$k missing: $(cat "$W/invoke.err")"; exit 1; }
    done
done
echo
stop_vms
python3 - "$W" << 'EOF'
import json, sys
w = sys.argv[1]
r = {k: json.load(open(f"{w}/{k}.json")) for k in ("a1", "a2", "b1", "b2")}
skip = {"count", "event", "runtime"}
known = {"hash"}  # Python's str hash seed: SECURITY.md
bad, seen = [], set()
for f in r["a1"]:
    if f in skip:
        continue
    for x in ("a1", "a2"):
        for y in ("b1", "b2"):
            if r[x][f] == r[y][f]:
                if f in known:
                    seen.add(f)
                else:
                    bad.append(f"{f} ({x} = {y}: {r[x][f]})")
print("shared between the two restores: " + ("; ".join(bad) if bad else "nothing") +
      (f" (known, by design: {', '.join(sorted(seen))})" if seen else ""))
sys.exit(1 if bad else 0)
EOF

echo "== 8 VMs restored from the snapshot, held after one invocation each, per VMM process"
for i in $(seq 1 8); do
    rm -f "$W/m$i.sock"
    $WRAP "$B/microvm" --restore "$SNAPFILE" --rootfs "$IMG" --vsock "$W/m$i.sock" > /dev/null 2>&1 &
    vm+=($!)
done
for i in $(seq 1 8); do invoke "$W/m$i.sock" m > /dev/null; done
for p in "${vm[@]}"; do cat "/proc/$(pgrep -P "$p" -x microvm || echo "$p")/smaps_rollup"; done |
    awk '/^Pss:/ {p += $2} /^Private_Dirty:/ {d += $2} END {printf "private dirty %.1f MB, PSS %.1f MB\n", d / 8 / 1024, p / 8 / 1024}'
stop_vms

p50() { sort -n | awk '{a[NR] = $1} END {print a[int((NR + 1) / 2)]}'; }
echo "== restore -> first response, $N runs"
for i in $(seq 1 "$N"); do
    rm -f "$W/t.sock"
    t0=$(date +%s%N)
    $WRAP "$B/microvm" --restore "$SNAPFILE" --rootfs "$IMG" --vsock "$W/t.sock" > /dev/null 2>&1 &
    vm+=($!)
    invoke "$W/t.sock" t > /dev/null
    ms $t0
    stop_vms
done | p50 | sed 's/^/p50 ms: /'
echo "== cold boot -> first response (no snapshot), $N runs"
for i in $(seq 1 "$N"); do
    rm -f "$W/t.sock"
    t0=$(date +%s%N)
    $WRAP "$B/microvm" --kernel "$K" --quiet --map-kernel --mem "$MEM" --rootfs "$IMG" --vsock "$W/t.sock" \
        --append agent -- "${CMD_COLD[@]}" > /dev/null 2>&1 &
    vm+=($!)
    invoke "$W/t.sock" t > /dev/null
    ms $t0
    stop_vms
done | p50 | sed 's/^/p50 ms: /'
echo "== with ${COLD[*]}, the runtime asks for no snapshot"
rm -f "$W/n.snap" "$W/t.sock"
$WRAP "$B/microvm" --kernel "$K" --quiet --map-kernel --mem "$MEM" --rootfs "$IMG" --vsock "$W/t.sock" \
    --append agent --snapshot "$W/n.snap" -- "${CMD_COLD[@]}" > /dev/null 2>&1 &
vm+=($!)
invoke "$W/t.sock" t > /dev/null
stop_vms
if [ -s "$W/n.snap" ]; then echo "FAILED: a snapshot was taken"; exit 1; fi # the VMM creates it up front
echo "ok: it served the invocation and took no snapshot"
