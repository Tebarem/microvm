#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Pre-patch a freshly built vmlinux's alternatives for this host's CPU view
# (kernel patch 0026; Linux / KVM twin of tools/prepatch-alternatives.ps1).
# Boots it twice in a VM, stopping just before and just after alternative
# patching, dumps guest memory each time, and has guest/kernel/prepatch.py
# copy what the patching wrote into the image.
#   tools/prepatch-alternatives.sh [-k VMLINUX] [-o OUT] [-a "KERNEL ARGS"] [-c CPUS]
# Without -o the kernel is pre-patched in place. -a adds kernel arguments to
# both snapshot boots: pass the ones you will boot with if they change CPU
# features or mitigations, or every boot falls back to patching. The result
# boots anywhere; on another CPU view it just patches as usual. -c boots
# CPUS vCPUs (an SMP kernel): an SMP kernel on one CPU patches its SMP
# alternatives out, so pre-patch it with -c 2 for boots with 2 or more.
# Env: EXE (default build/microvm), PYTHON (python3), WRAP (command prefix
# for the VMM, e.g. setpriv to run it unprivileged).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
EXE=${EXE:-build/microvm}
PYTHON=${PYTHON:-python3}
WRAP=${WRAP:-}
kernel=guest/kernel/out/vmlinux out="" append="" cpus=1
while getopts k:o:a:c: opt; do
    case $opt in
    k) kernel=$OPTARG ;;
    o) out=$OPTARG ;;
    a) append=$OPTARG ;;
    c) cpus=$OPTARG ;;
    *) exit 2 ;;
    esac
done
tmp=$(mktemp -d)
chmod 0777 "$tmp" # WRAP may run the VMM as another user
trap 'rm -rf "$tmp"' EXIT
for when in before after; do
    arg=alt_snapshot
    [ "$when" = before ] && arg=alt_snapshot=before
    [ -n "$append" ] && arg="$append $arg"
    # shellcheck disable=SC2086 # WRAP is a command prefix
    log=$($WRAP "$EXE" --kernel "$kernel" --cpus "$cpus" --append "$arg" --dump-mem "$tmp/$when.bin" 2>&1 || true)
    if [ ! -s "$tmp/$when.bin" ] || ! grep -q "snapshot point $when patching reached" <<<"$log"; then
        printf 'snapshot boot (%s) did not reach its stop point:\n%s\n' "$when" "$log" >&2
        exit 1
    fi
done
target=$kernel
if [ -n "$out" ]; then
    cp "$kernel" "$out"
    target=$out
fi
"$PYTHON" "$here/../guest/kernel/prepatch.py" --alternatives "$target" "$tmp/before.bin" "$tmp/after.bin"
