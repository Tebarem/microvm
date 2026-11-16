#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Cold-start benchmark (Linux / KVM). Every run is a fresh process.
#   N=100 tools/bench.sh --kernel guest/kernel/out/vmlinux --quiet --ws ws.txt
# Several configurations, interleaved run by run so clock and background-load
# drift hit them all equally (each one a quoted argument string):
#   tools/bench.sh -c "--kernel vmlinux --quiet" -c "--kernel vmlinux --quiet --ws ws.txt"
# Reports min / p50 / p90 for each MVMTRACE field plus wall-clock process
# time. Env: N (runs per configuration), EXE, WRAP (a command prefix, e.g.
# "setpriv --reuid=nobody --regid=nogroup --groups=kvm --no-new-privs" to
# run unprivileged), STATUS (the exit status every run must end with, 0).
set -euo pipefail
N=${N:-50}
EXE=${EXE:-build/microvm}
WRAP=${WRAP:-}
STATUS=${STATUS:-0}
configs=()
if [ "${1:-}" = "-c" ]; then
    while [ $# -gt 0 ]; do
        [ "$1" = "-c" ] && [ $# -ge 2 ] || { echo "usage: $0 [-c ARGS]... | ARGS..." >&2; exit 2; }
        configs+=("$2")
        shift 2
    done
else
    [ $# -gt 0 ] || set -- --hello
    configs+=("$*")
fi
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

for ((i = 0; i < N; i++)); do
    for ((c = 0; c < ${#configs[@]}; c++)); do
        t0=$(date +%s%N)
        set +e
        # shellcheck disable=SC2086 # word splitting of WRAP / the config is intended
        out=$($WRAP "$EXE" --trace ${configs[c]} 2>&1 >/dev/null)
        rc=$?
        set -e
        t1=$(date +%s%N)
        if [ "$rc" -ne "$STATUS" ]; then
            printf 'config %d run %d: status %d, expected %d\n%s\n' "$c" "$i" "$rc" "$STATUS" "$out" >&2
            exit 1
        fi
        line=$(printf '%s\n' "$out" | grep '^MVMTRACE' | tail -1)
        echo "$line wall_us=$(((t1 - t0) / 1000))" >>"$dir/$c"
    done
done

for ((c = 0; c < ${#configs[@]}; c++)); do
    echo "config $c, $N runs: ${configs[c]}"
    printf '  %-14s %10s %10s %10s\n' metric min p50 p90
    fields=$(tr ' ' '\n' <"$dir/$c" | grep -E '^[a-z0-9_]+=[0-9.]+$' | cut -d= -f1 | sort -u)
    for f in $fields; do
        [ "$f" = start_unix_us ] && continue
        tr ' ' '\n' <"$dir/$c" | grep "^$f=" | cut -d= -f2 | sort -g |
            awk -v f="$f" '{ a[NR] = $1 } END {
                printf "  %-14s %10.1f %10.1f %10.1f\n", f, a[1], a[int(0.5 * (NR - 1)) + 1], a[int(0.9 * (NR - 1)) + 1] }'
    done
done
