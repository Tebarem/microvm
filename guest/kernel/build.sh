#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Build the microvm guest kernel (uncompressed vmlinux with a built-in
# initramfs containing guest/init). Run on Linux or inside WSL; no KVM needed.
#
#   guest/kernel/build.sh            -> guest/kernel/out/vmlinux
#   VARIANT=smp guest/kernel/build.sh -> guest/kernel/out/vmlinux-smp: the
#       same kernel with config-smp.fragment on top, for VMs with several
#       vCPUs (--cpus), in its own source tree
#   KVER=6.18.60 WORK=/tmp/k ./build.sh
set -euo pipefail

KVER=${KVER:-6.18.60}
# Pinned on first download (trust-on-first-use); update together with KVER.
KSHA256=${KSHA256:-}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
WORK=${WORK:-$HOME/.cache/microvm-kernel}
OUT=$HERE/out
VARIANT=${VARIANT:-}
case "$VARIANT" in "" | smp) ;; *) echo "unknown VARIANT '$VARIANT'" >&2; exit 2 ;; esac
SUFFIX=${VARIANT:+-$VARIANT}
SRC=$WORK/linux-$KVER$SUFFIX
JOBS=${JOBS:-$(nproc)}

mkdir -p "$WORK" "$OUT"

# 1. /init: freestanding, static, stripped.
gcc -std=c2x -O2 -static -nostdlib -ffreestanding -fno-stack-protector \
    -fno-asynchronous-unwind-tables -fno-pie -no-pie -Wl,--build-id=none -s \
    -Wall -Wextra -Werror -o "$WORK/init" "$ROOT/guest/init/init.c" "$ROOT/guest/init/agent.c" \
    "$ROOT/guest/init/image.c" "$ROOT/guest/init/sbx.c"

# /dev/console is the null device: the kernel log goes to the microvm console
# port (no tty behind it), and /init talks to the VMM through ports, not stdio.
# A real tty node would only make the kernel warn that it can't open it.
cat > "$WORK/initramfs.list" <<EOF
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 1 3
nod /dev/kmsg 0600 0 0 c 1 11
nod /dev/urandom 0600 0 0 c 1 9
nod /dev/pmem0 0400 0 0 b 259 0
dir /rootfs 0755 0 0
file /init $WORK/init 0755 0 0
EOF

# 2. kernel source (verified) + our patches. Re-extracted whenever the patch
#    set changes, so the tree always equals tarball + patches/*.patch.
PATCH_ID=$(cat "$HERE"/patches/*.patch 2>/dev/null | sha256sum | cut -d' ' -f1)
if [ "$(cat "$SRC/.microvm-patched" 2>/dev/null)" != "$PATCH_ID" ]; then
    TARBALL=$WORK/linux-$KVER.tar.xz
    if [ ! -f "$TARBALL" ]; then
        curl -fL --proto '=https' -o "$TARBALL.part" \
            "https://cdn.kernel.org/pub/linux/kernel/v${KVER%%.*}.x/linux-$KVER.tar.xz"
        mv "$TARBALL.part" "$TARBALL"
    fi
    if [ -z "$KSHA256" ]; then
        # Cross-check against kernel.org's published sums when no pin is set.
        curl -fsSL --proto '=https' \
            "https://cdn.kernel.org/pub/linux/kernel/v${KVER%%.*}.x/sha256sums.asc" |
            grep " linux-$KVER.tar.xz\$" | (cd "$WORK" && sha256sum -c -)
    else
        echo "$KSHA256  $TARBALL" | sha256sum -c -
    fi
    rm -rf "$SRC" "$WORK/extract$SUFFIX"
    mkdir "$WORK/extract$SUFFIX"
    tar -xJf "$TARBALL" -C "$WORK/extract$SUFFIX"
    mv "$WORK/extract$SUFFIX/linux-$KVER" "$SRC"
    rmdir "$WORK/extract$SUFFIX"
    for p in "$HERE"/patches/*.patch; do
        [ -e "$p" ] || continue
        echo "applying $(basename "$p")"
        patch -d "$SRC" -p1 --forward < "$p"
    done
    echo "$PATCH_ID" > "$SRC/.microvm-patched"
fi

# 3. config: tinyconfig + our fragment.
cd "$SRC"
make -s tinyconfig
FRAGMENTS=("$HERE/config.fragment")
[ -n "$VARIANT" ] && FRAGMENTS+=("$HERE/config-$VARIANT.fragment")
scripts/kconfig/merge_config.sh -m .config "${FRAGMENTS[@]}" >/dev/null
scripts/config --set-str INITRAMFS_SOURCE "$WORK/initramfs.list"
make -s olddefconfig

# Fail loudly if Kconfig silently dropped something we rely on.
missing=0
while IFS= read -r line; do
    case "$line" in CONFIG_*=*) ;; *) continue ;; esac
    if ! grep -qx "$line" .config; then
        echo "warning: config.fragment wants '$line' but .config disagrees" >&2
        missing=1
    fi
done < <(cat "${FRAGMENTS[@]}" | awk -F= '/^CONFIG_/ { want[$1] = $0 } END { for (k in want) print want[k] }')
[ "$missing" = 0 ] || [ "${ALLOW_CONFIG_DRIFT:-0}" = 1 ] || {
    echo "set ALLOW_CONFIG_DRIFT=1 to build anyway" >&2
    exit 1
}

# 4. build.
make -s -j"$JOBS" vmlinux
cp vmlinux "$OUT/vmlinux$SUFFIX"
cp .config "$OUT/config$SUFFIX"
cp System.map "$OUT/System.map$SUFFIX"

# 5. pre-patch the return sites for this host's return thunk (patch 0019;
#    RETURN_THUNK=none keeps the image as compiled).
python3 "$HERE/prepatch.py" "$OUT/vmlinux$SUFFIX" "${RETURN_THUNK:-auto}"
if [ -n "$VARIANT" ]; then
    ls -l "$OUT/vmlinux$SUFFIX"
    exit 0
fi

# 6. the test root filesystem layer (ctest: microvm-mkrootfs + --rootfs).
T=$WORK/test-layer
rm -rf "$T" && mkdir -p "$T/bin" "$T/etc"
gcc -std=c2x -O2 -static -nostdlib -ffreestanding -fno-stack-protector \
    -fno-asynchronous-unwind-tables -fno-pie -no-pie -Wl,--build-id=none -s \
    -Wall -Wextra -Werror -o "$T/bin/probe" "$ROOT/guest/rootfs-test/probe.c"
gcc -std=c2x -O2 -static -nostdlib -ffreestanding -fno-stack-protector \
    -fno-asynchronous-unwind-tables -fno-pie -no-pie -Wl,--build-id=none -s \
    -Wall -Wextra -Werror -o "$T/bin/vsock-echo" "$ROOT/guest/rootfs-test/vsock-echo.c"
gcc -std=c2x -O2 -static -nostdlib -ffreestanding -fno-stack-protector \
    -fno-asynchronous-unwind-tables -fno-pie -no-pie -Wl,--build-id=none -s \
    -Wall -Wextra -Werror -o "$T/bin/fn-demo" "$ROOT/guest/rootfs-test/fn-demo.c"
gcc -std=c2x -O2 -static -nostdlib -ffreestanding -fno-stack-protector \
    -fno-asynchronous-unwind-tables -fno-pie -no-pie -Wl,--build-id=none -s \
    -Wall -Wextra -Werror -o "$T/bin/net-probe" "$ROOT/guest/rootfs-test/net-probe.c"
gcc -std=c2x -O2 -static -nostdlib -ffreestanding -fno-stack-protector \
    -fno-asynchronous-unwind-tables -fno-pie -no-pie -Wl,--build-id=none -s \
    -Wall -Wextra -Werror -o "$T/bin/sbx-demo" "$ROOT/guest/rootfs-test/sbx-demo.c"
printf 'root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000::/:/bin/sh\n' > "$T/etc/passwd"
printf 'root:x:0:\nuser:x:1000:\nextra:x:1001:user\n' > "$T/etc/group"
ln -s probe "$T/bin/p"
echo "from the image" > "$T/etc/message"
tar --numeric-owner --owner=0 --group=0 --mtime=@0 --sort=name -C "$T" \
    -cf "$OUT/test-layer.tar" .
ls -l "$OUT/vmlinux"
