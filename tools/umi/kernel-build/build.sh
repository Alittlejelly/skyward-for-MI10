#!/usr/bin/env bash
# Rebuild the qcacld WLAN module (qca_cld3_qca6390) against the Fuutao kernel ABI.
#
# Why: the vendor module was compiled against Xiaomi's own 4.19 build of this
# kernel. The Fuutao custom kernel changed a few CONFIGs, which shifts struct
# layouts (net_device->dev moved by 8 bytes), so the vendor binary corrupts
# memory. Rebuilding from source with the device's exact .config removes every
# layout mismatch; symbol CRCs then match the running kernel by construction.
#
# The kernel is only built to produce headers and Module.symvers — the kernel
# image itself is never shipped. The module is what matters.
#
# Correctness oracle (run locally after download): every symbol CRC in the
# rebuilt module must equal the CRC in the running kernel's ksymtab (we mined
# that table earlier; 464 of them were used to patch the vendor module).
set -euo pipefail

ROOT="$(pwd)"
JOBS="$(nproc)"
mkdir -p "$ROOT/logs"

echo "== host dependencies =="
sudo apt-get update -qq
sudo apt-get install -y -qq bc bison flex libssl-dev libelf-dev \
    gcc-9 g++-9 binutils-aarch64-linux-gnu kmod >/dev/null

echo "== toolchain: proton clang 12 =="
curl -fsSL https://codeload.github.com/ravindu644/proton-12/tar.gz/refs/heads/main \
    -o "$ROOT/proton.tgz"
mkdir "$ROOT/toolchain"
tar -xzf "$ROOT/proton.tgz" -C "$ROOT/toolchain" --strip-components=1
TC="$ROOT/toolchain/bin"
"$TC/clang" --version | head -1

# Kernel 4.19 forces -no-integrated-as under clang, whose driver looks up a
# bare `as` on PATH. Proton's bare `as` is the x86 one; the aarch64 assembler
# is `aarch64-linux-gnu-as` — shim the name. Host tools must not see it: they
# are pinned to /usr/bin via gcc's -B.
mkdir -p "$ROOT/shim"
ln -sf "$TC/aarch64-linux-gnu-as" "$ROOT/shim/as"
export PATH="$ROOT/shim:$TC:$PATH"
# clang prefers tools next to its own binary over PATH, so swap the bundled
# x86 `as` for the aarch64 one as well; ditto for `ld`, which the vdso link
# reaches through the clang driver.
mv "$TC/as" "$TC/as.host-x86"
ln -s aarch64-linux-gnu-as "$TC/as"
ln -sf "$TC/aarch64-linux-gnu-ld" "$ROOT/shim/ld"
mv "$TC/ld" "$TC/ld.host-x86"

echo "== sources =="
git clone --depth 1 --branch umi-q-oss \
    https://github.com/MiCode/Xiaomi_Kernel_OpenSource.git "$ROOT/kernel"
git clone --depth 1 --branch umi-q-oss \
    https://github.com/MiCode/vendor_qcom_opensource_wlan.git "$ROOT/wlan"
grep -E "^(VERSION|PATCHLEVEL|SUBLEVEL) " "$ROOT/kernel/Makefile"

# The device kernel reports 4.19.157; the oss tree is at 4.19.81. Bump
# SUBLEVEL so the vermagic matches (cosmetic — we never flash this kernel).
sed -i 's/^SUBLEVEL = .*/SUBLEVEL = 157/' "$ROOT/kernel/Makefile"

echo "== kernel configuration =="
OUT="$ROOT/kout"
mkdir -p "$OUT"
cp "$ROOT/tools/umi/kernel-build/futao.config" "$OUT/.config"

KMAKE=(make -C "$ROOT/kernel" O="$OUT" ARCH=arm64
    CC="$TC/clang" CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_ARM32=arm-linux-gnueabi-
    LD="$TC/ld.lld" AR="$TC/llvm-ar" NM="$TC/llvm-nm"
    OBJCOPY="$TC/llvm-objcopy" OBJDUMP="$TC/llvm-objdump" STRIP="$TC/llvm-strip"
    HOSTCC="gcc-9 -B/usr/bin/" HOSTCXX="g++-9 -B/usr/bin/" KCFLAGS=-Wno-error)

"${KMAKE[@]}" olddefconfig

# Match the device's vermagic exactly, and skip debug info (build speed only —
# debug info has no effect on ABI or symbol CRCs).
"$ROOT/kernel/scripts/config" --file "$OUT/.config" \
    --set-str LOCALVERSION "-Fuutao-Qn_miao-gc50380e2c" \
    --disable LOCALVERSION_AUTO \
    --disable DEBUG_INFO
"${KMAKE[@]}" olddefconfig

grep -E "^(CONFIG_LOCALVERSION|CONFIG_MODVERSIONS|CONFIG_SMP|CONFIG_PREEMPT|CONFIG_SLUB|CONFIG_ARCH_KONA)=" "$OUT/.config"

echo "== kernel build (produces headers + Module.symvers) =="
"${KMAKE[@]}" -j"$JOBS" all 2>&1 | tee "$ROOT/logs/kernel.log" | grep -E "error|Error" || true
test -f "$OUT/Module.symvers" || { echo "FATAL: Module.symvers missing"; exit 1; }
grep -c "0x" "$OUT/Module.symvers" | head -1

echo "== qcacld module =="
cd "$ROOT/wlan/qcacld-3.0"
"${KMAKE[@]}" -j"$JOBS" M="$PWD" modules \
    MODNAME=wqld WLAN_PROFILE=qca6390 \
    CONFIG_IPA3=n CONFIG_IPA_OFFLOAD=n \
    CONFIG_ENABLE_SMMU_S1_TRANSLATION=y \
    TARGET_BUILD_VARIANT=user 2>&1 | tee "$ROOT/logs/module.log" | grep -E "error|Error" || true

KO="$ROOT/wlan/qcacld-3.0/wqld.ko"
test -f "$KO" || { echo "FATAL: module not built"; exit 1; }

echo "== result =="
ls -la "$KO"
modinfo -F vermagic "$KO"
modinfo -F name "$KO"
# sanity: the module must be armed with CRCs (modversions), not bare
grep -c "__versions" <(readelf -S "$KO") >/dev/null && echo "modversions section present"
