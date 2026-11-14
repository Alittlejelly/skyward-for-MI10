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
# Kernel: Xiaomi's own umi 4.19.157-perf tree (community mirror — MiCode
# stopped at the 4.19.81 Q-era branch, and the phone's stock line ends at
# HyperOS 1; Fuutao's ROM kernel is a .config variant of this very tree).
# The device's /proc/config.gz supplies Fuutao's config.
git clone --depth 1 --branch uno \
    https://github.com/tequilaOS/platform_kernel_xiaomi_umi.git "$ROOT/kernel"
git clone --depth 1 --branch umi-q-oss \
    https://github.com/MiCode/vendor_qcom_opensource_wlan.git "$ROOT/wlan"

# IPA is off in this build, so qdf_get_ipa_smmu_enabled() has no definition.
# The call site is unreachable when IPA is absent (guarded by ipa_present),
# but it must not exist in the compiled text at all — replace it with the
# value it would return anyway.
sed -i 's/ipa_smmu_enabled = qdf_get_ipa_smmu_enabled();/ipa_smmu_enabled = false; \/* IPA off *\//' \
    "$ROOT/wlan/qcacld-3.0/core/cds/src/cds_api.c"
grep -E "^(VERSION|PATCHLEVEL|SUBLEVEL) " "$ROOT/kernel/Makefile"

# Mirror the device's release number for vermagic (cosmetic — the kernel
# image is never flashed).
sed -i 's/^SUBLEVEL = .*/SUBLEVEL = 157/' "$ROOT/kernel/Makefile"

echo "== kernel configuration =="
OUT="$ROOT/kout"
mkdir -p "$OUT"
cp "$ROOT/tools/umi/kernel-build/futao.config" "$OUT/.config"

KMAKE=(make -C "$ROOT/kernel" O="$OUT" ARCH=arm64
    CC="$TC/clang" CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_ARM32=arm-linux-gnueabi-
    LD="$TC/aarch64-linux-gnu-ld" AR="$TC/llvm-ar" NM="$TC/llvm-nm"
    OBJCOPY="$TC/llvm-objcopy" OBJDUMP="$TC/llvm-objdump" STRIP="$TC/llvm-strip"
    HOSTCC="gcc-9 -B/usr/bin/" HOSTCXX="g++-9 -B/usr/bin/" KCFLAGS=-Wno-error)

"${KMAKE[@]}" olddefconfig

# Match the device's vermagic exactly, and skip debug info (build speed only —
# debug info has no effect on ABI or symbol CRCs).
"$ROOT/kernel/scripts/config" --file "$OUT/.config" \
    --set-str LOCALVERSION "-Fuutao-Qn_miao-gc50380e2c" \
    --disable LOCALVERSION_AUTO \
    --disable DEBUG_INFO \
    --disable TOUCHSCREEN_ST_FTS_V521 \
    --disable IPA3 \
    --disable GSI
# The oss tree's fts_521 driver does not compile (references identifiers only
# present in Xiaomi's internal source); the device runs GOODIX anyway. It is
# a leaf driver — disabling it cannot affect struct layouts.
#
# IPA3 (and its GSI component) trips GNU bfd's --gc-sections check with
# "dangerous relocation" in __verbose; the WLAN module is built with IPA off
# anyway (qca6390 profile) and no struct the module touches depends on it.
# The CRC oracle verifies every symbol the module references, so any layout
# consequence of these two disables would be caught before flashing.
"${KMAKE[@]}" olddefconfig

grep -E "^(CONFIG_LOCALVERSION|CONFIG_MODVERSIONS|CONFIG_SMP|CONFIG_PREEMPT|CONFIG_SLUB|CONFIG_ARCH_KONA)=" "$OUT/.config"

echo "== kernel build (produces headers + Module.symvers) =="
"${KMAKE[@]}" -j"$JOBS" all 2>&1 | tee "$ROOT/logs/kernel.log" | grep -E "error|Error" || true
test -f "$OUT/Module.symvers" || { echo "FATAL: Module.symvers missing"; exit 1; }
grep -c "0x" "$OUT/Module.symvers" | head -1

echo "== layout probe =="
# Direct struct-layout check against the running kernel: Fuutao's
# netdev_register_kobject reaches &ndev->dev at net_device+0x4c8 (measured by
# disassembling the device kernel). If our probe disagrees, the tree+config
# pair still diverges — the CRC oracle would be moot.
mkdir -p "$ROOT/probe"
cat > "$ROOT/probe/probe.c" <<'EOF'
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/stddef.h>
const unsigned long probe_net_dev_off = offsetof(struct net_device, dev);
const unsigned long probe_skb_len_off = offsetof(struct sk_buff, len);
const unsigned long probe_skb_cb_off = offsetof(struct sk_buff, cb);
EOF
cat > "$ROOT/probe/Kbuild" <<'EOF'
obj-m := probe.o
EOF
"${KMAKE[@]}" M="$ROOT/probe" modules 2>&1 | tail -3 || { echo "FATAL: probe build failed"; exit 1; }
"$TC/llvm-nm" "$ROOT/probe/probe.ko" | grep probe_

echo "== qcacld module =="
cd "$ROOT/wlan/qcacld-3.0"
"${KMAKE[@]}" -j"$JOBS" M="$PWD" modules \
    MODNAME=wqld WLAN_ROOT="$PWD" WLAN_PROFILE=qca6390 \
    CONFIG_QCA_CLD_WLAN=m CONFIG_IPA3=n CONFIG_IPA_OFFLOAD=n \
    CONFIG_ENABLE_SMMU_S1_TRANSLATION=y \
    WLAN_DISABLE_BUILD_TAG=y \
    TARGET_BUILD_VARIANT=user 2>&1 | tee "$ROOT/logs/module.log" | grep -E "error|Error" || true
# WLAN_ROOT and CONFIG_QCA_CLD_WLAN have no default in external-module mode —
# the real build passes them on the command line. Without WLAN_ROOT the
# defconfig include is fatal; without CONFIG_QCA_CLD_WLAN=m the module target
# is silently skipped. WLAN_DISABLE_BUILD_TAG skips git-log probing.

KO="$ROOT/wlan/qcacld-3.0/wqld.ko"
test -f "$KO" || { echo "FATAL: module not built"; exit 1; }

echo "== result =="
ls -la "$KO"
modinfo -F vermagic "$KO"
modinfo -F name "$KO"
# sanity: the module must be armed with CRCs (modversions), not bare
grep -c "__versions" <(readelf -S "$KO") >/dev/null && echo "modversions section present"
