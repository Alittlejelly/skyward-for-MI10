#!/usr/bin/env python3
"""CRC oracle: verify a rebuilt WLAN module against kernel ground truth.

Ground truth: wlan7.ko is the vendor module whose __versions table was
rewritten with the running kernel's actual symbol CRCs (mined from the
Fuutao kernel's ksymtab/kcrctab and validated by the module loading and
probing successfully). Every CRC in wlan7 -- except the ten never-exported
debugfs symbols that kept their vendor values -- is therefore the exact
value the running kernel expects.

Usage: python check_crc.py <rebuilt.ko> [truth.ko]
Compare: for each symbol the rebuilt module references, its CRC must equal
the truth CRC. Any mismatch = struct layout divergence = do not flash.
"""
import struct
import sys


def read_versions(path):
    d = open(path, 'rb').read()
    assert d[:4] == b'\x7fELF' and d[4] == 2, f"{path}: not ELF64"
    e_shoff = struct.unpack_from('<Q', d, 0x28)[0]
    e_shnum = struct.unpack_from('<HHH', d, 0x3A)[1]
    e_shstrndx = struct.unpack_from('<HHH', d, 0x3A)[2]
    secs = [struct.unpack_from('<IIQQQQIIQQ', d, e_shoff + i * 64)
            for i in range(e_shnum)]
    shstr = secs[e_shstrndx]

    def sname(off):
        e = d.index(b'\0', shstr[4] + off)
        return d[shstr[4] + off:e].decode()

    ver = None
    for s in secs:
        if sname(s[0]) == '__versions':
            ver = s
            break
    if ver is None:
        raise SystemExit(f"{path}: no __versions (MODVERSIONS off?)")
    out = {}
    for i in range(ver[5] // 64):
        off = ver[4] + i * 64
        crc = struct.unpack_from('<Q', d, off)[0]
        name = d[off + 8:off + 64].split(b'\0')[0].decode()
        if name:
            out[name] = crc
    return out


def main():
    new = read_versions(sys.argv[1])
    truth = read_versions(sys.argv[2] if len(sys.argv) > 2
                          else r'C:/Users/18978/AppData/Local/Temp/wlan7.ko')
    common = set(new) & set(truth)
    only_new = sorted(set(new) - set(truth))
    only_truth = sorted(set(truth) - set(new))

    bad = [(n, truth[n], new[n]) for n in common if truth[n] != new[n]]
    print(f"rebuilt references {len(new)} symbols, truth has {len(truth)}")
    print(f"common: {len(common)}, CRC match: {len(common) - len(bad)}, "
          f"MISMATCH: {len(bad)}")
    for n, t, v in bad[:40]:
        print(f"  {n}: kernel={t:#x} rebuilt={v:#x}")
    if bad:
        print("\nVERDICT: FAIL — layout divergence, do not flash")
        sys.exit(1)
    print(f"only in rebuilt ({len(only_new)}): {only_new[:15]}")
    print(f"only in truth ({len(only_truth)}): {only_truth[:15]}")
    print("\nVERDICT: PASS — ABI matches the running kernel")


if __name__ == '__main__':
    main()
