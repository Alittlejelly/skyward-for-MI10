#!/usr/bin/env python3
"""Patch a rebuilt module's __versions table with the running kernel's CRCs.

Fuutao's tree carries header modifications, so a source-rebuilt module's
genksyms CRCs can never match its kcrctab by construction. But the kernel's
real CRC values were mined from its ksymtab/kcrctab and are proven correct:
wlan7.ko (the vendor module carrying them) passed the kernel's enforced
check_version for every symbol it references.

CRC correctness only gates loading. Memory safety depends on struct layout,
verified separately (layout probe + oracle match pattern). A layout-correct
module with patched CRCs loads and runs safely.

Usage: python patch_crcs.py <module.ko> <truth.ko> [-o out.ko]
"""
import struct
import sys

sys.path.insert(0, __file__.rsplit('/', 1)[0] if '/' in __file__ else '.')
from check_crc import read_versions


def main():
    path = sys.argv[1]
    truth_path = sys.argv[2] if len(sys.argv) > 2 else \
        r'C:/Users/18978/AppData/Local/Temp/wlan7.ko'
    out = sys.argv[sys.argv.index('-o') + 1] if '-o' in sys.argv else path

    truth = read_versions(truth_path)
    d = bytearray(open(path, 'rb').read())

    e_shoff = struct.unpack_from('<Q', d, 0x28)[0]
    e_shstrndx = struct.unpack_from('<HHH', d, 0x3A)[2]
    e_shnum = struct.unpack_from('<HHH', d, 0x3A)[1]
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
        raise SystemExit('no __versions section')

    n = ver[5] // 64
    patched = missing = 0
    for i in range(n):
        off = ver[4] + i * 64
        name = d[off + 8:off + 64].split(b'\0')[0].decode()
        if name in truth:
            struct.pack_into('<Q', d, off, truth[name])
            patched += 1
        else:
            missing += 1
            print(f"  WARN: {name} not in truth table — left as built")

    open(out, 'wb').write(d)
    print(f"patched {patched}/{n} CRCs, {missing} missing from truth -> {out}")


if __name__ == '__main__':
    main()
