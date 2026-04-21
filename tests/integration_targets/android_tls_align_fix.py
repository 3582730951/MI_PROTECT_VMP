#!/usr/bin/env python3
from __future__ import annotations

import argparse
import pathlib
import struct
import sys

PT_TLS = 7


def patch_tls_alignment(path: pathlib.Path) -> bool:
    with path.open('r+b') as f:
        ident = f.read(16)
        if ident[:4] != b'\x7fELF':
            raise SystemExit(f'{path} is not an ELF file')
        elf_class = ident[4]
        if elf_class not in (1, 2):
            raise SystemExit(f'{path} has unsupported ELF class {elf_class}')

        if elf_class == 1:
            f.seek(28)
            e_phoff = struct.unpack('<I', f.read(4))[0]
            f.seek(42)
            e_phentsize = struct.unpack('<H', f.read(2))[0]
            e_phnum = struct.unpack('<H', f.read(2))[0]
            min_align = 32
            align_field = 28
            align_fmt = '<I'
        else:
            f.seek(32)
            e_phoff = struct.unpack('<Q', f.read(8))[0]
            f.seek(54)
            e_phentsize = struct.unpack('<H', f.read(2))[0]
            e_phnum = struct.unpack('<H', f.read(2))[0]
            min_align = 64
            align_field = 48
            align_fmt = '<Q'

        patched = False
        for index in range(e_phnum):
            entry_off = e_phoff + index * e_phentsize
            f.seek(entry_off)
            p_type = struct.unpack('<I', f.read(4))[0]
            if p_type != PT_TLS:
                continue
            f.seek(entry_off + align_field)
            current = struct.unpack(align_fmt, f.read(struct.calcsize(align_fmt)))[0]
            if current >= min_align:
                continue
            f.seek(entry_off + align_field)
            f.write(struct.pack(align_fmt, min_align))
            patched = True
        return patched


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('elf')
    args = parser.parse_args()
    path = pathlib.Path(args.elf)
    patched = patch_tls_alignment(path)
    print(f'tls_align_patch elf={path} patched={str(patched).lower()}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
