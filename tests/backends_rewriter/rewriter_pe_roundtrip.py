#!/usr/bin/env python3
import json
import pathlib
import re
import shutil
import struct
import subprocess
import sys


def parse_sections(path: pathlib.Path):
    data = path.read_bytes()
    if data[:2] != b'MZ':
        raise SystemExit('not mz')
    pe_off = struct.unpack_from('<I', data, 0x3c)[0]
    if data[pe_off:pe_off+4] != b'PE\0\0':
        raise SystemExit('not pe')
    num = struct.unpack_from('<H', data, pe_off + 6)[0]
    opt = struct.unpack_from('<H', data, pe_off + 20)[0]
    sec_off = pe_off + 24 + opt
    names = []
    for i in range(num):
        name = data[sec_off + 40*i: sec_off + 40*i + 8].split(b'\0',1)[0].decode(errors='replace')
        names.append(name)
    return data, names


def main():
    tool = pathlib.Path(sys.argv[1])
    binary_dir = pathlib.Path(sys.argv[2])
    work = binary_dir / 'tests' / 'rewriter_pe_roundtrip'
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    compiler = shutil.which('x86_64-w64-mingw32-gcc') or shutil.which('x86_64-w64-mingw32-clang')
    if not compiler:
        print('SKIP_REASON: mingw compiler unavailable')
        return
    src = work / 'hello.c'
    src.write_text('int main(void){return 0;}\n')
    pe = work / 'hello.exe'
    subprocess.run([compiler, str(src), '-o', str(pe)], check=True)
    policy = work / 'policy.json'
    out = work / 'out.exe'
    policy.write_text(json.dumps({'schema_version':1,'defaults':{'language_origin':'binary','annotation_origin':'external_manifest','protection_domain':'native','jit_policy':'off','plaintext_budget':'transient_only','reaction_policy':'log','integrity_level':'basic','platform_caps':['windows','x64'],'sensitivity_level':'normal','profile_seed':1,'mobile_bridge_mode':'off','event_types':[]},'entries':[]}, indent=2))
    subprocess.run([str(tool), '--policy', str(policy), '--input', str(pe), '--output', str(out)], check=True)
    _, baseline_names = parse_sections(pe)
    _, names = parse_sections(out)
    fixed = {'.vmpload', '.vmpvm', '.vmptrmp', '.vmpcode', '.vmpstrings'}
    leaked = sorted(name for name in names if name in fixed)
    if leaked:
        raise SystemExit(f'fixed VMP section names still visible: {leaked}')
    randomized = [name for name in names if name not in baseline_names and re.fullmatch(r'\.[a-z0-9]{7}', name)]
    if not randomized:
        raise SystemExit(f'missing randomized metadata section: {names}')
    if '.CRT$XLB' not in names:
        raise SystemExit(f'missing .CRT$XLB callback section: {names}')
    print('rewriter_pe_roundtrip OK')

if __name__ == '__main__':
    main()
