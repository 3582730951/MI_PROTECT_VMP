#!/usr/bin/env python3
import json
import math
import pathlib
import re
import shutil
import struct
import subprocess
import sys
from collections import Counter


def fail(msg: str) -> None:
    raise SystemExit(msg)


def sh(cmd: list[str | pathlib.Path], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    text_cmd = [str(part) for part in cmd]
    res = subprocess.run(text_cmd, text=True, capture_output=True)
    if check and res.returncode != 0:
        raise SystemExit(
            f"command failed ({res.returncode}): {' '.join(text_cmd)}\nstdout:\n{res.stdout}\nstderr:\n{res.stderr}"
        )
    return res


def parse_pe(path: pathlib.Path):
    data = path.read_bytes()
    if data[:2] != b'MZ':
        fail('not mz')
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b'PE\0\0':
        fail('not pe')
    file_hdr_off = pe_off + 4
    machine, section_count, _, ptr_sym, nsyms, opt_size, _ = struct.unpack_from('<HHIIIHH', data, file_hdr_off)
    sec_off = file_hdr_off + 20 + opt_size
    string_table_off = ptr_sym + nsyms * 18
    string_table_size = 0
    if ptr_sym and string_table_off + 4 <= len(data):
        string_table_size = struct.unpack_from('<I', data, string_table_off)[0]

    def resolve_section_name(raw_field: bytes) -> str:
        short = raw_field.split(b'\0', 1)[0].decode(errors='replace')
        if not short.startswith('/') or len(short) == 1 or not short[1:].isdigit() or string_table_size < 4:
            return short
        offset = int(short[1:])
        if offset >= string_table_size:
            return short
        start = string_table_off + offset
        end = data.find(b'\0', start, string_table_off + string_table_size)
        if end == -1:
            end = string_table_off + string_table_size
        return data[start:end].decode(errors='replace')

    sections = []
    for idx in range(section_count):
        off = sec_off + idx * 40
        name = resolve_section_name(data[off:off + 8])
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from('<IIII', data, off + 8)
        characteristics = struct.unpack_from('<I', data, off + 36)[0]
        sections.append({
            'index': idx + 1,
            'name': name,
            'virtual_size': virtual_size,
            'virtual_address': virtual_address,
            'raw_size': raw_size,
            'raw_ptr': raw_ptr,
            'characteristics': characteristics,
        })
    return {
        'data': data,
        'machine': machine,
        'sections': sections,
    }


def section_bytes(pe: dict, section: dict) -> bytes:
    start = section['raw_ptr']
    end = start + section['raw_size']
    return pe['data'][start:end]


def entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    counts = Counter(blob)
    total = len(blob)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit('usage: metadata_encrypt_pe.py <vmp-protect> <vmp-trampoline-inject> <binary-dir>')

    protect_tool = pathlib.Path(sys.argv[1])
    trampoline_tool = pathlib.Path(sys.argv[2])
    binary_dir = pathlib.Path(sys.argv[3])
    source_root = pathlib.Path(__file__).resolve().parents[2]
    work = binary_dir / 'tests' / 'runtime_metadata_encrypt'
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    compiler = shutil.which('x86_64-w64-mingw32-gcc') or shutil.which('x86_64-w64-mingw32-clang')
    if not compiler:
        print('SKIP_REASON: mingw compiler unavailable')
        return

    src = source_root / 'tests' / 'integration_targets' / 'target_c.c'
    include_dir = source_root / 'bindings' / 'cpp' / 'include'
    baseline = work / 'target_c.exe'
    stage1 = work / 'target_c.stage1.exe'
    protected = work / 'target_c.protected.exe'
    sh([compiler, str(src), '-I', str(include_dir), '-O2', '-o', baseline])

    policy = work / 'policy.json'
    policy.write_text(json.dumps({
        'schema_version': 1,
        'defaults': {
            'language_origin': 'binary',
            'annotation_origin': 'external_manifest',
            'protection_domain': 'native',
            'jit_policy': 'off',
            'plaintext_budget': 'transient_only',
            'reaction_policy': 'log',
            'integrity_level': 'basic',
            'platform_caps': ['windows', 'x64'],
            'sensitivity_level': 'normal',
            'profile_seed': 1,
            'mobile_bridge_mode': 'off',
            'event_types': [],
        },
        'entries': [
            {
                'symbol_or_region': 'protected_mix_c',
                'language_origin': 'binary',
                'annotation_origin': 'external_manifest',
                'annotation_tags': ['vm_func'],
                'protection_domain': 'vm1',
                'jit_policy': 'off',
                'plaintext_budget': 'transient_only',
                'reaction_policy': 'log',
                'integrity_level': 'basic',
                'platform_caps': ['windows', 'x64'],
                'sensitivity_level': 'normal',
                'profile_seed': 1,
                'mobile_bridge_mode': 'off',
                'event_types': [],
            },
            {
                'symbol_or_region': 'kProtectedCString',
                'language_origin': 'binary',
                'annotation_origin': 'external_manifest',
                'annotation_tags': ['vm_string'],
                'protection_domain': 'native',
                'jit_policy': 'off',
                'plaintext_budget': 'transient_only',
                'reaction_policy': 'log',
                'integrity_level': 'basic',
                'platform_caps': ['windows', 'x64'],
                'sensitivity_level': 'highly_sensitive',
                'profile_seed': 1,
                'mobile_bridge_mode': 'off',
                'event_types': [],
            },
        ],
    }, indent=2))

    sh([protect_tool, '--policy', policy, '--input', baseline, '--output', stage1])
    sh([trampoline_tool, '--policy', policy, '--input', stage1, '--output', protected, '--key-context-id', '00112233445566778899aabbccddeeff'])

    strings_out = sh(['strings', '-a', protected]).stdout
    vmp_hits = [line for line in strings_out.splitlines() if re.search(r'vmp', line, re.IGNORECASE)]
    if vmp_hits:
        fail(f'protected binary still leaks vmp markers via strings -a: {vmp_hits[:10]}')

    objdump_h = sh(['objdump', '-h', protected]).stdout
    fixed_names = ['.vmpload', '.vmpvm', '.vmptrmp', '.vmpcode', '.vmpstrings']
    leaked_fixed = [name for name in fixed_names if name in objdump_h]
    if leaked_fixed:
        fail(f'objdump -h still shows fixed VMP section names: {leaked_fixed}')

    protected_pe = parse_pe(protected)
    baseline_pe = parse_pe(baseline)
    baseline_names = {section['name'] for section in baseline_pe['sections']}
    random_sections = [
        section for section in protected_pe['sections']
        if section['name'] not in baseline_names and re.fullmatch(r'\.[a-z0-9]{7}', section['name'])
    ]
    if len(random_sections) < 4:
        fail(f'expected >=4 randomized section names, got {[section["name"] for section in random_sections]}')

    data_sections = [section for section in random_sections if (section['characteristics'] & 0x20000000) == 0]
    if not data_sections:
        fail('no randomized non-executable data sections found')
    max_entropy = max(entropy(section_bytes(protected_pe, section)) for section in data_sections)
    if max_entropy <= 7.5:
        fail(f'max randomized data-section entropy too low: {max_entropy:.4f}')

    import_dump = sh(['objdump', '-p', protected]).stdout
    if re.search(r'\bVirtualProtect\b|\bVirtualQuery\b', import_dump):
        fail('import table still contains VirtualProtect/VirtualQuery')

    print('runtime_metadata_encrypt_pe OK')


if __name__ == '__main__':
    main()
