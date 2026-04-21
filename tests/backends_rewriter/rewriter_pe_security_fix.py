#!/usr/bin/env python3
import json
import pathlib
import re
import shutil
import struct
import subprocess
import sys


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
        'ptr_sym': ptr_sym,
        'nsyms': nsyms,
        'sections': sections,
    }


def find_section(pe: dict, name: str) -> dict:
    for sec in pe['sections']:
        if sec['name'] == name:
            return sec
    raise KeyError(name)


def section_bytes(pe: dict, name: str) -> bytes:
    sec = find_section(pe, name)
    start = sec['raw_ptr']
    end = start + sec['raw_size']
    return pe['data'][start:end]


def rva_to_file_offset(pe: dict, rva: int) -> int:
    for sec in pe['sections']:
        start = sec['virtual_address']
        span = max(sec['virtual_size'], sec['raw_size'])
        end = start + span
        if start <= rva < end:
            return sec['raw_ptr'] + (rva - start)
    raise KeyError(f'no section for rva 0x{rva:x}')


def parse_pdata(pe: dict) -> list[tuple[int, int]]:
    sec = find_section(pe, '.pdata')
    blob = pe['data'][sec['raw_ptr']:sec['raw_ptr'] + sec['raw_size']]
    out = []
    for off in range(0, len(blob), 12):
        if off + 12 > len(blob):
            break
        begin_rva, end_rva, _unwind = struct.unpack_from('<III', blob, off)
        if begin_rva and end_rva and end_rva > begin_rva:
            out.append((begin_rva, end_rva))
    return out


def find_function_rva_via_objdump(path: pathlib.Path, symbol: str) -> int:
    out = sh(['objdump', '-t', path], check=True).stdout
    pattern = re.compile(rf'^\[[^\n]*\]\(sec\s+(\d+)\)[^\n]*0x([0-9a-fA-F]+)\s+{re.escape(symbol)}$', re.MULTILINE)
    match = pattern.search(out)
    if not match:
        fail(f'failed to find symbol {symbol} in objdump -t output')
    sec_index = int(match.group(1))
    sec_value = int(match.group(2), 16)
    pe = parse_pe(path)
    sec = next((item for item in pe['sections'] if item['index'] == sec_index), None)
    if sec is None:
        fail(f'section index {sec_index} not found for {symbol}')
    return sec['virtual_address'] + sec_value


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit('usage: rewriter_pe_security_fix.py <vmp-protect> <vmp-trampoline-inject> <binary-dir>')

    protect_tool = pathlib.Path(sys.argv[1])
    trampoline_tool = pathlib.Path(sys.argv[2])
    binary_dir = pathlib.Path(sys.argv[3])
    source_root = pathlib.Path(__file__).resolve().parents[2]
    work = binary_dir / 'tests' / 'rewriter_pe_security_fix'
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

    baseline_pe = parse_pe(baseline)
    stage1_pe = parse_pe(stage1)
    protected_pe = parse_pe(protected)
    baseline_names = {sec['name'] for sec in baseline_pe['sections']}
    randomized = [sec for sec in protected_pe['sections'] if sec['name'] not in baseline_names and re.fullmatch(r'\.[a-z0-9]{7}', sec['name'])]
    if len(randomized) < 4:
        fail(f'expected >=4 randomized section names, got {[sec["name"] for sec in randomized]}')
    stage1_randomized = {
        sec['name'] for sec in stage1_pe['sections']
        if sec['name'] not in baseline_names and re.fullmatch(r'\.[a-z0-9]{7}', sec['name'])
    }
    protected_randomized = {
        sec['name'] for sec in protected_pe['sections']
        if sec['name'] not in baseline_names and re.fullmatch(r'\.[a-z0-9]{7}', sec['name'])
    }
    new_randomized = sorted(protected_randomized - stage1_randomized)
    if len(new_randomized) != 2:
        fail(f'expected exactly 2 new randomized sections after trampoline pass, got {new_randomized}')
    leaked_fixed = [name for name in ('.vmpload', '.vmpvm', '.vmptrmp', '.vmpcode', '.vmpstrings') if name in {sec['name'] for sec in protected_pe['sections']}]
    if leaked_fixed:
        fail(f'fixed VMP section names still visible: {leaked_fixed}')

    protected_strings = sh(['strings', '-a', protected], check=True).stdout
    if 'c-target::vm-string::delta-42' in protected_strings:
        fail('protected VM string still visible in strings -a output')

    table_output = sh(['objdump', '-t', protected], check=True).stdout
    if 'protected_mix_c' in table_output:
        fail('protected_mix_c still visible in objdump -t output')
    if 'kProtectedCString' in table_output:
        fail('kProtectedCString still visible in objdump -t output')

    func_rva = find_function_rva_via_objdump(baseline, 'protected_mix_c')
    pdata = parse_pdata(baseline_pe)
    end_rva = None
    for begin, end in pdata:
        if begin == func_rva:
            end_rva = end
            break
    if end_rva is None:
        fail(f'no .pdata range for protected_mix_c RVA 0x{func_rva:x}')
    func_size = end_rva - func_rva
    func_off = rva_to_file_offset(baseline_pe, func_rva)
    original_bytes = baseline_pe['data'][func_off:func_off + func_size]

    protected_off = rva_to_file_offset(protected_pe, func_rva)
    stub = protected_pe['data'][protected_off:protected_off + 29]
    if len(stub) < 29:
        fail('patched stub too small')
    if stub[0:4] != b'\x41\x52\x41\x53' or stub[4:6] != b'\x49\xBA' or stub[14:16] != b'\x49\xBB' or stub[24] != 0xE9:
        fail(f'original function head is not an in-place trampoline stub: {stub[:29].hex()}')
    if protected_pe['data'][protected_off:protected_off + len(original_bytes)] == original_bytes:
        fail('protected function bytes still identical to baseline at original address')

    candidate_exec_sections = [sec for sec in randomized if sec['characteristics'] & 0x20000000]
    if not candidate_exec_sections:
        fail('missing randomized executable section for relocated body')
    if not any(original_bytes in protected_pe['data'][sec['raw_ptr']:sec['raw_ptr'] + sec['raw_size']] for sec in candidate_exec_sections):
        fail('relocated original function body not found in any randomized executable section')

    print('rewriter_pe_security_fix OK')


if __name__ == '__main__':
    main()
