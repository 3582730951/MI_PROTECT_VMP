#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from common import ensure_tool, parse_ret_int, run

SENSITIVE_LITERAL = 'steady-secret-42'
MASTER_KEY = '1357135713571357135713571357135713571357135713571357135713571357'
FIXED_INPUT = [3, 14, 15, 92]

C_SRC = r'''
#include <stdint.h>
#include <stdio.h>
int main(void) {
  uint8_t in[4] = {3, 14, 15, 92};
  uint8_t out[4];
  uint32_t sum = 0;
  const uint8_t keys[4] = {0x5a, 0x2c, 0x11, 0x07};
  for (int i = 0; i < 4; ++i) {
    out[i] = (uint8_t)(in[i] ^ keys[i]);
    sum += out[i];
  }
  uint64_t packed = (uint64_t)out[0] | ((uint64_t)out[1] << 8) | ((uint64_t)out[2] << 16) | ((uint64_t)out[3] << 24) | ((uint64_t)sum << 32);
  printf("%016llx\n", (unsigned long long)packed);
  return 0;
}
'''

CPP_SRC = C_SRC.replace('int main(void)', 'int main()')

RUST_SRC = r'''
fn main() {
    let input = [3u8, 14, 15, 92];
    let keys = [0x5au8, 0x2c, 0x11, 0x07];
    let mut out = [0u8; 4];
    let mut sum: u32 = 0;
    for i in 0..4 {
        out[i] = input[i] ^ keys[i];
        sum += out[i] as u32;
    }
    let packed = (out[0] as u64)
        | ((out[1] as u64) << 8)
        | ((out[2] as u64) << 16)
        | ((out[3] as u64) << 24)
        | ((sum as u64) << 32);
    println!("{packed:016x}");
}
'''

VM1_ASM = r'''
entry:
  ldi_u64 vr4, 0
  ldi_u64 vr8, 90
  xor vr0, vr0, vr8
  add vr4, vr4, vr0
  ldi_u64 vr8, 44
  xor vr1, vr1, vr8
  add vr4, vr4, vr1
  ldi_u64 vr8, 17
  xor vr2, vr2, vr8
  add vr4, vr4, vr2
  ldi_u64 vr8, 7
  xor vr3, vr3, vr8
  add vr4, vr4, vr3
  ldi_u64 vr8, 8
  shl vr1, vr1, vr8
  ldi_u64 vr8, 16
  shl vr2, vr2, vr8
  ldi_u64 vr8, 24
  shl vr3, vr3, vr8
  ldi_u64 vr8, 32
  shl vr4, vr4, vr8
  add vr0, vr0, vr1
  add vr0, vr0, vr2
  add vr0, vr0, vr3
  add vr0, vr0, vr4
  ret
'''

VM2_ASM = r'''
  ildimm r4, 0
  ildimm r8, 90
  ixor r0, r0, r8
  iadd r4, r4, r0
  ildimm r8, 44
  ixor r1, r1, r8
  iadd r4, r4, r1
  ildimm r8, 17
  ixor r2, r2, r8
  iadd r4, r4, r2
  ildimm r8, 7
  ixor r3, r3, r8
  iadd r4, r4, r3
  ildimm r8, 8
  ishl r1, r1, r8
  ildimm r8, 16
  ishl r2, r2, r8
  ildimm r8, 24
  ishl r3, r3, r8
  ildimm r8, 32
  ishl r4, r4, r8
  iadd r0, r0, r1
  iadd r0, r0, r2
  iadd r0, r0, r3
  iadd r0, r0, r4
  bret
'''

VM_STRING_PROBE_SRC = r'''
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>

#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/strings/keyctx.h>
#include <vmp/runtime/vm1/vm1.h>

#include "tools/src/string_protect_common.h"

int main(int argc, char** argv) {
  if (argc != 5) {
    std::cerr << "usage: probe <pool> <idx> <key-env> <sleep-ms>\n";
    return 2;
  }
  const std::string pool_path = argv[1];
  const std::string idx_path = argv[2];
  const std::string key_env = argv[3];
  const auto sleep_ms = static_cast<unsigned>(std::stoul(argv[4]));

  const auto [index, salt] = vmp::tools::strings_tool::load_index_file(idx_path);
  auto pool = std::make_shared<vmp::runtime::strings::StringPool>(
      vmp::tools::strings_tool::read_binary(pool_path),
      index,
      vmp::runtime::strings::KeyContext(vmp::tools::strings_tool::key_from_env(key_env), salt));

  auto module = vmp::runtime::vm1::assemble_module_text(R"(
entry:
  load_tstr vr5, &sid42
  release_tstr vr5
  ret
)");
  vmp::runtime::vm1::Vm1Context context(module);
  context.string_pool = pool;
  vmp::runtime::vm1::Vm1Interpreter interpreter;

  std::cout << "PID=" << ::getpid() << "\nREADY\n" << std::flush;
  std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
  (void)interpreter.execute(context);
  std::cout << "AFTER_RUN active=" << context.active_transient_strings() << "\n" << std::flush;
  std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
  return 0;
}
'''


def compile_native(tmp: Path, source: str, compiler: str, output: str) -> Path:
    ext = '.c' if output.endswith('_c') else '.cpp'
    src = tmp / f'{output}{ext}'
    exe = tmp / output
    src.write_text(source)
    cmd = [compiler, str(src), '-O2', '-o', str(exe)]
    if output.endswith('_cpp'):
        cmd.insert(1, '-std=c++17')
    run(cmd)
    return exe


def compile_probe(tmp: Path, source_dir: Path, build_dir: Path) -> Path:
    src = tmp / 'vm_string_probe.cpp'
    exe = tmp / 'vm_string_probe'
    src.write_text(VM_STRING_PROBE_SRC)
    cmd = [
        ensure_tool('c++'),
        '-std=c++17',
        str(src),
        '-O2',
        '-I', str(source_dir),
        '-I', str(source_dir / 'runtime' / 'strings' / 'include'),
        '-I', str(source_dir / 'runtime' / 'vm1' / 'include'),
        '-I', str(source_dir / 'runtime' / 'audit' / 'include'),
        '-I', str(source_dir / 'runtime' / 'state' / 'include'),
        '-I', str(source_dir / 'arch' / 'common' / 'include'),
        '-I', str(source_dir / 'policy' / 'include'),
        '-Wl,--start-group',
        str(build_dir / 'runtime' / 'vm1' / 'libvmp_runtime_vm1.a'),
        str(build_dir / 'runtime' / 'strings' / 'libvmp_runtime_strings.a'),
        str(build_dir / 'runtime' / 'audit' / 'libvmp_runtime_audit.a'),
        str(build_dir / 'runtime' / 'state' / 'libvmp_runtime_state.a'),
        str(build_dir / 'runtime' / 'jit' / 'libvmp_runtime_jit.a'),
        str(build_dir / 'runtime' / 'vm2' / 'libvmp_runtime_vm2.a'),
        str(build_dir / 'policy' / 'libvmp_policy.a'),
        str(build_dir / 'arch' / 'common' / 'libvmp_arch_common.a'),
        '-Wl,--end-group',
        '-ldl',
        '-lpthread',
        '-o', str(exe),
    ]
    run(cmd, cwd=source_dir)
    return exe


def scan_process_memory(pid: int, needle: bytes) -> bool:
    maps_path = Path(f'/proc/{pid}/maps')
    mem_path = Path(f'/proc/{pid}/mem')
    if not maps_path.exists() or not mem_path.exists():
        raise SystemExit('memory scan is only supported on Linux /proc in this test matrix')
    with maps_path.open() as maps, mem_path.open('rb', buffering=0) as mem:
        for line in maps:
            parts = line.split()
            if not parts or 'r' not in parts[1] or parts[-1].startswith('[') and parts[-1] in {'[vvar]', '[vsyscall]'}:
                continue
            start_s, end_s = parts[0].split('-')
            start = int(start_s, 16)
            end = int(end_s, 16)
            size = end - start
            if size <= 0 or size > 8 * 1024 * 1024:
                continue
            try:
                mem.seek(start)
                data = mem.read(size)
            except OSError:
                continue
            if needle in data:
                return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--source-dir', required=True)
    ap.add_argument('--build-dir', required=True)
    ap.add_argument('--vm1-asm', required=True)
    ap.add_argument('--vm1-run', required=True)
    ap.add_argument('--vm2-asm', required=True)
    ap.add_argument('--vm2-run', required=True)
    ap.add_argument('--string-protect', required=True)
    args = ap.parse_args()

    source_dir = Path(args.source_dir)
    build_dir = Path(args.build_dir)
    out_dir = build_dir / 'tests' / 'final_matrix'
    out_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix='vmp_final_matrix_fn_') as td:
        tmp = Path(td)
        cc = ensure_tool('cc')
        cxx = ensure_tool('c++')
        rustc = ensure_tool('rustc')

        c_exe = compile_native(tmp, C_SRC, cc, 'kernel_c')
        cpp_exe = compile_native(tmp, CPP_SRC, cxx, 'kernel_cpp')
        rust_src = tmp / 'kernel_rs.rs'
        rust_src.write_text(RUST_SRC)
        rust_exe = tmp / 'kernel_rs'
        run([rustc, str(rust_src), '-O', '-o', str(rust_exe)])

        native_outputs = {
            'c': run([str(c_exe)]).stdout.strip(),
            'cpp': run([str(cpp_exe)]).stdout.strip(),
            'rust': run([str(rust_exe)]).stdout.strip(),
        }
        if len(set(native_outputs.values())) != 1:
            raise SystemExit(f'native equivalence failed: {native_outputs}')
        expected_hex = next(iter(native_outputs.values()))

        vm1_src = tmp / 'kernel.vm1s'
        vm1_mod = tmp / 'kernel.vm1'
        vm1_src.write_text(VM1_ASM)
        run([args.vm1_asm, str(vm1_src), str(vm1_mod)])
        vm1_ret = parse_ret_int(run([args.vm1_run, '--jit=off', str(vm1_mod), *map(str, FIXED_INPUT)]).stdout)

        vm2_src = tmp / 'kernel.vm2s'
        vm2_mod = tmp / 'kernel.vm2'
        vm2_src.write_text(VM2_ASM)
        run([args.vm2_asm, str(vm2_src), str(vm2_mod)])
        vm2_ret = parse_ret_int(run([args.vm2_run, '--jit=off', str(vm2_mod), *map(str, FIXED_INPUT)]).stdout)

        expected_int = int(expected_hex, 16)
        if vm1_ret != expected_int or vm2_ret != expected_int:
            raise SystemExit(f'VM/native mismatch: expected={expected_int} vm1={vm1_ret} vm2={vm2_ret}')

        policy = tmp / 'vm_string_policy.json'
        pool = tmp / 'vm_string_pool.bin'
        idx = tmp / 'vm_string_pool.idx.json'
        meta = tmp / 'vm_string_pool.kdf.json'
        policy.write_text(
            '{\n'
            '  "schema_version": 1,\n'
            '  "defaults": {"language_origin": "cpp", "annotation_origin": "attribute"},\n'
            '  "entries": [\n'
            '    {\n'
            '      "symbol_or_region": "sid42",\n'
            '      "annotation_tags": ["vm_string", "vm_string:function_scope"],\n'
            '      "plaintext_budget": "transient_only",\n'
            '      "sensitivity_level": "highly_sensitive",\n'
            '      "string_id": 42,\n'
            f'      "value": "{SENSITIVE_LITERAL}"\n'
            '    }\n'
            '  ]\n'
            '}\n'
        )
        env = os.environ.copy()
        env['VMP_STRING_MASTER_KEY'] = MASTER_KEY
        run([
            args.string_protect,
            '--policy', str(policy),
            '--out-bin', str(pool),
            '--out-idx', str(idx),
            '--out-kdf', str(meta),
        ], env=env)

        probe = compile_probe(tmp, source_dir, build_dir)
        proc = subprocess.Popen([str(probe), str(pool), str(idx), 'VMP_STRING_MASTER_KEY', '800'],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        assert proc.stdout is not None
        ready = proc.stdout.readline().strip()
        if not ready.startswith('PID='):
            stderr = proc.stderr.read() if proc.stderr else ''
            raise SystemExit(f'probe failed to start: {ready}\n{stderr}')
        pid = int(ready.split('=', 1)[1])
        state = proc.stdout.readline().strip()
        if state != 'READY':
            raise SystemExit(f'unexpected probe state: {state}')
        time.sleep(0.2)
        if scan_process_memory(pid, SENSITIVE_LITERAL.encode()):
            proc.kill()
            raise SystemExit('sensitive literal found in process memory before transient use')
        after = proc.stdout.readline().strip()
        if not after.startswith('AFTER_RUN active=0'):
            proc.kill()
            raise SystemExit(f'unexpected post-run state: {after}')
        time.sleep(0.2)
        if scan_process_memory(pid, SENSITIVE_LITERAL.encode()):
            proc.kill()
            raise SystemExit('sensitive literal found in process memory after transient release')
        proc.wait(timeout=5)
        if proc.returncode != 0:
            raise SystemExit(f'probe exited with {proc.returncode}: {proc.stderr.read() if proc.stderr else ""}')

        report = out_dir / 'functional_consistency.json'
        report.write_text(json.dumps({
            'expected_hex': expected_hex,
            'native': native_outputs,
            'vm1_ret': vm1_ret,
            'vm2_ret': vm2_ret,
        }, indent=2, sort_keys=True) + '\n')
        print('functional consistency OK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
