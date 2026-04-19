#!/usr/bin/env python3
import json
import pathlib
import shutil
import struct
import subprocess
import sys


def fail(msg):
    raise SystemExit(msg)


def sh(cmd, cwd=None, env=None, check=True):
    res = subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True)
    if check and res.returncode != 0:
        raise SystemExit(f"command failed ({res.returncode}): {' '.join(map(str, cmd))}\nstdout:\n{res.stdout}\nstderr:\n{res.stderr}")
    return res


def read_elf_sections(path):
    data = pathlib.Path(path).read_bytes()
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        fail('not a 64-bit little-endian ELF')
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
    shstr = struct.unpack_from('<IIQQQQIIQQ', data, e_shoff + e_shentsize * e_shstrndx)
    shstr_off, shstr_size = shstr[4], shstr[5]
    shstrtab = data[shstr_off:shstr_off + shstr_size]
    out = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh = struct.unpack_from('<IIQQQQIIQQ', data, off)
        name_off = sh[0]
        end = shstrtab.find(b'\x00', name_off)
        name = shstrtab[name_off:end].decode() if end != -1 and name_off < len(shstrtab) else ''
        out[name] = {'offset': sh[4], 'size': sh[5], 'addr': sh[2]}
    return data, out


def main():
    if len(sys.argv) != 4:
        raise SystemExit('usage: rewriter_lift_integration_elf_with_loop.py <vmp-protect> <source-root> <binary-dir>')
    tool = pathlib.Path(sys.argv[1])
    source_root = pathlib.Path(sys.argv[2])
    binary_dir = pathlib.Path(sys.argv[3])
    work = binary_dir / 'tests' / 'rewriter_lift_integration_elf_with_loop'
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    src = work / 'main.cpp'
    src.write_text(r'''
#include <elf.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <vmp/runtime/vm1/vm1.h>

extern "C" __attribute__((visibility("default"), noinline)) unsigned long protected_loop(unsigned long count, unsigned long step);
asm(
".text\n"
".global protected_loop\n"
".type protected_loop,@function\n"
"protected_loop:\n"
"  mov %rdi, %rcx\n"
"  mov %rsi, %rbx\n"
"  xor %eax, %eax\n"
"  xor %edx, %edx\n"
"  cmp %rdx, %rcx\n"
"  jle .Lexit\n"
"  mov $1, %r8d\n"
".Lloop:\n"
"  add %rbx, %rax\n"
"  sub %r8, %rcx\n"
"  cmp %rdx, %rcx\n"
"  jg .Lloop\n"
".Lexit:\n"
"  ret\n"
".size protected_loop, .-protected_loop\n");

struct Bundle { unsigned long id; std::vector<unsigned char> payload; };

static std::unordered_map<unsigned long, Bundle> load_bundles() {
  std::ifstream input("/proc/self/exe", std::ios::binary);
  std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  if (bytes.size() < sizeof(Elf64_Ehdr)) throw std::runtime_error("elf too small");
  Elf64_Ehdr eh{}; std::memcpy(&eh, bytes.data(), sizeof(eh));
  auto shdr_at = [&](std::size_t idx) { Elf64_Shdr sh{}; std::memcpy(&sh, bytes.data() + eh.e_shoff + idx * eh.e_shentsize, sizeof(sh)); return sh; };
  Elf64_Shdr shstr = shdr_at(eh.e_shstrndx);
  std::string shstrtab(reinterpret_cast<const char*>(bytes.data() + shstr.sh_offset), shstr.sh_size);
  Elf64_Shdr target{}; bool found=false;
  for (std::size_t i = 0; i < eh.e_shnum; ++i) {
    auto sh = shdr_at(i);
    const char* nm = sh.sh_name < shstrtab.size() ? shstrtab.c_str() + sh.sh_name : "";
    if (std::string(nm) == ".vmpcode") { target = sh; found = true; break; }
  }
  if (!found) throw std::runtime_error("missing .vmpcode");
  const unsigned char* p = bytes.data() + target.sh_offset;
  if (std::memcmp(p, "VMPC", 4) != 0) throw std::runtime_error("bad vmpcode magic");
  p += 4;
  auto rd32 = [&](const unsigned char*& q){ unsigned v=0; for(int i=0;i<4;++i) v |= unsigned(q[i]) << (i*8); q+=4; return v; };
  auto rd64 = [&](const unsigned char*& q){ unsigned long v=0; for(int i=0;i<8;++i) v |= (unsigned long)q[i] << (i*8); q+=8; return v; };
  unsigned count = rd32(p);
  std::unordered_map<unsigned long, Bundle> out;
  for (unsigned i = 0; i < count; ++i) {
    unsigned long id = rd64(p);
    unsigned domain = *p++;
    unsigned sym_len = rd32(p);
    unsigned payload_len = rd32(p);
    p += sym_len;
    std::vector<unsigned char> payload(p, p + payload_len);
    p += payload_len;
    if (domain == 1) out.emplace(id, Bundle{id, std::move(payload)});
  }
  return out;
}

extern "C" __attribute__((visibility("default"))) unsigned long vmp_dispatch_vm1_sysv2(unsigned long bundle_id, unsigned long a0, unsigned long a1) {
  static std::unordered_map<unsigned long, Bundle> bundles = load_bundles();
  auto it = bundles.find(bundle_id);
  if (it == bundles.end()) throw std::runtime_error("bundle not found");
  auto module = vmp::runtime::vm1::Vm1Module::load_from_bytes(it->second.payload);
  vmp::runtime::vm1::Vm1Context ctx(module);
  ctx.vr[0] = a0;
  ctx.vr[1] = a1;
  vmp::runtime::vm1::Vm1Interpreter interp;
  return interp.execute(ctx).ret_int;
}

int main() {
  std::cout << protected_loop(0, 7) << "," << protected_loop(4, 3);
  return 0;
}
''')
    cm = work / 'CMakeLists.txt'
    cm.write_text(f'''
cmake_minimum_required(VERSION 3.20)
project(rewriter_lift_loop_sample LANGUAGES CXX ASM)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE OFF)
add_link_options(-no-pie)
find_package(nlohmann_json REQUIRED)
add_executable(rewriter_lift_loop_sample main.cpp)
add_library(vmp_runtime_audit STATIC
  {source_root}/runtime/audit/src/audit.cpp
  {source_root}/runtime/audit/src/reaction.cpp
  {source_root}/runtime/audit/src/detector.cpp
  {source_root}/runtime/audit/src/placeholder.cpp)
target_include_directories(vmp_runtime_audit PUBLIC {source_root}/runtime/audit/include)
add_library(vmp_policy STATIC {source_root}/policy/src/policy_ir.cpp)
target_include_directories(vmp_policy PUBLIC {source_root}/policy/include)
target_link_libraries(vmp_policy PUBLIC nlohmann_json::nlohmann_json)
add_library(vmp_runtime_strings STATIC
  {source_root}/runtime/strings/src/strings.cpp
  {source_root}/runtime/strings/src/keyctx.cpp)
target_include_directories(vmp_runtime_strings PUBLIC {source_root}/runtime/strings/include {source_root}/policy/include {source_root}/runtime/audit/include)
target_link_libraries(vmp_runtime_strings PUBLIC vmp_policy vmp_runtime_audit nlohmann_json::nlohmann_json)
add_library(vmp_arch_common STATIC
  {source_root}/arch/common/src/lifting.cpp
  {source_root}/arch/common/src/label_resolver.cpp)
target_include_directories(vmp_arch_common PUBLIC
  {source_root}/arch/common/include
  {source_root}/runtime/vm1/include
  {source_root}/runtime/vm2/include
  {source_root}/runtime/audit/include
  {source_root}/runtime/bridge/include
  {source_root}/runtime/strings/include
  {source_root}/policy/include)
add_library(vmp_runtime_vm1 STATIC
  {source_root}/runtime/vm1/src/vm1.cpp
  {source_root}/runtime/vm1/src/interpreter.cpp
  {source_root}/runtime/vm1/src/bridge.cpp)
target_include_directories(vmp_runtime_vm1 PUBLIC {source_root}/runtime/vm1/include {source_root}/runtime/strings/include {source_root}/runtime/audit/include {source_root}/policy/include {source_root}/arch/common/include)
target_link_libraries(vmp_runtime_vm1 PUBLIC vmp_runtime_strings vmp_runtime_audit vmp_policy vmp_arch_common nlohmann_json::nlohmann_json)
target_link_libraries(rewriter_lift_loop_sample PRIVATE vmp_runtime_vm1 vmp_runtime_strings vmp_runtime_audit vmp_policy vmp_arch_common nlohmann_json::nlohmann_json)
''')
    build = work / 'build'
    sh(['cmake', '-S', str(work), '-B', str(build), '-G', 'Ninja'])
    sh(['cmake', '--build', str(build), '-j'])
    exe = build / 'rewriter_lift_loop_sample'
    policy = work / 'policy.json'
    out = work / 'rewritten_loop.elf'
    policy.write_text(json.dumps({
        'schema_version': 1,
        'defaults': {
            'language_origin': 'binary', 'annotation_origin': 'external_manifest', 'protection_domain': 'native',
            'jit_policy': 'off', 'plaintext_budget': 'transient_only', 'reaction_policy': 'log',
            'integrity_level': 'basic', 'platform_caps': ['linux', 'x64'], 'sensitivity_level': 'normal',
            'profile_seed': 1, 'mobile_bridge_mode': 'off', 'event_types': []
        },
        'entries': [{
            'symbol_or_region': 'protected_loop', 'language_origin': 'binary', 'annotation_origin': 'external_manifest',
            'protection_domain': 'vm1', 'jit_policy': 'off', 'plaintext_budget': 'transient_only',
            'reaction_policy': 'log', 'integrity_level': 'basic', 'platform_caps': ['linux', 'x64'],
            'sensitivity_level': 'sensitive', 'profile_seed': 1, 'mobile_bridge_mode': 'off', 'event_types': []
        }]
    }, indent=2))
    sh([str(tool), '--policy', str(policy), '--input', str(exe), '--output', str(out), '--lift'])
    out.chmod(0o755)
    data, sections = read_elf_sections(out)
    if '.vmpcode' not in sections:
        fail('missing .vmpcode section')
    if '.vmpvmthk' not in sections:
        fail('missing .vmpvmthk section')
    meta = data[sections['.vmpvmthk']['offset']:sections['.vmpvmthk']['offset'] + sections['.vmpvmthk']['size']].rstrip(b'\x00')
    if b'"mode": "lifted"' not in meta:
        fail('thunk metadata does not record lifted mode')
    run = sh([str(out)])
    if run.stdout.strip() != '0,12':
        fail(f'unexpected program output: {run.stdout!r}')
    print('rewriter_lift_integration_elf_with_loop OK')


if __name__ == '__main__':
    main()
