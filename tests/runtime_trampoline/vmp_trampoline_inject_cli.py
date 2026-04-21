#!/usr/bin/env python3
import json, pathlib, shutil, struct, subprocess, sys


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
        raise SystemExit('usage: vmp_trampoline_inject_cli.py <vmp-trampoline-inject> <source-root> <binary-dir>')
    tool = pathlib.Path(sys.argv[1])
    source_root = pathlib.Path(sys.argv[2])
    binary_dir = pathlib.Path(sys.argv[3])
    work = binary_dir / 'tests' / 'vmp_trampoline_inject_cli'
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    src = work / 'main.cpp'
    src.write_text(r'''
#include <elf.h>
#include <sys/mman.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include <vmp/runtime/trampoline/trampoline.h>

extern "C" __attribute__((visibility("default"), noinline)) unsigned long protected_add(unsigned long a, unsigned long b);
asm(
".text\n"
".global protected_add\n"
".type protected_add,@function\n"
"protected_add:\n"
"  mov %rdi, %rax\n"
"  mov %rax, %rcx\n"
"  mov %rcx, %r8\n"
"  mov %r8, %r9\n"
"  mov %r9, %rax\n"
"  xor %r10, %r10\n"
"  add %r10, %rax\n"
"  add %rsi, %rax\n"
"  mov %rax, %rcx\n"
"  mov %rcx, %rax\n"
"  nop\n"
"  nop\n"
"  nop\n"
"  nop\n"
"  nop\n"
"  nop\n"
"  nop\n"
"  nop\n"
"  nop\n"
"  nop\n"
"  ret\n"
".size protected_add, .-protected_add\n");

extern "C" __attribute__((visibility("default"))) unsigned long vmp_dispatch_token_bridge(unsigned long token_lo,
                                                                                           unsigned long token_hi,
                                                                                           unsigned long a0,
                                                                                           unsigned long a1);
asm(
".text\n"
".global vmp_dispatch_token_sysv2\n"
".type vmp_dispatch_token_sysv2,@function\n"
"vmp_dispatch_token_sysv2:\n"
"  mov %rdx, %r8\n"
"  mov %rsi, %rcx\n"
"  mov %rdi, %rdx\n"
"  mov %r8, %rsi\n"
"  mov %rax, %rdi\n"
"  jmp vmp_dispatch_token_bridge\n"
".size vmp_dispatch_token_sysv2, .-vmp_dispatch_token_sysv2\n");

struct RuntimeState {
  std::vector<unsigned char> exec_blob;
  void* mapping = nullptr;
  std::size_t mapping_size = 0;
  std::unique_ptr<vmp::runtime::trampoline::StackFunctionTable> table;
};

static RuntimeState& runtime_state() {
  static RuntimeState state;
  if (state.table) return state;

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
    if (std::string(nm) == ".vmptrmp") { target = sh; found = true; break; }
  }
  if (!found) throw std::runtime_error("missing .vmptrmp");
  std::vector<std::uint8_t> blob(bytes.begin() + target.sh_offset, bytes.begin() + target.sh_offset + target.sh_size);
  const auto bundle = vmp::runtime::trampoline::TrampolineBundle::deserialize(blob);
  if (bundle.code_blob.empty()) throw std::runtime_error("empty code blob");
  state.mapping_size = bundle.code_blob.size();
  state.mapping = ::mmap(nullptr, state.mapping_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (state.mapping == MAP_FAILED) throw std::runtime_error("mmap failed");
  std::memcpy(state.mapping, bundle.code_blob.data(), bundle.code_blob.size());
  auto entries = bundle.instantiate(reinterpret_cast<std::uintptr_t>(state.mapping));
  state.table = std::make_unique<vmp::runtime::trampoline::StackFunctionTable>(entries, bundle.key_context_id);
  return state;
}

extern "C" __attribute__((visibility("default"))) unsigned long vmp_dispatch_token_bridge(unsigned long token_lo,
                                                                                           unsigned long token_hi,
                                                                                           unsigned long a0,
                                                                                           unsigned long a1) {
  auto& state = runtime_state();
  vmp::runtime::trampoline::Dispatcher dispatcher(*state.table);
  const auto addr = dispatcher.dispatch_or_throw(vmp::runtime::trampoline::token_from_halves(token_lo, token_hi));
  using Fn = unsigned long (*)(unsigned long, unsigned long);
  auto fn = reinterpret_cast<Fn>(static_cast<std::uintptr_t>(addr));
  return fn(a0, a1);
}

int main() {
  std::cout << protected_add(2, 3);
  return 0;
}
''')

    cm = work / 'CMakeLists.txt'
    cm.write_text(f'''
cmake_minimum_required(VERSION 3.20)
project(vmp_trampoline_sample LANGUAGES CXX ASM)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE OFF)
add_link_options(-no-pie)
find_package(nlohmann_json REQUIRED)
add_library(vmp_policy STATIC {source_root}/policy/src/policy_ir.cpp)
target_include_directories(vmp_policy PUBLIC {source_root}/policy/include)
target_link_libraries(vmp_policy PUBLIC nlohmann_json::nlohmann_json)
add_library(vmp_runtime_audit STATIC
  {source_root}/runtime/audit/src/audit.cpp
  {source_root}/runtime/audit/src/reaction.cpp
  {source_root}/runtime/audit/src/detector.cpp
  {source_root}/runtime/audit/src/placeholder.cpp)
target_include_directories(vmp_runtime_audit PUBLIC {source_root}/runtime/audit/include {source_root}/runtime/state/include {source_root}/policy/include)
target_link_libraries(vmp_runtime_audit PUBLIC vmp_policy)
add_library(vmp_runtime_strings STATIC
  {source_root}/runtime/strings/src/strings.cpp
  {source_root}/runtime/strings/src/keyctx.cpp)
target_include_directories(vmp_runtime_strings PUBLIC {source_root}/runtime/strings/include {source_root}/policy/include {source_root}/runtime/audit/include)
target_link_libraries(vmp_runtime_strings PUBLIC vmp_policy vmp_runtime_audit nlohmann_json::nlohmann_json)
add_library(vmp_runtime_trusted_oracle STATIC
  {source_root}/runtime/trusted_oracle/src/oracle.cpp
  {source_root}/runtime/trusted_oracle/src/syscall_linux_x64.asm.S)
target_include_directories(vmp_runtime_trusted_oracle PUBLIC {source_root}/runtime/trusted_oracle/include {source_root}/runtime/strings/include {source_root}/runtime/audit/include {source_root}/policy/include)
target_link_libraries(vmp_runtime_trusted_oracle PUBLIC vmp_runtime_strings vmp_runtime_audit nlohmann_json::nlohmann_json)
add_library(vmp_runtime_stack_probe STATIC
  {source_root}/runtime/stack_probe/src/probe.cpp)
target_include_directories(vmp_runtime_stack_probe PUBLIC {source_root}/runtime/stack_probe/include {source_root}/runtime/trusted_oracle/include {source_root}/runtime/audit/include {source_root}/policy/include)
target_link_libraries(vmp_runtime_stack_probe PUBLIC vmp_runtime_audit vmp_runtime_trusted_oracle nlohmann_json::nlohmann_json)
add_library(vmp_runtime_env_detectors STATIC
  {source_root}/runtime/env_detectors/src/detectors.cpp)
target_include_directories(vmp_runtime_env_detectors PUBLIC {source_root}/runtime/env_detectors/include {source_root}/runtime/trusted_oracle/include {source_root}/runtime/strings/include {source_root}/runtime/audit/include {source_root}/policy/include)
target_link_libraries(vmp_runtime_env_detectors PUBLIC vmp_runtime_trusted_oracle vmp_runtime_strings vmp_runtime_audit nlohmann_json::nlohmann_json)
add_library(vmp_runtime_trampoline STATIC
  {source_root}/runtime/trampoline/src/trampoline.cpp)
target_include_directories(vmp_runtime_trampoline PUBLIC {source_root}/runtime/trampoline/include {source_root}/runtime/env_detectors/include {source_root}/runtime/strings/include {source_root}/runtime/audit/include {source_root}/runtime/trusted_oracle/include {source_root}/runtime/stack_probe/include {source_root}/policy/include)
target_link_libraries(vmp_runtime_trampoline PUBLIC vmp_runtime_env_detectors vmp_runtime_stack_probe vmp_runtime_strings vmp_runtime_audit vmp_runtime_trusted_oracle nlohmann_json::nlohmann_json)
add_executable(vmp_trampoline_sample main.cpp)
target_include_directories(vmp_trampoline_sample PRIVATE {source_root}/runtime/trampoline/include {source_root}/runtime/env_detectors/include {source_root}/runtime/strings/include {source_root}/runtime/audit/include {source_root}/runtime/trusted_oracle/include {source_root}/runtime/stack_probe/include {source_root}/policy/include)
target_link_libraries(vmp_trampoline_sample PRIVATE vmp_runtime_trampoline vmp_runtime_env_detectors vmp_runtime_stack_probe vmp_runtime_strings vmp_runtime_audit vmp_runtime_trusted_oracle vmp_policy nlohmann_json::nlohmann_json)
''')

    build = work / 'build'
    sh(['cmake', '-S', str(work), '-B', str(build), '-G', 'Ninja'])
    sh(['cmake', '--build', str(build), '-j'])

    exe = build / 'vmp_trampoline_sample'
    policy = work / 'policy.json'
    out = work / 'rewritten.elf'
    policy.write_text(json.dumps({
        'schema_version': 1,
        'defaults': {
            'language_origin': 'binary', 'annotation_origin': 'external_manifest', 'protection_domain': 'native',
            'jit_policy': 'off', 'plaintext_budget': 'transient_only', 'reaction_policy': 'log',
            'integrity_level': 'basic', 'platform_caps': ['linux', 'x64'], 'sensitivity_level': 'normal',
            'profile_seed': 1, 'mobile_bridge_mode': 'off', 'event_types': []
        },
        'entries': [{
            'symbol_or_region': 'protected_add', 'language_origin': 'binary', 'annotation_origin': 'external_manifest',
            'protection_domain': 'vm1', 'jit_policy': 'off', 'plaintext_budget': 'transient_only',
            'reaction_policy': 'log', 'integrity_level': 'basic', 'platform_caps': ['linux', 'x64'],
            'sensitivity_level': 'sensitive', 'profile_seed': 1, 'mobile_bridge_mode': 'off', 'event_types': []
        }]
    }, indent=2))

    sh([str(tool), '--policy', str(policy), '--input', str(exe), '--output', str(out),
        '--dispatcher-symbol', 'vmp_dispatch_token_sysv2',
        '--key-context-id', '00112233445566778899aabbccddeeff'])
    out.chmod(0o755)

    data, sections = read_elf_sections(out)
    if '.vmptrmp' not in sections:
        fail('missing .vmptrmp section')
    if '.vmpvmthk' not in sections:
        fail('missing .vmpvmthk section')
    meta = data[sections['.vmpvmthk']['offset']:sections['.vmpvmthk']['offset'] + sections['.vmpvmthk']['size']].rstrip(b'\x00')
    if b'"mode": "token_trampoline"' not in meta:
        fail('metadata missing token_trampoline mode')
    if b'VMPT' not in data[sections['.vmptrmp']['offset']:sections['.vmptrmp']['offset'] + 4]:
        fail('bundle magic missing')

    run = sh([str(out)])
    if run.stdout.strip() != '5':
        fail(f'unexpected rewritten output: {run.stdout!r}')

    print('vmp_trampoline_inject_cli OK')


if __name__ == '__main__':
    main()
