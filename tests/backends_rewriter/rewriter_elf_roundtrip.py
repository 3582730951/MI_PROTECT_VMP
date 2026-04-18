#!/usr/bin/env python3
import json, os, pathlib, shutil, struct, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]

def fail(msg):
    raise SystemExit(msg)

def sh(cmd, cwd=None, env=None, check=True):
    res = subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True)
    if check and res.returncode != 0:
        raise SystemExit(f"command failed ({res.returncode}): {' '.join(cmd)}\nstdout:\n{res.stdout}\nstderr:\n{res.stderr}")
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
        raise SystemExit('usage: rewriter_elf_roundtrip.py <vmp-protect> <source-root> <binary-dir>')
    tool = pathlib.Path(sys.argv[1])
    source_root = pathlib.Path(sys.argv[2])
    binary_dir = pathlib.Path(sys.argv[3])
    work = binary_dir / 'tests' / 'rewriter_elf_roundtrip'
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    src = work / 'main.cpp'
    src.write_text(r'''
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/strings/keyctx.h>
#include <nlohmann/json.hpp>

extern "C" __attribute__((visibility("default"))) const char kProtectedString[] = "hello-from-rewriter";
extern "C" __attribute__((visibility("default"))) std::uint32_t kProtectedStringLen = sizeof(kProtectedString) - 1;
static std::uint32_t stable_string_id(const char* s) { std::uint32_t v=5381u; for (; *s; ++s) v=((v<<5u)+v)^static_cast<unsigned char>(*s); return v ? v : 1u; }
extern "C" __attribute__((visibility("default"))) std::uint32_t kProtectedStringId = stable_string_id("kProtectedString");

static std::string load_from_pool() {
  const char* idx_path = std::getenv("VMP_REWRITER_STRING_IDX");
  const char* bin_path = std::getenv("VMP_REWRITER_STRING_BIN");
  const char* key_hex = std::getenv("VMP_STRING_MASTER_KEY");
  if (!idx_path || !bin_path || !key_hex) {
    return std::string(kProtectedString, kProtectedStringLen);
  }
  auto idx_text = std::ifstream(idx_path);
  nlohmann::json root; idx_text >> root;
  const auto key = vmp::runtime::strings::hex_decode(key_hex);
  auto salt = vmp::runtime::strings::hex_decode(root.at("key_context").at("salt").get<std::string>());
  vmp::runtime::strings::KeyContext ctx(vmp::runtime::strings::MasterKeyHandle([key](){ return key; }), salt);
  const auto dk = ctx.derive_subkey("string-pool");
  const auto entry = root.at("entries").at(std::to_string(kProtectedStringId));
  auto noncev = vmp::runtime::strings::hex_decode(entry.at("nonce").get<std::string>());
  std::ifstream bin(bin_path, std::ios::binary);
  std::vector<std::uint8_t> blob((std::istreambuf_iterator<char>(bin)), std::istreambuf_iterator<char>());
  std::uint32_t off = entry.at("offset").get<std::uint32_t>();
  std::uint32_t len = entry.at("length").get<std::uint32_t>();
  std::vector<std::uint8_t> rec(blob.begin()+off, blob.begin()+off+len);
  vmp::runtime::strings::Nonce nonce{};
  std::copy(noncev.begin(), noncev.end(), nonce.begin());
  auto plain = vmp::runtime::strings::decrypt_string_record(dk.bytes(), nonce, rec);
  return std::string(reinterpret_cast<const char*>(plain.data()), plain.size());
}

int main() {
  std::cout << load_from_pool();
  return 0;
}
''')
    cm = work / 'CMakeLists.txt'
    cm.write_text(f'''
cmake_minimum_required(VERSION 3.20)
project(rewriter_elf_sample LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
find_package(nlohmann_json REQUIRED)
add_executable(rewriter_elf_sample main.cpp)
target_include_directories(rewriter_elf_sample PRIVATE {source_root}/runtime/strings/include {source_root}/policy/include)
add_library(vmp_runtime_strings STATIC
  {source_root}/runtime/strings/src/strings.cpp
  {source_root}/runtime/strings/src/keyctx.cpp)
target_link_libraries(vmp_runtime_strings PUBLIC nlohmann_json::nlohmann_json)
target_include_directories(vmp_runtime_strings PUBLIC {source_root}/runtime/strings/include {source_root}/policy/include {source_root}/runtime/audit/include)
add_library(vmp_runtime_audit STATIC {source_root}/runtime/audit/src/audit.cpp {source_root}/runtime/audit/src/reaction.cpp {source_root}/runtime/audit/src/detector.cpp {source_root}/runtime/audit/src/placeholder.cpp)
target_include_directories(vmp_runtime_audit PUBLIC {source_root}/runtime/audit/include)
add_library(vmp_policy STATIC {source_root}/policy/src/policy_ir.cpp)
target_include_directories(vmp_policy PUBLIC {source_root}/policy/include)
target_link_libraries(vmp_policy PUBLIC nlohmann_json::nlohmann_json)
target_link_libraries(vmp_runtime_strings PUBLIC vmp_policy vmp_runtime_audit)
target_link_libraries(rewriter_elf_sample PRIVATE vmp_runtime_strings vmp_policy vmp_runtime_audit nlohmann_json::nlohmann_json)
''')
    build = work / 'build'
    sh(['cmake', '-S', str(work), '-B', str(build), '-G', 'Ninja'])
    sh(['cmake', '--build', str(build), '-j'])
    exe = build / 'rewriter_elf_sample'
    policy = work / 'policy.json'
    pool = work / 'pool.bin'
    idx = work / 'pool.idx.json'
    out = work / 'rewritten.elf'
    policy.write_text(json.dumps({
        'schema_version': 1,
        'defaults': {
            'language_origin': 'binary', 'annotation_origin': 'external_manifest', 'protection_domain': 'native',
            'jit_policy': 'off', 'plaintext_budget': 'transient_only', 'reaction_policy': 'log',
            'integrity_level': 'basic', 'platform_caps': ['linux','x64'], 'sensitivity_level': 'normal',
            'profile_seed': 1, 'mobile_bridge_mode': 'off', 'event_types': []
        },
        'entries': [{
            'symbol_or_region': 'kProtectedString', 'language_origin': 'binary', 'annotation_origin': 'external_manifest',
            'protection_domain': 'native', 'jit_policy': 'off', 'plaintext_budget': 'transient_only',
            'reaction_policy': 'log', 'integrity_level': 'basic', 'platform_caps': ['linux','x64'],
            'sensitivity_level': 'highly_sensitive', 'profile_seed': 1, 'mobile_bridge_mode': 'off',
            'annotation_tags': ['vm_string'], 'event_types': []
        }]
    }, indent=2))
    key = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
    env = os.environ.copy()
    env['VMP_STRING_MASTER_KEY'] = key
    sh([str(tool), '--policy', str(policy), '--input', str(exe), '--output', str(out), '--strings-pool', str(pool), '--strings-idx', str(idx)], env=env)
    out.chmod(0o755)
    data, sections = read_elf_sections(out)
    if '.vmpstrings' not in sections:
        fail('missing .vmpstrings section')
    if b'hello-from-rewriter' in data:
        fail('original literal still present in output ELF')
    run = sh([str(out)], env={**env, 'VMP_REWRITER_STRING_BIN': str(pool), 'VMP_REWRITER_STRING_IDX': str(idx)})
    if run.stdout.strip() != 'hello-from-rewriter':
        fail(f'unexpected program output: {run.stdout!r}')
    print('rewriter_elf_roundtrip OK')

if __name__ == '__main__':
    main()
