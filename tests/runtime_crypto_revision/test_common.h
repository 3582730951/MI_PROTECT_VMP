#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <vmp/runtime/cryptor/rolling_opcode_vm1.h>
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/strings/keyctx.h>
#include <vmp/runtime/trampoline/trampoline.h>
#include <vmp/runtime/vm1/vm1.h>

namespace vmp::tests::runtime_crypto_revision {

inline void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

inline std::vector<std::uint8_t> concat(std::vector<std::uint8_t> lhs,
                                        const std::vector<std::uint8_t>& rhs) {
  lhs.insert(lhs.end(), rhs.begin(), rhs.end());
  return lhs;
}

inline void append_le32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xffu));
  }
}

inline void append_le64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xffu));
  }
}

inline std::uint32_t read_le32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  return static_cast<std::uint32_t>(bytes.at(offset)) |
         (static_cast<std::uint32_t>(bytes.at(offset + 1)) << 8u) |
         (static_cast<std::uint32_t>(bytes.at(offset + 2)) << 16u) |
         (static_cast<std::uint32_t>(bytes.at(offset + 3)) << 24u);
}

inline std::uint64_t read_le64(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  std::uint64_t value = 0;
  for (unsigned shift = 0; shift < 64; shift += 8) {
    value |= static_cast<std::uint64_t>(bytes.at(offset + shift / 8u)) << shift;
  }
  return value;
}

inline std::vector<std::uint8_t> token_to_vector(const vmp::runtime::trampoline::TokenBytes& token) {
  return std::vector<std::uint8_t>(token.begin(), token.end());
}

inline std::array<std::uint8_t, 16> bytes16(std::uint8_t base) {
  std::array<std::uint8_t, 16> out{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>(base + static_cast<std::uint8_t>(i));
  }
  return out;
}

inline std::vector<std::uint8_t> vec16(std::uint8_t base) {
  const auto data = bytes16(base);
  return std::vector<std::uint8_t>(data.begin(), data.end());
}

inline std::string hex(const std::vector<std::uint8_t>& bytes) {
  return vmp::runtime::strings::hex_encode(bytes);
}

inline std::vector<std::uint8_t> token_input(const vmp::runtime::trampoline::KeyContextId& key_context_id,
                                             std::uint64_t original_address,
                                             std::string_view symbol_name) {
  std::vector<std::uint8_t> input(key_context_id.begin(), key_context_id.end());
  append_le64(input, original_address);
  input.insert(input.end(), symbol_name.begin(), symbol_name.end());
  return input;
}

inline std::vector<std::uint8_t> namespaced_salt(const std::vector<std::uint8_t>& base,
                                                 std::string_view info) {
  auto salt = base;
  salt.insert(salt.end(), info.begin(), info.end());
  return salt;
}

inline vmp::runtime::trampoline::TokenBytes expected_token_v2(
    const vmp::runtime::trampoline::KeyContextId& key_context_id,
    std::uint64_t original_address,
    std::string_view symbol_name) {
  constexpr std::string_view kInfo = "vmp.trampoline.token.v2";
  const auto salt = namespaced_salt(std::vector<std::uint8_t>(key_context_id.begin(), key_context_id.end()), kInfo);
  const auto prk = vmp::runtime::strings::hkdf_extract_sha256(salt, token_input(key_context_id, original_address, symbol_name));
  const auto okm = vmp::runtime::strings::hkdf_expand_sha256(prk, vmp::runtime::strings::to_bytes(kInfo), 16);
  vmp::runtime::trampoline::TokenBytes token{};
  std::copy(okm.begin(), okm.end(), token.begin());
  return token;
}

inline std::array<std::uint8_t, 32> expected_static_hmac_key_v2(
    const vmp::runtime::trampoline::KeyContextId& key_context_id) {
  constexpr std::string_view kInfo = "vmp.trampoline.hmac.v2";
  const auto salt = namespaced_salt(std::vector<std::uint8_t>(key_context_id.begin(), key_context_id.end()), kInfo);
  const auto prk = vmp::runtime::strings::hkdf_extract_sha256(salt, vmp::runtime::strings::to_bytes("stack-table.static.v2"));
  const auto okm = vmp::runtime::strings::hkdf_expand_sha256(prk, vmp::runtime::strings::to_bytes(kInfo), 32);
  std::array<std::uint8_t, 32> out{};
  std::copy(okm.begin(), okm.end(), out.begin());
  return out;
}

inline std::array<std::uint8_t, 32> expected_ephemeral_hmac_key_v2(
    const vmp::runtime::trampoline::KeyContextId& key_context_id,
    std::uint64_t stack_canary,
    std::uint64_t return_address,
    std::uint64_t nonce) {
  constexpr std::string_view kInfo = "vmp.trampoline.hmac.v2";
  const auto salt = namespaced_salt(std::vector<std::uint8_t>(key_context_id.begin(), key_context_id.end()), kInfo);
  const auto mix = stack_canary ^ return_address ^ nonce;
  std::vector<std::uint8_t> ikm;
  append_le64(ikm, mix);
  const auto label = vmp::runtime::strings::to_bytes("dispatch.ephemeral.v2");
  ikm.insert(ikm.end(), label.begin(), label.end());
  const auto prk = vmp::runtime::strings::hkdf_extract_sha256(salt, ikm);
  const auto okm = vmp::runtime::strings::hkdf_expand_sha256(prk, vmp::runtime::strings::to_bytes(kInfo), 32);
  std::array<std::uint8_t, 32> out{};
  std::copy(okm.begin(), okm.end(), out.begin());
  return out;
}

inline std::array<std::uint8_t, 32> expected_string_key_v2(const std::vector<std::uint8_t>& salt,
                                                           const std::vector<std::uint8_t>& master) {
  constexpr std::string_view kInfo = "vmp.strings.key.v2";
  const auto hkdf_salt = namespaced_salt(salt, kInfo);
  const auto prk = vmp::runtime::strings::hkdf_extract_sha256(hkdf_salt, master);
  const auto okm = vmp::runtime::strings::hkdf_expand_sha256(prk, vmp::runtime::strings::to_bytes(kInfo), 32);
  std::array<std::uint8_t, 32> out{};
  std::copy(okm.begin(), okm.end(), out.begin());
  return out;
}

inline vmp::runtime::vm1::Vm1Module make_vm1_module(std::string_view text, std::uint8_t seed_base = 0x10) {
  vmp::runtime::vm1::AssembleOptions options;
  options.encrypt_opcodes = true;
  options.opcode_seed = bytes16(seed_base);
  return vmp::runtime::vm1::assemble_module_text(text, options);
}

inline std::array<std::uint8_t, 32> expected_rolling_prk_v2(const vmp::runtime::cryptor::ModuleDescriptor& descriptor,
                                                            std::uint32_t epoch_id,
                                                            vmp::runtime::cryptor::RotationReason reason,
                                                            const std::vector<std::uint8_t>& key_override) {
  constexpr std::string_view kInfo = "vmp.cryptor.epoch.v2";
  auto key_material = key_override.empty() ? descriptor.key_context_material : key_override;
  if (key_material.empty()) {
    key_material = descriptor.master_key_material;
  }
  if (key_material.empty()) {
    key_material.assign(16, 0u);
  }
  std::vector<std::uint8_t> material = descriptor.base_seed;
  append_le64(material, descriptor.module_id);
  append_le32(material, epoch_id);
  material.push_back(static_cast<std::uint8_t>(reason));
  material.push_back(static_cast<std::uint8_t>(descriptor.domain));
  material.insert(material.end(), key_material.begin(), key_material.end());
  const auto salt = namespaced_salt(key_material, kInfo);
  const auto prk = vmp::runtime::strings::hkdf_extract_sha256(salt, material);
  std::array<std::uint8_t, 32> out{};
  std::copy_n(prk.begin(), out.size(), out.begin());
  return out;
}

inline std::array<std::uint8_t, 16> expected_rolling_seed_v2(const vmp::runtime::cryptor::ModuleDescriptor& descriptor,
                                                             std::uint32_t epoch_id,
                                                             vmp::runtime::cryptor::RotationReason reason,
                                                             const std::vector<std::uint8_t>& key_override) {
  constexpr std::string_view kInfo = "vmp.cryptor.epoch.v2";
  auto key_material = key_override.empty() ? descriptor.key_context_material : key_override;
  if (key_material.empty()) {
    key_material = descriptor.master_key_material;
  }
  if (key_material.empty()) {
    key_material.assign(16, 0u);
  }
  std::vector<std::uint8_t> material = descriptor.base_seed;
  append_le64(material, descriptor.module_id);
  append_le32(material, epoch_id);
  material.push_back(static_cast<std::uint8_t>(reason));
  material.push_back(static_cast<std::uint8_t>(descriptor.domain));
  material.insert(material.end(), key_material.begin(), key_material.end());
  const auto salt = namespaced_salt(key_material, kInfo);
  const auto prk = vmp::runtime::strings::hkdf_extract_sha256(salt, material);
  const auto okm = vmp::runtime::strings::hkdf_expand_sha256(prk, vmp::runtime::strings::to_bytes(kInfo), 48);
  std::array<std::uint8_t, 16> out{};
  std::copy_n(okm.begin() + 32, out.size(), out.begin());
  return out;
}

}  // namespace vmp::tests::runtime_crypto_revision
