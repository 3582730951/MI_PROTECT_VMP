#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include <vmp/runtime/strings/aes256_ctr.h>
#include <vmp/runtime/strings/cipher.h>

namespace vmp::backend::rewriter::detail {

using json = nlohmann::json;

enum class MetadataBlobKind : std::uint8_t {
  section_map = 1,
  thunk_map = 2,
  trampoline_map = 3,
};

inline void append_le(std::vector<std::uint8_t>& bytes, std::uint64_t value, std::size_t width) {
  const auto start = bytes.size();
  bytes.resize(start + width, 0);
  for (std::size_t i = 0; i < width; ++i) {
    bytes[start + i] = static_cast<std::uint8_t>((value >> (i * 8u)) & 0xffu);
  }
}

inline std::vector<std::uint8_t> random_bytes_local(std::size_t n) {
  std::vector<std::uint8_t> out(n);
  std::random_device rd;
  for (auto& b : out) {
    b = static_cast<std::uint8_t>(rd());
  }
  return out;
}

struct MetadataSectionNames {
  std::optional<std::string> vmload;
  std::optional<std::string> thunk_meta;
  std::optional<std::string> string_pool;
  std::optional<std::string> code_blob;
  std::optional<std::string> trampoline_meta;

  [[nodiscard]] json to_json() const {
    json out;
    if (vmload.has_value()) out["vmload"] = *vmload;
    if (thunk_meta.has_value()) out["thunk_meta"] = *thunk_meta;
    if (string_pool.has_value()) out["string_pool"] = *string_pool;
    if (code_blob.has_value()) out["code_blob"] = *code_blob;
    if (trampoline_meta.has_value()) out["trampoline_meta"] = *trampoline_meta;
    return out;
  }
};

inline std::vector<std::uint8_t> expand_key_context(const vmp::runtime::trampoline::KeyContextId& key_context_id,
                                                    std::string_view info,
                                                    std::size_t out_len) {
  std::vector<std::uint8_t> ikm(key_context_id.begin(), key_context_id.end());
  const auto prk = vmp::runtime::strings::hkdf_extract_sha256({}, ikm);
  return vmp::runtime::strings::hkdf_expand_sha256(prk, vmp::runtime::strings::to_bytes(info), out_len);
}

inline std::string hmac_id_hex(const vmp::runtime::trampoline::KeyContextId& key_context_id,
                               std::string_view input) {
  const auto key = expand_key_context(key_context_id, "vmp.metadata.symbol.v1", 32);
  const auto mac = vmp::runtime::strings::hmac_sha256(key, vmp::runtime::strings::to_bytes(input));
  return vmp::runtime::strings::hex_encode(std::vector<std::uint8_t>(mac.begin(), mac.begin() + 8));
}

inline vmp::runtime::strings::AesCtrNonce random_metadata_nonce() {
  const auto bytes = random_bytes_local(16u);
  vmp::runtime::strings::AesCtrNonce nonce{};
  std::copy(bytes.begin(), bytes.end(), nonce.begin());
  return nonce;
}

inline std::vector<std::uint8_t> encrypt_metadata_json(const vmp::runtime::trampoline::KeyContextId& key_context_id,
                                                       MetadataBlobKind kind,
                                                       std::string_view logical_name,
                                                       const json& plain) {
  auto key = expand_key_context(key_context_id, std::string("vmp.metadata.v1|") + std::string(logical_name), 32);
  const auto nonce = random_metadata_nonce();
  const auto plaintext = vmp::runtime::strings::to_bytes(plain.dump());
  const auto ciphertext = vmp::runtime::strings::aes256_ctr_xor(key, nonce, plaintext);

  std::vector<std::uint8_t> out;
  out.reserve(4u + 1u + 1u + 2u + nonce.size() + 4u + ciphertext.size());
  out.push_back(0x91u);
  out.push_back(0xC4u);
  out.push_back(0x5Au);
  out.push_back(0x17u);
  out.push_back(1u);
  out.push_back(static_cast<std::uint8_t>(kind));
  out.push_back(0u);
  out.push_back(0u);
  out.insert(out.end(), nonce.begin(), nonce.end());
  append_le(out, plaintext.size(), 4u);
  out.insert(out.end(), ciphertext.begin(), ciphertext.end());
  const auto target_size = static_cast<std::size_t>(((out.size() + 511u) / 512u) * 512u);
  if (target_size > out.size()) {
    const auto pad = random_bytes_local(target_size - out.size());
    out.insert(out.end(), pad.begin(), pad.end());
  }
  vmp::runtime::strings::secure_memzero(key.data(), key.size());
  return out;
}

inline std::string random_section_name(std::set<std::string>& used_names) {
  static constexpr char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
  std::random_device rd;
  std::mt19937_64 rng((static_cast<std::uint64_t>(rd()) << 32u) ^ static_cast<std::uint64_t>(rd()));
  std::uniform_int_distribution<std::size_t> dist(0u, sizeof(kAlphabet) - 2u);
  for (;;) {
    std::string name{"."};
    name.reserve(8u);
    for (std::size_t i = 0; i < 7u; ++i) {
      name.push_back(kAlphabet[dist(rng)]);
    }
    if (used_names.insert(name).second) {
      return name;
    }
  }
}

}  // namespace vmp::backend::rewriter::detail
