#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <cstdlib>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include <vmp/backend/rewriter_backend.h>
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/strings/keyctx.h>

namespace vmp::backend::rewriter::detail {

using json = nlohmann::json;

inline std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("rewriter: failed to open " + path.string());
  }
  return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

inline void write_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  if (!path.parent_path().empty()) std::filesystem::create_directories(path.parent_path());
  std::ofstream output(path, std::ios::binary);
  if (!output) {
    throw std::runtime_error("rewriter: failed to write " + path.string());
  }
  output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

inline void write_text(const std::filesystem::path& path, const std::string& text) {
  if (!path.parent_path().empty()) std::filesystem::create_directories(path.parent_path());
  std::ofstream output(path);
  if (!output) {
    throw std::runtime_error("rewriter: failed to write text " + path.string());
  }
  output << text;
}

inline std::uint64_t align_up(std::uint64_t value, std::uint64_t alignment) {
  if (alignment == 0) {
    return value;
  }
  const auto rem = value % alignment;
  return rem == 0 ? value : value + (alignment - rem);
}

inline void ensure_size(const std::vector<std::uint8_t>& bytes, std::size_t offset, std::size_t size, const char* what) {
  if (offset + size > bytes.size()) {
    throw std::runtime_error(std::string("rewriter: truncated ") + what);
  }
}

template <typename T>
inline T read_le(const std::vector<std::uint8_t>& bytes, std::size_t offset, const char* what) {
  ensure_size(bytes, offset, sizeof(T), what);
  T value{};
  for (std::size_t i = 0; i < sizeof(T); ++i) {
    value |= static_cast<T>(bytes[offset + i]) << (i * 8u);
  }
  return value;
}

template <>
inline std::uint8_t read_le<std::uint8_t>(const std::vector<std::uint8_t>& bytes, std::size_t offset, const char* what) {
  ensure_size(bytes, offset, 1, what);
  return bytes[offset];
}

inline void write_le(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value, std::size_t width) {
  if (offset + width > bytes.size()) {
    bytes.resize(offset + width, 0);
  }
  for (std::size_t i = 0; i < width; ++i) {
    bytes[offset + i] = static_cast<std::uint8_t>((value >> (i * 8u)) & 0xffu);
  }
}

inline std::string read_c_string(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  if (offset >= bytes.size()) {
    return {};
  }
  std::size_t end = offset;
  while (end < bytes.size() && bytes[end] != 0) {
    ++end;
  }
  return std::string(reinterpret_cast<const char*>(bytes.data() + offset), end - offset);
}

struct BinaryPolicyTarget {
  std::string container_path;
  std::string symbol;
  std::uint64_t offset = 0;
  bool has_offset = false;
  bool vm_string = false;
  bool vm1 = false;
  bool vm2 = false;
  bool highly_sensitive = false;
  vmp::policy::PolicyEntry entry;
};

inline BinaryPolicyTarget decode_target(const vmp::policy::PolicyEntry& entry) {
  BinaryPolicyTarget out;
  out.entry = entry;
  out.vm_string = std::find(entry.annotation_tags.begin(), entry.annotation_tags.end(), "vm_string") != entry.annotation_tags.end();
  out.vm1 = entry.protection_domain == vmp::policy::ProtectionDomain::vm1;
  out.vm2 = entry.protection_domain == vmp::policy::ProtectionDomain::vm2;
  out.highly_sensitive = entry.sensitivity_level == vmp::policy::SensitivityLevel::highly_sensitive;
  std::string raw = entry.symbol_or_region;
  const auto dcolon = raw.find("::");
  if (dcolon != std::string::npos) {
    out.container_path = raw.substr(0, dcolon);
    raw = raw.substr(dcolon + 2);
  }
  const auto plus = raw.rfind('+');
  if (plus != std::string::npos && plus + 1 < raw.size() && raw[plus + 1] == '0' && plus + 2 < raw.size() && (raw[plus + 2] == 'x' || raw[plus + 2] == 'X')) {
    out.symbol = raw.substr(0, plus);
    out.offset = std::stoull(raw.substr(plus + 3), nullptr, 16);
    out.has_offset = true;
  } else {
    out.symbol = raw;
  }
  return out;
}

struct StringRecordRequest {
  std::uint32_t string_id = 0;
  std::string symbol;
  std::string plaintext;
};

inline std::vector<std::uint8_t> random_bytes(std::size_t n) {
  std::vector<std::uint8_t> out(n);
  std::random_device rd;
  for (auto& b : out) b = static_cast<std::uint8_t>(rd());
  return out;
}

inline std::vector<std::uint8_t> resolve_master_key() {
  if (const char* env = std::getenv("VMP_STRING_MASTER_KEY"); env != nullptr && *env != '\0') {
    return vmp::runtime::strings::hex_decode(env);
  }
  return std::vector<std::uint8_t>(32, 0x42);
}

struct StringPoolArtifacts {
  std::vector<std::uint8_t> blob;
  json index_json;
  json kdf_json;
};

inline StringPoolArtifacts build_string_pool(const std::vector<StringRecordRequest>& requests) {
  auto master = resolve_master_key();
  auto salt = random_bytes(32);
  vmp::runtime::strings::KeyContext ctx(vmp::runtime::strings::MasterKeyHandle([master]() { return master; }), salt);
  const auto dk = ctx.derive_subkey("string-pool");
  StringPoolArtifacts out;
  out.index_json["key_context"] = {
      {"salt", vmp::runtime::strings::hex_encode(salt)},
      {"kdf", "HKDF-SHA256"},
      {"purpose_tag", "string-pool"},
      {"master_key_source", "env_or_fallback"},
  };
  for (const auto& request : requests) {
    const auto nonce = vmp::runtime::strings::u32_to_nonce(request.string_id);
    const auto rec = vmp::runtime::strings::encrypt_string_record(dk.bytes(), nonce,
                                                                  vmp::runtime::strings::to_bytes(request.plaintext));
    const auto offset = static_cast<std::uint32_t>(out.blob.size());
    out.blob.insert(out.blob.end(), rec.ciphertext.begin(), rec.ciphertext.end());
    out.index_json["entries"][std::to_string(request.string_id)] = {
        {"offset", offset},
        {"length", static_cast<std::uint32_t>(rec.ciphertext.size())},
        {"nonce", vmp::runtime::strings::hex_encode(std::vector<std::uint8_t>(nonce.begin(), nonce.end()))},
        {"plaintext_budget", "transient_only"},
        {"symbol_or_region", request.symbol},
    };
  }
  out.kdf_json = {
      {"salt", out.index_json["key_context"]["salt"]},
      {"kdf", "HKDF-SHA256"},
      {"purpose_tag", "string-pool"},
      {"master_key_source", "env_or_fallback"},
      {"string_count", requests.size()},
  };
  vmp::runtime::strings::secure_memzero(master.data(), master.size());
  return out;
}

inline std::uint32_t stable_string_id(std::string_view symbol) {
  std::uint32_t value = 5381u;
  for (unsigned char ch : symbol) {
    value = ((value << 5u) + value) ^ ch;
  }
  return value ? value : 1u;
}

inline std::vector<BinaryPolicyTarget> binary_targets(const vmp::policy::PolicyIR& policy_ir) {
  std::vector<BinaryPolicyTarget> out;
  for (const auto& entry : policy_ir.entries) {
    if (entry.language_origin != vmp::policy::LanguageOrigin::binary) {
      continue;
    }
    out.push_back(decode_target(entry));
  }
  return out;
}

inline std::string vm_thunk_descriptor_json(const std::vector<BinaryPolicyTarget>& targets,
                                            const RewriteOptions& options,
                                            std::string_view container_tag) {
  json root;
  root["container"] = container_tag;
  if (!options.vm1_module_path.empty()) {
    root["vm1_module_path"] = options.vm1_module_path.string();
  }
  if (!options.vm2_module_path.empty()) {
    root["vm2_module_path"] = options.vm2_module_path.string();
  }
  for (const auto& target : targets) {
    if (!target.vm1 && !target.vm2) {
      continue;
    }
    root["thunks"].push_back({
        {"symbol", target.symbol},
        {"domain", target.vm2 ? "vm2" : "vm1"},
        {"bridge_symbol", target.vm2 ? "vmp_runtime_bridge_vm2" : "vmp_runtime_bridge_vm1"},
    });
  }
  return root.dump(2);
}

}  // namespace vmp::backend::rewriter::detail
