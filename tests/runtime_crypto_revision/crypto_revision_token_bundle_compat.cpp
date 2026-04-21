#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_crypto_revision;

namespace {

std::vector<std::uint8_t> serialize_v1_bundle(const vmp::runtime::trampoline::KeyContextId& key_context_id,
                                              std::uint64_t token,
                                              std::uint64_t original_address,
                                              std::uint64_t relocated_offset,
                                              std::uint32_t code_size,
                                              std::string_view symbol_name,
                                              const std::vector<std::uint8_t>& code_blob) {
  std::vector<std::uint8_t> out;
  out.insert(out.end(), {'V', 'M', 'P', 'T'});
  out.push_back(1u);
  out.push_back(0u);
  out.push_back(static_cast<std::uint8_t>(vmp::runtime::trampoline::TrampolineArch::x64));
  out.push_back(0u);
  append_le32(out, 1u);
  out.insert(out.end(), key_context_id.begin(), key_context_id.end());
  append_le32(out, static_cast<std::uint32_t>(code_blob.size()));
  append_le32(out, 0u);
  append_le64(out, token);
  append_le64(out, original_address);
  append_le64(out, relocated_offset);
  append_le32(out, code_size);
  out.push_back(static_cast<std::uint8_t>(symbol_name.size() & 0xffu));
  out.push_back(static_cast<std::uint8_t>((symbol_name.size() >> 8u) & 0xffu));
  out.push_back(0u);
  out.push_back(0u);
  out.insert(out.end(), symbol_name.begin(), symbol_name.end());
  out.insert(out.end(), code_blob.begin(), code_blob.end());
  return out;
}

}  // namespace

int main() {
  using namespace vmp::runtime::trampoline;

  require(kTrampolineBundleVersion == 2u, "bundle serializer must write VMPT v2");

  const KeyContextId key_context{
      0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
      0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
  };

  TrampolineBundle bundle;
  bundle.arch = TrampolineArch::x64;
  bundle.key_context_id = key_context;
  bundle.code_blob = {0x90, 0x90, 0xC3, 0x90};
  TokenEntry entry;
  entry.token = token_from_halves(0x1122334455667788ull, 0x99aabbccddeeff00ull);
  entry.original_address = 0x401000u;
  entry.symbol_name = "alpha";
  entry.key_context_id = key_context;
  bundle.records.push_back({entry, 1u, 3u});

  const auto bytes = bundle.serialize();
  require(read_le32(bytes, 8) == 1u, "v2 record count mismatch");
  require(bytes[4] == 2u && bytes[5] == 0u, "serialized VMPT version should be 2");

  const auto roundtrip = TrampolineBundle::deserialize(bytes);
  require(roundtrip.records.size() == 1u, "v2 roundtrip record count mismatch");
  require(roundtrip.records[0].entry.token == entry.token, "v2 roundtrip token mismatch");
  require(roundtrip.records[0].entry.symbol_name == "alpha", "v2 roundtrip symbol mismatch");

  const auto instantiated = roundtrip.instantiate(0x900000u);
  require(instantiated[0].relocated_address == 0x900001u, "v2 instantiated relocated address mismatch");
  require(instantiated[0].token == entry.token, "v2 instantiated token mismatch");

  const auto legacy_bytes = serialize_v1_bundle(key_context,
                                                0x0123456789abcdefull,
                                                0x402000u,
                                                2u,
                                                4u,
                                                "legacy",
                                                {0xC3, 0x90, 0x90, 0x90});
  const auto legacy = TrampolineBundle::deserialize(legacy_bytes);
  require(legacy.records.size() == 1u, "v1 compatibility record count mismatch");
  require(legacy.records[0].entry.token == token_from_low64(0x0123456789abcdefull), "v1 token upgrade mismatch");
  require(token_high64(legacy.records[0].entry.token) == 0u, "v1 legacy token high 64 should be zero-extended");
  require(legacy.records[0].entry.symbol_name == "legacy", "v1 symbol mismatch");
  require(legacy.code_blob.size() == 4u, "v1 code blob size mismatch");

  std::cout << "crypto_revision_token_bundle_compat OK\n";
  return 0;
}
