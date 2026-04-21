#include <iostream>
#include <stdexcept>
#include <vector>

#include <vmp/runtime/trampoline/trampoline.h>

namespace {

void require(bool condition, const char* message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

}  // namespace

int main() {
  using namespace vmp::runtime::trampoline;

  TrampolineBundle bundle;
  bundle.arch = TrampolineArch::x64;
  bundle.key_context_id = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
                           0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50};
  bundle.code_blob = {0x90, 0x90, 0xC3, 0x90};
  TokenEntry entry;
  entry.token = token_from_low64(0x1234u);
  entry.original_address = 0x401000u;
  entry.symbol_name = "alpha";
  entry.key_context_id = bundle.key_context_id;
  bundle.records.push_back({entry, 1u, 3u});

  const auto bytes = bundle.serialize();
  const auto roundtrip = TrampolineBundle::deserialize(bytes);
  require(roundtrip.arch == TrampolineArch::x64, "bundle arch mismatch");
  require(roundtrip.key_context_id == bundle.key_context_id, "bundle key context mismatch");
  require(roundtrip.code_blob == bundle.code_blob, "bundle code blob mismatch");
  require(roundtrip.records.size() == 1u, "bundle record count mismatch");
  require(roundtrip.records[0].entry.token == token_from_low64(0x1234u), "bundle token mismatch");
  require(roundtrip.records[0].entry.symbol_name == "alpha", "bundle symbol mismatch");
  require(roundtrip.records[0].relocated_offset == 1u, "bundle relocated offset mismatch");
  require(roundtrip.records[0].code_size == 3u, "bundle code size mismatch");

  const auto instantiated = roundtrip.instantiate(0x900000u);
  require(instantiated.size() == 1u, "instantiated record count mismatch");
  require(instantiated[0].relocated_address == 0x900001u, "instantiated relocated address mismatch");

  std::cout << "trampoline_bundle_roundtrip OK\n";
  return 0;
}
