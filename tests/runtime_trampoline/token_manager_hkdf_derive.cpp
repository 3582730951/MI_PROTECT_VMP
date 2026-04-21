#include <array>
#include <cstdint>
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

  TokenManager manager;
  const std::array<std::uint8_t, 16> key_context_a{
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  };
  const std::array<std::uint8_t, 16> key_context_b{
      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
  };

  const auto entry_a = manager.register_entry(key_context_a, 0x401000u, 0x501000u, "alpha");
  const auto entry_a_repeat = manager.register_entry(key_context_a, 0x401000u, 0x501000u, "alpha");
  const auto entry_b = manager.register_entry(key_context_a, 0x401100u, 0x501100u, "beta");
  const auto entry_c = manager.register_entry(key_context_b, 0x401000u, 0x501000u, "alpha");

  require(entry_a.token != TokenBytes{}, "token must not be zero");
  require(entry_a.token.size() == 16u, "token must be 128-bit");
  require(entry_a.token == entry_a_repeat.token, "token derivation must be deterministic");
  require(entry_a.token != entry_b.token, "different function address must change token");
  require(entry_a.token != entry_c.token, "different key context must change token");
  require(entry_a.original_address == 0x401000u, "original address mismatch");
  require(entry_a.relocated_address == 0x501000u, "relocated address mismatch");
  require(entry_a.symbol_name == "alpha", "symbol name mismatch");
  require(manager.entries().size() == 3u, "deduplicated entry count mismatch");

  std::cout << "token_manager_hkdf_derive OK\n";
  return 0;
}
