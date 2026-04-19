#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace vmp::tests::runtime_opcode_cryptor {

inline void require(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

inline std::array<std::uint8_t, 16> bytes16(std::uint8_t base) {
  std::array<std::uint8_t, 16> out{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>(base + static_cast<std::uint8_t>(i));
  }
  return out;
}

}  // namespace vmp::tests::runtime_opcode_cryptor
