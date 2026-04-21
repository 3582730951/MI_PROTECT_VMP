#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace vmp::runtime::strings {

using AesCtrNonce = std::array<std::uint8_t, 16>;

std::vector<std::uint8_t> aes256_ctr_xor(const std::vector<std::uint8_t>& key,
                                         const AesCtrNonce& nonce,
                                         const std::vector<std::uint8_t>& input);

}  // namespace vmp::runtime::strings
