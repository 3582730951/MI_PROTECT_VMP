#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_crypto_revision;

int main() {
  namespace strings = vmp::runtime::strings;

  const std::vector<std::uint8_t> same_a{0x10, 0x20, 0x30, 0x40};
  const std::vector<std::uint8_t> same_b{0x10, 0x20, 0x30, 0x40};
  const std::vector<std::uint8_t> diff_first{0x11, 0x20, 0x30, 0x40};
  const std::vector<std::uint8_t> diff_last{0x10, 0x20, 0x30, 0x41};
  const std::vector<std::uint8_t> short_vec{0x10, 0x20, 0x30};

  require(strings::constant_time_equal(same_a, same_b), "equal vectors must compare equal");
  require(!strings::constant_time_equal(same_a, diff_first), "first-byte mismatch must compare unequal");
  require(!strings::constant_time_equal(same_a, diff_last), "last-byte mismatch must compare unequal");
  require(!strings::constant_time_equal(same_a, short_vec), "length mismatch must compare unequal");

  std::array<std::uint8_t, 32> key{};
  for (std::size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<std::uint8_t>(0x80 + i);
  }
  const auto nonce = strings::u32_to_nonce(0x12345678u);
  const auto record = strings::encrypt_string_record(key, nonce, strings::to_bytes("armor-breaking"));
  auto tampered = record.ciphertext;
  tampered.back() ^= 0x01u;

  bool failed = false;
  try {
    (void)strings::decrypt_string_record(key, nonce, tampered);
  } catch (const std::runtime_error&) {
    failed = true;
  }
  require(failed, "tampered HMAC must be rejected");

  std::cout << "crypto_revision_constant_time_hmac OK\n";
  return 0;
}
