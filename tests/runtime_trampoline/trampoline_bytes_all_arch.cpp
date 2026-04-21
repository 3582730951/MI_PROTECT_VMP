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

std::uint32_t read_le32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  return static_cast<std::uint32_t>(bytes.at(offset)) |
         (static_cast<std::uint32_t>(bytes.at(offset + 1)) << 8u) |
         (static_cast<std::uint32_t>(bytes.at(offset + 2)) << 16u) |
         (static_cast<std::uint32_t>(bytes.at(offset + 3)) << 24u);
}

std::uint64_t read_le64(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  std::uint64_t value = 0;
  for (unsigned shift = 0; shift < 64; shift += 8) {
    value |= static_cast<std::uint64_t>(bytes.at(offset + shift / 8u)) << shift;
  }
  return value;
}

}  // namespace

int main() {
  using namespace vmp::runtime::trampoline;

  {
    const auto stub = generate_trampoline(
        TrampolineArch::x64,
        token_from_halves(0x1122334455667788ull, 0x99aabbccddeeff00ull),
        0x1000ull,
        0x2000ull);
    require(stub.bytes.size() == 35u, "x64 trampoline size mismatch");
    require(stub.bytes[0] == 0x48u && stub.bytes[1] == 0x8Bu && stub.bytes[2] == 0x05u, "x64 low-half mov opcode mismatch");
    require(read_le32(stub.bytes, 3) == 0x0000000cu, "x64 low-half displacement mismatch");
    require(stub.bytes[7] == 0x48u && stub.bytes[8] == 0x8Bu && stub.bytes[9] == 0x15u, "x64 high-half mov opcode mismatch");
    require(read_le32(stub.bytes, 10) == 0x0000000du, "x64 high-half displacement mismatch");
    require(stub.bytes[14] == 0xE9u, "x64 jmp opcode mismatch");
    require(read_le32(stub.bytes, 15) == 0x00000fedu, "x64 rel32 mismatch");
    require(read_le64(stub.bytes, 19) == 0x1122334455667788ull, "x64 low-half token payload mismatch");
    require(read_le64(stub.bytes, 27) == 0x99aabbccddeeff00ull, "x64 high-half token payload mismatch");
  }

  {
    const auto stub = generate_trampoline(TrampolineArch::x86, token_from_low64(0xAABBCCDDEEFF0011ull), 0x3000ull, 0x4000ull);
    require(stub.bytes.size() == 11u, "x86 trampoline size mismatch");
    require(stub.bytes[0] == 0xB8u, "x86 mov opcode mismatch");
    require(read_le32(stub.bytes, 1) == 0xEEFF0011u, "x86 token immediate mismatch");
    require(stub.bytes[5] == 0xE9u, "x86 jmp opcode mismatch");
    require(read_le32(stub.bytes, 6) == 0x00000ff6u, "x86 rel32 mismatch");
    require(stub.bytes[10] == 0x90u, "x86 final nop mismatch");
  }

  {
    const auto stub = generate_trampoline(TrampolineArch::arm64, token_from_low64(0x12345678ull), 0x5000ull, 0x5100ull);
    require(stub.bytes.size() == 12u, "arm64 trampoline size mismatch");
    require(read_le32(stub.bytes, 0) == 0xD28ACF10u, "arm64 movz mismatch");
    require(read_le32(stub.bytes, 4) == 0xF2A24690u, "arm64 movk mismatch");
    require(read_le32(stub.bytes, 8) == 0x1400003Eu, "arm64 branch mismatch");
  }

  {
    const auto stub = generate_trampoline(TrampolineArch::arm, token_from_low64(0xCAFEBABEull), 0x7000ull, 0x7100ull);
    require(stub.bytes.size() == 12u, "arm trampoline size mismatch");
    require(read_le32(stub.bytes, 0) == 0xE59FC000u, "arm ldr mismatch");
    require(read_le32(stub.bytes, 4) == 0xEA00003Du, "arm branch mismatch");
    require(read_le32(stub.bytes, 8) == 0xCAFEBABEu, "arm token word mismatch");
  }

  std::cout << "trampoline_bytes_all_arch OK\n";
  return 0;
}
