#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_crypto_revision;

int main() {
  using namespace vmp::runtime::trampoline;

  const auto token = token_from_halves(0x1122334455667788ull, 0x99aabbccddeeff00ull);
  const auto stub = generate_trampoline(TrampolineArch::x64, token, 0x1000ull, 0x2000ull);

  require(stub.bytes.size() == 35u, "x64 128-bit trampoline size mismatch");
  require(stub.bytes[0] == 0x48u && stub.bytes[1] == 0x8Bu && stub.bytes[2] == 0x05u,
          "x64 low-half mov opcode mismatch");
  require(read_le32(stub.bytes, 3) == 0x0000000cu, "x64 low-half RIP displacement mismatch");
  require(stub.bytes[7] == 0x48u && stub.bytes[8] == 0x8Bu && stub.bytes[9] == 0x15u,
          "x64 high-half mov opcode mismatch");
  require(read_le32(stub.bytes, 10) == 0x0000000du, "x64 high-half RIP displacement mismatch");
  require(stub.bytes[14] == 0xE9u, "x64 jmp opcode mismatch");
  require(read_le32(stub.bytes, 15) == 0x00000fedu, "x64 rel32 mismatch");
  require(read_le64(stub.bytes, 19) == 0x1122334455667788ull, "x64 low-half token payload mismatch");
  require(read_le64(stub.bytes, 27) == 0x99aabbccddeeff00ull, "x64 high-half token payload mismatch");

  std::cout << "crypto_revision_trampoline_x64_128bit OK\n";
  return 0;
}
