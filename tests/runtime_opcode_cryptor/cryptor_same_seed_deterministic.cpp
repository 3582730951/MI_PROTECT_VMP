#include "test_common.h"

#include <iostream>

#include <vmp/runtime/vm1/vm1.h>
#include <vmp/runtime/vm2/vm2.h>

namespace vm1 = vmp::runtime::vm1;
namespace vm2 = vmp::runtime::vm2;
using namespace vmp::tests::runtime_opcode_cryptor;

int main() {
  try {
    const auto master_key = bytes16(0x33);
    const auto seed = bytes16(0x44);

    {
      const auto a = vm1::OpcodeCryptor::from_seed(master_key, seed);
      const auto b = vm1::OpcodeCryptor::from_seed(master_key, seed);
      for (const auto opcode : vm1::canonical_opcode_sequence()) {
        require(a.encode(opcode) == b.encode(opcode), "vm1 same-seed encode mismatch");
      }
    }

    {
      const auto a = vm2::OpcodeCryptor::from_seed(master_key, seed);
      const auto b = vm2::OpcodeCryptor::from_seed(master_key, seed);
      for (const auto opcode : vm2::canonical_opcode_sequence()) {
        require(a.encode(opcode) == b.encode(opcode), "vm2 same-seed encode mismatch");
      }
    }

    std::cout << "cryptor_same_seed_deterministic OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "cryptor_same_seed_deterministic failed: " << ex.what() << '\n';
    return 1;
  }
}
