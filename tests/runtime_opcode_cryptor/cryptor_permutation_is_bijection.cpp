#include "test_common.h"

#include <iostream>
#include <unordered_set>

#include <vmp/runtime/vm1/vm1.h>
#include <vmp/runtime/vm2/vm2.h>

namespace vm1 = vmp::runtime::vm1;
namespace vm2 = vmp::runtime::vm2;
using namespace vmp::tests::runtime_opcode_cryptor;

int main() {
  try {
    const auto master_key = bytes16(0x10);
    const auto seed = bytes16(0x80);

    {
      const auto cryptor = vm1::OpcodeCryptor::from_seed(master_key, seed);
      std::unordered_set<std::uint16_t> seen;
      for (const auto opcode : vm1::canonical_opcode_sequence()) {
        const auto encoded = cryptor.encode(opcode);
        require(seen.insert(encoded).second, "vm1 permutation must be bijective");
        require(cryptor.decode(encoded) == opcode, "vm1 decode(encode(op)) must round-trip");
      }
      require(seen.size() == vm1::canonical_opcode_sequence().size(), "vm1 encoded opcode cardinality mismatch");
    }

    {
      const auto cryptor = vm2::OpcodeCryptor::from_seed(master_key, seed);
      std::unordered_set<std::uint16_t> seen;
      for (const auto opcode : vm2::canonical_opcode_sequence()) {
        const auto encoded = cryptor.encode(opcode);
        require(seen.insert(encoded).second, "vm2 permutation must be bijective");
        require(cryptor.decode(encoded) == opcode, "vm2 decode(encode(op)) must round-trip");
      }
      require(seen.size() == vm2::canonical_opcode_sequence().size(), "vm2 encoded opcode cardinality mismatch");
    }

    std::cout << "cryptor_permutation_is_bijection OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "cryptor_permutation_is_bijection failed: " << ex.what() << '\n';
    return 1;
  }
}
