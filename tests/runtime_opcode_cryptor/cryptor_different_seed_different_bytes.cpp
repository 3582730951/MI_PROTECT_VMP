#include "test_common.h"

#include <array>
#include <iostream>

#include <vmp/runtime/vm1/vm1.h>

namespace vm1 = vmp::runtime::vm1;
using namespace vmp::tests::runtime_opcode_cryptor;

int main() {
  try {
    const auto master_key = bytes16(0x21);
    const auto seed_a = bytes16(0x31);
    const auto seed_b = bytes16(0x91);
    const auto cryptor_a = vm1::OpcodeCryptor::from_seed(master_key, seed_a);
    const auto cryptor_b = vm1::OpcodeCryptor::from_seed(master_key, seed_b);

    constexpr std::array<vm1::Opcode, 15> fib20_sequence{{
        vm1::Opcode::call,
        vm1::Opcode::ret,
        vm1::Opcode::ldi_u64,
        vm1::Opcode::jlt,
        vm1::Opcode::mov,
        vm1::Opcode::ldi_u64,
        vm1::Opcode::sub,
        vm1::Opcode::call,
        vm1::Opcode::mov,
        vm1::Opcode::ldi_u64,
        vm1::Opcode::sub,
        vm1::Opcode::call,
        vm1::Opcode::add,
        vm1::Opcode::ret,
        vm1::Opcode::ret,
    }};

    std::size_t differing = 0;
    for (const auto opcode : fib20_sequence) {
      if (cryptor_a.encode(opcode) != cryptor_b.encode(opcode)) {
        ++differing;
      }
    }

    require(differing * 100 >= fib20_sequence.size() * 95,
            "expected >=95% fib20 opcode-word divergence across different seeds");
    std::cout << "cryptor_different_seed_different_bytes OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "cryptor_different_seed_different_bytes failed: " << ex.what() << '\n';
    return 1;
  }
}
