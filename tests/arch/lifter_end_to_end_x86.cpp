#include "test_common.h"

#include <iostream>
#include <vector>

#include <vmp/arch/x86/x86.h>

namespace {
std::uint64_t native_loop_sum(std::uint64_t count, std::uint64_t step) {
  std::uint64_t sum = 0;
  while (count > 0) {
    sum += step;
    --count;
  }
  return sum;
}
}  // namespace

int main() {
  try {
    using namespace vmp::arch;
    common::FunctionView view;
    view.base_addr = 0x6100;
    view.cc = common::CallingConvention::cdecl_x86;
    view.endian = common::ArchEndianness::little;
    view.code = {
        0x55, 0x89, 0xE5, 0x8B, 0x4D, 0x08, 0x8B, 0x5D, 0x0C, 0xB8, 0x00, 0x00, 0x00, 0x00,
        0xBA, 0x00, 0x00, 0x00, 0x00, 0x39, 0xD1, 0x7E, 0x0D, 0xBE, 0x01, 0x00, 0x00, 0x00,
        0x01, 0xD8, 0x29, 0xF1, 0x39, 0xD1, 0x7F, 0xF8, 0x5D, 0xC3,
    };
    x86::X86Lifter lifter;
    const auto lifted = lifter.lift(view);
    vmp::tests::arch::require(lifted.ok(), "x86 loop lift failed");
    for (const auto& tc : std::vector<std::pair<std::uint64_t, std::uint64_t>>{{0, 7}, {4, 3}, {6, 2}}) {
      const auto actual = vmp::tests::arch::run_vm1_abi(lifted.module, view.cc, {tc.first, tc.second});
      vmp::tests::arch::require(actual == native_loop_sum(tc.first, tc.second), "x86 loop result mismatch");
    }
    std::cout << "lifter_end_to_end_x86 OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "lifter_end_to_end_x86 failed: " << ex.what() << '\n';
    return 1;
  }
}
