#include "test_common.h"

#include <iostream>
#include <vector>

#include <vmp/arch/arm/arm.h>

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
    view.base_addr = 0x8100;
    view.cc = common::CallingConvention::aapcs32;
    view.endian = common::ArchEndianness::little;
    view.code = {
        0x02, 0x20, 0x22, 0xE0, 0x00, 0x40, 0xA0, 0xE1, 0x00, 0x00, 0x20, 0xE0, 0x02, 0x00,
        0x54, 0xE1, 0x04, 0x00, 0x00, 0xDA, 0x10, 0x30, 0x9F, 0xE5, 0x01, 0x00, 0x80, 0xE0,
        0x03, 0x40, 0x44, 0xE0, 0x02, 0x00, 0x54, 0xE1, 0xFB, 0xFF, 0xFF, 0xCA, 0x1E, 0xFF,
        0x2F, 0xE1, 0x01, 0x00, 0x00, 0x00,
    };
    arm::ArmLifter lifter;
    const auto lifted = lifter.lift(view);
    vmp::tests::arch::require(lifted.ok(), "arm loop lift failed");
    for (const auto& tc : std::vector<std::pair<std::uint64_t, std::uint64_t>>{{0, 7}, {4, 3}, {6, 2}}) {
      const auto actual = vmp::tests::arch::run_vm1_abi(lifted.module, view.cc, {tc.first, tc.second});
      vmp::tests::arch::require(actual == native_loop_sum(tc.first, tc.second), "arm loop result mismatch");
    }
    std::cout << "lifter_end_to_end_arm OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "lifter_end_to_end_arm failed: " << ex.what() << '\n';
    return 1;
  }
}
