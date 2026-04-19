#include "test_common.h"

#include <iostream>
#include <vector>

#include <vmp/arch/arm64/arm64.h>

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
    view.base_addr = 0x9100;
    view.cc = common::CallingConvention::aapcs64;
    view.endian = common::ArchEndianness::little;
    view.code = {
        0x42, 0x00, 0x02, 0xCA, 0x04, 0x00, 0x02, 0x8B, 0x40, 0x00, 0x02, 0x8B, 0x9F, 0x00,
        0x02, 0xEB, 0xCD, 0x00, 0x00, 0x54, 0xE3, 0x00, 0x00, 0x58, 0x00, 0x00, 0x01, 0x8B,
        0x84, 0x00, 0x03, 0xCB, 0x9F, 0x00, 0x02, 0xEB, 0xAC, 0xFF, 0xFF, 0x54, 0xC0, 0x03,
        0x5F, 0xD6, 0x1F, 0x20, 0x03, 0xD5, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    arm64::Arm64Lifter lifter;
    const auto lifted = lifter.lift(view);
    vmp::tests::arch::require(lifted.ok(), "arm64 loop lift failed");
    for (const auto& tc : std::vector<std::pair<std::uint64_t, std::uint64_t>>{{0, 7}, {4, 3}, {6, 2}}) {
      const auto actual = vmp::tests::arch::run_vm1_abi(lifted.module, view.cc, {tc.first, tc.second});
      vmp::tests::arch::require(actual == native_loop_sum(tc.first, tc.second), "arm64 loop result mismatch");
    }
    std::cout << "lifter_end_to_end_arm64 OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "lifter_end_to_end_arm64 failed: " << ex.what() << '\n';
    return 1;
  }
}
