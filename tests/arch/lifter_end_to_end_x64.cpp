#include "test_common.h"

#include <iostream>
#include <vector>

#include <vmp/arch/x64/x64.h>

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
    view.base_addr = 0x7100;
    view.cc = common::CallingConvention::sysv_x64;
    view.endian = common::ArchEndianness::little;
    view.code = {
        0x48, 0x89, 0xF9, 0x48, 0x89, 0xF3, 0x31, 0xC0, 0x31, 0xD2, 0x48, 0x39, 0xD1, 0x7E,
        0x11, 0x41, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x01, 0xD8, 0x4C, 0x29, 0xC1, 0x48,
        0x39, 0xD1, 0x7F, 0xF5, 0xC3,
    };
    x64::X64Lifter lifter(common::TargetDomain::vm1);
    const auto lifted = lifter.lift(view);
    vmp::tests::arch::require(lifted.ok(), "x64 loop lift failed");
    for (const auto& tc : std::vector<std::pair<std::uint64_t, std::uint64_t>>{{0, 7}, {4, 3}, {6, 2}}) {
      const auto actual = vmp::tests::arch::run_vm1_abi(lifted.module, view.cc, {tc.first, tc.second});
      vmp::tests::arch::require(actual == native_loop_sum(tc.first, tc.second), "x64 loop result mismatch");
    }
    std::cout << "lifter_end_to_end_x64 OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "lifter_end_to_end_x64 failed: " << ex.what() << '\n';
    return 1;
  }
}
