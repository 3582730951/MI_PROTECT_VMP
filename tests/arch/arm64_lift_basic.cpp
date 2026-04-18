#include "test_common.h"

#include <iostream>

#include <vmp/arch/arm64/arm64.h>

int main() {
  try {
    using namespace vmp::arch;
    common::FunctionView view;
    view.base_addr = 0x5000;
    view.cc = common::CallingConvention::aapcs64;
    view.endian = common::ArchEndianness::little;
    view.code = {0x00, 0x00, 0x01, 0x8B, 0xC0, 0x03, 0x5F, 0xD6};
    arm64::Arm64Lifter lifter;
    auto lifted = lifter.lift(view);
    vmp::tests::arch::require(lifted.ok(), "arm64 lift failed");
    const auto value = vmp::tests::arch::run_vm1_abi(lifted.module, view.cc, {2, 3});
    vmp::tests::arch::require(value == 5, "arm64 add returned unexpected value");
    std::cout << "arm64_lift_basic OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "arm64_lift_basic failed: " << ex.what() << '\n';
    return 1;
  }
}
