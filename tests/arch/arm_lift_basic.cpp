#include "test_common.h"

#include <iostream>

#include <vmp/arch/arm/arm.h>

int main() {
  try {
    using namespace vmp::arch;
    common::FunctionView view;
    view.base_addr = 0x4000;
    view.cc = common::CallingConvention::aapcs32;
    view.endian = common::ArchEndianness::little;
    view.code = {0x01, 0x00, 0x80, 0xE0, 0x1E, 0xFF, 0x2F, 0xE1};
    arm::ArmLifter lifter;
    auto lifted = lifter.lift(view);
    vmp::tests::arch::require(lifted.ok(), "arm lift failed");
    const auto value = vmp::tests::arch::run_vm1_abi(lifted.module, view.cc, {2, 3});
    vmp::tests::arch::require(value == 5, "arm add returned unexpected value");
    std::cout << "arm_lift_basic OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "arm_lift_basic failed: " << ex.what() << '\n';
    return 1;
  }
}
