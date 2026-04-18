#include "test_common.h"

#include <iostream>

#include <vmp/arch/x64/x64.h>

int main() {
  try {
    using namespace vmp::arch;
    common::FunctionView view;
    view.base_addr = 0x2000;
    view.cc = common::CallingConvention::sysv_x64;
    view.endian = common::ArchEndianness::little;
    view.code = {0x48, 0x89, 0xF8, 0x48, 0x01, 0xF0, 0xC3};
    x64::X64Lifter lifter;
    auto lifted = lifter.lift(view);
    vmp::tests::arch::require(lifted.ok(), "x64 sysv lift failed");
    const auto value = vmp::tests::arch::run_vm1_abi(lifted.module, view.cc, {2, 3});
    vmp::tests::arch::require(value == 5, "x64 sysv add returned unexpected value");
    std::cout << "x64_lift_basic_sysv OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "x64_lift_basic_sysv failed: " << ex.what() << '\n';
    return 1;
  }
}
