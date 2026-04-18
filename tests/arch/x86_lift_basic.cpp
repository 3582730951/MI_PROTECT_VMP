#include "test_common.h"

#include <iostream>

#include <vmp/arch/x86/x86.h>

int main() {
  try {
    using namespace vmp::arch;
    common::FunctionView view;
    view.base_addr = 0x1000;
    view.cc = common::CallingConvention::cdecl_x86;
    view.endian = common::ArchEndianness::little;
    view.code = {0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x03, 0x45, 0x0C, 0x5D, 0xC3};
    x86::X86Lifter lifter;
    auto lifted = lifter.lift(view);
    vmp::tests::arch::require(lifted.ok(), "x86 lift failed");
    const auto value = vmp::tests::arch::run_vm1_abi(lifted.module, view.cc, {2, 3});
    vmp::tests::arch::require(value == 5, "x86 add returned unexpected value");
    std::cout << "x86_lift_basic OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "x86_lift_basic failed: " << ex.what() << '\n';
    return 1;
  }
}
