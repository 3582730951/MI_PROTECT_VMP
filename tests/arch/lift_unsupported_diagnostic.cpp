#include "test_common.h"

#include <iostream>

#include <vmp/arch/x64/x64.h>

int main() {
  try {
    vmp::arch::common::FunctionView view;
    view.base_addr = 0x6000;
    view.cc = vmp::arch::common::CallingConvention::sysv_x64;
    view.endian = vmp::arch::common::ArchEndianness::little;
    view.code = {0x0F, 0x28, 0xC1};
    vmp::arch::x64::X64Lifter lifter;
    auto lifted = lifter.lift(view);
    vmp::tests::arch::require(!lifted.ok(), "unsupported opcode should not lift");
    vmp::tests::arch::require(!lifted.diagnostics.empty(), "missing diagnostic");
    vmp::tests::arch::require(lifted.diagnostics.front().kind == vmp::arch::common::DiagnosticKind::unsupported_opcode,
                              "wrong diagnostic kind");
    vmp::tests::arch::require(lifted.diagnostics.front().offset == 0, "wrong diagnostic offset");
    std::cout << "lift_unsupported_diagnostic OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "lift_unsupported_diagnostic failed: " << ex.what() << '\n';
    return 1;
  }
}
