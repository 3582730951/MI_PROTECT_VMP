#include "test_common.h"

#include <iostream>
#include <string>

#include <vmp/arch/x64/x64.h>

int main() {
  try {
    using namespace vmp::arch;
    common::FunctionView view;
    view.base_addr = 0x7000;
    view.cc = common::CallingConvention::sysv_x64;
    view.endian = common::ArchEndianness::little;
    view.code = {0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xC3};
    view.relocs = std::vector<common::RelocationEntry>{{2, 8, 0x1122334455667788ULL, "abs64"}};
    x64::X64Lifter lifter;
    auto lifted = lifter.lift(view);
    vmp::tests::arch::require(lifted.ok(), "relocation lift failed");
    const auto value = vmp::tests::arch::run_vm1_abi(lifted.module, view.cc, {});
    vmp::tests::arch::require(value == 0x1122334455667788ULL, "relocation runtime value mismatch");
    vmp::tests::arch::require(!lifted.module.const_pool.empty(), "relocation const pool not carried");
    const std::string payload(lifted.module.const_pool.front().bytes.begin(), lifted.module.const_pool.front().bytes.end());
    vmp::tests::arch::require(payload.find("reloc:abs64") != std::string::npos, "relocation tag missing");
    std::cout << "lift_relocation_carrying OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "lift_relocation_carrying failed: " << ex.what() << '\n';
    return 1;
  }
}
