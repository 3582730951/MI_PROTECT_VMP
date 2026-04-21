#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_bogus_flow;

int main() {
  try {
    const std::string program = R"(
entry:
  ldi_u64 vr0, 7
  ldi_u64 vr1, 5
  add vr0, vr0, vr1
  ldi_u64 vr2, 3
  sub vr0, vr0, vr2
  ldi_u64 vr3, 9
  add vr0, vr0, vr3
  ret
)";

    const auto plain = vmp::runtime::vm1::assemble_module_text(program);
    vmp::runtime::vm1::AssembleOptions options;
    options.enable_mba_obfuscation = true;
    options.enable_opaque_predicates = true;
    options.obfuscation_depth = 3;
    const auto obfuscated = vmp::runtime::vm1::assemble_module_text(program, options);

    vmp::runtime::vm1::Vm1Context plain_ctx(plain);
    vmp::runtime::vm1::Vm1Context obf_ctx(obfuscated);
    const auto plain_result = vmp::runtime::vm1::Vm1Interpreter{}.execute(plain_ctx).ret_int;
    const auto obf_result = vmp::runtime::vm1::Vm1Interpreter{}.execute(obf_ctx).ret_int;
    require(plain_result == obf_result, "vm1 bogus flow must preserve execution result");

    const auto plain_dis = vmp::runtime::vm1::disassemble_module(plain);
    const auto obf_dis = vmp::runtime::vm1::disassemble_module(obfuscated);
    require(count_opcode_lines(obf_dis, "jmp ") > count_opcode_lines(plain_dis, "jmp "),
            "vm1 bogus flow must inject extra jmp edges");
    require(vmp::runtime::vm1::instruction_lengths(obfuscated).size() >
                vmp::runtime::vm1::instruction_lengths(plain).size() * 2u,
            "vm1 bogus flow must grow bytecode stream");

    std::cout << "runtime_bogus_flow_vm1_runtime OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "runtime_bogus_flow_vm1_runtime failed: " << ex.what() << '\n';
    return 1;
  }
}
