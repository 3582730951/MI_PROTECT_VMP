#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_bogus_flow;

int main() {
  try {
    const std::string program = R"(
entry:
  ildimm r0, 7
  ildimm r1, 5
  iadd r0, r0, r1
  ildimm r2, 3
  isub r0, r0, r2
  ildimm r3, 9
  iadd r0, r0, r3
  bret
)";

    const auto plain = vmp::runtime::vm2::assemble_module_text(program);
    vmp::runtime::vm2::AssembleOptions options;
    options.enable_mba_obfuscation = true;
    options.enable_opaque_predicates = true;
    options.obfuscation_depth = 3;
    const auto obfuscated = vmp::runtime::vm2::assemble_module_text(program, options);

    vmp::runtime::vm2::Vm2Context plain_ctx(plain);
    vmp::runtime::vm2::Vm2Context obf_ctx(obfuscated);
    const auto plain_result = vmp::runtime::vm2::Vm2Interpreter{}.execute(plain_ctx).ret_int;
    const auto obf_result = vmp::runtime::vm2::Vm2Interpreter{}.execute(obf_ctx).ret_int;
    require(plain_result == obf_result, "vm2 bogus flow must preserve execution result");

    const auto plain_dis = vmp::runtime::vm2::disassemble_module(plain);
    const auto obf_dis = vmp::runtime::vm2::disassemble_module(obfuscated);
    require(count_opcode_lines(obf_dis, "jmp ") > count_opcode_lines(plain_dis, "jmp "),
            "vm2 bogus flow must inject extra jmp edges");
    require(vmp::runtime::vm2::instruction_lengths(obfuscated).size() >
                vmp::runtime::vm2::instruction_lengths(plain).size() * 2u,
            "vm2 bogus flow must grow bytecode stream");

    std::cout << "runtime_bogus_flow_vm2_runtime OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "runtime_bogus_flow_vm2_runtime failed: " << ex.what() << '\n';
    return 1;
  }
}
