#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_reverse_layout;

int main() {
  try {
    const auto text = read_text(std::filesystem::path(VMP_RUNTIME_REVERSE_LAYOUT_FIXTURES_DIR) / "branches.vm1s");

    vmp::runtime::vm1::AssembleOptions forward_options;
    const auto forward_module = vmp::runtime::vm1::assemble_module_text(text, forward_options);

    vmp::runtime::vm1::AssembleOptions reverse_options;
    reverse_options.module_flags = vmp::runtime::vm1::VMP_FLAG_REVERSE_ORDER;
    const auto reverse_module = vmp::runtime::vm1::assemble_module_text(text, reverse_options);

    const auto loaded_forward = vmp::runtime::vm1::Vm1Module::load_from_bytes(forward_module.serialize());
    const auto loaded_reverse = vmp::runtime::vm1::Vm1Module::load_from_bytes(reverse_module.serialize());

    require_int(execute_vm1(loaded_forward, 0), 15, "forward branch program");
    require_int(execute_vm1(loaded_reverse, 0), 15, "reverse branch program");

    require(sum_lengths(loaded_reverse.reverse_insn_lengths) == loaded_reverse.code.size(), "length table sum mismatch");
    std::uint32_t forward_pc = 0;
    for (std::uint16_t length : loaded_reverse.reverse_insn_lengths) {
      const auto reverse_pc = static_cast<std::uint32_t>(loaded_reverse.code.size() - forward_pc - length);
      require(reverse_pc < loaded_reverse.reverse_pc_to_forward_pc.size(), "reverse pc map truncated");
      require(loaded_reverse.reverse_pc_to_forward_pc[reverse_pc] == forward_pc,
              "reverse pc must map back to the original forward pc");
      forward_pc += length;
    }

    std::cout << "reverse_layout_branches_forward_pc OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "reverse_layout_branches_forward_pc failed: " << ex.what() << '\n';
    return 1;
  }
}
