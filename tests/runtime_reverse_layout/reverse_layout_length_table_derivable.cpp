#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_reverse_layout;

int main() {
  try {
    const auto vm1_text = read_text(repo_path("tests/runtime_vm1/fixtures/fib20.vm1s"));
    vmp::runtime::vm1::AssembleOptions vm1_options;
    vm1_options.module_flags = vmp::runtime::vm1::VMP_FLAG_REVERSE_ORDER;
    const auto vm1_module =
        vmp::runtime::vm1::Vm1Module::load_from_bytes(vmp::runtime::vm1::assemble_module_text(vm1_text, vm1_options).serialize());

    const auto vm1_lengths = vmp::runtime::vm1::instruction_lengths(vm1_module);
    require(vm1_lengths == vm1_module.reverse_insn_lengths, "vm1 derived lengths must match stored table");
    require(sum_lengths(vm1_lengths) == vm1_module.code.size(), "vm1 length sum mismatch");

    const auto vm2_text = read_text(repo_path("tests/runtime_vm2/fixtures/fib20.vm2s"));
    vmp::runtime::vm2::AssembleOptions vm2_options;
    vm2_options.module_flags = vmp::runtime::vm2::VMP_FLAG_REVERSE_ORDER;
    const auto vm2_module =
        vmp::runtime::vm2::Vm2Module::load_from_bytes(vmp::runtime::vm2::assemble_module_text(vm2_text, vm2_options).serialize());

    const auto vm2_lengths = vmp::runtime::vm2::instruction_lengths(vm2_module);
    require(vm2_lengths == vm2_module.reverse_insn_lengths, "vm2 derived lengths must match stored table");
    require(sum_lengths(vm2_lengths) == vm2_module.code.size(), "vm2 length sum mismatch");

    std::cout << "reverse_layout_length_table_derivable OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "reverse_layout_length_table_derivable failed: " << ex.what() << '\n';
    return 1;
  }
}
