#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_reverse_layout;

int main() {
  try {
    const auto fib_text = read_text(repo_path("tests/runtime_vm2/fixtures/fib20.vm2s"));

    vmp::runtime::vm2::AssembleOptions fib_forward_options;
    const auto fib_forward = vmp::runtime::vm2::assemble_module_text(fib_text, fib_forward_options);

    vmp::runtime::vm2::AssembleOptions fib_reverse_options;
    fib_reverse_options.module_flags = vmp::runtime::vm2::VMP_FLAG_REVERSE_ORDER;
    const auto fib_reverse = vmp::runtime::vm2::assemble_module_text(fib_text, fib_reverse_options);

    const auto forward_bytes = fib_forward.serialize();
    const auto reverse_bytes = fib_reverse.serialize();
    const auto loaded_forward = vmp::runtime::vm2::Vm2Module::load_from_bytes(forward_bytes);
    const auto loaded_reverse = vmp::runtime::vm2::Vm2Module::load_from_bytes(reverse_bytes);
    const auto reverse_view = parse_vm2_image(reverse_bytes);

    require_int(execute_vm2(loaded_forward, 20), 6765, "vm2 forward fib20");
    require_int(execute_vm2(loaded_reverse, 20), 6765, "vm2 reverse fib20");
    require(reverse_view.code == mirror_instruction_blocks(loaded_forward.code, loaded_reverse),
            "vm2 reverse code section must mirror forward instruction blocks");

    const auto branch_text = read_text(std::filesystem::path(VMP_RUNTIME_REVERSE_LAYOUT_FIXTURES_DIR) / "branches.vm2s");
    vmp::runtime::vm2::AssembleOptions branch_forward_options;
    const auto branch_forward = vmp::runtime::vm2::Vm2Module::load_from_bytes(
        vmp::runtime::vm2::assemble_module_text(branch_text, branch_forward_options).serialize());
    vmp::runtime::vm2::AssembleOptions branch_reverse_options;
    branch_reverse_options.module_flags = vmp::runtime::vm2::VMP_FLAG_REVERSE_ORDER;
    const auto branch_reverse = vmp::runtime::vm2::Vm2Module::load_from_bytes(
        vmp::runtime::vm2::assemble_module_text(branch_text, branch_reverse_options).serialize());

    require_int(execute_vm2(branch_forward, 0), 15, "vm2 forward branch program");
    require_int(execute_vm2(branch_reverse, 0), 15, "vm2 reverse branch program");

    std::cout << "reverse_layout_vm2_equivalent OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "reverse_layout_vm2_equivalent failed: " << ex.what() << '\n';
    return 1;
  }
}
