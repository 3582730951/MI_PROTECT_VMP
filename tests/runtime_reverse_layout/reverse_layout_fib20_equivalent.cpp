#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_reverse_layout;

int main() {
  try {
    const auto text = read_text(repo_path("tests/runtime_vm1/fixtures/fib20.vm1s"));

    vmp::runtime::vm1::AssembleOptions forward_options;
    forward_options.encrypt_opcodes = false;
    const auto forward_module = vmp::runtime::vm1::assemble_module_text(text, forward_options);
    const auto forward_bytes = forward_module.serialize();

    vmp::runtime::vm1::AssembleOptions reverse_options;
    reverse_options.module_flags = vmp::runtime::vm1::VMP_FLAG_REVERSE_ORDER;
    reverse_options.encrypt_opcodes = false;
    const auto reverse_module = vmp::runtime::vm1::assemble_module_text(text, reverse_options);
    const auto reverse_bytes = reverse_module.serialize();

    const auto forward_view = parse_vm1_image(forward_bytes);
    const auto reverse_view = parse_vm1_image(reverse_bytes);
    require((reverse_view.flags & vmp::runtime::vm1::VMP_FLAG_REVERSE_ORDER) != 0u, "reverse flag missing");

    const auto loaded_forward = vmp::runtime::vm1::Vm1Module::load_from_bytes(forward_bytes);
    const auto loaded_reverse = vmp::runtime::vm1::Vm1Module::load_from_bytes(reverse_bytes);

    require_int(execute_vm1(loaded_forward, 20), 6765, "forward fib20");
    require_int(execute_vm1(loaded_reverse, 20), 6765, "reverse fib20");

    require(!loaded_reverse.reverse_insn_lengths.empty(), "reverse length table missing");
    const auto expected_mirror = mirror_instruction_blocks(loaded_forward.code, loaded_reverse);
    require(reverse_view.code == expected_mirror, "reverse code section must mirror forward instruction blocks");
    require(forward_view.code == loaded_forward.code, "forward code section should remain canonical");

    std::cout << "reverse_layout_fib20_equivalent OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "reverse_layout_fib20_equivalent failed: " << ex.what() << '\n';
    return 1;
  }
}
