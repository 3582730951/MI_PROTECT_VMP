#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_bogus_flow;

int main() {
  try {
    const std::string program = R"(
entry:
  ldi_u64 vr0, 1
  ldi_u64 vr1, 2
  add vr2, vr0, vr1
  sub vr3, vr2, vr1
  ldi_u64 vr4, 3
  add vr5, vr4, vr2
  sub vr6, vr5, vr1
  ldi_u64 vr7, 4
  add vr8, vr7, vr6
  sub vr9, vr8, vr0
  ret
)";

    const auto rewritten = vmp::runtime::obfuscation::obfuscate_vm1_assembly(program, 3, true);
    const auto dead_labels = count_label_defs(rewritten, "__vmp_vm1_bogus_dead_");
    const auto real_labels = count_label_defs(rewritten, "__vmp_vm1_bogus_real_");
    const auto join_labels = count_label_defs(rewritten, "__vmp_vm1_bogus_join_");

    require(dead_labels >= 3 && dead_labels <= 5,
            "vm1 bogus block ratio must stay within 30-50%");
    require(real_labels == dead_labels, "vm1 bogus real labels must match dead labels");
    require(join_labels == dead_labels, "vm1 bogus join labels must match dead labels");
    require(count_substring(rewritten, "jmp @__vmp_vm1_bogus_join_") == dead_labels,
            "vm1 bogus blocks must rejoin through jmp");

    const auto first_block =
        extract_first_labeled_block(rewritten, "__vmp_vm1_bogus_dead_", "__vmp_vm1_bogus_join_");
    require(!first_block.empty(), "vm1 bogus block should exist");
    require(first_block.find("vr") != std::string::npos,
            "vm1 bogus block must reference live vm registers");
    require(first_block.find("add ") != std::string::npos ||
                first_block.find("sub ") != std::string::npos ||
                first_block.find("ldi_u64 ") != std::string::npos,
            "vm1 bogus block must contain legal opcodes");
    require(first_block.find("ud2") == std::string::npos && first_block.find("int3") == std::string::npos,
            "vm1 bogus block must not expose trap markers");

    std::cout << "runtime_bogus_flow_vm1_rewriter OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "runtime_bogus_flow_vm1_rewriter failed: " << ex.what() << '\n';
    return 1;
  }
}
