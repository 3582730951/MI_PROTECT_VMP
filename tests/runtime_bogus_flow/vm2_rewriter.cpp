#include "test_common.h"

#include <iostream>

using namespace vmp::tests::runtime_bogus_flow;

int main() {
  try {
    const std::string program = R"(
entry:
  ildimm r0, 1
  ildimm r1, 2
  iadd r2, r0, r1
  isub r3, r2, r1
  ildimm r4, 3
  iadd r5, r4, r2
  isub r6, r5, r1
  ildimm r7, 4
  iadd r8, r7, r6
  isub r9, r8, r0
  bret
)";

    const auto rewritten = vmp::runtime::obfuscation::obfuscate_vm2_assembly(program, 3, true);
    const auto dead_labels = count_label_defs(rewritten, "__vmp_vm2_bogus_dead_");
    const auto real_labels = count_label_defs(rewritten, "__vmp_vm2_bogus_real_");
    const auto join_labels = count_label_defs(rewritten, "__vmp_vm2_bogus_join_");

    require(dead_labels >= 3 && dead_labels <= 5,
            "vm2 bogus block ratio must stay within 30-50%");
    require(real_labels == dead_labels, "vm2 bogus real labels must match dead labels");
    require(join_labels == dead_labels, "vm2 bogus join labels must match dead labels");
    require(count_substring(rewritten, "jmp @__vmp_vm2_bogus_join_") == dead_labels,
            "vm2 bogus blocks must rejoin through jmp");

    const auto first_block =
        extract_first_labeled_block(rewritten, "__vmp_vm2_bogus_dead_", "__vmp_vm2_bogus_join_");
    require(!first_block.empty(), "vm2 bogus block should exist");
    require(first_block.find("r") != std::string::npos,
            "vm2 bogus block must reference live vm registers");
    require(first_block.find("iadd ") != std::string::npos ||
                first_block.find("isub ") != std::string::npos ||
                first_block.find("ildimm ") != std::string::npos,
            "vm2 bogus block must contain legal opcodes");
    require(first_block.find("ud2") == std::string::npos && first_block.find("int3") == std::string::npos,
            "vm2 bogus block must not expose trap markers");

    std::cout << "runtime_bogus_flow_vm2_rewriter OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "runtime_bogus_flow_vm2_rewriter failed: " << ex.what() << '\n';
    return 1;
  }
}
