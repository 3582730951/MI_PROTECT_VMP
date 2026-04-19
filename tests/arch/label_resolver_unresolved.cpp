#include "test_common.h"

#include <iostream>

#include <vmp/arch/common/label_resolver.h>

namespace common = vmp::arch::common;

int main() {
  try {
    common::LabelResolver resolver;
    resolver.reference(common::Fixup{0, common::FixupField::jump_offset_s32, common::Label{"missing"}, common::Range{-16, 16}, 0, 0});
    const auto result = resolver.resolve();
    vmp::tests::arch::require(!result.ok(), "unresolved label resolution should fail");
    vmp::tests::arch::require(result.diagnostics.size() == 1, "expected a single unresolved diagnostic");
    vmp::tests::arch::require(result.diagnostics.front().kind == common::ResolverDiagnosticKind::unresolved_label,
                              "expected unresolved_label diagnostic");
    std::cout << "label_resolver_unresolved OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "label_resolver_unresolved failed: " << ex.what() << '\n';
    return 1;
  }
}
