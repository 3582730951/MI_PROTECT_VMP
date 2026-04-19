#include "test_common.h"

#include <iostream>

#include <vmp/arch/common/label_resolver.h>

namespace common = vmp::arch::common;

int main() {
  try {
    common::LabelResolver resolver;
    resolver.define(common::Label{"dup"}, 4);
    resolver.define(common::Label{"dup"}, 9);
    const auto result = resolver.resolve();
    vmp::tests::arch::require(!result.ok(), "duplicate label resolution should fail");
    vmp::tests::arch::require(result.diagnostics.size() == 1, "expected a single duplicate diagnostic");
    vmp::tests::arch::require(result.diagnostics.front().kind == common::ResolverDiagnosticKind::duplicate_label,
                              "expected duplicate_label diagnostic");
    std::cout << "label_resolver_duplicate OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "label_resolver_duplicate failed: " << ex.what() << '\n';
    return 1;
  }
}
