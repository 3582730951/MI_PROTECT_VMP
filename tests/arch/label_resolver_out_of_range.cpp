#include "test_common.h"

#include <cstdint>
#include <iostream>
#include <vector>

#include <vmp/arch/common/label_resolver.h>
#include <vmp/runtime/vm1/isa.h>

namespace common = vmp::arch::common;
namespace vm1 = vmp::runtime::vm1;

namespace {
using vmp::tests::arch::require;

void append_u16(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFFu));
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& bytes, std::size_t off) {
  return static_cast<std::uint32_t>(bytes.at(off)) |
         (static_cast<std::uint32_t>(bytes.at(off + 1)) << 8u) |
         (static_cast<std::uint32_t>(bytes.at(off + 2)) << 16u) |
         (static_cast<std::uint32_t>(bytes.at(off + 3)) << 24u);
}
}  // namespace

int main() {
  try {
    std::vector<std::uint8_t> code;
    append_u16(code, static_cast<std::uint16_t>(vm1::Opcode::jmp));
    append_u32(code, 0x11121314u);
    append_u16(code, static_cast<std::uint16_t>(vm1::Opcode::jeq));
    code.push_back(0);
    code.push_back(1);
    append_u32(code, 0x21222324u);
    append_u16(code, static_cast<std::uint16_t>(vm1::Opcode::ret));

    common::LabelResolver resolver(&code);
    resolver.define(common::Label{"near"}, 10);
    resolver.define(common::Label{"too_far"}, 2u * 1024u * 1024u);
    resolver.reference(common::Fixup{0, common::FixupField::jump_offset_s32, common::Label{"near"}, common::Range{-0x1000, 0x1000}, 0, 2});
    resolver.reference(common::Fixup{1, common::FixupField::jump_offset_s32, common::Label{"too_far"}, common::Range{-1048576, 1048572}, 6, 10});

    const auto result = resolver.resolve();
    require(!result.ok(), "out-of-range resolution should fail");
    require(result.diagnostics.size() == 1, "expected exactly one diagnostic");
    require(result.diagnostics.front().kind == common::ResolverDiagnosticKind::out_of_range,
            "expected out_of_range diagnostic");
    require(read_u32(code, 2) == 0x11121314u, "successful fixup must not patch when any diagnostic exists");
    require(read_u32(code, 10) == 0x21222324u, "out-of-range fixup must leave placeholder bytes untouched");
    std::cout << "label_resolver_out_of_range OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "label_resolver_out_of_range failed: " << ex.what() << '\n';
    return 1;
  }
}
