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

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFFu));
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& bytes, std::size_t off) {
  return static_cast<std::uint32_t>(bytes.at(off)) |
         (static_cast<std::uint32_t>(bytes.at(off + 1)) << 8u) |
         (static_cast<std::uint32_t>(bytes.at(off + 2)) << 16u) |
         (static_cast<std::uint32_t>(bytes.at(off + 3)) << 24u);
}

std::uint64_t read_u64(const std::vector<std::uint8_t>& bytes, std::size_t off) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(bytes.at(off + static_cast<std::size_t>(i))) << (8u * i);
  }
  return value;
}
}  // namespace

int main() {
  try {
    std::vector<std::uint8_t> code;
    append_u16(code, static_cast<std::uint16_t>(vm1::Opcode::jmp));
    append_u32(code, 0xA1A2A3A4u);  // pc 0, fixup at [2,6)
    append_u16(code, static_cast<std::uint16_t>(vm1::Opcode::nop));
    append_u16(code, static_cast<std::uint16_t>(vm1::Opcode::jeq));  // pc 8
    code.push_back(0);
    code.push_back(1);
    append_u32(code, 0xB1B2B3B4u);  // fixup at [12,16)
    append_u16(code, static_cast<std::uint16_t>(vm1::Opcode::call));  // pc 16
    append_u32(code, 0xC1C2C3C4u);  // fixup at [18,22)
    code.push_back(0);
    append_u16(code, static_cast<std::uint16_t>(vm1::Opcode::ldi_u64));  // pc 23
    code.push_back(2);
    append_u64(code, 0xD1D2D3D4D5D6D7D8ull);  // fixup at [26,34)
    append_u16(code, static_cast<std::uint16_t>(vm1::Opcode::ret));      // pc 34

    common::LabelResolver resolver(&code);
    resolver.define(common::Label{"entry"}, 0);
    resolver.define(common::Label{"loop"}, 8);
    resolver.define(common::Label{"exit"}, 34);

    resolver.reference(common::Fixup{0, common::FixupField::jump_offset_s32, common::Label{"loop"}, common::Range{-0x1000, 0x1000}, 0, 2});
    resolver.reference(common::Fixup{2, common::FixupField::jump_offset_s32, common::Label{"entry"}, common::Range{-0x1000, 0x1000}, 8, 12});
    resolver.reference(common::Fixup{3, common::FixupField::call_offset_s32, common::Label{"exit"}, common::Range{-0x1000, 0x1000}, 16, 18});
    resolver.reference(common::Fixup{4, common::FixupField::address_materialize_s64, common::Label{"entry"}, common::Range{0, 0x1000}, 23, 26});

    const auto result = resolver.resolve();
    require(result.ok(), "basic label resolution should succeed");
    require(read_u32(code, 2) == 8u, "jmp target patch mismatch");
    require(read_u32(code, 12) == 0u, "backward jeq target patch mismatch");
    require(read_u32(code, 18) == 34u, "call target patch mismatch");
    require(read_u64(code, 26) == 0u, "address materialization patch mismatch");
    std::cout << "label_resolver_basic OK\n";
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "label_resolver_basic failed: " << ex.what() << '\n';
    return 1;
  }
}
