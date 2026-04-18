#include <vmp/arch/common/lifting.h>

#include <sstream>

namespace vmp::arch::common {

const RelocationEntry* find_overlapping_relocation(const FunctionView& view,
                                                   std::size_t offset,
                                                   std::size_t width) noexcept {
  if (!view.relocs.has_value()) {
    return nullptr;
  }
  for (const auto& reloc : *view.relocs) {
    if (reloc.overlaps(offset, width)) {
      return &reloc;
    }
  }
  return nullptr;
}

std::uint64_t read_integer(const FunctionView& view, std::size_t offset, std::size_t width) {
  if (width == 0 || width > 8 || offset + width > view.code.size()) {
    throw std::runtime_error("lifter: integer read out of range");
  }
  std::uint64_t value = 0;
  if (view.endian == ArchEndianness::little) {
    for (std::size_t i = 0; i < width; ++i) {
      value |= static_cast<std::uint64_t>(view.code[offset + i]) << (i * 8u);
    }
  } else {
    for (std::size_t i = 0; i < width; ++i) {
      value = (value << 8u) | view.code[offset + i];
    }
  }
  if (const auto* reloc = find_overlapping_relocation(view, offset, width)) {
    value = reloc->resolved_value;
  }
  return value;
}

std::string const_tag_payload(const RelocationEntry& reloc) {
  std::ostringstream oss;
  oss << "reloc:" << reloc.tag << ":0x" << std::hex << reloc.resolved_value;
  return oss.str();
}

}  // namespace vmp::arch::common
