#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <vmp/runtime/vm1/vm1.h>
#include <vmp/runtime/vm2/vm2.h>

namespace vmp::arch::common {

enum class CallingConvention : std::uint8_t {
  cdecl_x86,
  stdcall_x86,
  sysv_x64,
  msvc_x64,
  aapcs32,
  aapcs64,
};

enum class ArchEndianness : std::uint8_t {
  little,
  big,
};

enum class TargetDomain : std::uint8_t {
  vm1,
  vm2,
};

enum class DiagnosticKind : std::uint8_t {
  unsupported_opcode,
  malformed_instruction,
  unsupported_thumb_mode,
  invalid_relocation,
  out_of_range,
  unresolved_label,
  duplicate_label,
};

struct Diagnostic {
  DiagnosticKind kind = DiagnosticKind::unsupported_opcode;
  std::size_t offset = 0;
  std::string detail;
};

struct RelocationEntry {
  std::size_t offset = 0;
  std::size_t width = 0;
  std::uint64_t resolved_value = 0;
  std::string tag;

  bool overlaps(std::size_t other_offset, std::size_t other_width) const noexcept {
    const std::size_t a0 = offset;
    const std::size_t a1 = offset + width;
    const std::size_t b0 = other_offset;
    const std::size_t b1 = other_offset + other_width;
    return a0 < b1 && b0 < a1;
  }
};

struct FunctionView {
  std::uint64_t base_addr = 0;
  std::vector<std::uint8_t> code;
  std::optional<std::vector<RelocationEntry>> relocs;
  CallingConvention cc = CallingConvention::sysv_x64;
  ArchEndianness endian = ArchEndianness::little;
};

struct LiftedFunction {
  vmp::runtime::vm1::Vm1Module module;
  std::optional<vmp::runtime::vm2::Vm2Module> vm2_module;
  std::vector<Diagnostic> diagnostics;

  bool ok() const noexcept {
    return diagnostics.empty() && (!module.code.empty() || (vm2_module.has_value() && !vm2_module->code.empty()));
  }
};

class IsaLifter {
 public:
  virtual ~IsaLifter() = default;
  virtual std::string isa_name() const = 0;
  virtual bool can_lift(const FunctionView&) const = 0;
  virtual LiftedFunction lift(const FunctionView&) const = 0;
};

const RelocationEntry* find_overlapping_relocation(const FunctionView& view,
                                                   std::size_t offset,
                                                   std::size_t width) noexcept;
std::uint64_t read_integer(const FunctionView& view, std::size_t offset, std::size_t width);
std::string const_tag_payload(const RelocationEntry& reloc);

}  // namespace vmp::arch::common
