#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include <vmp/arch/common/pc_relative.h>

namespace vmp::arch::common {

using VmPc = std::uint64_t;

struct Range {
  std::int64_t min = std::numeric_limits<std::int64_t>::min();
  std::int64_t max = std::numeric_limits<std::int64_t>::max();

  [[nodiscard]] bool contains(std::int64_t value) const noexcept {
    return value >= min && value <= max;
  }
};

enum class FixupField : std::uint8_t {
  jump_offset_s32,
  call_offset_s32,
  load_disp_s32,
  address_materialize_s64,
};

struct Fixup {
  std::size_t instruction_index = 0;  // VM bytecode stream index (not byte offset)
  FixupField field = FixupField::jump_offset_s32;
  Label target_label;
  Range allowed_range;
  VmPc source_vm_pc = 0;              // byte-oriented VM pc used for range validation
  std::size_t code_offset = 0;        // byte offset in module.code to patch
};

enum class ResolverDiagnosticKind : std::uint8_t {
  out_of_range,
  unresolved_label,
  duplicate_label,
};

struct ResolverDiagnostic {
  ResolverDiagnosticKind kind = ResolverDiagnosticKind::unresolved_label;
  std::size_t instruction_index = 0;
  Label target_label;
  std::string detail;
};

struct Result {
  std::vector<ResolverDiagnostic> diagnostics;

  [[nodiscard]] bool ok() const noexcept { return diagnostics.empty(); }
};

class ResolutionError : public std::runtime_error {
 public:
  explicit ResolutionError(Result result);

  [[nodiscard]] const Result& result() const noexcept { return result_; }

 private:
  Result result_;
};

class LabelResolver {
 public:
  explicit LabelResolver(std::vector<std::uint8_t>* code = nullptr) : code_(code) {}

  void bind(std::vector<std::uint8_t>* code) noexcept { code_ = code; }
  void define(Label, VmPc);            // pass 1: record label location as lifter emits VM bytecode
  void reference(Fixup);               // pass 1: record forward/backward reference
  Result resolve();                    // pass 2: validate and patch all fixups without partial writes
  void clear();

 private:
  struct LabelDefinition {
    Label label;
    VmPc pc = 0;
  };

  std::vector<LabelDefinition> definitions_;
  std::vector<Fixup> fixups_;
  std::vector<std::uint8_t>* code_ = nullptr;
};

}  // namespace vmp::arch::common
