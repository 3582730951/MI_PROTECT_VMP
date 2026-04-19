#include <vmp/arch/common/label_resolver.h>

#include <algorithm>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <tuple>
#include <utility>

namespace vmp::arch::common {
namespace {

struct PendingPatch {
  std::size_t code_offset = 0;
  std::size_t width = 0;
  std::uint64_t value = 0;
};

std::size_t patch_width(FixupField field) {
  switch (field) {
    case FixupField::jump_offset_s32:
    case FixupField::call_offset_s32:
    case FixupField::load_disp_s32:
      return 4;
    case FixupField::address_materialize_s64:
      return 8;
  }
  throw std::runtime_error("label_resolver: unsupported patch width");
}

std::string field_name(FixupField field) {
  switch (field) {
    case FixupField::jump_offset_s32: return "jump_offset_s32";
    case FixupField::call_offset_s32: return "call_offset_s32";
    case FixupField::load_disp_s32: return "load_disp_s32";
    case FixupField::address_materialize_s64: return "address_materialize_s64";
  }
  return "unknown";
}

std::string diagnostic_name(ResolverDiagnosticKind kind) {
  switch (kind) {
    case ResolverDiagnosticKind::out_of_range: return "out_of_range";
    case ResolverDiagnosticKind::unresolved_label: return "unresolved_label";
    case ResolverDiagnosticKind::duplicate_label: return "duplicate_label";
  }
  return "unknown";
}

std::int64_t range_metric(const Fixup& fixup, VmPc target_pc) {
  switch (fixup.field) {
    case FixupField::jump_offset_s32:
    case FixupField::call_offset_s32:
    case FixupField::load_disp_s32:
      return static_cast<std::int64_t>(target_pc) - static_cast<std::int64_t>(fixup.source_vm_pc);
    case FixupField::address_materialize_s64:
      return static_cast<std::int64_t>(target_pc);
  }
  throw std::runtime_error("label_resolver: unsupported range metric");
}

std::uint64_t patch_value(const Fixup& fixup, VmPc target_pc) {
  switch (fixup.field) {
    case FixupField::jump_offset_s32:
    case FixupField::call_offset_s32:
      return target_pc;
    case FixupField::load_disp_s32:
      return static_cast<std::uint32_t>(static_cast<std::int32_t>(static_cast<std::int64_t>(target_pc) -
                                                                  static_cast<std::int64_t>(fixup.source_vm_pc)));
    case FixupField::address_materialize_s64:
      return target_pc;
  }
  throw std::runtime_error("label_resolver: unsupported patch value");
}

bool patch_value_fits(const Fixup& fixup, VmPc target_pc) {
  switch (fixup.field) {
    case FixupField::jump_offset_s32:
    case FixupField::call_offset_s32:
      return target_pc <= std::numeric_limits<std::uint32_t>::max();
    case FixupField::load_disp_s32: {
      const auto delta = static_cast<std::int64_t>(target_pc) - static_cast<std::int64_t>(fixup.source_vm_pc);
      return delta >= std::numeric_limits<std::int32_t>::min() &&
             delta <= std::numeric_limits<std::int32_t>::max();
    }
    case FixupField::address_materialize_s64:
      return true;
  }
  return false;
}

void write_patch(std::vector<std::uint8_t>& code, const PendingPatch& patch) {
  if (patch.code_offset + patch.width > code.size()) {
    throw std::runtime_error("label_resolver: patch offset out of range");
  }
  for (std::size_t i = 0; i < patch.width; ++i) {
    code[patch.code_offset + i] = static_cast<std::uint8_t>((patch.value >> (8u * i)) & 0xFFu);
  }
}

std::string format_result(const Result& result) {
  std::ostringstream oss;
  oss << "label_resolver:";
  for (const auto& diagnostic : result.diagnostics) {
    oss << ' ' << diagnostic_name(diagnostic.kind) << '[' << diagnostic.target_label.name << "]@"
        << diagnostic.instruction_index;
    if (!diagnostic.detail.empty()) {
      oss << '(' << diagnostic.detail << ')';
    }
  }
  return oss.str();
}

ResolverDiagnostic make_diagnostic(ResolverDiagnosticKind kind,
                                   const Fixup& fixup,
                                   std::string detail) {
  ResolverDiagnostic diagnostic;
  diagnostic.kind = kind;
  diagnostic.instruction_index = fixup.instruction_index;
  diagnostic.target_label = fixup.target_label;
  diagnostic.detail = std::move(detail);
  return diagnostic;
}

}  // namespace

ResolutionError::ResolutionError(Result result)
    : std::runtime_error(format_result(result)), result_(std::move(result)) {}

void LabelResolver::define(Label label, VmPc pc) {
  label.resolved_vm_pc = pc;
  definitions_.push_back(LabelDefinition{std::move(label), pc});
}

void LabelResolver::reference(Fixup fixup) {
  fixup.target_label.resolved_vm_pc.reset();
  fixups_.push_back(std::move(fixup));
}

Result LabelResolver::resolve() {
  Result result;
  std::map<std::string, std::vector<VmPc>> definitions_by_name;
  for (const auto& definition : definitions_) {
    definitions_by_name[definition.label.name].push_back(definition.pc);
  }

  for (auto& [name, pcs] : definitions_by_name) {
    std::sort(pcs.begin(), pcs.end());
    if (pcs.size() > 1) {
      ResolverDiagnostic diagnostic;
      diagnostic.kind = ResolverDiagnosticKind::duplicate_label;
      diagnostic.target_label = Label{name, pcs.front()};
      std::ostringstream detail;
      detail << "multiple definitions:";
      for (const auto pc : pcs) {
        detail << " 0x" << std::hex << pc;
      }
      diagnostic.detail = detail.str();
      result.diagnostics.push_back(std::move(diagnostic));
    }
  }

  auto sorted_fixups = fixups_;
  std::sort(sorted_fixups.begin(), sorted_fixups.end(), [](const Fixup& lhs, const Fixup& rhs) {
    return std::tie(lhs.target_label.name, lhs.instruction_index, lhs.code_offset, lhs.source_vm_pc, lhs.field) <
           std::tie(rhs.target_label.name, rhs.instruction_index, rhs.code_offset, rhs.source_vm_pc, rhs.field);
  });

  std::vector<PendingPatch> patches;
  patches.reserve(sorted_fixups.size());

  for (const auto& fixup : sorted_fixups) {
    const auto def_it = definitions_by_name.find(fixup.target_label.name);
    if (def_it == definitions_by_name.end()) {
      result.diagnostics.push_back(make_diagnostic(
          ResolverDiagnosticKind::unresolved_label,
          fixup,
          "label '" + fixup.target_label.name + "' was never defined"));
      continue;
    }
    if (def_it->second.size() != 1) {
      continue;
    }

    const auto target_pc = def_it->second.front();
    const auto metric = range_metric(fixup, target_pc);
    if (!fixup.allowed_range.contains(metric)) {
      std::ostringstream detail;
      detail << field_name(fixup.field) << " metric=" << metric << " not in [" << fixup.allowed_range.min
             << ", " << fixup.allowed_range.max << "]";
      result.diagnostics.push_back(make_diagnostic(ResolverDiagnosticKind::out_of_range, fixup, detail.str()));
      continue;
    }
    if (!patch_value_fits(fixup, target_pc)) {
      std::ostringstream detail;
      detail << field_name(fixup.field) << " target=0x" << std::hex << target_pc
             << " does not fit encoded patch width";
      result.diagnostics.push_back(make_diagnostic(ResolverDiagnosticKind::out_of_range, fixup, detail.str()));
      continue;
    }

    patches.push_back(PendingPatch{fixup.code_offset, patch_width(fixup.field), patch_value(fixup, target_pc)});
  }

  std::sort(result.diagnostics.begin(), result.diagnostics.end(), [](const ResolverDiagnostic& lhs,
                                                                     const ResolverDiagnostic& rhs) {
    return std::tie(lhs.target_label.name, lhs.instruction_index, lhs.kind, lhs.detail) <
           std::tie(rhs.target_label.name, rhs.instruction_index, rhs.kind, rhs.detail);
  });

  if (!result.ok() || code_ == nullptr) {
    return result;
  }

  std::sort(patches.begin(), patches.end(), [](const PendingPatch& lhs, const PendingPatch& rhs) {
    return std::tie(lhs.code_offset, lhs.width, lhs.value) < std::tie(rhs.code_offset, rhs.width, rhs.value);
  });
  for (const auto& patch : patches) {
    write_patch(*code_, patch);
  }
  return result;
}

void LabelResolver::clear() {
  definitions_.clear();
  fixups_.clear();
}

}  // namespace vmp::arch::common
