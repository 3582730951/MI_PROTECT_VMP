#include <fstream>
#include <stdexcept>
#include <variant>

#include <vmp/backend/rewriter_backend.h>

#include "internal/common.h"

namespace vmp::backend::rewriter::formats::elf {
ElfContainer load(const std::filesystem::path& path);
ElfContainer apply(const ElfContainer& input, const vmp::policy::PolicyIR& policy_ir, const RewriteOptions& options);
void write(const ElfContainer& container, const std::filesystem::path& out_path);
bool sniff(const std::vector<std::uint8_t>& bytes);
}
namespace vmp::backend::rewriter::formats::pe {
PeContainer load(const std::filesystem::path& path);
PeContainer apply(const PeContainer& input, const vmp::policy::PolicyIR& policy_ir, const RewriteOptions& options);
void write(const PeContainer& container, const std::filesystem::path& out_path);
bool sniff(const std::vector<std::uint8_t>& bytes);
}
namespace vmp::backend::rewriter::formats::macho {
MachOContainer load(const std::filesystem::path& path);
MachOContainer apply(const MachOContainer& input, const vmp::policy::PolicyIR& policy_ir, const RewriteOptions& options);
void write(const MachOContainer& container, const std::filesystem::path& out_path);
bool sniff(const std::vector<std::uint8_t>& bytes);
}
namespace vmp::backend::rewriter::formats::zip {
std::vector<ZipEntryInfo> load_entries(const std::filesystem::path& path);
ApkContainer load_apk(const std::filesystem::path& path);
IpaContainer load_ipa(const std::filesystem::path& path);
void write_apk(const ApkContainer& apk, const std::filesystem::path& out_path);
void write_ipa(const IpaContainer& ipa, const std::filesystem::path& out_path);
bool sniff(const std::vector<std::uint8_t>& bytes);
bool looks_like_apk(const std::vector<ZipEntryInfo>& entries);
bool looks_like_ipa(const std::vector<ZipEntryInfo>& entries);
}

namespace vmp::backend::rewriter {
namespace {

[[noreturn]] void throw_unknown_format() {
  throw std::runtime_error("binary_format_unknown: input is not PE/ELF/Mach-O/APK/IPA");
}

std::string basename(std::string_view path) {
  const auto pos = path.find_last_of('/');
  if (pos == std::string::npos) return std::string(path);
  return std::string(path.substr(pos + 1));
}

Container load_from_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  if (formats::pe::sniff(bytes)) return formats::pe::load(path);
  if (formats::elf::sniff(bytes)) return formats::elf::load(path);
  if (formats::macho::sniff(bytes)) return formats::macho::load(path);
  if (formats::zip::sniff(bytes)) {
    const auto entries = formats::zip::load_entries(path);
    if (formats::zip::looks_like_apk(entries)) return formats::zip::load_apk(path);
    if (formats::zip::looks_like_ipa(entries)) return formats::zip::load_ipa(path);
  }
  throw_unknown_format();
}

bool target_matches_path(const detail::BinaryPolicyTarget& target, const std::string& entry_path) {
  return target.container_path.empty() || target.container_path == entry_path || target.container_path == basename(entry_path);
}

}  // namespace

ContainerKind kind_of(const Container& container) noexcept {
  return std::visit([](const auto& item) -> ContainerKind {
    using T = std::decay_t<decltype(item)>;
    if constexpr (std::is_same_v<T, PeContainer>) return ContainerKind::pe;
    if constexpr (std::is_same_v<T, ElfContainer>) return ContainerKind::elf;
    if constexpr (std::is_same_v<T, MachOContainer>) return ContainerKind::macho;
    if constexpr (std::is_same_v<T, ApkContainer>) return ContainerKind::apk;
    return ContainerKind::ipa;
  }, container);
}

std::string to_string(ContainerKind kind) {
  switch (kind) {
    case ContainerKind::pe: return "PE";
    case ContainerKind::elf: return "ELF";
    case ContainerKind::macho: return "Mach-O";
    case ContainerKind::apk: return "APK";
    case ContainerKind::ipa: return "IPA";
  }
  return "unknown";
}

Container BinaryRewriter::load(const std::filesystem::path& path) const {
  return load_from_bytes(path, detail::read_file(path));
}

RewrittenContainer BinaryRewriter::apply(const Container& container,
                                         const vmp::policy::PolicyIR& policy_ir,
                                         const RewriteOptions& options) const {
  return std::visit([&](const auto& item) -> RewrittenContainer {
    using T = std::decay_t<decltype(item)>;
    if constexpr (std::is_same_v<T, PeContainer>) {
      return formats::pe::apply(item, policy_ir, options);
    } else if constexpr (std::is_same_v<T, ElfContainer>) {
      return formats::elf::apply(item, policy_ir, options);
    } else if constexpr (std::is_same_v<T, MachOContainer>) {
      return formats::macho::apply(item, policy_ir, options);
    } else if constexpr (std::is_same_v<T, ApkContainer>) {
      ApkContainer apk = item;
      const auto targets = detail::binary_targets(policy_ir);
      for (auto& entry : apk.entries) {
        if (entry.path.rfind("lib/", 0) == 0 && entry.path.size() > 3 && entry.path.find(".so") != std::string::npos) {
          vmp::policy::PolicyIR scoped = policy_ir;
          scoped.entries.clear();
          for (const auto& original : policy_ir.entries) {
            const auto decoded = detail::decode_target(original);
            if (!target_matches_path(decoded, entry.path)) {
              continue;
            }
            auto adjusted = original;
            adjusted.symbol_or_region = decoded.symbol + (decoded.has_offset ? (std::string("+0x") + [&decoded](){ std::ostringstream oss; oss << std::hex << decoded.offset; return oss.str(); }()) : std::string());
            scoped.entries.push_back(std::move(adjusted));
          }
          if (scoped.entries.empty()) continue;
          const auto temp = std::filesystem::temp_directory_path() / ("vmp-apk-" + basename(entry.path));
          detail::write_file(temp, entry.data);
          auto inner = formats::elf::load(temp);
          inner.source_path = entry.path;
          inner = formats::elf::apply(inner, scoped, options);
          entry.data = inner.bytes;
        }
      }
      return apk;
    } else {
      IpaContainer ipa = item;
      if (ipa.main_executable_path.empty()) {
        throw std::runtime_error("rewriter: IPA CFBundleExecutable not found");
      }
      for (auto& entry : ipa.entries) {
        if (entry.path == ipa.main_executable_path) {
          const auto temp = std::filesystem::temp_directory_path() / ("vmp-ipa-" + basename(entry.path));
          detail::write_file(temp, entry.data);
          auto inner = formats::macho::load(temp);
          inner.source_path = entry.path;
          inner = formats::macho::apply(inner, policy_ir, options);
          entry.data = inner.bytes;
        }
      }
      return ipa;
    }
  }, container);
}

void BinaryRewriter::write(const Container& container, const std::filesystem::path& out_path) const {
  std::visit([&](const auto& item) {
    using T = std::decay_t<decltype(item)>;
    if constexpr (std::is_same_v<T, PeContainer>) {
      formats::pe::write(item, out_path);
    } else if constexpr (std::is_same_v<T, ElfContainer>) {
      formats::elf::write(item, out_path);
    } else if constexpr (std::is_same_v<T, MachOContainer>) {
      formats::macho::write(item, out_path);
    } else if constexpr (std::is_same_v<T, ApkContainer>) {
      formats::zip::write_apk(item, out_path);
    } else {
      formats::zip::write_ipa(item, out_path);
    }
  }, container);
}

const char* RewriterBackendFacade::status() const noexcept { return "rewriter_backend_ready"; }

}  // namespace vmp::backend::rewriter
