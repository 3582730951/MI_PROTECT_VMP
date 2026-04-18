#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <variant>
#include <vector>

#include <vmp/policy/policy_ir.h>

namespace vmp::backend::rewriter {

enum class ContainerKind : std::uint8_t {
  pe,
  elf,
  macho,
  apk,
  ipa,
};

struct RewriteOptions {
  std::filesystem::path strings_pool_path;
  std::filesystem::path strings_index_path;
  std::filesystem::path strings_kdf_path;
  std::filesystem::path vm1_module_path;
  std::filesystem::path vm2_module_path;
};

struct SectionInfo {
  std::string name;
  std::uint64_t address = 0;
  std::uint64_t offset = 0;
  std::uint64_t size = 0;
};

struct SymbolInfo {
  std::string name;
  std::uint64_t address = 0;
  std::uint64_t size = 0;
  std::string section_name;
};

struct PeContainer {
  std::filesystem::path source_path;
  std::vector<std::uint8_t> bytes;
  std::vector<SectionInfo> sections;
  std::vector<SymbolInfo> symbols;
};

struct ElfContainer {
  std::filesystem::path source_path;
  std::vector<std::uint8_t> bytes;
  std::vector<SectionInfo> sections;
  std::vector<SymbolInfo> symbols;
};

struct MachOContainer {
  std::filesystem::path source_path;
  std::vector<std::uint8_t> bytes;
  std::vector<SectionInfo> sections;
  std::vector<SymbolInfo> symbols;
};

struct ZipEntryInfo {
  std::string path;
  std::vector<std::uint8_t> data;
};

struct ApkContainer {
  std::filesystem::path source_path;
  std::vector<ZipEntryInfo> entries;
};

struct IpaContainer {
  std::filesystem::path source_path;
  std::vector<ZipEntryInfo> entries;
  std::string main_executable_path;
};

using Container = std::variant<PeContainer, ElfContainer, MachOContainer, ApkContainer, IpaContainer>;
using RewrittenContainer = Container;

class BinaryRewriter {
 public:
  Container load(const std::filesystem::path& path) const;
  RewrittenContainer apply(const Container& container,
                           const vmp::policy::PolicyIR& policy_ir,
                           const RewriteOptions& options = {}) const;
  void write(const Container& container, const std::filesystem::path& out_path) const;
};

ContainerKind kind_of(const Container& container) noexcept;
std::string to_string(ContainerKind kind);

struct RewriterBackendFacade {
  const char* status() const noexcept;
};

}  // namespace vmp::backend::rewriter
