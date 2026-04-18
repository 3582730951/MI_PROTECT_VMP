#include <algorithm>
#include <array>
#include <cstring>
#include <set>

#include "../internal/common.h"

namespace vmp::backend::rewriter::formats::pe {
namespace {
#pragma pack(push, 1)
struct ImageFileHeader {
  std::uint16_t machine;
  std::uint16_t number_of_sections;
  std::uint32_t time_date_stamp;
  std::uint32_t pointer_to_symbol_table;
  std::uint32_t number_of_symbols;
  std::uint16_t size_of_optional_header;
  std::uint16_t characteristics;
};
struct ImageSectionHeader {
  std::array<char, 8> name;
  std::uint32_t virtual_size;
  std::uint32_t virtual_address;
  std::uint32_t size_of_raw_data;
  std::uint32_t pointer_to_raw_data;
  std::uint32_t pointer_to_relocations;
  std::uint32_t pointer_to_linenumbers;
  std::uint16_t number_of_relocations;
  std::uint16_t number_of_linenumbers;
  std::uint32_t characteristics;
};
#pragma pack(pop)

struct ParsedSection {
  std::string name;
  ImageSectionHeader hdr{};
};

struct ParsedPe {
  std::vector<std::uint8_t> bytes;
  std::uint32_t pe_offset = 0;
  ImageFileHeader file_header{};
  std::uint16_t optional_magic = 0;
  std::uint32_t section_alignment = 0x1000;
  std::uint32_t file_alignment = 0x200;
  std::uint32_t size_of_image_offset = 0;
  std::uint32_t export_rva = 0;
  std::uint32_t import_rva = 0;
  std::uint32_t resource_rva = 0;
  std::uint32_t reloc_rva = 0;
  std::vector<ParsedSection> sections;
};

std::string trim_name(const std::array<char, 8>& in) {
  std::size_t n = 0;
  while (n < in.size() && in[n] != '\0') ++n;
  return std::string(in.data(), n);
}

ParsedPe parse_bytes(const std::vector<std::uint8_t>& bytes) {
  ParsedPe out;
  out.bytes = bytes;
  if (bytes.size() < 0x40 || bytes[0] != 'M' || bytes[1] != 'Z') {
    throw std::runtime_error("rewriter: unsupported PE format");
  }
  out.pe_offset = detail::read_le<std::uint32_t>(bytes, 0x3c, "pe e_lfanew");
  detail::ensure_size(bytes, out.pe_offset, 4 + sizeof(ImageFileHeader), "pe headers");
  if (std::memcmp(bytes.data() + out.pe_offset, "PE\0\0", 4) != 0) {
    throw std::runtime_error("rewriter: invalid PE signature");
  }
  std::memcpy(&out.file_header, bytes.data() + out.pe_offset + 4, sizeof(ImageFileHeader));
  const auto optional_off = out.pe_offset + 4 + sizeof(ImageFileHeader);
  out.optional_magic = detail::read_le<std::uint16_t>(bytes, optional_off, "pe optional magic");
  if (out.optional_magic == 0x20b) {
    out.section_alignment = detail::read_le<std::uint32_t>(bytes, optional_off + 0x20, "pe section alignment");
    out.file_alignment = detail::read_le<std::uint32_t>(bytes, optional_off + 0x24, "pe file alignment");
    out.size_of_image_offset = optional_off + 0x38;
    const auto data_dir = optional_off + 0x70;
    out.export_rva = detail::read_le<std::uint32_t>(bytes, data_dir + 0x00, "pe export rva");
    out.import_rva = detail::read_le<std::uint32_t>(bytes, data_dir + 0x08, "pe import rva");
    out.resource_rva = detail::read_le<std::uint32_t>(bytes, data_dir + 0x10, "pe resource rva");
    out.reloc_rva = detail::read_le<std::uint32_t>(bytes, data_dir + 0x28, "pe reloc rva");
  } else {
    throw std::runtime_error("rewriter: only PE32+ is supported in MVP");
  }
  const auto section_table = optional_off + out.file_header.size_of_optional_header;
  detail::ensure_size(bytes, section_table, static_cast<std::size_t>(out.file_header.number_of_sections) * sizeof(ImageSectionHeader), "pe section table");
  for (std::size_t i = 0; i < out.file_header.number_of_sections; ++i) {
    ParsedSection sec;
    std::memcpy(&sec.hdr, bytes.data() + section_table + i * sizeof(ImageSectionHeader), sizeof(ImageSectionHeader));
    sec.name = trim_name(sec.hdr.name);
    out.sections.push_back(sec);
  }
  return out;
}

PeContainer to_container(const ParsedPe& pe, const std::filesystem::path& path) {
  PeContainer out;
  out.source_path = path;
  out.bytes = pe.bytes;
  for (const auto& sec : pe.sections) {
    out.sections.push_back(SectionInfo{sec.name, sec.hdr.virtual_address, sec.hdr.pointer_to_raw_data, sec.hdr.virtual_size});
  }
  out.symbols.push_back(SymbolInfo{"__exports__", pe.export_rva, 0, ".edata"});
  out.symbols.push_back(SymbolInfo{"__imports__", pe.import_rva, 0, ".idata"});
  out.symbols.push_back(SymbolInfo{"__resources__", pe.resource_rva, 0, ".rsrc"});
  out.symbols.push_back(SymbolInfo{"__relocs__", pe.reloc_rva, 0, ".reloc"});
  return out;
}

std::vector<std::uint8_t> add_sections(ParsedPe pe,
                                       const std::vector<std::pair<std::string, std::vector<std::uint8_t>>>& sections_to_add) {
  auto bytes = pe.bytes;
  const auto optional_off = pe.pe_offset + 4 + sizeof(ImageFileHeader);
  const auto section_table = optional_off + pe.file_header.size_of_optional_header;
  const auto first_raw = pe.sections.empty() ? detail::align_up(section_table + sizeof(ImageSectionHeader) * (pe.file_header.number_of_sections + sections_to_add.size()), pe.file_alignment)
                                             : pe.sections.front().hdr.pointer_to_raw_data;
  const auto existing_headers_end = section_table + static_cast<std::size_t>(pe.file_header.number_of_sections) * sizeof(ImageSectionHeader);
  const auto needed_header_end = section_table + static_cast<std::size_t>(pe.file_header.number_of_sections + sections_to_add.size()) * sizeof(ImageSectionHeader);
  if (needed_header_end > first_raw) {
    throw std::runtime_error("rewriter: PE header slack insufficient for new sections");
  }
  auto last = pe.sections.back().hdr;
  std::uint32_t raw_ptr = detail::align_up(last.pointer_to_raw_data + last.size_of_raw_data, pe.file_alignment);
  std::uint32_t virt = detail::align_up(last.virtual_address + std::max(last.virtual_size, last.size_of_raw_data), pe.section_alignment);
  for (std::size_t i = 0; i < sections_to_add.size(); ++i) {
    const auto& [name, data] = sections_to_add[i];
    ImageSectionHeader sh{};
    std::memcpy(sh.name.data(), name.c_str(), std::min<std::size_t>(name.size(), 8));
    sh.virtual_size = data.size();
    sh.virtual_address = virt;
    sh.size_of_raw_data = detail::align_up(data.size(), pe.file_alignment);
    sh.pointer_to_raw_data = raw_ptr;
    sh.characteristics = 0x40000040u; // readable initialized data
    if (bytes.size() < raw_ptr) bytes.resize(raw_ptr, 0);
    bytes.insert(bytes.end(), data.begin(), data.end());
    bytes.resize(detail::align_up(bytes.size(), pe.file_alignment), 0);
    std::memcpy(bytes.data() + section_table + (pe.file_header.number_of_sections + i) * sizeof(ImageSectionHeader), &sh, sizeof(sh));
    raw_ptr += sh.size_of_raw_data;
    virt += detail::align_up(std::max(sh.virtual_size, sh.size_of_raw_data), pe.section_alignment);
  }
  pe.file_header.number_of_sections += sections_to_add.size();
  std::memcpy(bytes.data() + pe.pe_offset + 4, &pe.file_header, sizeof(ImageFileHeader));
  detail::write_le(bytes, pe.size_of_image_offset, virt, 4);
  return bytes;
}

}  // namespace

PeContainer load(const std::filesystem::path& path) { return to_container(parse_bytes(detail::read_file(path)), path); }

PeContainer apply(const PeContainer& input, const vmp::policy::PolicyIR& policy_ir, const RewriteOptions& options) {
  auto parsed = parse_bytes(input.bytes);
  const auto targets = detail::binary_targets(policy_ir);
  std::vector<detail::BinaryPolicyTarget> thunk_targets;
  for (const auto& target : targets) {
    if (!target.container_path.empty()) continue;
    if (target.vm1 || target.vm2) thunk_targets.push_back(target);
  }
  std::vector<std::pair<std::string, std::vector<std::uint8_t>>> additions;
  const std::string vmpload = "vmp_windows_loader_dll_main\0vmp_windows_init\0";
  additions.push_back({".vmpload", std::vector<std::uint8_t>(vmpload.begin(), vmpload.end())});
  const bool has_xlb = std::any_of(parsed.sections.begin(), parsed.sections.end(), [](const auto& sec) { return sec.name == ".CRT$XLB"; });
  if (!has_xlb) {
    const std::string crt = "vmp_windows_init\0";
    additions.push_back({".CRT$XLB", std::vector<std::uint8_t>(crt.begin(), crt.end())});
  }
  if (!thunk_targets.empty()) {
    const auto thunk = detail::vm_thunk_descriptor_json(thunk_targets, options, "pe");
    additions.push_back({".vmpvm", std::vector<std::uint8_t>(thunk.begin(), thunk.end())});
  }
  auto out = input;
  out.bytes = add_sections(parsed, additions);
  out = to_container(parse_bytes(out.bytes), input.source_path);
  return out;
}

void write(const PeContainer& container, const std::filesystem::path& out_path) { detail::write_file(out_path, container.bytes); }

bool sniff(const std::vector<std::uint8_t>& bytes) { return bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z'; }

}  // namespace vmp::backend::rewriter::formats::pe
