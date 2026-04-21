#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <limits>
#include <optional>
#include <set>
#include <string_view>
#include <vector>
#include <unordered_map>

#include <vmp/arch/x64/ir.h>

#include "../internal/common.h"
#include "../internal/metadata_obfuscation.h"

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

struct CoffSymbol {
  std::string name;
  std::uint32_t value = 0;
  std::int16_t section_number = 0;
  std::uint16_t type = 0;
  std::uint8_t storage_class = 0;
  std::uint8_t aux_symbols = 0;
  std::size_t table_index = 0;
};

struct PdataEntry {
  std::uint32_t begin_rva = 0;
  std::uint32_t end_rva = 0;
  std::uint32_t unwind_rva = 0;
};

struct SectionAddition {
  std::string name;
  std::vector<std::uint8_t> data;
  std::uint32_t characteristics = 0x40000040u;
};

struct PlannedSection {
  SectionAddition addition;
  std::uint32_t virtual_address = 0;
  std::uint32_t pointer_to_raw_data = 0;
  std::uint32_t size_of_raw_data = 0;
};

struct TrampolineRecord {
  std::uint32_t record_id = 0;
  std::uint32_t original_rva = 0;
  std::uint32_t relocated_rva = 0;
  std::uint32_t bridge_rva = 0;
  std::uint32_t code_size = 0;
  vmp::runtime::trampoline::TokenBytes token{};
};

struct ImageImportDescriptor {
  std::uint32_t original_first_thunk = 0;
  std::uint32_t time_date_stamp = 0;
  std::uint32_t forwarder_chain = 0;
  std::uint32_t name = 0;
  std::uint32_t first_thunk = 0;
};

struct ImageExportDirectory {
  std::uint32_t characteristics = 0;
  std::uint32_t time_date_stamp = 0;
  std::uint16_t major_version = 0;
  std::uint16_t minor_version = 0;
  std::uint32_t name = 0;
  std::uint32_t base = 0;
  std::uint32_t number_of_functions = 0;
  std::uint32_t number_of_names = 0;
  std::uint32_t address_of_functions = 0;
  std::uint32_t address_of_names = 0;
  std::uint32_t address_of_name_ordinals = 0;
};

struct ParsedPe {
  std::vector<std::uint8_t> bytes;
  std::uint32_t pe_offset = 0;
  ImageFileHeader file_header{};
  std::uint16_t optional_magic = 0;
  std::uint32_t section_alignment = 0x1000;
  std::uint32_t file_alignment = 0x200;
  std::uint32_t size_of_image_offset = 0;
  std::uint64_t image_base = 0;
  std::uint32_t address_of_entry_point = 0;
  std::uint32_t export_rva = 0;
  std::uint32_t import_rva = 0;
  std::uint32_t resource_rva = 0;
  std::uint32_t reloc_rva = 0;
  std::uint32_t optional_header_offset = 0;
  std::vector<ParsedSection> sections;
  std::vector<CoffSymbol> symbols;
  std::vector<PdataEntry> pdata;
  std::uint32_t symbol_table_offset = 0;
  std::uint32_t symbol_table_size = 0;
  std::uint32_t string_table_offset = 0;
  std::uint32_t string_table_size = 0;
};

std::string trim_name(const std::array<char, 8>& in) {
  std::size_t n = 0;
  while (n < in.size() && in[n] != '\0') {
    ++n;
  }
  return std::string(in.data(), n);
}

std::string resolve_section_name(const std::vector<std::uint8_t>& bytes,
                                 std::uint32_t pointer_to_symbol_table,
                                 std::uint32_t number_of_symbols,
                                 const std::array<char, 8>& raw_name) {
  const auto short_name = trim_name(raw_name);
  if (short_name.empty() || short_name[0] != '/' || short_name.size() == 1u) {
    return short_name;
  }
  const auto digits = short_name.substr(1);
  if (!std::all_of(digits.begin(), digits.end(), [](unsigned char ch) { return std::isdigit(ch) != 0; })) {
    return short_name;
  }
  const auto string_table_offset =
      static_cast<std::size_t>(pointer_to_symbol_table) + static_cast<std::size_t>(number_of_symbols) * 18u;
  if (string_table_offset + 4u > bytes.size()) {
    return short_name;
  }
  const auto string_table_size = detail::read_le<std::uint32_t>(bytes, string_table_offset, "pe string table size");
  const auto name_offset = static_cast<std::size_t>(std::stoul(digits));
  if (string_table_size < 4u || name_offset >= string_table_size) {
    return short_name;
  }
  return detail::read_c_string(bytes, string_table_offset + name_offset);
}

void append_le32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xffu));
  out.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xffu));
  out.push_back(static_cast<std::uint8_t>((value >> 16u) & 0xffu));
  out.push_back(static_cast<std::uint8_t>((value >> 24u) & 0xffu));
}

void append_le64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (unsigned shift = 0; shift < 64; shift += 8u) {
    out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
  }
}

void append_padding(std::vector<std::uint8_t>& out, std::size_t alignment) {
  if (alignment == 0) {
    return;
  }
  const auto aligned = static_cast<std::size_t>(detail::align_up(out.size(), alignment));
  if (aligned > out.size()) {
    out.resize(aligned, 0);
  }
}

std::int64_t checked_rel32(std::uint64_t source_after, std::uint64_t target) {
  const auto rel = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(source_after);
  if (rel < static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::min()) ||
      rel > static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::max())) {
    throw std::runtime_error("rewriter: PE rel32 target out of range");
  }
  return rel;
}

bool has_section(const ParsedPe& pe, std::string_view name) {
  return std::any_of(pe.sections.begin(), pe.sections.end(), [name](const ParsedSection& sec) {
    return sec.name == name;
  });
}

const ParsedSection* find_section(const ParsedPe& pe, std::string_view name) {
  const auto it = std::find_if(pe.sections.begin(), pe.sections.end(), [name](const ParsedSection& sec) {
    return sec.name == name;
  });
  return it == pe.sections.end() ? nullptr : &*it;
}

bool is_lower_hex_ascii(std::uint8_t ch) {
  return (ch >= static_cast<std::uint8_t>('0') && ch <= static_cast<std::uint8_t>('9')) ||
         (ch >= static_cast<std::uint8_t>('a') && ch <= static_cast<std::uint8_t>('f'));
}

bool has_vmp_crt_marker(const ParsedPe& pe) {
  const auto* crt = find_section(pe, ".CRT$XLB");
  if (crt == nullptr || crt->hdr.pointer_to_raw_data == 0 || crt->hdr.size_of_raw_data < 16u) {
    return false;
  }
  const auto start = static_cast<std::size_t>(crt->hdr.pointer_to_raw_data);
  if (start + 16u > pe.bytes.size()) {
    return false;
  }
  return std::all_of(pe.bytes.begin() + static_cast<std::ptrdiff_t>(start),
                     pe.bytes.begin() + static_cast<std::ptrdiff_t>(start + 16u),
                     [](std::uint8_t ch) { return is_lower_hex_ascii(ch); });
}

bool has_vmp_metadata_magic(const ParsedPe& pe) {
  static constexpr std::array<std::uint8_t, 4> kMagic{0x91u, 0xC4u, 0x5Au, 0x17u};
  return std::any_of(pe.sections.begin(), pe.sections.end(), [&](const ParsedSection& sec) {
    if (sec.hdr.pointer_to_raw_data == 0 || sec.hdr.size_of_raw_data < kMagic.size()) {
      return false;
    }
    const auto start = static_cast<std::size_t>(sec.hdr.pointer_to_raw_data);
    if (start + kMagic.size() > pe.bytes.size()) {
      return false;
    }
    return std::equal(kMagic.begin(), kMagic.end(), pe.bytes.begin() + static_cast<std::ptrdiff_t>(start));
  });
}

bool looks_like_vmp_protected(const ParsedPe& pe) {
  return has_vmp_crt_marker(pe) && has_vmp_metadata_magic(pe);
}

std::string read_coff_name(const std::vector<std::uint8_t>& bytes,
                           std::size_t symbol_offset,
                           std::size_t string_table_offset,
                           std::size_t string_table_size) {
  detail::ensure_size(bytes, symbol_offset, 18, "pe symbol entry");
  const bool long_name = detail::read_le<std::uint32_t>(bytes, symbol_offset, "pe symbol name marker") == 0u;
  if (long_name) {
    const auto name_offset = detail::read_le<std::uint32_t>(bytes, symbol_offset + 4, "pe symbol long name offset");
    if (name_offset >= string_table_size) {
      return {};
    }
    return detail::read_c_string(bytes, string_table_offset + name_offset);
  }
  std::array<char, 8> name_bytes{};
  std::memcpy(name_bytes.data(), bytes.data() + symbol_offset, name_bytes.size());
  return trim_name(name_bytes);
}

void parse_symbols(ParsedPe& out) {
  if (out.file_header.pointer_to_symbol_table == 0 || out.file_header.number_of_symbols == 0) {
    return;
  }
  out.symbol_table_offset = out.file_header.pointer_to_symbol_table;
  out.symbol_table_size = out.file_header.number_of_symbols * 18u;
  detail::ensure_size(out.bytes, out.symbol_table_offset, out.symbol_table_size + 4u, "pe symbol table");
  out.string_table_offset = out.symbol_table_offset + out.symbol_table_size;
  out.string_table_size = detail::read_le<std::uint32_t>(out.bytes, out.string_table_offset, "pe string table size");
  if (out.string_table_size < 4u) {
    out.string_table_size = 4u;
  }
  detail::ensure_size(out.bytes, out.string_table_offset, out.string_table_size, "pe string table");

  for (std::size_t i = 0; i < out.file_header.number_of_symbols;) {
    const auto symbol_offset = static_cast<std::size_t>(out.symbol_table_offset) + i * 18u;
    CoffSymbol symbol;
    symbol.name = read_coff_name(out.bytes, symbol_offset, out.string_table_offset, out.string_table_size);
    symbol.value = detail::read_le<std::uint32_t>(out.bytes, symbol_offset + 8, "pe symbol value");
    symbol.section_number = static_cast<std::int16_t>(detail::read_le<std::uint16_t>(out.bytes, symbol_offset + 12, "pe symbol section"));
    symbol.type = detail::read_le<std::uint16_t>(out.bytes, symbol_offset + 14, "pe symbol type");
    symbol.storage_class = detail::read_le<std::uint8_t>(out.bytes, symbol_offset + 16, "pe symbol storage class");
    symbol.aux_symbols = detail::read_le<std::uint8_t>(out.bytes, symbol_offset + 17, "pe symbol aux count");
    symbol.table_index = i;
    out.symbols.push_back(std::move(symbol));
    i += 1u + out.symbols.back().aux_symbols;
  }
}

void parse_pdata(ParsedPe& out) {
  const auto it = std::find_if(out.sections.begin(), out.sections.end(), [](const ParsedSection& sec) {
    return sec.name == ".pdata";
  });
  if (it == out.sections.end() || it->hdr.pointer_to_raw_data == 0 || it->hdr.size_of_raw_data < 12u) {
    return;
  }
  const auto count = it->hdr.size_of_raw_data / 12u;
  for (std::size_t idx = 0; idx < count; ++idx) {
    const auto off = static_cast<std::size_t>(it->hdr.pointer_to_raw_data) + idx * 12u;
    if (off + 12u > out.bytes.size()) {
      break;
    }
    PdataEntry entry;
    entry.begin_rva = detail::read_le<std::uint32_t>(out.bytes, off + 0, "pe pdata begin");
    entry.end_rva = detail::read_le<std::uint32_t>(out.bytes, off + 4, "pe pdata end");
    entry.unwind_rva = detail::read_le<std::uint32_t>(out.bytes, off + 8, "pe pdata unwind");
    if (entry.begin_rva != 0 && entry.end_rva > entry.begin_rva) {
      out.pdata.push_back(entry);
    }
  }
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
  out.optional_header_offset = out.pe_offset + 4 + sizeof(ImageFileHeader);
  out.optional_magic = detail::read_le<std::uint16_t>(bytes, out.optional_header_offset, "pe optional magic");
  if (out.optional_magic == 0x20b) {
    out.address_of_entry_point = detail::read_le<std::uint32_t>(bytes, out.optional_header_offset + 0x10, "pe entrypoint");
    out.image_base = detail::read_le<std::uint64_t>(bytes, out.optional_header_offset + 0x18, "pe image base");
    out.section_alignment = detail::read_le<std::uint32_t>(bytes, out.optional_header_offset + 0x20, "pe section alignment");
    out.file_alignment = detail::read_le<std::uint32_t>(bytes, out.optional_header_offset + 0x24, "pe file alignment");
    out.size_of_image_offset = out.optional_header_offset + 0x38;
    const auto data_dir = out.optional_header_offset + 0x70;
    out.export_rva = detail::read_le<std::uint32_t>(bytes, data_dir + 0x00, "pe export rva");
    out.import_rva = detail::read_le<std::uint32_t>(bytes, data_dir + 0x08, "pe import rva");
    out.resource_rva = detail::read_le<std::uint32_t>(bytes, data_dir + 0x10, "pe resource rva");
    out.reloc_rva = detail::read_le<std::uint32_t>(bytes, data_dir + 0x28, "pe reloc rva");
  } else {
    throw std::runtime_error("rewriter: only PE32+ is supported in MVP");
  }
  const auto section_table = out.optional_header_offset + out.file_header.size_of_optional_header;
  detail::ensure_size(bytes, section_table,
                      static_cast<std::size_t>(out.file_header.number_of_sections) * sizeof(ImageSectionHeader),
                      "pe section table");
  for (std::size_t i = 0; i < out.file_header.number_of_sections; ++i) {
    ParsedSection sec;
    std::memcpy(&sec.hdr, bytes.data() + section_table + i * sizeof(ImageSectionHeader), sizeof(ImageSectionHeader));
    sec.name = resolve_section_name(bytes,
                                    out.file_header.pointer_to_symbol_table,
                                    out.file_header.number_of_symbols,
                                    sec.hdr.name);
    out.sections.push_back(sec);
  }
  parse_symbols(out);
  parse_pdata(out);
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

const ParsedSection* section_by_number(const ParsedPe& pe, std::int16_t section_number) {
  if (section_number <= 0) {
    return nullptr;
  }
  const auto index = static_cast<std::size_t>(section_number - 1);
  if (index >= pe.sections.size()) {
    return nullptr;
  }
  return &pe.sections[index];
}

std::optional<std::pair<const CoffSymbol*, const ParsedSection*>> find_symbol(const ParsedPe& pe, std::string_view name) {
  for (const auto& symbol : pe.symbols) {
    if (symbol.name != name) {
      continue;
    }
    if (const auto* sec = section_by_number(pe, symbol.section_number); sec != nullptr) {
      return std::make_pair(&symbol, sec);
    }
  }
  return std::nullopt;
}

std::uint64_t section_extent(const ParsedSection& sec) {
  return std::max<std::uint64_t>(sec.hdr.virtual_size, sec.hdr.size_of_raw_data);
}

std::uint64_t symbol_rva(const CoffSymbol& symbol, const ParsedSection& sec) {
  return static_cast<std::uint64_t>(sec.hdr.virtual_address) + symbol.value;
}

std::size_t symbol_file_offset(const ParsedSection& sec, std::uint32_t symbol_value, std::uint64_t extra = 0) {
  return static_cast<std::size_t>(sec.hdr.pointer_to_raw_data) + symbol_value + static_cast<std::size_t>(extra);
}

std::optional<std::uint32_t> next_symbol_value_in_section(const ParsedPe& pe, const CoffSymbol& symbol) {
  std::optional<std::uint32_t> next;
  for (const auto& candidate : pe.symbols) {
    if (candidate.section_number != symbol.section_number) {
      continue;
    }
    if (candidate.value <= symbol.value) {
      continue;
    }
    if (!next.has_value() || candidate.value < *next) {
      next = candidate.value;
    }
  }
  return next;
}

std::vector<std::uint8_t> read_symbol_data(const ParsedPe& pe, const CoffSymbol& symbol, const ParsedSection& sec, std::uint64_t extra_offset = 0) {
  const auto file_off = symbol_file_offset(sec, symbol.value, extra_offset);
  if (file_off >= pe.bytes.size()) {
    return {};
  }
  const auto section_available = static_cast<std::size_t>(std::min<std::uint64_t>(section_extent(sec), std::numeric_limits<std::size_t>::max()));
  if (symbol.value >= section_available) {
    return {};
  }
  std::size_t max_len = section_available - symbol.value - static_cast<std::size_t>(extra_offset);
  if (const auto next = next_symbol_value_in_section(pe, symbol); next.has_value() && *next > symbol.value) {
    const auto candidate = static_cast<std::size_t>(*next - symbol.value - static_cast<std::uint32_t>(extra_offset));
    max_len = std::min(max_len, candidate);
  }
  max_len = std::min(max_len, pe.bytes.size() - file_off);
  if (max_len == 0) {
    return {};
  }
  std::vector<std::uint8_t> data(pe.bytes.begin() + static_cast<std::ptrdiff_t>(file_off),
                                 pe.bytes.begin() + static_cast<std::ptrdiff_t>(file_off + max_len));
  if (const auto zero = std::find(data.begin(), data.end(), 0); zero != data.end()) {
    data.resize(static_cast<std::size_t>(std::distance(data.begin(), zero)) + 1u);
  }
  return data;
}

void zero_symbol_data(std::vector<std::uint8_t>& bytes, const ParsedSection& sec, const CoffSymbol& symbol, std::size_t length) {
  const auto file_off = symbol_file_offset(sec, symbol.value);
  if (file_off + length > bytes.size()) {
    throw std::runtime_error("rewriter: symbol range exceeds PE image");
  }
  std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(file_off),
            bytes.begin() + static_cast<std::ptrdiff_t>(file_off + length),
            0);
}

std::size_t function_size(const ParsedPe& pe, const CoffSymbol& symbol, const ParsedSection& sec) {
  const auto rva = static_cast<std::uint32_t>(symbol_rva(symbol, sec));
  for (const auto& entry : pe.pdata) {
    if (entry.begin_rva == rva && entry.end_rva > entry.begin_rva) {
      return static_cast<std::size_t>(entry.end_rva - entry.begin_rva);
    }
  }
  if (const auto next = next_symbol_value_in_section(pe, symbol); next.has_value() && *next > symbol.value) {
    return static_cast<std::size_t>(*next - symbol.value);
  }
  return static_cast<std::size_t>(section_extent(sec) - symbol.value);
}

vmp::runtime::trampoline::KeyContextId resolve_trampoline_key_context(const RewriteOptions& options,
                                                                      const std::string& seed_text_base,
                                                                      std::uint16_t machine) {
  using vmp::runtime::trampoline::KeyContextId;
  KeyContextId key_context{};
  if (!options.trampoline_key_context_id.empty()) {
    if (options.trampoline_key_context_id.size() != key_context.size()) {
      throw std::runtime_error("rewriter: trampoline key_context_id must be exactly 16 bytes");
    }
    std::copy(options.trampoline_key_context_id.begin(), options.trampoline_key_context_id.end(), key_context.begin());
    return key_context;
  }
  const auto seed_text = seed_text_base + "|" + std::to_string(machine) + "|" + options.trampoline_dispatcher_symbol;
  const auto digest = vmp::runtime::strings::sha256(vmp::runtime::strings::to_bytes(seed_text));
  std::copy(digest.begin(), digest.begin() + static_cast<std::ptrdiff_t>(key_context.size()), key_context.begin());
  return key_context;
}

std::vector<std::uint8_t> make_windows_x64_trampoline(const vmp::runtime::trampoline::TokenBytes& token,
                                                      std::uint64_t site_address,
                                                      std::uint64_t bridge_address) {
  std::vector<std::uint8_t> out;
  out.reserve(29);
  out.push_back(0x41);
  out.push_back(0x52);
  out.push_back(0x41);
  out.push_back(0x53);
  out.push_back(0x49);
  out.push_back(0xBA);
  append_le64(out, vmp::runtime::trampoline::token_low64(token));
  out.push_back(0x49);
  out.push_back(0xBB);
  append_le64(out, vmp::runtime::trampoline::token_high64(token));
  out.push_back(0xE9);
  append_le32(out, static_cast<std::uint32_t>(checked_rel32(site_address + 29u, bridge_address)));
  return out;
}

std::vector<std::uint8_t> make_rel32_jump_stub(std::uint64_t source_address, std::uint64_t target_address) {
  std::vector<std::uint8_t> out;
  out.reserve(9);
  out.push_back(0x41);
  out.push_back(0x5B);
  out.push_back(0x41);
  out.push_back(0x5A);
  out.push_back(0xE9);
  append_le32(out, static_cast<std::uint32_t>(checked_rel32(source_address + 9u, target_address)));
  return out;
}

std::vector<std::uint8_t> x64_nop_fill(std::size_t size) {
  return std::vector<std::uint8_t>(size, 0x90);
}

void patch_last_rel32(std::vector<std::uint8_t>& encoding, std::int64_t disp) {
  if (disp < static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::min()) ||
      disp > static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::max()) || encoding.size() < 4u) {
    throw std::runtime_error("rewriter: x64 relocation requires rel32");
  }
  const auto base = encoding.size() - 4u;
  for (std::size_t i = 0; i < 4u; ++i) {
    encoding[base + i] = static_cast<std::uint8_t>((static_cast<std::uint32_t>(disp) >> (i * 8u)) & 0xffu);
  }
}

void patch_last_rel8(std::vector<std::uint8_t>& encoding, std::int64_t disp) {
  if (disp < -128 || disp > 127 || encoding.empty()) {
    throw std::runtime_error("rewriter: x64 relocation requires rel8");
  }
  encoding.back() = static_cast<std::uint8_t>(static_cast<std::int8_t>(disp));
}

std::uint64_t remap_internal_target(std::uint64_t absolute_target,
                                    std::uint64_t original_base,
                                    std::uint64_t relocated_base,
                                    std::size_t code_size) {
  if (absolute_target >= original_base && absolute_target < original_base + code_size) {
    return relocated_base + (absolute_target - original_base);
  }
  return absolute_target;
}

std::vector<std::uint8_t> relocate_x64_function(const std::vector<std::uint8_t>& code,
                                                std::uint64_t original_address,
                                                std::uint64_t relocated_address) {
  std::vector<vmp::arch::common::Diagnostic> diagnostics;
  const auto instructions = vmp::arch::x64::decode_stream(code, original_address, &diagnostics);
  std::vector<std::uint8_t> out;
  out.reserve(code.size());
  for (const auto& insn : instructions) {
    std::vector<std::uint8_t> encoding = insn.encoding;
    if (encoding.empty()) {
      encoding.assign(code.begin() + static_cast<std::ptrdiff_t>(insn.offset),
                      code.begin() + static_cast<std::ptrdiff_t>(insn.offset + insn.size));
    }

    if (insn.pc_relative_target.has_value()) {
      const auto target = remap_internal_target(insn.pc_relative_target->computed_absolute,
                                                original_address,
                                                relocated_address,
                                                code.size());
      const auto new_source_pc = relocated_address + insn.offset + insn.size;
      if (insn.memory.rip_relative) {
        patch_last_rel32(encoding, vmp::arch::common::encode_rel32(new_source_pc, target));
      } else if (insn.has_relative_target) {
        if (!encoding.empty() && (encoding[0] == 0xE8 || encoding[0] == 0xE9)) {
          patch_last_rel32(encoding, vmp::arch::common::encode_rel32(new_source_pc, target));
        } else if (encoding.size() >= 2u && encoding[0] == 0x0F && (encoding[1] & 0xF0u) == 0x80u) {
          patch_last_rel32(encoding, vmp::arch::common::encode_rel32(new_source_pc, target));
        } else if (!encoding.empty() && ((encoding[0] >= 0x70u && encoding[0] <= 0x7Fu) || encoding[0] == 0xEBu || encoding[0] == 0xE3u)) {
          patch_last_rel8(encoding, vmp::arch::common::encode_rel8(new_source_pc, target));
        }
      }
    }

    out.insert(out.end(), encoding.begin(), encoding.end());
  }
  if (out.size() != code.size()) {
    throw std::runtime_error("rewriter: relocated x64 function size mismatch");
  }
  return out;
}


std::optional<std::size_t> rva_to_file_offset(const ParsedPe& pe, std::uint32_t rva) {
  for (const auto& sec : pe.sections) {
    const auto span = static_cast<std::uint32_t>(section_extent(sec));
    if (rva >= sec.hdr.virtual_address && rva < sec.hdr.virtual_address + span) {
      return static_cast<std::size_t>(sec.hdr.pointer_to_raw_data) + (rva - sec.hdr.virtual_address);
    }
  }
  if (!pe.sections.empty() && rva < pe.sections.front().hdr.pointer_to_raw_data) {
    return static_cast<std::size_t>(rva);
  }
  return std::nullopt;
}

bool iequals_ascii(std::string_view lhs, std::string_view rhs) {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  for (std::size_t i = 0; i < lhs.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(lhs[i])) != std::tolower(static_cast<unsigned char>(rhs[i]))) {
      return false;
    }
  }
  return true;
}

std::optional<std::filesystem::path> locate_kernel32_image() {
  if (const char* env = std::getenv("VMP_KERNEL32_DLL"); env != nullptr && *env != '\0') {
    const std::filesystem::path candidate(env);
    if (std::filesystem::exists(candidate)) {
      return candidate;
    }
  }
  if (const char* system_root = std::getenv("SystemRoot"); system_root != nullptr && *system_root != '\0') {
    const std::filesystem::path candidate = std::filesystem::path(system_root) / "System32" / "kernel32.dll";
    if (std::filesystem::exists(candidate)) {
      return candidate;
    }
  }
  const std::array<std::filesystem::path, 4> candidates{{
      "/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/kernel32.dll",
      "/usr/lib64/wine/x86_64-windows/kernel32.dll",
      "/usr/lib/wine/x86_64-windows/kernel32.dll",
      "/opt/homebrew/Cellar/wine/9.0/lib/wine/x86_64-windows/kernel32.dll",
  }};
  for (const auto& candidate : candidates) {
    if (std::filesystem::exists(candidate)) {
      return candidate;
    }
  }
  return std::nullopt;
}

std::unordered_map<std::string, std::uint16_t> resolve_kernel32_ordinals(const std::vector<std::string>& names) {
  std::unordered_map<std::string, std::uint16_t> out;
  const auto image = locate_kernel32_image();
  if (!image.has_value()) {
    return out;
  }
  const auto pe = parse_bytes(detail::read_file(*image));
  if (pe.export_rva == 0) {
    return out;
  }
  const auto export_off = rva_to_file_offset(pe, pe.export_rva);
  if (!export_off.has_value()) {
    return out;
  }
  detail::ensure_size(pe.bytes, *export_off, sizeof(ImageExportDirectory), "kernel32 export directory");
  ImageExportDirectory exports{};
  std::memcpy(&exports, pe.bytes.data() + *export_off, sizeof(exports));
  const auto names_off = rva_to_file_offset(pe, exports.address_of_names);
  const auto ordinals_off = rva_to_file_offset(pe, exports.address_of_name_ordinals);
  if (!names_off.has_value() || !ordinals_off.has_value()) {
    return out;
  }
  for (std::uint32_t idx = 0; idx < exports.number_of_names; ++idx) {
    const auto name_rva = detail::read_le<std::uint32_t>(pe.bytes, *names_off + idx * 4u, "kernel32 export name rva");
    const auto name_off = rva_to_file_offset(pe, name_rva);
    if (!name_off.has_value()) {
      continue;
    }
    const auto export_name = detail::read_c_string(pe.bytes, *name_off);
    if (std::find(names.begin(), names.end(), export_name) == names.end()) {
      continue;
    }
    const auto ordinal_index = detail::read_le<std::uint16_t>(pe.bytes, *ordinals_off + idx * 2u, "kernel32 export ordinal");
    out.emplace(export_name, static_cast<std::uint16_t>(exports.base + ordinal_index));
  }
  return out;
}

void scrub_ascii_occurrences(std::vector<std::uint8_t>& bytes, std::string_view needle) {
  if (needle.empty() || bytes.size() < needle.size()) {
    return;
  }
  for (std::size_t offset = 0; offset + needle.size() <= bytes.size(); ++offset) {
    if (std::memcmp(bytes.data() + offset, needle.data(), needle.size()) == 0) {
      std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                bytes.begin() + static_cast<std::ptrdiff_t>(offset + needle.size()),
                0);
    }
  }
}

void sanitize_kernel32_imports(std::vector<std::uint8_t>& bytes) {
  const auto ordinals = resolve_kernel32_ordinals({"VirtualProtect", "VirtualQuery"});
  if (ordinals.empty()) {
    return;
  }
  auto pe = parse_bytes(bytes);
  if (pe.import_rva == 0) {
    return;
  }
  const auto imports_off = rva_to_file_offset(pe, pe.import_rva);
  if (!imports_off.has_value()) {
    return;
  }
  for (std::size_t descriptor_off = *imports_off; descriptor_off + sizeof(ImageImportDescriptor) <= bytes.size(); descriptor_off += sizeof(ImageImportDescriptor)) {
    ImageImportDescriptor descriptor{};
    std::memcpy(&descriptor, bytes.data() + descriptor_off, sizeof(descriptor));
    if (descriptor.original_first_thunk == 0 && descriptor.first_thunk == 0 && descriptor.name == 0) {
      break;
    }
    const auto dll_name_off = rva_to_file_offset(pe, descriptor.name);
    if (!dll_name_off.has_value()) {
      continue;
    }
    const auto dll_name = detail::read_c_string(bytes, *dll_name_off);
    if (!iequals_ascii(dll_name, "KERNEL32.dll")) {
      continue;
    }
    const auto thunk_rva = descriptor.original_first_thunk != 0 ? descriptor.original_first_thunk : descriptor.first_thunk;
    const auto thunk_off = rva_to_file_offset(pe, thunk_rva);
    const auto iat_off = rva_to_file_offset(pe, descriptor.first_thunk);
    if (!thunk_off.has_value() || !iat_off.has_value()) {
      continue;
    }
    for (std::size_t idx = 0;; ++idx) {
      const auto thunk_entry_off = *thunk_off + idx * 8u;
      const auto iat_entry_off = *iat_off + idx * 8u;
      detail::ensure_size(bytes, thunk_entry_off, 8u, "pe thunk entry");
      detail::ensure_size(bytes, iat_entry_off, 8u, "pe iat entry");
      const auto thunk_value = detail::read_le<std::uint64_t>(bytes, thunk_entry_off, "pe thunk value");
      if (thunk_value == 0) {
        break;
      }
      if ((thunk_value & 0x8000000000000000ull) != 0) {
        continue;
      }
      const auto name_rva = static_cast<std::uint32_t>(thunk_value & 0xffffffffu);
      const auto name_off = rva_to_file_offset(pe, name_rva);
      if (!name_off.has_value()) {
        continue;
      }
      const auto import_name = detail::read_c_string(bytes, *name_off + 2u);
      const auto it = ordinals.find(import_name);
      if (it == ordinals.end()) {
        continue;
      }
      const auto ordinal_thunk = 0x8000000000000000ull | static_cast<std::uint64_t>(it->second);
      detail::write_le(bytes, thunk_entry_off, ordinal_thunk, 8u);
      detail::write_le(bytes, iat_entry_off, ordinal_thunk, 8u);
      std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(*name_off + 2u),
                bytes.begin() + static_cast<std::ptrdiff_t>(*name_off + 2u + import_name.size()),
                0);
    }
  }
  scrub_ascii_occurrences(bytes, "VirtualProtect");
  scrub_ascii_occurrences(bytes, "VirtualQuery");
}

std::uint32_t next_section_virtual_address(const ParsedPe& pe, const std::vector<SectionAddition>& additions_before) {
  std::uint64_t next_va = 0;
  for (const auto& sec : pe.sections) {
    const auto end = detail::align_up(sec.hdr.virtual_address + section_extent(sec), pe.section_alignment);
    next_va = std::max(next_va, end);
  }
  for (const auto& addition : additions_before) {
    const auto raw_size = detail::align_up(addition.data.size(), pe.file_alignment);
    next_va = detail::align_up(next_va + std::max<std::uint64_t>(addition.data.size(), raw_size), pe.section_alignment);
  }
  return static_cast<std::uint32_t>(next_va);
}

std::vector<PlannedSection> plan_sections(const ParsedPe& pe, const std::vector<SectionAddition>& additions) {
  std::vector<PlannedSection> planned;
  planned.reserve(additions.size());
  std::uint64_t next_va = next_section_virtual_address(pe, {});
  std::uint64_t raw_ptr = detail::align_up(pe.bytes.size(), pe.file_alignment);
  for (const auto& addition : additions) {
    PlannedSection item;
    item.addition = addition;
    item.virtual_address = static_cast<std::uint32_t>(next_va);
    item.pointer_to_raw_data = static_cast<std::uint32_t>(raw_ptr);
    item.size_of_raw_data = static_cast<std::uint32_t>(detail::align_up(addition.data.size(), pe.file_alignment));
    planned.push_back(item);
    raw_ptr += item.size_of_raw_data;
    next_va = detail::align_up(next_va + std::max<std::uint64_t>(addition.data.size(), item.size_of_raw_data), pe.section_alignment);
  }
  return planned;
}

std::vector<std::uint8_t> add_sections(ParsedPe pe,
                                       const std::vector<SectionAddition>& additions,
                                       const std::vector<std::uint8_t>& base_bytes) {
  if (additions.empty()) {
    return base_bytes;
  }
  auto bytes = base_bytes;
  const auto optional_off = pe.optional_header_offset;
  const auto section_table = optional_off + pe.file_header.size_of_optional_header;
  std::uint32_t first_raw = std::numeric_limits<std::uint32_t>::max();
  for (const auto& sec : pe.sections) {
    if (sec.hdr.pointer_to_raw_data == 0) {
      continue;
    }
    first_raw = std::min(first_raw, sec.hdr.pointer_to_raw_data);
  }
  if (first_raw == std::numeric_limits<std::uint32_t>::max()) {
    first_raw = static_cast<std::uint32_t>(detail::align_up(section_table + sizeof(ImageSectionHeader) * (pe.file_header.number_of_sections + additions.size()), pe.file_alignment));
  }
  const auto needed_header_end = section_table + static_cast<std::size_t>(pe.file_header.number_of_sections + additions.size()) * sizeof(ImageSectionHeader);
  if (needed_header_end > first_raw) {
    throw std::runtime_error("rewriter: PE header slack insufficient for new sections");
  }

  const auto planned = plan_sections(pe, additions);
  for (std::size_t idx = 0; idx < planned.size(); ++idx) {
    const auto& plan = planned[idx];
    if (bytes.size() < plan.pointer_to_raw_data) {
      bytes.resize(plan.pointer_to_raw_data, 0);
    }
    const auto end = static_cast<std::size_t>(plan.pointer_to_raw_data) + plan.size_of_raw_data;
    if (bytes.size() < end) {
      bytes.resize(end, 0);
    }
    std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(plan.pointer_to_raw_data),
              bytes.begin() + static_cast<std::ptrdiff_t>(end),
              0);
    std::copy(plan.addition.data.begin(), plan.addition.data.end(),
              bytes.begin() + static_cast<std::ptrdiff_t>(plan.pointer_to_raw_data));

    ImageSectionHeader sh{};
    std::memcpy(sh.name.data(), plan.addition.name.c_str(), std::min<std::size_t>(plan.addition.name.size(), sh.name.size()));
    sh.virtual_size = static_cast<std::uint32_t>(plan.addition.data.size());
    sh.virtual_address = plan.virtual_address;
    sh.size_of_raw_data = plan.size_of_raw_data;
    sh.pointer_to_raw_data = plan.pointer_to_raw_data;
    sh.characteristics = plan.addition.characteristics;
    std::memcpy(bytes.data() + section_table + (pe.file_header.number_of_sections + idx) * sizeof(ImageSectionHeader), &sh, sizeof(sh));
  }

  pe.file_header.number_of_sections += static_cast<std::uint16_t>(planned.size());
  std::memcpy(bytes.data() + pe.pe_offset + 4, &pe.file_header, sizeof(ImageFileHeader));
  std::uint64_t final_size_of_image = next_section_virtual_address(pe, {});
  if (!planned.empty()) {
    const auto& tail = planned.back();
    final_size_of_image = detail::align_up(
        static_cast<std::uint64_t>(tail.virtual_address) +
            std::max<std::uint64_t>(tail.addition.data.size(), tail.size_of_raw_data),
        pe.section_alignment);
  }
  detail::write_le(bytes, pe.size_of_image_offset, final_size_of_image, 4);
  return bytes;
}

void strip_symbol_table(std::vector<std::uint8_t>& bytes,
                        const ParsedPe& pe,
                        const std::vector<std::pair<std::string, std::string>>& long_section_names) {
  std::vector<std::uint8_t> new_string_table;
  if (pe.string_table_size >= 4u &&
      static_cast<std::size_t>(pe.string_table_offset) + pe.string_table_size <= bytes.size()) {
    new_string_table.assign(bytes.begin() + static_cast<std::ptrdiff_t>(pe.string_table_offset),
                            bytes.begin() + static_cast<std::ptrdiff_t>(pe.string_table_offset + pe.string_table_size));
  } else {
    new_string_table.assign(4u, 0);
  }

  auto append_name = [&](std::string_view name) {
    const auto offset = static_cast<std::uint32_t>(new_string_table.size());
    new_string_table.insert(new_string_table.end(), name.begin(), name.end());
    new_string_table.push_back(0);
    return offset;
  };

  const auto section_table = pe.optional_header_offset + pe.file_header.size_of_optional_header;
  for (std::size_t idx = 0; idx < pe.sections.size(); ++idx) {
    const auto& current_name = pe.sections[idx].name;
    const auto it = std::find_if(long_section_names.begin(), long_section_names.end(), [&](const auto& entry) {
      return entry.first == current_name;
    });
    if (it == long_section_names.end()) {
      continue;
    }
    if (it->second.size() <= 8u) {
      std::array<char, 8> raw{};
      std::memcpy(raw.data(), it->second.c_str(), it->second.size());
      std::memcpy(bytes.data() + section_table + idx * sizeof(ImageSectionHeader), raw.data(), raw.size());
      continue;
    }
    const auto offset = append_name(it->second);
    std::array<char, 8> raw{};
    const auto slash_name = "/" + std::to_string(offset);
    std::memcpy(raw.data(), slash_name.c_str(), std::min<std::size_t>(slash_name.size(), raw.size()));
    std::memcpy(bytes.data() + section_table + idx * sizeof(ImageSectionHeader), raw.data(), raw.size());
  }

  detail::write_le(new_string_table, 0, new_string_table.size(), 4);

  if (pe.file_header.pointer_to_symbol_table != 0 && pe.file_header.number_of_symbols != 0) {
    const auto start = static_cast<std::size_t>(pe.file_header.pointer_to_symbol_table);
    std::size_t end = start + static_cast<std::size_t>(pe.file_header.number_of_symbols) * 18u;
    if (pe.string_table_size >= 4u) {
      end = std::max(end, static_cast<std::size_t>(pe.string_table_offset) + pe.string_table_size);
    }
    end = std::min(end, bytes.size());
    if (start < end) {
      std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(start), bytes.begin() + static_cast<std::ptrdiff_t>(end), 0);
    }
  }

  const auto new_string_table_offset = static_cast<std::uint32_t>(detail::align_up(bytes.size(), pe.file_alignment));
  if (bytes.size() < new_string_table_offset) {
    bytes.resize(new_string_table_offset, 0);
  }
  bytes.insert(bytes.end(), new_string_table.begin(), new_string_table.end());

  ImageFileHeader header{};
  std::memcpy(&header, bytes.data() + pe.pe_offset + 4, sizeof(ImageFileHeader));
  header.pointer_to_symbol_table = new_string_table_offset;
  header.number_of_symbols = 0;
  std::memcpy(bytes.data() + pe.pe_offset + 4, &header, sizeof(ImageFileHeader));
}

}  // namespace

PeContainer load(const std::filesystem::path& path) { return to_container(parse_bytes(detail::read_file(path)), path); }

PeContainer apply(const PeContainer& input, const vmp::policy::PolicyIR& policy_ir, const RewriteOptions& options) {
  auto parsed = parse_bytes(input.bytes);
  auto working_bytes = input.bytes;
  const auto targets = detail::binary_targets(policy_ir);

  std::vector<detail::BinaryPolicyTarget> thunk_targets;
  std::vector<detail::StringRecordRequest> string_requests;
  std::set<std::string> resolved;

  for (const auto& target : targets) {
    if (!target.container_path.empty()) {
      continue;
    }
    if (target.vm1 || target.vm2) {
      thunk_targets.push_back(target);
    }
    if (!(target.vm_string && target.highly_sensitive)) {
      continue;
    }
    const auto located = find_symbol(parsed, target.symbol);
    if (!located.has_value()) {
      continue;
    }
    const auto& [symbol, section] = *located;
    auto plaintext = read_symbol_data(parsed, *symbol, *section, target.offset);
    if (plaintext.empty()) {
      continue;
    }
    string_requests.push_back(detail::StringRecordRequest{
        detail::stable_string_id(target.symbol),
        target.symbol,
        std::string(reinterpret_cast<const char*>(plaintext.data()), plaintext.size()),
    });
    zero_symbol_data(working_bytes, *section, *symbol, plaintext.size());
    resolved.insert(target.symbol);
  }

  for (const auto& target : targets) {
    if (!target.container_path.empty()) {
      continue;
    }
    if ((target.vm_string && target.highly_sensitive) || target.vm1 || target.vm2) {
      if (resolved.find(target.symbol) == resolved.end() && !find_symbol(parsed, target.symbol).has_value()) {
        throw std::runtime_error("rewriter: PE symbol not found: " + target.symbol);
      }
    }
  }

  const auto metadata_key_context = resolve_trampoline_key_context(options, input.source_path.string(), parsed.file_header.machine);
  const bool already_vmp_protected = looks_like_vmp_protected(parsed);
  std::set<std::string> used_section_names;
  for (const auto& section : parsed.sections) {
    used_section_names.insert(section.name);
  }

  detail::MetadataSectionNames section_names;
  if (!already_vmp_protected) {
    section_names.vmload = detail::random_section_name(used_section_names);
    if (!thunk_targets.empty()) {
      section_names.thunk_meta = detail::random_section_name(used_section_names);
    }
    if (!string_requests.empty()) {
      section_names.string_pool = detail::random_section_name(used_section_names);
    }
  }
  if (options.enable_trampoline && !thunk_targets.empty()) {
    section_names.code_blob = detail::random_section_name(used_section_names);
    section_names.trampoline_meta = detail::random_section_name(used_section_names);
  }

  const auto section_map = section_names.to_json();
  std::vector<SectionAddition> additions;

  if (section_names.vmload.has_value()) {
    detail::json vmload_meta;
    vmload_meta["container"] = "pe";
    vmload_meta["sections"] = section_map;
    vmload_meta["loader_entry_id"] = detail::hmac_id_hex(metadata_key_context,
        vmp::runtime::strings::obf::decode(VMP_OBFSTR("vmp_windows_loader_dll_main")));
    vmload_meta["init_id"] = detail::hmac_id_hex(metadata_key_context,
        vmp::runtime::strings::obf::decode(VMP_OBFSTR("vmp_windows_init")));
    additions.push_back(SectionAddition{*section_names.vmload,
                                        detail::encrypt_metadata_json(metadata_key_context,
                                                                      detail::MetadataBlobKind::section_map,
                                                                      "pe.vmload",
                                                                      vmload_meta),
                                        0x40000040u});
  }

  if (!has_section(parsed, ".CRT$XLB")) {
    const auto crt_id = detail::hmac_id_hex(metadata_key_context,
        vmp::runtime::strings::obf::decode(VMP_OBFSTR("vmp_windows_init")));
    additions.push_back(SectionAddition{".CRT$XLB", std::vector<std::uint8_t>(crt_id.begin(), crt_id.end()), 0x40000040u});
  }

  if (!thunk_targets.empty() && section_names.thunk_meta.has_value()) {
    detail::json thunk_meta;
    thunk_meta["container"] = "pe";
    thunk_meta["sections"] = section_map;
    for (const auto& target : thunk_targets) {
      if (!target.vm1 && !target.vm2) {
        continue;
      }
      thunk_meta["thunks"].push_back({
          {"id", detail::hmac_id_hex(metadata_key_context, target.symbol)},
          {"domain", target.vm2 ? "vm2" : "vm1"},
          {"bridge_id", detail::hmac_id_hex(metadata_key_context,
              target.vm2 ? vmp::runtime::strings::obf::decode(VMP_OBFSTR("vmp_runtime_bridge_vm2"))
                         : vmp::runtime::strings::obf::decode(VMP_OBFSTR("vmp_runtime_bridge_vm1")))}
      });
    }
    additions.push_back(SectionAddition{*section_names.thunk_meta,
                                        detail::encrypt_metadata_json(metadata_key_context,
                                                                      detail::MetadataBlobKind::thunk_map,
                                                                      "pe.thunks",
                                                                      thunk_meta),
                                        0x40000040u});
  }

  if (!string_requests.empty() && section_names.string_pool.has_value()) {
    const auto artifacts = detail::build_string_pool(string_requests);
    if (!options.strings_pool_path.empty()) {
      detail::write_file(options.strings_pool_path, artifacts.blob);
    }
    if (!options.strings_index_path.empty()) {
      detail::write_text(options.strings_index_path, artifacts.index_json.dump(2));
    }
    if (!options.strings_kdf_path.empty()) {
      detail::write_text(options.strings_kdf_path, artifacts.kdf_json.dump(2));
    }
    additions.push_back(SectionAddition{*section_names.string_pool, artifacts.blob, 0x40000040u});
  }

  if (options.enable_trampoline && !thunk_targets.empty()) {
    if (parsed.file_header.machine != 0x8664u) {
      throw std::runtime_error("rewriter: PE trampoline patching currently supports x86_64 only");
    }
    if (!section_names.code_blob.has_value() || !section_names.trampoline_meta.has_value()) {
      throw std::runtime_error("rewriter: internal PE section-name planning failure");
    }

    const auto vmpcode_rva = next_section_virtual_address(parsed, additions);

    std::vector<std::uint8_t> code_blob;
    std::vector<TrampolineRecord> records;
    records.reserve(thunk_targets.size());

    for (const auto& target : thunk_targets) {
      const auto located = find_symbol(parsed, target.symbol);
      if (!located.has_value()) {
        throw std::runtime_error("rewriter: PE symbol not found for trampoline target: " + target.symbol);
      }
      const auto& [symbol, section] = *located;
      const auto code_size = function_size(parsed, *symbol, *section);
      const auto file_off = symbol_file_offset(*section, symbol->value);
      if (code_size == 0 || file_off + code_size > working_bytes.size()) {
        throw std::runtime_error("rewriter: invalid PE function range for trampoline target: " + target.symbol);
      }

      append_padding(code_blob, 16);
      const auto body_offset = static_cast<std::uint32_t>(code_blob.size());
      const auto original_rva = static_cast<std::uint32_t>(symbol_rva(*symbol, *section));
      const auto original_va = parsed.image_base + original_rva;
      const auto relocated_rva = vmpcode_rva + body_offset;
      const auto relocated_va = parsed.image_base + relocated_rva;
      std::vector<std::uint8_t> original_bytes(working_bytes.begin() + static_cast<std::ptrdiff_t>(file_off),
                                               working_bytes.begin() + static_cast<std::ptrdiff_t>(file_off + code_size));
      auto relocated = relocate_x64_function(original_bytes, original_va, relocated_va);
      code_blob.insert(code_blob.end(), relocated.begin(), relocated.end());

      append_padding(code_blob, 16);
      const auto bridge_offset = static_cast<std::uint32_t>(code_blob.size());
      const auto bridge_rva = vmpcode_rva + bridge_offset;
      const auto bridge_va = parsed.image_base + bridge_rva;
      auto bridge = make_rel32_jump_stub(bridge_va, relocated_va);
      code_blob.insert(code_blob.end(), bridge.begin(), bridge.end());

      const auto token = vmp::runtime::trampoline::TokenManager::derive_token(metadata_key_context, original_va, target.symbol);
      const auto stub = make_windows_x64_trampoline(token, original_va, bridge_va);
      if (code_size < stub.size()) {
        throw std::runtime_error("rewriter: function too small for PE trampoline patch: " + target.symbol);
      }
      auto fill = x64_nop_fill(code_size);
      std::copy(fill.begin(), fill.end(), working_bytes.begin() + static_cast<std::ptrdiff_t>(file_off));
      std::copy(stub.begin(), stub.end(), working_bytes.begin() + static_cast<std::ptrdiff_t>(file_off));

      records.push_back(TrampolineRecord{
          detail::stable_string_id(target.symbol),
          original_rva,
          relocated_rva,
          bridge_rva,
          static_cast<std::uint32_t>(code_size),
          token,
      });
    }

    if (!code_blob.empty()) {
      additions.push_back(SectionAddition{*section_names.code_blob, code_blob, 0x60000020u});
      detail::json meta;
      meta["container"] = "pe";
      meta["arch"] = "x64-win-local";
      meta["sections"] = section_map;
      meta["dispatcher_id"] = detail::hmac_id_hex(metadata_key_context, options.trampoline_dispatcher_symbol);
      for (const auto& record : records) {
        meta["entries"].push_back({
            {"record_id", record.record_id},
            {"original_rva", record.original_rva},
            {"relocated_rva", record.relocated_rva},
            {"bridge_rva", record.bridge_rva},
            {"code_size", record.code_size},
            {"token", vmp::runtime::trampoline::token_hex(record.token)},
        });
      }
      additions.push_back(SectionAddition{*section_names.trampoline_meta,
                                          detail::encrypt_metadata_json(metadata_key_context,
                                                                        detail::MetadataBlobKind::trampoline_map,
                                                                        "pe.trampoline",
                                                                        meta),
                                          0x40000040u});
    }
  }

  auto out = input;
  out.bytes = add_sections(parsed, additions, working_bytes);
  sanitize_kernel32_imports(out.bytes);
  if (options.enable_trampoline && !thunk_targets.empty()) {
    strip_symbol_table(out.bytes, parsed, {});
  }
  out = to_container(parse_bytes(out.bytes), input.source_path);
  return out;
}

void write(const PeContainer& container, const std::filesystem::path& out_path) { detail::write_file(out_path, container.bytes); }

bool sniff(const std::vector<std::uint8_t>& bytes) { return bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z'; }

}  // namespace vmp::backend::rewriter::formats::pe
