#include <elf.h>

#include <map>
#include <set>

#include "../internal/common.h"

namespace vmp::backend::rewriter::formats::elf {
namespace {

struct ParsedSection {
  std::string name;
  Elf64_Shdr shdr{};
};

struct ParsedSymbol {
  std::string name;
  Elf64_Sym sym{};
};

struct ParsedElf {
  std::vector<std::uint8_t> bytes;
  Elf64_Ehdr ehdr{};
  std::vector<Elf64_Phdr> phdrs;
  std::vector<ParsedSection> sections;
  std::vector<ParsedSymbol> symbols;
};

ParsedElf parse_bytes(const std::vector<std::uint8_t>& bytes) {
  ParsedElf out;
  out.bytes = bytes;
  detail::ensure_size(bytes, 0, sizeof(Elf64_Ehdr), "elf ehdr");
  std::memcpy(&out.ehdr, bytes.data(), sizeof(Elf64_Ehdr));
  if (std::memcmp(out.ehdr.e_ident, ELFMAG, SELFMAG) != 0 || out.ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
      out.ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
    throw std::runtime_error("rewriter: unsupported ELF format");
  }
  detail::ensure_size(bytes, out.ehdr.e_phoff, static_cast<std::size_t>(out.ehdr.e_phentsize) * out.ehdr.e_phnum, "elf phdrs");
  for (std::size_t i = 0; i < out.ehdr.e_phnum; ++i) {
    Elf64_Phdr ph{};
    std::memcpy(&ph, bytes.data() + out.ehdr.e_phoff + i * out.ehdr.e_phentsize, sizeof(Elf64_Phdr));
    out.phdrs.push_back(ph);
  }
  detail::ensure_size(bytes, out.ehdr.e_shoff, static_cast<std::size_t>(out.ehdr.e_shentsize) * out.ehdr.e_shnum, "elf shdrs");
  if (out.ehdr.e_shstrndx >= out.ehdr.e_shnum) {
    throw std::runtime_error("rewriter: invalid ELF shstrndx");
  }
  Elf64_Shdr shstr{};
  std::memcpy(&shstr, bytes.data() + out.ehdr.e_shoff + out.ehdr.e_shstrndx * out.ehdr.e_shentsize, sizeof(Elf64_Shdr));
  detail::ensure_size(bytes, shstr.sh_offset, shstr.sh_size, "elf shstrtab");
  std::vector<std::uint8_t> shstrtab(bytes.begin() + shstr.sh_offset, bytes.begin() + shstr.sh_offset + shstr.sh_size);
  for (std::size_t i = 0; i < out.ehdr.e_shnum; ++i) {
    ParsedSection sec;
    std::memcpy(&sec.shdr, bytes.data() + out.ehdr.e_shoff + i * out.ehdr.e_shentsize, sizeof(Elf64_Shdr));
    sec.name = sec.shdr.sh_name < shstrtab.size() ? detail::read_c_string(shstrtab, sec.shdr.sh_name) : std::string();
    out.sections.push_back(sec);
  }
  for (const auto& sec : out.sections) {
    if (sec.shdr.sh_type != SHT_SYMTAB && sec.shdr.sh_type != SHT_DYNSYM) {
      continue;
    }
    if (sec.shdr.sh_link >= out.sections.size() || sec.shdr.sh_entsize == 0) {
      continue;
    }
    const auto& strtab_hdr = out.sections[sec.shdr.sh_link].shdr;
    detail::ensure_size(bytes, strtab_hdr.sh_offset, strtab_hdr.sh_size, "elf strtab");
    std::vector<std::uint8_t> strtab(bytes.begin() + strtab_hdr.sh_offset, bytes.begin() + strtab_hdr.sh_offset + strtab_hdr.sh_size);
    const std::size_t count = sec.shdr.sh_size / sec.shdr.sh_entsize;
    detail::ensure_size(bytes, sec.shdr.sh_offset, sec.shdr.sh_size, "elf symtab");
    for (std::size_t i = 0; i < count; ++i) {
      ParsedSymbol sym;
      std::memcpy(&sym.sym, bytes.data() + sec.shdr.sh_offset + i * sec.shdr.sh_entsize, sizeof(Elf64_Sym));
      sym.name = sym.sym.st_name < strtab.size() ? detail::read_c_string(strtab, sym.sym.st_name) : std::string();
      if (!sym.name.empty()) {
        out.symbols.push_back(sym);
      }
    }
  }
  return out;
}

std::optional<std::pair<ParsedSymbol, ParsedSection>> find_symbol(const ParsedElf& elf, std::string_view name) {
  for (const auto& symbol : elf.symbols) {
    if (symbol.name != name) continue;
    if (symbol.sym.st_shndx >= elf.sections.size()) continue;
    return std::make_pair(symbol, elf.sections[symbol.sym.st_shndx]);
  }
  return std::nullopt;
}

std::size_t symbol_file_offset(const ParsedSymbol& symbol, const ParsedSection& sec, std::uint64_t addend) {
  if (symbol.sym.st_value < sec.shdr.sh_addr) {
    throw std::runtime_error("rewriter: invalid ELF symbol address");
  }
  return static_cast<std::size_t>(sec.shdr.sh_offset + (symbol.sym.st_value - sec.shdr.sh_addr) + addend);
}

std::string infer_plaintext(const ParsedElf& elf, const ParsedSymbol& sym, const ParsedSection& sec, std::uint64_t addend) {
  const auto base = symbol_file_offset(sym, sec, addend);
  if (base >= elf.bytes.size()) {
    throw std::runtime_error("rewriter: invalid ELF symbol offset");
  }
  std::size_t limit = sym.sym.st_size > addend ? static_cast<std::size_t>(sym.sym.st_size - addend) : 0u;
  if (limit == 0) {
    while (base + limit < elf.bytes.size() && elf.bytes[base + limit] != 0) ++limit;
  } else {
    while (limit > 0 && elf.bytes[base + limit - 1] == 0) --limit;
  }
  return std::string(reinterpret_cast<const char*>(elf.bytes.data() + base), limit);
}

void zero_symbol(std::vector<std::uint8_t>& bytes, const ParsedSymbol& sym, const ParsedSection& sec, std::uint64_t addend) {
  const auto base = symbol_file_offset(sym, sec, addend);
  std::size_t count = sym.sym.st_size > addend ? static_cast<std::size_t>(sym.sym.st_size - addend) : 0u;
  if (count == 0) {
    while (base + count < bytes.size() && bytes[base + count] != 0) ++count;
    if (base + count < bytes.size()) ++count;
  }
  if (base + count > bytes.size()) {
    throw std::runtime_error("rewriter: ELF zero range out of bounds");
  }
  std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(base), bytes.begin() + static_cast<std::ptrdiff_t>(base + count), 0);
}

ElfContainer to_container(const ParsedElf& elf, const std::filesystem::path& path) {
  ElfContainer out;
  out.source_path = path;
  out.bytes = elf.bytes;
  for (const auto& sec : elf.sections) {
    out.sections.push_back(SectionInfo{sec.name, sec.shdr.sh_addr, sec.shdr.sh_offset, sec.shdr.sh_size});
  }
  for (const auto& sym : elf.symbols) {
    std::string sec_name;
    if (sym.sym.st_shndx < elf.sections.size()) sec_name = elf.sections[sym.sym.st_shndx].name;
    out.symbols.push_back(SymbolInfo{sym.name, sym.sym.st_value, sym.sym.st_size, sec_name});
  }
  return out;
}

std::vector<std::uint8_t> rebuild_with_extra_sections(const ParsedElf& elf,
                                                      const std::vector<std::pair<std::string, std::vector<std::uint8_t>>>& new_sections,
                                                      const std::vector<std::uint8_t>& mutated_bytes) {
  auto ehdr = elf.ehdr;
  std::vector<std::uint8_t> body(mutated_bytes.begin(), mutated_bytes.begin() + static_cast<std::ptrdiff_t>(elf.ehdr.e_shoff));
  std::vector<Elf64_Shdr> shdrs;
  shdrs.reserve(elf.sections.size() + new_sections.size());
  std::string shstrtab(1, '\0');
  std::size_t shstr_index = ehdr.e_shstrndx;
  for (std::size_t i = 0; i < elf.sections.size(); ++i) {
    auto shdr = elf.sections[i].shdr;
    shdr.sh_name = static_cast<Elf64_Word>(shstrtab.size());
    shstrtab += elf.sections[i].name;
    shstrtab.push_back('\0');
    if (i == shstr_index) {
      shdr.sh_offset = 0;
      shdr.sh_size = 0;
    }
    shdrs.push_back(shdr);
  }
  for (const auto& [name, data] : new_sections) {
    Elf64_Shdr shdr{};
    shdr.sh_name = static_cast<Elf64_Word>(shstrtab.size());
    shstrtab += name;
    shstrtab.push_back('\0');
    shdr.sh_type = (name.find("init_array") != std::string::npos) ? SHT_INIT_ARRAY : SHT_PROGBITS;
    shdr.sh_flags = 0;
    shdr.sh_addralign = 8;
    shdr.sh_entsize = (name.find("init_array") != std::string::npos) ? 8 : 0;
    shdr.sh_size = data.size();
    shdrs.push_back(shdr);
  }
  for (std::size_t i = elf.sections.size(); i < shdrs.size(); ++i) {
    auto& shdr = shdrs[i];
    const auto& data = new_sections[i - elf.sections.size()].second;
    const auto aligned = detail::align_up(body.size(), shdr.sh_addralign == 0 ? 1 : shdr.sh_addralign);
    body.resize(static_cast<std::size_t>(aligned), 0);
    shdr.sh_offset = body.size();
    body.insert(body.end(), data.begin(), data.end());
  }
  {
    auto& shdr = shdrs[shstr_index];
    const auto aligned = detail::align_up(body.size(), 1);
    body.resize(static_cast<std::size_t>(aligned), 0);
    shdr.sh_offset = body.size();
    shdr.sh_size = shstrtab.size();
    body.insert(body.end(), shstrtab.begin(), shstrtab.end());
  }
  const auto shoff = detail::align_up(body.size(), 8);
  body.resize(static_cast<std::size_t>(shoff), 0);
  ehdr.e_shoff = shoff;
  ehdr.e_shnum = shdrs.size();
  std::memcpy(body.data(), &ehdr, sizeof(Elf64_Ehdr));
  for (const auto& shdr : shdrs) {
    const auto pos = body.size();
    body.resize(pos + sizeof(Elf64_Shdr));
    std::memcpy(body.data() + pos, &shdr, sizeof(Elf64_Shdr));
  }
  return body;
}

}  // namespace

ElfContainer load(const std::filesystem::path& path) { return to_container(parse_bytes(detail::read_file(path)), path); }

ElfContainer apply(const ElfContainer& input, const vmp::policy::PolicyIR& policy_ir, const RewriteOptions& options) {
  auto parsed = parse_bytes(input.bytes);
  auto bytes = parsed.bytes;
  const auto targets = detail::binary_targets(policy_ir);
  std::vector<detail::StringRecordRequest> requests;
  std::vector<detail::BinaryPolicyTarget> thunk_targets;
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
    if (!located) {
      continue;
    }
    const auto& [sym, sec] = *located;
    auto plain = infer_plaintext(parsed, sym, sec, target.offset);
    requests.push_back(detail::StringRecordRequest{detail::stable_string_id(target.symbol), target.symbol, plain});
    zero_symbol(bytes, sym, sec, target.offset);
    resolved.insert(target.symbol);
  }
  for (const auto& target : targets) {
    if (!target.container_path.empty()) continue;
    if ((target.vm_string && target.highly_sensitive) || target.vm1 || target.vm2) {
      if (resolved.find(target.symbol) == resolved.end() && !find_symbol(parsed, target.symbol)) {
        throw std::runtime_error("rewriter: ELF symbol not found: " + target.symbol);
      }
    }
  }
  std::vector<std::pair<std::string, std::vector<std::uint8_t>>> extra_sections;
  if (!requests.empty()) {
    const auto artifacts = detail::build_string_pool(requests);
    if (!options.strings_pool_path.empty()) detail::write_file(options.strings_pool_path, artifacts.blob);
    if (!options.strings_index_path.empty()) detail::write_text(options.strings_index_path, artifacts.index_json.dump(2));
    if (!options.strings_kdf_path.empty()) detail::write_text(options.strings_kdf_path, artifacts.kdf_json.dump(2));
    extra_sections.push_back({".vmpstrings", artifacts.blob});
  }
  extra_sections.push_back({".vmp_init_array", std::vector<std::uint8_t>(8, 0)});
  if (!thunk_targets.empty()) {
    const auto thunk = detail::vm_thunk_descriptor_json(thunk_targets, options, "elf");
    extra_sections.push_back({".vmpvmthk", std::vector<std::uint8_t>(thunk.begin(), thunk.end())});
  }
  auto out = input;
  out.bytes = rebuild_with_extra_sections(parsed, extra_sections, bytes);
  auto reparsed = parse_bytes(out.bytes);
  out = to_container(reparsed, input.source_path);
  return out;
}

void write(const ElfContainer& container, const std::filesystem::path& out_path) { detail::write_file(out_path, container.bytes); }

bool sniff(const std::vector<std::uint8_t>& bytes) {
  return bytes.size() >= 4 && bytes[0] == 0x7f && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F';
}

}  // namespace vmp::backend::rewriter::formats::elf
