#if defined(__APPLE__) || defined(_WIN32)
#include "../internal/elf_types.h"
#else
#include <elf.h>
#endif

#include <cstddef>

#include <map>
#include <set>

#include <nlohmann/json.hpp>

#include <vmp/arch/arm/arm.h>
#include <vmp/arch/arm64/arm64.h>
#include <vmp/arch/x64/x64.h>
#include <vmp/arch/x86/x86.h>

#include "../internal/common.h"

namespace vmp::backend::rewriter::formats::elf {
namespace {
static_assert(sizeof(Elf64_Ehdr) == 64, "Elf64_Ehdr layout mismatch");
static_assert(offsetof(Elf64_Ehdr, e_phoff) == 32, "Elf64_Ehdr::e_phoff offset mismatch");
static_assert(offsetof(Elf64_Ehdr, e_shoff) == 40, "Elf64_Ehdr::e_shoff offset mismatch");
static_assert(sizeof(Elf64_Phdr) == 56, "Elf64_Phdr layout mismatch");
static_assert(offsetof(Elf64_Phdr, p_offset) == 8, "Elf64_Phdr::p_offset offset mismatch");
static_assert(sizeof(Elf64_Shdr) == 64, "Elf64_Shdr layout mismatch");
static_assert(offsetof(Elf64_Shdr, sh_offset) == 24, "Elf64_Shdr::sh_offset offset mismatch");
static_assert(sizeof(Elf64_Sym) == 24, "Elf64_Sym layout mismatch");
static_assert(offsetof(Elf64_Sym, st_value) == 8, "Elf64_Sym::st_value offset mismatch");
using json = nlohmann::json;

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

struct VmpCodeRecord {
  std::uint64_t bundle_id = 0;
  std::uint8_t domain = 1;  // 1 vm1, 2 vm2
  std::string symbol;
  std::vector<std::uint8_t> payload;
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
    if (sec.shdr.sh_type != SHT_SYMTAB && sec.shdr.sh_type != SHT_DYNSYM) continue;
    if (sec.shdr.sh_link >= out.sections.size() || sec.shdr.sh_entsize == 0) continue;
    const auto& strtab_hdr = out.sections[sec.shdr.sh_link].shdr;
    detail::ensure_size(bytes, strtab_hdr.sh_offset, strtab_hdr.sh_size, "elf strtab");
    std::vector<std::uint8_t> strtab(bytes.begin() + strtab_hdr.sh_offset, bytes.begin() + strtab_hdr.sh_offset + strtab_hdr.sh_size);
    const std::size_t count = sec.shdr.sh_size / sec.shdr.sh_entsize;
    detail::ensure_size(bytes, sec.shdr.sh_offset, sec.shdr.sh_size, "elf symtab");
    for (std::size_t i = 0; i < count; ++i) {
      ParsedSymbol sym;
      std::memcpy(&sym.sym, bytes.data() + sec.shdr.sh_offset + i * sec.shdr.sh_entsize, sizeof(Elf64_Sym));
      sym.name = sym.sym.st_name < strtab.size() ? detail::read_c_string(strtab, sym.sym.st_name) : std::string();
      if (!sym.name.empty()) out.symbols.push_back(sym);
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
  if (symbol.sym.st_value < sec.shdr.sh_addr) throw std::runtime_error("rewriter: invalid ELF symbol address");
  return static_cast<std::size_t>(sec.shdr.sh_offset + (symbol.sym.st_value - sec.shdr.sh_addr) + addend);
}

std::string infer_plaintext(const ParsedElf& elf, const ParsedSymbol& sym, const ParsedSection& sec, std::uint64_t addend) {
  const auto base = symbol_file_offset(sym, sec, addend);
  if (base >= elf.bytes.size()) throw std::runtime_error("rewriter: invalid ELF symbol offset");
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
  if (base + count > bytes.size()) throw std::runtime_error("rewriter: ELF zero range out of bounds");
  std::fill(bytes.begin() + static_cast<std::ptrdiff_t>(base), bytes.begin() + static_cast<std::ptrdiff_t>(base + count), 0);
}

ElfContainer to_container(const ParsedElf& elf, const std::filesystem::path& path) {
  ElfContainer out;
  out.source_path = path;
  out.bytes = elf.bytes;
  for (const auto& sec : elf.sections) out.sections.push_back(SectionInfo{sec.name, sec.shdr.sh_addr, sec.shdr.sh_offset, sec.shdr.sh_size});
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

std::vector<std::uint8_t> serialize_vmpcode(const std::vector<VmpCodeRecord>& records) {
  std::vector<std::uint8_t> out{'V', 'M', 'P', 'C'};
  detail::write_le(out, out.size(), records.size(), 4);
  for (const auto& rec : records) {
    detail::write_le(out, out.size(), rec.bundle_id, 8);
    detail::write_le(out, out.size(), rec.domain, 1);
    detail::write_le(out, out.size(), rec.symbol.size(), 4);
    detail::write_le(out, out.size(), rec.payload.size(), 4);
    out.insert(out.end(), rec.symbol.begin(), rec.symbol.end());
    out.insert(out.end(), rec.payload.begin(), rec.payload.end());
  }
  return out;
}

std::vector<std::uint8_t> make_x64_sysv2_thunk(std::uint64_t helper_addr, std::uint64_t bundle_id, std::size_t total_size) {
  std::vector<std::uint8_t> stub = {
      0x48, 0x89, 0xF2,              // mov rdx, rsi
      0x48, 0x89, 0xFE,              // mov rsi, rdi
      0x48, 0xBF,                    // mov rdi, imm64
  };
  for (unsigned i = 0; i < 8; ++i) stub.push_back(static_cast<std::uint8_t>((bundle_id >> (i * 8u)) & 0xFFu));
  stub.push_back(0x48); stub.push_back(0xB8);  // mov rax, imm64
  for (unsigned i = 0; i < 8; ++i) stub.push_back(static_cast<std::uint8_t>((helper_addr >> (i * 8u)) & 0xFFu));
  stub.push_back(0xFF); stub.push_back(0xE0);  // jmp rax
  if (stub.size() > total_size) throw std::runtime_error("rewriter: thunk exceeds original function size");
  stub.resize(total_size, 0x90);
  return stub;
}

std::unique_ptr<vmp::arch::common::IsaLifter> make_lifter(const ParsedElf& elf,
                                                          const detail::BinaryPolicyTarget& target,
                                                          vmp::arch::common::CallingConvention& cc_out) {
  using namespace vmp::arch;
  switch (elf.ehdr.e_machine) {
    case EM_X86_64:
      cc_out = vmp::arch::common::CallingConvention::sysv_x64;
      return std::make_unique<x64::X64Lifter>(target.vm2 ? vmp::arch::common::TargetDomain::vm2
                                                          : vmp::arch::common::TargetDomain::vm1);
    case EM_386:
      cc_out = vmp::arch::common::CallingConvention::cdecl_x86;
      return std::make_unique<x86::X86Lifter>();
    case EM_ARM:
      cc_out = vmp::arch::common::CallingConvention::aapcs32;
      return std::make_unique<arm::ArmLifter>();
    case EM_AARCH64:
      cc_out = vmp::arch::common::CallingConvention::aapcs64;
      return std::make_unique<arm64::Arm64Lifter>();
    default:
      return nullptr;
  }
}

json lift_diag_json(const std::vector<vmp::arch::common::Diagnostic>& diags) {
  json out = json::array();
  for (const auto& d : diags) {
    out.push_back({{"offset", d.offset}, {"detail", d.detail}});
  }
  return out;
}

std::optional<vmp::runtime::trampoline::TrampolineArch> trampoline_arch_for_machine(Elf64_Half machine) {
  using vmp::runtime::trampoline::TrampolineArch;
  switch (machine) {
    case EM_X86_64: return TrampolineArch::x64;
    case EM_386: return TrampolineArch::x86;
    case EM_ARM: return TrampolineArch::arm;
    case EM_AARCH64: return TrampolineArch::arm64;
    default: return std::nullopt;
  }
}

vmp::runtime::trampoline::KeyContextId resolve_trampoline_key_context(const RewriteOptions& options,
                                                                      const std::string& seed_text_base,
                                                                      Elf64_Half machine) {
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

std::vector<std::uint8_t> arch_nop_fill(vmp::runtime::trampoline::TrampolineArch arch, std::size_t size) {
  std::vector<std::uint8_t> out(size, 0);
  switch (arch) {
    case vmp::runtime::trampoline::TrampolineArch::x86:
    case vmp::runtime::trampoline::TrampolineArch::x64:
      std::fill(out.begin(), out.end(), 0x90);
      return out;
    case vmp::runtime::trampoline::TrampolineArch::arm: {
      const std::uint32_t nop = 0xE1A00000u;
      for (std::size_t i = 0; i + 4 <= size; i += 4) {
        out[i] = static_cast<std::uint8_t>(nop & 0xffu);
        out[i + 1] = static_cast<std::uint8_t>((nop >> 8u) & 0xffu);
        out[i + 2] = static_cast<std::uint8_t>((nop >> 16u) & 0xffu);
        out[i + 3] = static_cast<std::uint8_t>((nop >> 24u) & 0xffu);
      }
      return out;
    }
    case vmp::runtime::trampoline::TrampolineArch::arm64: {
      const std::uint32_t nop = 0xD503201Fu;
      for (std::size_t i = 0; i + 4 <= size; i += 4) {
        out[i] = static_cast<std::uint8_t>(nop & 0xffu);
        out[i + 1] = static_cast<std::uint8_t>((nop >> 8u) & 0xffu);
        out[i + 2] = static_cast<std::uint8_t>((nop >> 16u) & 0xffu);
        out[i + 3] = static_cast<std::uint8_t>((nop >> 24u) & 0xffu);
      }
      return out;
    }
  }
  return out;
}

}  // namespace

ElfContainer load(const std::filesystem::path& path) { return to_container(parse_bytes(detail::read_file(path)), path); }

ElfContainer apply(const ElfContainer& input, const vmp::policy::PolicyIR& policy_ir, const RewriteOptions& options) {
  auto parsed = parse_bytes(input.bytes);
  auto bytes = parsed.bytes;
  const auto targets = detail::binary_targets(policy_ir);
  std::vector<detail::StringRecordRequest> requests;
  std::set<std::string> resolved;
  json thunk_meta;
  thunk_meta["container"] = "elf";
  thunk_meta["thunks"] = json::array();
  std::vector<VmpCodeRecord> vmpcode_records;
  vmp::runtime::trampoline::TrampolineBundle trampoline_bundle;
  const auto trampoline_arch = trampoline_arch_for_machine(parsed.ehdr.e_machine);
  if (options.enable_trampoline) {
    if (!trampoline_arch.has_value()) {
      throw std::runtime_error("rewriter: trampoline injection unsupported for this ELF machine");
    }
    trampoline_bundle.arch = *trampoline_arch;
    trampoline_bundle.key_context_id = resolve_trampoline_key_context(options, input.source_path.string(), parsed.ehdr.e_machine);
    thunk_meta["trampoline"] = {
        {"arch", vmp::runtime::trampoline::to_string(*trampoline_arch)},
        {"dispatcher_symbol", options.trampoline_dispatcher_symbol},
        {"key_context_id", vmp::runtime::strings::hex_encode(std::vector<std::uint8_t>(
                               trampoline_bundle.key_context_id.begin(), trampoline_bundle.key_context_id.end()))},
    };
  }
  vmp::runtime::trampoline::TokenManager token_manager;
  std::uint64_t next_bundle_id = 1;
  std::uint64_t vm1_helper_addr = 0;
  if (const auto helper = find_symbol(parsed, "vmp_dispatch_vm1_sysv2")) vm1_helper_addr = helper->first.sym.st_value;

  for (const auto& target : targets) {
    if (!target.container_path.empty()) continue;
    const auto located = find_symbol(parsed, target.symbol);
    if (target.vm1 || target.vm2) {
      json thunk_entry{{"symbol", target.symbol}, {"domain", target.vm2 ? "vm2" : "vm1"}, {"mode", "passthrough"}};
      if (options.enable_trampoline && located) {
        const auto dispatcher = find_symbol(parsed, options.trampoline_dispatcher_symbol);
        if (!dispatcher) {
          throw std::runtime_error("rewriter: trampoline dispatcher symbol not found: " + options.trampoline_dispatcher_symbol);
        }
        const auto& [sym, sec] = *located;
        const auto file_off = symbol_file_offset(sym, sec, 0);
        const auto code_size = static_cast<std::size_t>(sym.sym.st_size);
        if (code_size == 0 || file_off + code_size > parsed.bytes.size()) {
          throw std::runtime_error("rewriter: invalid ELF function range for trampoline target: " + target.symbol);
        }
        auto entry = token_manager.register_entry(trampoline_bundle.key_context_id, sym.sym.st_value, 0, target.symbol);
        const auto stub = vmp::runtime::trampoline::generate_trampoline(
            *trampoline_arch, entry.token, sym.sym.st_value, dispatcher->first.sym.st_value);
        if (code_size < stub.bytes.size()) {
          throw std::runtime_error("rewriter: function too small for trampoline patch: " + target.symbol);
        }
        const auto relocated_offset = static_cast<std::uint64_t>(trampoline_bundle.code_blob.size());
        trampoline_bundle.code_blob.insert(trampoline_bundle.code_blob.end(),
                                           parsed.bytes.begin() + static_cast<std::ptrdiff_t>(file_off),
                                           parsed.bytes.begin() + static_cast<std::ptrdiff_t>(file_off + code_size));
        trampoline_bundle.records.push_back(
            vmp::runtime::trampoline::TrampolineBundleRecord{entry, relocated_offset, static_cast<std::uint32_t>(code_size)});
        auto fill = arch_nop_fill(*trampoline_arch, code_size);
        std::copy(fill.begin(), fill.end(), bytes.begin() + static_cast<std::ptrdiff_t>(file_off));
        std::copy(stub.bytes.begin(), stub.bytes.end(), bytes.begin() + static_cast<std::ptrdiff_t>(file_off));
        thunk_entry["mode"] = "token_trampoline";
        thunk_entry["token"] = vmp::runtime::trampoline::token_hex(entry.token);
        thunk_entry["dispatcher_symbol"] = options.trampoline_dispatcher_symbol;
        thunk_entry["patched"] = true;
        thunk_entry["relocated_size"] = code_size;
      } else if (options.enable_lift && located) {
        vmp::arch::common::CallingConvention cc{};
        if (auto lifter = make_lifter(parsed, target, cc); lifter) {
          const auto& [sym, sec] = *located;
          const auto file_off = symbol_file_offset(sym, sec, 0);
          const auto code_size = static_cast<std::size_t>(sym.sym.st_size);
          if (code_size > 0 && file_off + code_size <= parsed.bytes.size()) {
            vmp::arch::common::FunctionView view;
            view.base_addr = sym.sym.st_value;
            view.cc = cc;
            view.endian = vmp::arch::common::ArchEndianness::little;
            view.code.assign(parsed.bytes.begin() + static_cast<std::ptrdiff_t>(file_off),
                             parsed.bytes.begin() + static_cast<std::ptrdiff_t>(file_off + code_size));
            if (!lifter->can_lift(view)) {
              thunk_entry["lift_failed"] = true;
              thunk_entry["diagnostics"] = json::array({{{"offset", 0}, {"detail", "incompatible function view"}}});
            } else {
              auto lifted = lifter->lift(view);
              if (lifted.ok()) {
                thunk_entry["mode"] = "lifted";
                thunk_entry["bundle_id"] = next_bundle_id;
                if (target.vm2 && lifted.vm2_module.has_value()) {
                  vmpcode_records.push_back(VmpCodeRecord{next_bundle_id, 2, target.symbol, lifted.vm2_module->serialize()});
                } else {
                  vmpcode_records.push_back(VmpCodeRecord{next_bundle_id, 1, target.symbol, lifted.module.serialize()});
                }
                if (parsed.ehdr.e_machine == EM_X86_64 && !target.vm2 && vm1_helper_addr != 0 && sym.sym.st_size >= 28) {
                  const auto stub = make_x64_sysv2_thunk(vm1_helper_addr, next_bundle_id, static_cast<std::size_t>(sym.sym.st_size));
                  std::copy(stub.begin(), stub.end(), bytes.begin() + static_cast<std::ptrdiff_t>(file_off));
                  thunk_entry["patched"] = true;
                } else {
                  thunk_entry["patched"] = false;
                }
                ++next_bundle_id;
              } else {
                thunk_entry["mode"] = "passthrough";
                thunk_entry["lift_failed"] = true;
                thunk_entry["diagnostics"] = lift_diag_json(lifted.diagnostics);
              }
            }
          }
        }
      }
      thunk_meta["thunks"].push_back(thunk_entry);
    }

    if (!(target.vm_string && target.highly_sensitive)) continue;
    if (!located) continue;
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
  if (!vmpcode_records.empty()) {
    extra_sections.push_back({".vmpcode", serialize_vmpcode(vmpcode_records)});
  }
  if (!trampoline_bundle.records.empty()) {
    extra_sections.push_back({".vmptrmp", trampoline_bundle.serialize()});
  }
  extra_sections.push_back({".vmp_init_array", std::vector<std::uint8_t>(8, 0)});
  if (!thunk_meta["thunks"].empty()) {
    const auto thunk = thunk_meta.dump(2);
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
