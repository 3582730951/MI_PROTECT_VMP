#include <algorithm>
#include <array>
#include <cstring>
#include <map>

#include "../internal/common.h"

namespace vmp::backend::rewriter::formats::macho {
namespace {

constexpr std::uint32_t MH_MAGIC_64 = 0xfeedfacf;
constexpr std::uint32_t LC_SEGMENT_64 = 0x19;
constexpr std::uint32_t LC_SYMTAB = 0x2;
constexpr std::uint32_t LC_DYSYMTAB = 0xb;
constexpr std::uint32_t LC_DYLD_INFO = 0x22;

#pragma pack(push, 1)
struct mach_header_64 {
  std::uint32_t magic;
  std::int32_t cputype;
  std::int32_t cpusubtype;
  std::uint32_t filetype;
  std::uint32_t ncmds;
  std::uint32_t sizeofcmds;
  std::uint32_t flags;
  std::uint32_t reserved;
};
struct load_command {
  std::uint32_t cmd;
  std::uint32_t cmdsize;
};
struct segment_command_64 {
  std::uint32_t cmd;
  std::uint32_t cmdsize;
  char segname[16];
  std::uint64_t vmaddr;
  std::uint64_t vmsize;
  std::uint64_t fileoff;
  std::uint64_t filesize;
  std::uint32_t maxprot;
  std::uint32_t initprot;
  std::uint32_t nsects;
  std::uint32_t flags;
};
struct section_64 {
  char sectname[16];
  char segname[16];
  std::uint64_t addr;
  std::uint64_t size;
  std::uint32_t offset;
  std::uint32_t align;
  std::uint32_t reloff;
  std::uint32_t nreloc;
  std::uint32_t flags;
  std::uint32_t reserved1;
  std::uint32_t reserved2;
  std::uint32_t reserved3;
};
struct symtab_command {
  std::uint32_t cmd;
  std::uint32_t cmdsize;
  std::uint32_t symoff;
  std::uint32_t nsyms;
  std::uint32_t stroff;
  std::uint32_t strsize;
};
struct dysymtab_command {
  std::uint32_t cmd;
  std::uint32_t cmdsize;
  std::uint32_t ilocalsym;
  std::uint32_t nlocalsym;
  std::uint32_t iextdefsym;
  std::uint32_t nextdefsym;
  std::uint32_t iundefsym;
  std::uint32_t nundefsym;
  std::uint32_t tocoff;
  std::uint32_t ntoc;
  std::uint32_t modtaboff;
  std::uint32_t nmodtab;
  std::uint32_t extrefsymoff;
  std::uint32_t nextrefsyms;
  std::uint32_t indirectsymoff;
  std::uint32_t nindirectsyms;
  std::uint32_t extreloff;
  std::uint32_t nextrel;
  std::uint32_t locreloff;
  std::uint32_t nlocrel;
};
struct nlist_64 {
  std::uint32_t n_un;
  std::uint8_t n_type;
  std::uint8_t n_sect;
  std::uint16_t n_desc;
  std::uint64_t n_value;
};
#pragma pack(pop)

struct ParsedSection {
  std::string segname;
  std::string sectname;
  section_64 sh{};
  std::vector<std::uint8_t> data;
};
struct ParsedSegment {
  std::string segname;
  segment_command_64 cmd{};
  std::vector<ParsedSection> sections;
};
struct ParsedSymbol {
  std::string name;
  nlist_64 sym{};
};
struct ParsedMachO {
  std::vector<std::uint8_t> bytes;
  mach_header_64 header{};
  std::vector<ParsedSegment> segments;
  std::vector<ParsedSymbol> symbols;
  bool has_dyld_info = false;
  bool has_symtab = false;
  bool has_dysymtab = false;
};

std::string trim16(const char* s) {
  std::size_t n = 0;
  while (n < 16 && s[n] != '\0') ++n;
  return std::string(s, n);
}

ParsedMachO parse_bytes(const std::vector<std::uint8_t>& bytes) {
  ParsedMachO out;
  out.bytes = bytes;
  detail::ensure_size(bytes, 0, sizeof(mach_header_64), "mach_header_64");
  std::memcpy(&out.header, bytes.data(), sizeof(mach_header_64));
  if (out.header.magic != MH_MAGIC_64) {
    throw std::runtime_error("rewriter: unsupported Mach-O format");
  }
  std::size_t off = sizeof(mach_header_64);
  symtab_command symtab{};
  for (std::size_t i = 0; i < out.header.ncmds; ++i) {
    load_command lc{};
    std::memcpy(&lc, bytes.data() + off, sizeof(load_command));
    if (lc.cmd == LC_SEGMENT_64) {
      ParsedSegment seg;
      std::memcpy(&seg.cmd, bytes.data() + off, sizeof(segment_command_64));
      seg.segname = trim16(seg.cmd.segname);
      std::size_t sec_off = off + sizeof(segment_command_64);
      for (std::size_t s = 0; s < seg.cmd.nsects; ++s) {
        ParsedSection sec;
        std::memcpy(&sec.sh, bytes.data() + sec_off, sizeof(section_64));
        sec.segname = trim16(sec.sh.segname);
        sec.sectname = trim16(sec.sh.sectname);
        if (sec.sh.size > 0 && sec.sh.offset > 0 && sec.sh.offset + sec.sh.size <= bytes.size()) {
          sec.data.assign(bytes.begin() + sec.sh.offset, bytes.begin() + sec.sh.offset + sec.sh.size);
        }
        seg.sections.push_back(sec);
        sec_off += sizeof(section_64);
      }
      out.segments.push_back(seg);
    } else if (lc.cmd == LC_DYLD_INFO) {
      out.has_dyld_info = true;
    } else if (lc.cmd == LC_SYMTAB) {
      out.has_symtab = true;
      std::memcpy(&symtab, bytes.data() + off, sizeof(symtab_command));
    } else if (lc.cmd == LC_DYSYMTAB) {
      out.has_dysymtab = true;
    }
    off += lc.cmdsize;
  }
  if (out.has_symtab && symtab.strsize > 0 && symtab.stroff + symtab.strsize <= bytes.size()) {
    for (std::size_t i = 0; i < symtab.nsyms; ++i) {
      nlist_64 nl{};
      std::memcpy(&nl, bytes.data() + symtab.symoff + i * sizeof(nlist_64), sizeof(nlist_64));
      ParsedSymbol sym;
      sym.sym = nl;
      sym.name = detail::read_c_string(bytes, symtab.stroff + nl.n_un);
      if (!sym.name.empty()) out.symbols.push_back(sym);
    }
  }
  return out;
}

MachOContainer to_container(const ParsedMachO& macho, const std::filesystem::path& path) {
  MachOContainer out;
  out.source_path = path;
  out.bytes = macho.bytes;
  for (const auto& seg : macho.segments) {
    for (const auto& sec : seg.sections) {
      out.sections.push_back(SectionInfo{sec.segname + "," + sec.sectname, sec.sh.addr, sec.sh.offset, sec.sh.size});
    }
  }
  for (const auto& sym : macho.symbols) {
    out.symbols.push_back(SymbolInfo{sym.name, sym.sym.n_value, 0, {}});
  }
  return out;
}

std::vector<std::uint8_t> rebuild(const ParsedMachO& in,
                                  const std::vector<std::pair<std::string, std::vector<std::uint8_t>>>& add_data_sections,
                                  const std::vector<std::pair<std::string, std::vector<std::uint8_t>>>& add_init_sections) {
  ParsedMachO macho = in;
  auto it = std::find_if(macho.segments.begin(), macho.segments.end(), [](const auto& seg) { return seg.segname == "__DATA"; });
  if (it == macho.segments.end()) {
    ParsedSegment seg;
    seg.segname = "__DATA";
    std::memset(&seg.cmd, 0, sizeof(seg.cmd));
    seg.cmd.cmd = LC_SEGMENT_64;
    std::memcpy(seg.cmd.segname, "__DATA", 6);
    seg.cmd.maxprot = 3;
    seg.cmd.initprot = 3;
    macho.segments.push_back(seg);
    it = std::prev(macho.segments.end());
  }
  for (const auto& [name, data] : add_data_sections) {
    ParsedSection sec{};
    sec.segname = "__DATA";
    sec.sectname = name;
    std::memset(&sec.sh, 0, sizeof(sec.sh));
    std::memcpy(sec.sh.segname, "__DATA", 6);
    std::memcpy(sec.sh.sectname, name.c_str(), std::min<std::size_t>(name.size(), 15));
    sec.sh.align = 3;
    sec.data = data;
    it->sections.push_back(sec);
  }
  for (const auto& [name, data] : add_init_sections) {
    ParsedSection sec{};
    sec.segname = "__DATA";
    sec.sectname = name;
    std::memset(&sec.sh, 0, sizeof(sec.sh));
    std::memcpy(sec.sh.segname, "__DATA", 6);
    std::memcpy(sec.sh.sectname, name.c_str(), std::min<std::size_t>(name.size(), 15));
    sec.sh.align = 3;
    sec.data = data;
    it->sections.push_back(sec);
  }
  std::vector<std::uint8_t> out(sizeof(mach_header_64), 0);
  mach_header_64 header = macho.header;
  header.ncmds = macho.segments.size() + (macho.has_symtab ? 1 : 0) + (macho.has_dysymtab ? 1 : 0) + (macho.has_dyld_info ? 1 : 0);
  header.sizeofcmds = 0;
  std::vector<std::vector<std::uint8_t>> load_bytes;
  std::uint64_t fileoff = sizeof(mach_header_64);
  for (const auto& seg : macho.segments) {
    segment_command_64 sc = seg.cmd;
    sc.cmd = LC_SEGMENT_64;
    sc.nsects = seg.sections.size();
    sc.cmdsize = sizeof(segment_command_64) + sc.nsects * sizeof(section_64);
    header.sizeofcmds += sc.cmdsize;
    std::vector<std::uint8_t> bytes(sc.cmdsize, 0);
    std::memcpy(bytes.data(), &sc, sizeof(sc));
    load_bytes.push_back(std::move(bytes));
  }
  if (macho.has_dyld_info) { load_command lc{LC_DYLD_INFO, sizeof(load_command)}; header.sizeofcmds += lc.cmdsize; load_bytes.emplace_back(sizeof(lc)); std::memcpy(load_bytes.back().data(), &lc, sizeof(lc)); }
  if (macho.has_symtab) { symtab_command lc{LC_SYMTAB, sizeof(symtab_command), 0, 0, 0, 0}; header.sizeofcmds += lc.cmdsize; load_bytes.emplace_back(sizeof(lc)); std::memcpy(load_bytes.back().data(), &lc, sizeof(lc)); }
  if (macho.has_dysymtab) { dysymtab_command lc{}; lc.cmd = LC_DYSYMTAB; lc.cmdsize = sizeof(dysymtab_command); header.sizeofcmds += lc.cmdsize; load_bytes.emplace_back(sizeof(lc)); std::memcpy(load_bytes.back().data(), &lc, sizeof(lc)); }
  out.resize(sizeof(mach_header_64) + header.sizeofcmds, 0);
  std::memcpy(out.data(), &header, sizeof(header));
  std::size_t lc_off = sizeof(mach_header_64);
  for (std::size_t idx = 0; idx < macho.segments.size(); ++idx) {
    auto sc = *reinterpret_cast<segment_command_64*>(load_bytes[idx].data());
    std::size_t sec_off = sizeof(segment_command_64);
    for (auto& sec : macho.segments[idx].sections) {
      fileoff = detail::align_up(out.size(), 1u << sec.sh.align);
      out.resize(fileoff, 0);
      sec.sh.offset = fileoff;
      sec.sh.size = sec.data.size();
      sec.sh.addr = 0x100000000ull + fileoff;
      out.insert(out.end(), sec.data.begin(), sec.data.end());
      std::memcpy(load_bytes[idx].data() + sec_off, &sec.sh, sizeof(section_64));
      sec_off += sizeof(section_64);
    }
    sc.fileoff = sizeof(mach_header_64) + header.sizeofcmds;
    sc.filesize = out.size() - sc.fileoff;
    sc.vmaddr = 0x100000000ull + sc.fileoff;
    sc.vmsize = sc.filesize;
    std::memcpy(load_bytes[idx].data(), &sc, sizeof(sc));
  }
  for (const auto& lc : load_bytes) {
    std::copy(lc.begin(), lc.end(), out.begin() + static_cast<std::ptrdiff_t>(lc_off));
    lc_off += lc.size();
  }
  return out;
}

}  // namespace

MachOContainer load(const std::filesystem::path& path) { return to_container(parse_bytes(detail::read_file(path)), path); }

MachOContainer apply(const MachOContainer& input, const vmp::policy::PolicyIR& policy_ir, const RewriteOptions& options) {
  auto parsed = parse_bytes(input.bytes);
  const auto targets = detail::binary_targets(policy_ir);
  std::vector<detail::BinaryPolicyTarget> thunk_targets;
  for (const auto& target : targets) {
    if (!target.container_path.empty()) continue;
    if (target.vm1 || target.vm2) thunk_targets.push_back(target);
  }
  std::vector<std::pair<std::string, std::vector<std::uint8_t>>> data_sections;
  std::vector<std::pair<std::string, std::vector<std::uint8_t>>> init_sections;
  data_sections.push_back({"__vmp_strings", std::vector<std::uint8_t>{0x56,0x4d,0x50,0x53}});
  init_sections.push_back({"__mod_init_func", std::vector<std::uint8_t>(8, 0)});
  data_sections.push_back({"__vmp_load", std::vector<std::uint8_t>{'v','m','p','_','i','o','s','_','i','n','i','t',0}});
  if (!thunk_targets.empty()) {
    const auto thunk = detail::vm_thunk_descriptor_json(thunk_targets, options, "macho");
    data_sections.push_back({"__vmp_vmthk", std::vector<std::uint8_t>(thunk.begin(), thunk.end())});
  }
  auto out = input;
  out.bytes = rebuild(parsed, data_sections, init_sections);
  out = to_container(parse_bytes(out.bytes), input.source_path);
  return out;
}

void write(const MachOContainer& container, const std::filesystem::path& out_path) { detail::write_file(out_path, container.bytes); }

bool sniff(const std::vector<std::uint8_t>& bytes) {
  return bytes.size() >= 4 && detail::read_le<std::uint32_t>(bytes, 0, "macho magic") == MH_MAGIC_64;
}

}  // namespace vmp::backend::rewriter::formats::macho
