#include <vmp/runtime/vm2/vm2.h>

#include <algorithm>
#include <vmp/runtime/integrity/crc32.h>
#include <vmp/runtime/strings/cipher.h>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <numeric>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace vmp::runtime::detail {
void audit_reverse_layout_active_once(const std::string& vm_name) noexcept;
}  // namespace vmp::runtime::detail

namespace vmp::runtime::vm2 {
namespace {
using ByteVector = std::vector<std::uint8_t>;
std::atomic<std::uint64_t> g_next_vm2_module_id{1};

void append_u16(ByteVector& out, std::uint16_t value);
void append_u32(ByteVector& out, std::uint32_t value);
std::uint16_t read_u16(const ByteVector& bytes, std::size_t& offset);
std::uint32_t read_u32(const ByteVector& bytes, std::size_t& offset);
std::size_t decode_instruction_size(const ByteVector& code, std::size_t pc);
std::size_t instruction_size(Opcode opcode);

constexpr std::size_t kVm2LegacyHeaderSize = 4u + 2u + 2u + 4u + 4u + 4u + 4u;
constexpr std::size_t kVm2HeaderSize = kVm2LegacyHeaderSize + kOpcodeMapSeedSize;
constexpr char kOpcodeMapPurposeTag[] = "vmp.cryptor.epoch.v2";
constexpr std::array<std::uint8_t, 8> kVm2OpcodeMarkerMagic{{'O', 'P', 'M', 'A', 'P', 'C', 'R', 'C'}};

std::string hex_u32(std::uint32_t value) {
  std::ostringstream oss;
  oss << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << value;
  return oss.str();
}

void append_module_crc_mismatch_audit(const std::string& note) noexcept {
  try {
    vmp::runtime::audit::AuditWriter writer(vmp::runtime::audit::AuditWriter::default_path());
    writer.append(vmp::runtime::audit::make_event("vm2_module_crc_mismatch", note, 0, "vm2"));
    writer.flush();
  } catch (...) {
  }
}

void append_opcode_map_invalid_audit(const std::string& note) noexcept {
  try {
    vmp::runtime::audit::AuditWriter writer(vmp::runtime::audit::AuditWriter::default_path());
    writer.append(vmp::runtime::audit::make_event("opcode_map_invalid", note, 0, "vm2"));
    writer.flush();
  } catch (...) {
  }
}

std::size_t vm2_header_size_for_version(std::uint16_t version) {
  if (version == kVm2LegacyVersion) return kVm2LegacyHeaderSize;
  if (version == kVm2Version) return kVm2HeaderSize;
  throw std::runtime_error("vm2: unsupported version");
}

bool seed_is_zero(const std::array<std::uint8_t, kOpcodeMapSeedSize>& seed) {
  return std::all_of(seed.begin(), seed.end(), [](std::uint8_t byte) { return byte == 0; });
}

std::array<std::uint8_t, kOpcodeMapSeedSize> random_opcode_seed() {
  std::array<std::uint8_t, kOpcodeMapSeedSize> seed{};
  std::random_device rd;
  for (auto& byte : seed) {
    byte = static_cast<std::uint8_t>(rd());
  }
  return seed;
}

Vm2ConstPoolEntry make_opcode_marker_entry(std::uint32_t marker_crc32) {
  Vm2ConstPoolEntry entry{};
  std::copy(kVm2OpcodeMarkerMagic.begin(), kVm2OpcodeMarkerMagic.end(), entry.bytes.begin());
  for (int i = 0; i < 4; ++i) {
    entry.bytes[8 + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>((marker_crc32 >> (8 * i)) & 0xFFu);
    entry.bytes[12 + static_cast<std::size_t>(i)] =
        static_cast<std::uint8_t>((~marker_crc32 >> (8 * i)) & 0xFFu);
  }
  return entry;
}

bool parse_opcode_marker_entry(const Vm2ConstPoolEntry& entry, std::uint32_t& marker_crc32) {
  if (!std::equal(kVm2OpcodeMarkerMagic.begin(), kVm2OpcodeMarkerMagic.end(), entry.bytes.begin())) {
    return false;
  }
  std::uint32_t marker = 0;
  std::uint32_t inverse = 0;
  for (int i = 0; i < 4; ++i) {
    marker |= static_cast<std::uint32_t>(entry.bytes[8 + static_cast<std::size_t>(i)]) << (8 * i);
    inverse |= static_cast<std::uint32_t>(entry.bytes[12 + static_cast<std::size_t>(i)]) << (8 * i);
  }
  if (inverse != ~marker) {
    throw std::runtime_error("vm2: malformed opcode-map marker");
  }
  marker_crc32 = marker;
  return true;
}

OpcodeCryptor opcode_cryptor_for_module(const Vm2Module& module) {
  return OpcodeCryptor::from_seed(module.key_context_id, module.opcode_map_seed);
}

ByteVector encode_code_stream(const ByteVector& canonical_code, const OpcodeCryptor& cryptor) {
  ByteVector encoded;
  encoded.reserve(canonical_code.size());
  std::size_t pc = 0;
  while (pc < canonical_code.size()) {
    std::size_t cursor = pc;
    const auto opcode = static_cast<Opcode>(read_u16(canonical_code, cursor));
    const auto size = instruction_size(opcode);
    if (pc + size > canonical_code.size()) {
      throw std::runtime_error("vm2: truncated canonical code");
    }
    append_u16(encoded, cryptor.encode(opcode));
    encoded.insert(encoded.end(),
                   canonical_code.begin() + static_cast<std::ptrdiff_t>(cursor),
                   canonical_code.begin() + static_cast<std::ptrdiff_t>(pc + size));
    pc += size;
  }
  return encoded;
}

ByteVector decode_code_stream(const ByteVector& encoded_code, const OpcodeCryptor& cryptor) {
  ByteVector decoded;
  decoded.reserve(encoded_code.size());
  std::size_t pc = 0;
  while (pc < encoded_code.size()) {
    std::size_t cursor = pc;
    const auto on_disk = read_u16(encoded_code, cursor);
    const auto opcode = cryptor.decode(on_disk);
    const auto size = instruction_size(opcode);
    if (pc + size > encoded_code.size()) {
      throw std::runtime_error("vm2: truncated encoded code");
    }
    append_u16(decoded, static_cast<std::uint16_t>(opcode));
    decoded.insert(decoded.end(),
                   encoded_code.begin() + static_cast<std::ptrdiff_t>(cursor),
                   encoded_code.begin() + static_cast<std::ptrdiff_t>(pc + size));
    pc += size;
  }
  return decoded;
}

std::uint16_t module_version_for_serialize(const Vm2Module& module) {
  if ((module.module_flags & VMP_FLAG_OPCODE_ENCRYPTED) != 0) {
    return kVm2Version;
  }
  if (module.version == kVm2LegacyVersion && seed_is_zero(module.opcode_map_seed)) {
    return kVm2LegacyVersion;
  }
  return kVm2Version;
}

std::vector<std::uint16_t> derive_instruction_lengths_from_code(const ByteVector& code) {
  std::vector<std::uint16_t> lengths;
  lengths.reserve(code.size() / 2u);
  std::size_t pc = 0;
  while (pc < code.size()) {
    const auto size = decode_instruction_size(code, pc);
    lengths.push_back(static_cast<std::uint16_t>(size));
    pc += size;
  }
  return lengths;
}

ByteVector serialize_length_table(const std::vector<std::uint16_t>& lengths) {
  ByteVector out;
  out.reserve(lengths.size() * sizeof(std::uint16_t));
  for (const auto length : lengths) {
    append_u16(out, length);
  }
  return out;
}

ByteVector reverse_instruction_storage(const ByteVector& forward_code,
                                       const std::vector<std::uint16_t>& lengths) {
  ByteVector reversed;
  reversed.reserve(forward_code.size());
  std::vector<std::size_t> starts;
  starts.reserve(lengths.size());
  std::size_t forward_pc = 0;
  for (const auto length : lengths) {
    if (length == 0u || forward_pc + length > forward_code.size()) {
      throw std::runtime_error("vm2: invalid reverse instruction length");
    }
    starts.push_back(forward_pc);
    forward_pc += length;
  }
  if (forward_pc != forward_code.size()) {
    throw std::runtime_error("vm2: reverse length table/code size mismatch");
  }
  for (std::size_t i = lengths.size(); i > 0; --i) {
    const auto start = starts[i - 1];
    const auto length = lengths[i - 1];
    reversed.insert(reversed.end(),
                    forward_code.begin() + static_cast<std::ptrdiff_t>(start),
                    forward_code.begin() + static_cast<std::ptrdiff_t>(start + length));
  }
  return reversed;
}

ByteVector materialize_forward_code_from_reverse_storage(const ByteVector& reverse_storage,
                                                         const std::vector<std::uint16_t>& lengths,
                                                         const OpcodeCryptor* cryptor) {
  ByteVector forward(reverse_storage.size(), 0);
  std::size_t forward_pc = 0;
  for (const auto length : lengths) {
    if (length < 2u) {
      throw std::runtime_error("vm2: reverse instruction length too small");
    }
    if (forward_pc + length > reverse_storage.size()) {
      throw std::runtime_error("vm2: reverse instruction length exceeds code size");
    }
    const auto reverse_pc = reverse_storage.size() - forward_pc - length;
    if (reverse_pc + length > reverse_storage.size()) {
      throw std::runtime_error("vm2: reverse instruction offset out of range");
    }
    std::size_t opcode_cursor = reverse_pc;
    const auto raw_opcode = read_u16(reverse_storage, opcode_cursor);
    const auto opcode = cryptor == nullptr ? static_cast<Opcode>(raw_opcode) : cryptor->decode(raw_opcode);
    forward[forward_pc] = static_cast<std::uint8_t>(static_cast<std::uint16_t>(opcode) & 0xFFu);
    forward[forward_pc + 1] = static_cast<std::uint8_t>((static_cast<std::uint16_t>(opcode) >> 8u) & 0xFFu);
    std::copy(reverse_storage.begin() + static_cast<std::ptrdiff_t>(reverse_pc + 2u),
              reverse_storage.begin() + static_cast<std::ptrdiff_t>(reverse_pc + length),
              forward.begin() + static_cast<std::ptrdiff_t>(forward_pc + 2u));
    forward_pc += length;
  }
  return forward;
}

void validate_length_table_against_code(const ByteVector& forward_code,
                                        const std::vector<std::uint16_t>& lengths) {
  std::size_t forward_pc = 0;
  for (const auto length : lengths) {
    if (forward_pc + length > forward_code.size()) {
      throw std::runtime_error("vm2: reverse length table exceeds code size");
    }
    if (decode_instruction_size(forward_code, forward_pc) != length) {
      throw std::runtime_error("vm2: reverse length table disagrees with decoded instruction size");
    }
    forward_pc += length;
  }
  if (forward_pc != forward_code.size()) {
    throw std::runtime_error("vm2: reverse length table sum mismatch");
  }
}

void clear_reverse_layout_cache(Vm2Module& module) {
  module.reverse_code.clear();
  module.reverse_insn_lengths.clear();
  module.forward_instruction_start_by_pc.clear();
  module.forward_instruction_length_by_pc.clear();
  module.reverse_pc_to_forward_pc.clear();
}

void populate_reverse_layout_cache(Vm2Module& module,
                                   const std::vector<std::uint16_t>& lengths) {
  clear_reverse_layout_cache(module);
  validate_length_table_against_code(module.code, lengths);
  module.reverse_insn_lengths = lengths;
  module.reverse_code = reverse_instruction_storage(module.code, module.reverse_insn_lengths);
  module.forward_instruction_start_by_pc.assign(module.code.size(), 0);
  module.forward_instruction_length_by_pc.assign(module.code.size(), 0);
  module.reverse_pc_to_forward_pc.assign(module.code.size(), std::numeric_limits<std::uint64_t>::max());
  std::size_t forward_pc = 0;
  for (const auto length : module.reverse_insn_lengths) {
    const auto reverse_pc = module.code.size() - forward_pc - length;
    for (std::size_t i = 0; i < length; ++i) {
      module.forward_instruction_start_by_pc[forward_pc + i] = static_cast<std::uint32_t>(forward_pc);
      module.forward_instruction_length_by_pc[forward_pc + i] = length;
      module.reverse_pc_to_forward_pc[reverse_pc + i] = forward_pc;
    }
    forward_pc += length;
  }
}


struct MemoryOperand {
  std::uint8_t base = 0;
  std::int32_t offset = 0;
};

struct InstructionLine {
  std::string op;
  std::vector<std::string> operands;
  std::uint32_t pc = 0;
};

struct ParsedProgram {
  std::vector<InstructionLine> instructions;
  std::unordered_map<std::string, std::uint32_t> labels;
  std::vector<Vm2ConstPoolEntry> const_pool;
  std::unordered_map<std::string, std::uint32_t> const_labels;
  std::array<std::uint8_t, kVm2KeyContextIdSize> key_context_id{};
};

std::string trim(std::string_view value) {
  std::size_t begin = 0;
  while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
    ++begin;
  }
  std::size_t end = value.size();
  while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
    --end;
  }
  return std::string(value.substr(begin, end - begin));
}

std::string strip_comment(std::string_view value) {
  bool in_string = false;
  for (std::size_t i = 0; i < value.size(); ++i) {
    const char ch = value[i];
    if (ch == '"' && (i == 0 || value[i - 1] != '\\')) {
      in_string = !in_string;
    }
    if (!in_string && (ch == ';' || ch == '#')) {
      return std::string(value.substr(0, i));
    }
  }
  return std::string(value);
}

std::vector<std::string> split_operands(const std::string& text) {
  std::vector<std::string> out;
  std::string current;
  bool in_string = false;
  int bracket_depth = 0;
  for (std::size_t i = 0; i < text.size(); ++i) {
    const char ch = text[i];
    if (ch == '"' && (i == 0 || text[i - 1] != '\\')) {
      in_string = !in_string;
      current.push_back(ch);
      continue;
    }
    if (!in_string) {
      if (ch == '[') {
        ++bracket_depth;
      } else if (ch == ']') {
        --bracket_depth;
      } else if (ch == ',' && bracket_depth == 0) {
        out.push_back(trim(current));
        current.clear();
        continue;
      }
    }
    current.push_back(ch);
  }
  if (!trim(current).empty()) {
    out.push_back(trim(current));
  }
  return out;
}

void append_u16(ByteVector& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void append_u32(ByteVector& out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFFu));
  }
}

void append_u64(ByteVector& out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFFu));
  }
}

void append_i32(ByteVector& out, std::int32_t value) { append_u32(out, static_cast<std::uint32_t>(value)); }

std::uint16_t read_u16(const ByteVector& bytes, std::size_t& offset) {
  if (offset + 2 > bytes.size()) {
    throw std::runtime_error("vm2: truncated u16");
  }
  const auto value = static_cast<std::uint16_t>(bytes[offset]) |
                     static_cast<std::uint16_t>(bytes[offset + 1] << 8u);
  offset += 2;
  return value;
}

std::uint32_t read_u32(const ByteVector& bytes, std::size_t& offset) {
  if (offset + 4 > bytes.size()) {
    throw std::runtime_error("vm2: truncated u32");
  }
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(bytes[offset + static_cast<std::size_t>(i)]) << (8 * i);
  }
  offset += 4;
  return value;
}

std::uint64_t read_u64(const ByteVector& bytes, std::size_t& offset) {
  if (offset + 8 > bytes.size()) {
    throw std::runtime_error("vm2: truncated u64");
  }
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(bytes[offset + static_cast<std::size_t>(i)]) << (8 * i);
  }
  offset += 8;
  return value;
}

std::int32_t read_i32(const ByteVector& bytes, std::size_t& offset) {
  return static_cast<std::int32_t>(read_u32(bytes, offset));
}

std::size_t decode_instruction_size(const ByteVector& code, std::size_t pc) {
  std::size_t cursor = pc;
  const auto opcode = static_cast<Opcode>(read_u16(code, cursor));
  switch (opcode) {
    case Opcode::nop:
    case Opcode::bret:
    case Opcode::pret:
    case Opcode::xret:
    case Opcode::ifence:
    case Opcode::brk:
      return 2;
    case Opcode::ftrap:
    case Opcode::jmp:
    case Opcode::syscall_proxy:
      return 6;
    case Opcode::ildimm:
    case Opcode::dldimm:
      return 11;
    case Opcode::vldimm:
    case Opcode::tsload:
      return 7;
    case Opcode::imov:
    case Opcode::ineg:
    case Opcode::inot:
    case Opcode::dmov:
    case Opcode::ipopcnt:
    case Opcode::iclz:
    case Opcode::ictz:
    case Opcode::ibswap:
    case Opcode::isetcc:
    case Opcode::istrlen:
    case Opcode::dsqrt:
    case Opcode::i64tof:
    case Opcode::f64toi:
    case Opcode::icmp:
    case Opcode::itest:
    case Opcode::dcmp:
      return 4;
    case Opcode::tsrelease:
    case Opcode::tswipe:
      return 3;

    case Opcode::iadd:
    case Opcode::isub:
    case Opcode::imul:
    case Opcode::idiv:
    case Opcode::imod:
    case Opcode::iand:
    case Opcode::ior:
    case Opcode::ixor:
    case Opcode::ishl:
    case Opcode::ishr:
    case Opcode::isar:
    case Opcode::dadd:
    case Opcode::dsub:
    case Opcode::dmul:
    case Opcode::ddiv:
    case Opcode::vadd128:
    case Opcode::vsub128:
    case Opcode::vmul128:
    case Opcode::vxor128:
    case Opcode::imemcpy:
    case Opcode::imemset:
    case Opcode::istrcmp:
      return 5;
    case Opcode::imemld8:
    case Opcode::imemld16:
    case Opcode::imemld32:
    case Opcode::imemld64:
    case Opcode::imemst8:
    case Opcode::imemst16:
    case Opcode::imemst32:
    case Opcode::imemst64:
    case Opcode::vmemld128:
    case Opcode::vmemst128:
      return 8;
    case Opcode::jp:
    case Opcode::jnp:
      return 7;
    case Opcode::blnk:
      return 7;
    case Opcode::pcall:
      return 8;
    case Opcode::xcall:
      return 10;
    case Opcode::bridgeargs:
      return 5;
    case Opcode::icas64:
      return 10;
    case Opcode::ixchg64:
      return 9;
    case Opcode::tsread8:
      return 5;
  }
  throw std::runtime_error("vm2: unknown opcode while collecting function entries");
}

std::size_t instruction_size(Opcode opcode) {
  switch (opcode) {
    case Opcode::nop:
    case Opcode::bret:
    case Opcode::pret:
    case Opcode::xret:
    case Opcode::ifence:
    case Opcode::brk:
      return 2;
    case Opcode::ftrap:
    case Opcode::jmp:
    case Opcode::syscall_proxy:
      return 6;
    case Opcode::ildimm:
    case Opcode::dldimm:
      return 11;
    case Opcode::vldimm:
    case Opcode::tsload:
      return 7;
    case Opcode::imov:
    case Opcode::ineg:
    case Opcode::inot:
    case Opcode::dmov:
    case Opcode::ipopcnt:
    case Opcode::iclz:
    case Opcode::ictz:
    case Opcode::ibswap:
    case Opcode::isetcc:
    case Opcode::istrlen:
    case Opcode::dsqrt:
    case Opcode::i64tof:
    case Opcode::f64toi:
    case Opcode::icmp:
    case Opcode::itest:
    case Opcode::dcmp:
      return 4;
    case Opcode::tsrelease:
    case Opcode::tswipe:
      return 3;
    case Opcode::iadd:
    case Opcode::isub:
    case Opcode::imul:
    case Opcode::idiv:
    case Opcode::imod:
    case Opcode::iand:
    case Opcode::ior:
    case Opcode::ixor:
    case Opcode::ishl:
    case Opcode::ishr:
    case Opcode::isar:
    case Opcode::dadd:
    case Opcode::dsub:
    case Opcode::dmul:
    case Opcode::ddiv:
    case Opcode::vadd128:
    case Opcode::vsub128:
    case Opcode::vmul128:
    case Opcode::vxor128:
    case Opcode::imemcpy:
    case Opcode::imemset:
    case Opcode::istrcmp:
      return 5;
    case Opcode::imemld8:
    case Opcode::imemld16:
    case Opcode::imemld32:
    case Opcode::imemld64:
    case Opcode::imemst8:
    case Opcode::imemst16:
    case Opcode::imemst32:
    case Opcode::imemst64:
    case Opcode::vmemld128:
    case Opcode::vmemst128:
      return 8;
    case Opcode::jp:
    case Opcode::jnp:
      return 7;
    case Opcode::blnk:
      return 7;
    case Opcode::pcall:
      return 8;
    case Opcode::xcall:
      return 10;
    case Opcode::bridgeargs:
      return 5;
    case Opcode::icas64:
      return 10;
    case Opcode::ixchg64:
      return 9;
    case Opcode::tsread8:
      return 5;
  }
  throw std::runtime_error("vm2: unknown opcode size");
}

const std::vector<Opcode>& canonical_opcode_sequence_internal() {
  static const std::vector<Opcode> sequence{
      Opcode::nop,        Opcode::ildimm,      Opcode::vldimm,      Opcode::imov,         Opcode::dldimm,
      Opcode::dmov,       Opcode::iadd,        Opcode::isub,        Opcode::imul,         Opcode::idiv,
      Opcode::imod,       Opcode::ineg,        Opcode::iand,        Opcode::ior,          Opcode::ixor,
      Opcode::ishl,       Opcode::ishr,        Opcode::isar,        Opcode::inot,         Opcode::ipopcnt,
      Opcode::iclz,       Opcode::ictz,        Opcode::ibswap,      Opcode::icmp,         Opcode::itest,
      Opcode::isetcc,     Opcode::imemld8,     Opcode::imemld16,    Opcode::imemld32,     Opcode::imemld64,
      Opcode::imemst8,    Opcode::imemst16,    Opcode::imemst32,    Opcode::imemst64,     Opcode::vmemld128,
      Opcode::vmemst128,  Opcode::jmp,         Opcode::jp,          Opcode::jnp,          Opcode::blnk,
      Opcode::bret,       Opcode::pcall,       Opcode::pret,        Opcode::dadd,         Opcode::dsub,
      Opcode::dmul,       Opcode::ddiv,        Opcode::dsqrt,       Opcode::i64tof,       Opcode::f64toi,
      Opcode::dcmp,       Opcode::vadd128,     Opcode::vsub128,     Opcode::vmul128,      Opcode::vxor128,
      Opcode::imemcpy,    Opcode::imemset,     Opcode::istrcmp,     Opcode::istrlen,      Opcode::icas64,
      Opcode::ixchg64,    Opcode::ifence,      Opcode::brk,         Opcode::ftrap,        Opcode::syscall_proxy,
      Opcode::xcall,      Opcode::xret,        Opcode::bridgeargs,  Opcode::tsload,       Opcode::tsrelease,
      Opcode::tsread8,    Opcode::tswipe,
  };
  return sequence;
}

std::unordered_set<std::uint32_t> collect_function_entries(const ByteVector& code, std::uint32_t entry_pc) {
  std::unordered_set<std::uint32_t> entries{entry_pc};
  std::size_t pc = 0;
  while (pc < code.size()) {
    std::size_t cursor = pc;
    const auto opcode = static_cast<Opcode>(read_u16(code, cursor));
    switch (opcode) {
      case Opcode::blnk: {
        const auto target = read_u32(code, cursor);
        entries.insert(target);
        break;
      }
      case Opcode::pcall: {
        ++cursor;
        const auto target = read_u32(code, cursor);
        entries.insert(target);
        break;
      }
      default:
        break;
    }
    pc += decode_instruction_size(code, pc);
  }
  return entries;
}

std::int64_t parse_i64(const std::string& text) {
  std::size_t idx = 0;
  int base = 10;
  if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    base = 16;
  } else if (text.size() > 3 && text[0] == '-' && text[1] == '0' && (text[2] == 'x' || text[2] == 'X')) {
    base = 16;
  }
  long long value = std::stoll(text, &idx, base);
  if (idx != text.size()) {
    throw std::runtime_error("vm2 asm: invalid integer '" + text + "'");
  }
  return static_cast<std::int64_t>(value);
}

std::uint64_t parse_u64_value(const std::string& text) {
  std::size_t idx = 0;
  int base = 10;
  if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    base = 16;
  }
  const auto value = std::stoull(text, &idx, base);
  if (idx != text.size()) {
    throw std::runtime_error("vm2 asm: invalid unsigned integer '" + text + "'");
  }
  return static_cast<std::uint64_t>(value);
}

double parse_double_value(const std::string& text) {
  std::size_t idx = 0;
  const auto value = std::stod(text, &idx);
  if (idx != text.size()) {
    throw std::runtime_error("vm2 asm: invalid double '" + text + "'");
  }
  return value;
}

std::uint64_t bit_cast_u64(double value) {
  std::uint64_t out = 0;
  std::memcpy(&out, &value, sizeof(out));
  return out;
}

double bit_cast_double(std::uint64_t value) {
  double out = 0.0;
  std::memcpy(&out, &value, sizeof(out));
  return out;
}

std::uint8_t parse_general_register(const std::string& token) {
  if (token.size() < 2 || token[0] != 'r') {
    throw std::runtime_error("vm2 asm: expected integer register, got '" + token + "'");
  }
  const auto value = static_cast<std::uint32_t>(parse_u64_value(token.substr(1)));
  if (!is_valid_general_register(static_cast<std::uint8_t>(value))) {
    throw std::runtime_error("vm2 asm: integer register out of range");
  }
  return static_cast<std::uint8_t>(value);
}

std::uint8_t parse_vector_register(const std::string& token) {
  if (token.size() < 2 || token[0] != 'q') {
    throw std::runtime_error("vm2 asm: expected vector register, got '" + token + "'");
  }
  const auto value = static_cast<std::uint32_t>(parse_u64_value(token.substr(1)));
  if (!is_valid_vector_register(static_cast<std::uint8_t>(value))) {
    throw std::runtime_error("vm2 asm: vector register out of range");
  }
  return static_cast<std::uint8_t>(value);
}

std::uint8_t parse_float_register(const std::string& token) {
  if (token.size() < 2 || token[0] != 'd') {
    throw std::runtime_error("vm2 asm: expected float register, got '" + token + "'");
  }
  const auto value = static_cast<std::uint32_t>(parse_u64_value(token.substr(1)));
  if (!is_valid_float_register(static_cast<std::uint8_t>(value))) {
    throw std::runtime_error("vm2 asm: float register out of range");
  }
  return static_cast<std::uint8_t>(value);
}

std::uint8_t parse_predicate(const std::string& token) {
  if (token.size() < 2 || token[0] != 'p') {
    throw std::runtime_error("vm2 asm: expected predicate register, got '" + token + "'");
  }
  const auto value = static_cast<std::uint32_t>(parse_u64_value(token.substr(1)));
  if (!is_valid_predicate(static_cast<std::uint8_t>(value))) {
    throw std::runtime_error("vm2 asm: predicate out of range");
  }
  return static_cast<std::uint8_t>(value);
}

MemoryOperand parse_memory_operand(const std::string& token) {
  if (token.size() < 4 || token.front() != '[' || token.back() != ']') {
    throw std::runtime_error("vm2 asm: expected memory operand, got '" + token + "'");
  }
  const auto inner = token.substr(1, token.size() - 2);
  const auto plus = inner.find_first_of("+-", 1);
  const std::string base_text = plus == std::string::npos ? inner : inner.substr(0, plus);
  const std::string offset_text = plus == std::string::npos ? "+0" : inner.substr(plus);
  MemoryOperand operand;
  if (base_text == "sp") {
    operand.base = static_cast<std::uint8_t>(MemoryBase::sp);
  } else {
    operand.base = parse_general_register(base_text);
  }
  operand.offset = static_cast<std::int32_t>(parse_i64(offset_text));
  return operand;
}

std::uint8_t parse_domain_token(const std::string& token) {
  if (token == "native") return 0;
  if (token == "vm1") return 1;
  if (token == "vm2") return 2;
  throw std::runtime_error("vm2 asm: unknown domain '" + token + "'");
}

std::array<std::uint8_t, kVm2KeyContextIdSize> parse_keyctx_hex(const std::string& token) {
  auto hex = token;
  if (hex.rfind("0x", 0) == 0 || hex.rfind("0X", 0) == 0) {
    hex = hex.substr(2);
  }
  if (hex.size() != kVm2KeyContextIdSize * 2) {
    throw std::runtime_error("vm2 asm: keyctx expects 16-byte hex");
  }
  std::array<std::uint8_t, kVm2KeyContextIdSize> out{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    const auto part = hex.substr(i * 2, 2);
    out[i] = static_cast<std::uint8_t>(std::stoul(part, nullptr, 16));
  }
  return out;
}

std::uint32_t instruction_size(const InstructionLine& inst) {
  const auto& op = inst.op;
  if (op == "nop" || op == "bret" || op == "pret" || op == "xret" || op == "ifence" || op == "brk") return 2;
  if (op == "ftrap" || op == "jmp" || op == "syscall_proxy") return 6;
  if (op == "ildimm" || op == "dldimm") return 11;
  if (op == "vldimm" || op == "tsload") return 7;
  if (op == "imov" || op == "ineg" || op == "inot" || op == "dmov" || op == "ipopcnt" || op == "iclz" || op == "ictz" || op == "ibswap" || op == "isetcc" || op == "istrlen" || op == "dsqrt" || op == "i64tof" || op == "f64toi" || op == "icmp" || op == "itest" || op == "dcmp") return 4;
  if (op == "tsrelease" || op == "tswipe") return 3;
  if (op == "iadd" || op == "isub" || op == "imul" || op == "idiv" || op == "imod" || op == "iand" || op == "ior" || op == "ixor" ||
      op == "ishl" || op == "ishr" || op == "isar" || op == "dadd" || op == "dsub" || op == "dmul" ||
      op == "ddiv" || op == "vadd128" || op == "vsub128" || op == "vmul128" || op == "vxor128" || op == "imemcpy" ||
      op == "imemset" || op == "istrcmp") return 5;
  if (op == "imemld8" || op == "imemld16" || op == "imemld32" || op == "imemld64" || op == "imemst8" || op == "imemst16" ||
      op == "imemst32" || op == "imemst64" || op == "vmemld128" || op == "vmemst128") return 8;
  if (op == "jp" || op == "jnp") return 7;
  if (op == "blnk") return 7;
  if (op == "pcall") return 8;
  if (op == "xcall" || op == "icas64") return 10;
  if (op == "ixchg64") return 9;
  if (op == "bridgeargs") return 5;
  if (op == "tsread8") return 5;
  throw std::runtime_error("vm2 asm: unknown opcode '" + op + "'");
}

Opcode parse_opcode(const std::string& op) {
  static const std::unordered_map<std::string, Opcode> map = {
      {"nop", Opcode::nop},           {"ildimm", Opcode::ildimm},       {"vldimm", Opcode::vldimm},
      {"imov", Opcode::imov},         {"dldimm", Opcode::dldimm},       {"dmov", Opcode::dmov},
      {"iadd", Opcode::iadd},         {"isub", Opcode::isub},           {"imul", Opcode::imul},
      {"idiv", Opcode::idiv},         {"imod", Opcode::imod},           {"ineg", Opcode::ineg},
      {"iand", Opcode::iand},         {"ior", Opcode::ior},             {"ixor", Opcode::ixor},
      {"ishl", Opcode::ishl},         {"ishr", Opcode::ishr},           {"isar", Opcode::isar},
      {"inot", Opcode::inot},         {"ipopcnt", Opcode::ipopcnt},     {"iclz", Opcode::iclz},
      {"ictz", Opcode::ictz},         {"ibswap", Opcode::ibswap},       {"icmp", Opcode::icmp},
      {"itest", Opcode::itest},       {"isetcc", Opcode::isetcc},       {"imemld8", Opcode::imemld8},
      {"imemld16", Opcode::imemld16}, {"imemld32", Opcode::imemld32},   {"imemld64", Opcode::imemld64},
      {"imemst8", Opcode::imemst8},   {"imemst16", Opcode::imemst16},   {"imemst32", Opcode::imemst32},
      {"imemst64", Opcode::imemst64}, {"vmemld128", Opcode::vmemld128}, {"vmemst128", Opcode::vmemst128},
      {"jmp", Opcode::jmp},           {"jp", Opcode::jp},               {"jnp", Opcode::jnp},
      {"blnk", Opcode::blnk},         {"bret", Opcode::bret},           {"pcall", Opcode::pcall},
      {"pret", Opcode::pret},         {"dadd", Opcode::dadd},           {"dsub", Opcode::dsub},
      {"dmul", Opcode::dmul},         {"ddiv", Opcode::ddiv},           {"dsqrt", Opcode::dsqrt},
      {"i64tof", Opcode::i64tof},     {"f64toi", Opcode::f64toi},       {"dcmp", Opcode::dcmp},
      {"vadd128", Opcode::vadd128},   {"vsub128", Opcode::vsub128},     {"vmul128", Opcode::vmul128},
      {"vxor128", Opcode::vxor128},   {"imemcpy", Opcode::imemcpy},     {"imemset", Opcode::imemset},
      {"istrcmp", Opcode::istrcmp},   {"istrlen", Opcode::istrlen},     {"icas64", Opcode::icas64},
      {"ixchg64", Opcode::ixchg64},   {"ifence", Opcode::ifence},       {"brk", Opcode::brk},
      {"ftrap", Opcode::ftrap},       {"syscall_proxy", Opcode::syscall_proxy},
      {"xcall", Opcode::xcall},       {"xret", Opcode::xret},           {"bridgeargs", Opcode::bridgeargs},
      {"tsload", Opcode::tsload},     {"tsrelease", Opcode::tsrelease}, {"tsread8", Opcode::tsread8},
      {"tswipe", Opcode::tswipe},
  };
  const auto it = map.find(op);
  if (it == map.end()) throw std::runtime_error("vm2 asm: unknown opcode '" + op + "'");
  return it->second;
}

std::uint32_t resolve_target(const std::string& token, const std::unordered_map<std::string, std::uint32_t>& labels) {
  if (!token.empty() && token[0] == '@') {
    const auto name = token.substr(1);
    const auto it = labels.find(name);
    if (it == labels.end()) {
      throw std::runtime_error("vm2 asm: undefined label '" + name + "'");
    }
    return it->second;
  }
  return static_cast<std::uint32_t>(parse_u64_value(token));
}

std::uint64_t parse_u64_or_label(const std::string& token,
                                 const std::unordered_map<std::string, std::uint32_t>& labels) {
  if (!token.empty() && token[0] == '@') {
    return resolve_target(token, labels);
  }
  return parse_u64_value(token);
}

std::uint32_t resolve_const(const std::string& token, const std::unordered_map<std::string, std::uint32_t>& const_labels) {
  auto key = token;
  if (!key.empty() && key[0] == '&') key = key.substr(1);
  const auto it = const_labels.find(key);
  if (it != const_labels.end()) return it->second;
  return static_cast<std::uint32_t>(parse_u64_value(key));
}

std::string make_label(std::uint32_t pc) {
  std::ostringstream oss;
  oss << 'L' << std::hex << std::setw(4) << std::setfill('0') << pc;
  return oss.str();
}

std::string base_name(std::uint8_t base) {
  if (base == static_cast<std::uint8_t>(MemoryBase::sp)) return "sp";
  std::ostringstream oss;
  oss << 'r' << static_cast<unsigned>(base);
  return oss.str();
}

std::string memory_operand_text(std::uint8_t base, std::int32_t offset) {
  std::ostringstream oss;
  oss << '[' << base_name(base);
  if (offset >= 0) {
    oss << '+' << offset;
  } else {
    oss << offset;
  }
  oss << ']';
  return oss.str();
}

ParsedProgram parse_assembly(std::string_view text) {
  ParsedProgram program;
  std::uint32_t pc = 0;
  std::istringstream input{std::string(text)};
  std::string raw_line;
  while (std::getline(input, raw_line)) {
    auto line = trim(strip_comment(raw_line));
    if (line.empty()) continue;
    if (line.back() == ':') {
      program.labels.emplace(line.substr(0, line.size() - 1), pc);
      continue;
    }
    if (line.rfind(".keyctx", 0) == 0) {
      const auto args = split_operands(trim(line.substr(7)));
      if (args.size() != 1) throw std::runtime_error("vm2 asm: .keyctx expects one operand");
      program.key_context_id = parse_keyctx_hex(args[0]);
      continue;
    }
    if (line.rfind(".vconst", 0) == 0) {
      const auto args = split_operands(trim(line.substr(7)));
      if (args.size() != 3) throw std::runtime_error("vm2 asm: .vconst expects name, lo, hi");
      Vm2ConstPoolEntry entry{};
      const auto lo = parse_u64_value(args[1]);
      const auto hi = parse_u64_value(args[2]);
      for (int i = 0; i < 8; ++i) entry.bytes[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>((lo >> (8 * i)) & 0xFFu);
      for (int i = 0; i < 8; ++i) entry.bytes[8 + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>((hi >> (8 * i)) & 0xFFu);
      const auto index = static_cast<std::uint32_t>(program.const_pool.size());
      program.const_labels.emplace(args[0], index);
      program.const_pool.push_back(entry);
      continue;
    }
    std::string op;
    std::string operand_text;
    const auto space = line.find_first_of(" \t");
    if (space == std::string::npos) {
      op = line;
    } else {
      op = line.substr(0, space);
      operand_text = trim(line.substr(space + 1));
    }
    InstructionLine inst{op, split_operands(operand_text), pc};
    pc += instruction_size(inst);
    program.instructions.push_back(std::move(inst));
  }
  return program;
}

}  // namespace

const std::vector<Opcode>& canonical_opcode_sequence() {
  return canonical_opcode_sequence_internal();
}

OpcodeCryptor OpcodeCryptor::identity() {
  OpcodeCryptor cryptor;
  cryptor.canonical_words_.reserve(canonical_opcode_sequence_internal().size());
  cryptor.encoded_words_.reserve(canonical_opcode_sequence_internal().size());
  cryptor.decoded_words_.reserve(canonical_opcode_sequence_internal().size());
  for (const auto opcode : canonical_opcode_sequence_internal()) {
    const auto word = static_cast<std::uint16_t>(opcode);
    cryptor.canonical_index_by_word_[word] = cryptor.canonical_words_.size();
    cryptor.encoded_index_by_word_[word] = cryptor.canonical_words_.size();
    cryptor.canonical_words_.push_back(word);
    cryptor.encoded_words_.push_back(word);
    cryptor.decoded_words_.push_back(word);
  }
  return cryptor;
}

OpcodeCryptor OpcodeCryptor::from_seed(const MasterKey& master_key, const Seed& seed) {
  auto cryptor = OpcodeCryptor::identity();
  std::vector<std::size_t> permutation(cryptor.canonical_words_.size());
  std::iota(permutation.begin(), permutation.end(), 0u);

  auto salt = std::vector<std::uint8_t>(master_key.begin(), master_key.end());
  salt.insert(salt.end(), std::begin(kOpcodeMapPurposeTag), std::end(kOpcodeMapPurposeTag) - 1);
  const auto prk = vmp::runtime::strings::hkdf_extract_sha256(
      salt,
      std::vector<std::uint8_t>(seed.begin(), seed.end()));
  const auto okm = vmp::runtime::strings::hkdf_expand_sha256(prk,
                                                             vmp::runtime::strings::to_bytes(kOpcodeMapPurposeTag),
                                                             vmp::runtime::strings::kChaCha20KeySize);
  vmp::runtime::strings::Nonce nonce{};
  std::vector<std::uint8_t> zeroes(4096, 0);
  const auto keystream = vmp::runtime::strings::chacha20_xor(okm, nonce, 0, zeroes);

  std::size_t offset = 0;
  auto next_u32 = [&]() -> std::uint32_t {
    if (offset + 4 > keystream.size()) {
      throw std::runtime_error("vm2: opcode keystream exhausted");
    }
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
      value |= static_cast<std::uint32_t>(keystream[offset + static_cast<std::size_t>(i)]) << (8 * i);
    }
    offset += 4;
    return value;
  };

  for (std::size_t i = permutation.size(); i > 1; --i) {
    const auto bound = static_cast<std::uint32_t>(i);
    const auto limit = std::numeric_limits<std::uint32_t>::max() -
                       (std::numeric_limits<std::uint32_t>::max() % bound);
    std::uint32_t sample = 0;
    do {
      sample = next_u32();
    } while (sample > limit);
    const auto j = static_cast<std::size_t>(sample % bound);
    std::swap(permutation[i - 1], permutation[j]);
  }

  cryptor.encoded_words_.assign(cryptor.canonical_words_.size(), 0);
  cryptor.decoded_words_.assign(cryptor.canonical_words_.size(), 0);
  cryptor.encoded_index_by_word_.clear();
  for (std::size_t i = 0; i < permutation.size(); ++i) {
    const auto encoded_word = cryptor.canonical_words_[permutation[i]];
    cryptor.encoded_words_[i] = encoded_word;
    cryptor.decoded_words_[permutation[i]] = cryptor.canonical_words_[i];
    cryptor.encoded_index_by_word_[encoded_word] = permutation[i];
  }
  return cryptor;
}

std::uint16_t OpcodeCryptor::encode(Opcode opcode) const {
  const auto word = static_cast<std::uint16_t>(opcode);
  const auto it = canonical_index_by_word_.find(word);
  if (it == canonical_index_by_word_.end()) {
    throw std::runtime_error("invalid_opcode");
  }
  return encoded_words_.at(it->second);
}

Opcode OpcodeCryptor::decode(std::uint16_t on_disk) const {
  const auto it = encoded_index_by_word_.find(on_disk);
  if (it == encoded_index_by_word_.end()) {
    throw std::runtime_error("invalid_opcode");
  }
  return static_cast<Opcode>(decoded_words_.at(it->second));
}

std::uint32_t OpcodeCryptor::sanity_marker_crc32() const {
  ByteVector material;
  material.reserve(4 + encoded_words_.size() * 2);
  append_u32(material, static_cast<std::uint32_t>(encoded_words_.size()));
  for (const auto word : encoded_words_) {
    append_u16(material, word);
  }
  return vmp::runtime::integrity::crc32_compute(material.data(), material.size());
}

Vm2Exception::Vm2Exception(std::uint32_t pc, std::string message) : std::runtime_error(std::move(message)), pc_(pc) {}

Vm2Context::Vm2Context(const Vm2Module& module_in, std::size_t stack_size)
    : pc(module_in.entry_pc), sp(stack_size), module(&module_in), stack_(stack_size, 0) {
  if ((sp & 0xFu) != 0) {
    sp &= ~std::uint64_t(0xFu);
  }
}

std::size_t Vm2Context::stack_size() const noexcept { return stack_.size(); }

void Vm2Context::set_sp(std::uint64_t value) {
  if (value > stack_.size()) throw Vm2StackOverflow(pc, "vm2: sp out of range");
  if ((value & 0xFu) != 0) throw Vm2StackOverflow(pc, "vm2: sp must remain 16-byte aligned");
  sp = value;
}

void Vm2Context::ensure_memory_range(std::uint64_t address, std::size_t width) const {
  if (address > stack_.size() || width > stack_.size() || address + width > stack_.size()) {
    throw Vm2Exception(pc, "vm2: memory access out of bounds");
  }
}

Vec128 Vm2Context::read_vec128(std::uint64_t address) const {
  Vec128 value{};
  value.u64.lo = read_memory<std::uint64_t>(address);
  value.u64.hi = read_memory<std::uint64_t>(address + 8);
  return value;
}

void Vm2Context::write_vec128(std::uint64_t address, const Vec128& value) {
  write_memory<std::uint64_t>(address, value.u64.lo);
  write_memory<std::uint64_t>(address + 8, value.u64.hi);
}

std::uint64_t Vm2Context::allocate_spill(std::size_t bytes, const char* reason) {
  const auto aligned = (bytes + 15u) & ~std::size_t(15u);
  if (aligned > sp) {
    throw Vm2StackOverflow(pc, std::string("vm2: stack overflow during ") + reason);
  }
  sp -= static_cast<std::uint64_t>(aligned);
  return sp;
}

std::array<std::uint8_t, kVm2KeyContextIdSize> Vm2Context::current_key_context_id() const {
  std::array<std::uint8_t, kVm2KeyContextIdSize> out{};
  if (!key_context) return out;
  auto subkey = key_context->derive_subkey("vm2-key-context-id");
  std::vector<std::uint8_t> material(subkey.bytes().begin(), subkey.bytes().end());
  const auto digest = vmp::runtime::strings::sha256(material);
  std::copy_n(digest.begin(), out.size(), out.begin());
  return out;
}

std::uint64_t Vm2Context::materialize_transient_string(std::uint32_t id) {
  if (!string_pool) {
    throw Vm2Exception(pc, "vm2: string pool not configured");
  }
  if (module != nullptr) {
    const auto actual = current_key_context_id();
    if (module->key_context_id != std::array<std::uint8_t, kVm2KeyContextIdSize>{} && actual != module->key_context_id) {
      if (audit_dispatcher != nullptr) {
        audit_dispatcher->dispatch(vmp::runtime::audit::make_event("string_pool_error", "vm2 key context mismatch", pc, "vm2"),
                                   vmp::runtime::audit::ReactionPolicy::audit_only);
      }
      throw Vm2Exception(pc, "vm2: key context mismatch");
    }
  }
  string_pool->set_audit_dispatcher(audit_dispatcher);
  auto view = string_pool->decrypt(id);
  const auto handle = next_transient_handle_++;
  transient_strings_[handle] = std::make_unique<vmp::runtime::strings::TransientView>(std::move(view));
  register_transient_handle(handle);
  return handle;
}

void Vm2Context::release_transient_string(std::uint64_t handle) {
  const auto it = transient_strings_.find(handle);
  if (it == transient_strings_.end()) {
    throw Vm2Exception(pc, "vm2: transient string handle not found");
  }
  remove_transient_handle_owner(handle);
  transient_strings_.erase(it);
}

std::string Vm2Context::transient_string(std::uint64_t handle) const {
  const auto it = transient_strings_.find(handle);
  if (it == transient_strings_.end() || it->second == nullptr) {
    throw Vm2Exception(pc, "vm2: transient string handle not found");
  }
  return std::string(it->second->view());
}

std::size_t Vm2Context::active_transient_strings() const noexcept { return transient_strings_.size(); }

void Vm2Context::register_transient_handle(std::uint64_t handle) {
  if (frames_.empty()) {
    root_transient_handles_.push_back(handle);
  } else {
    frames_.back().transient_handles.push_back(handle);
  }
}

void Vm2Context::remove_transient_handle_owner(std::uint64_t handle) {
  auto erase_from = [handle](std::vector<std::uint64_t>& handles) {
    handles.erase(std::remove(handles.begin(), handles.end(), handle), handles.end());
  };
  erase_from(root_transient_handles_);
  for (auto& frame : frames_) erase_from(frame.transient_handles);
}

void Vm2Context::clear_frame_transient_strings() {
  std::vector<std::uint64_t> handles;
  if (frames_.empty()) {
    handles.swap(root_transient_handles_);
  } else {
    handles.swap(frames_.back().transient_handles);
  }
  for (const auto handle : handles) transient_strings_.erase(handle);
}

void Vm2Context::clear_all_transient_strings() noexcept {
  transient_strings_.clear();
  root_transient_handles_.clear();
  for (auto& frame : frames_) frame.transient_handles.clear();
}

Vm2Module Vm2Module::load_from_file(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("vm2: failed to open module '" + path + "'");
  std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  return load_from_bytes(bytes);
}

Vm2Module Vm2Module::load_from_bytes(const std::vector<std::uint8_t>& bytes) {
  if (bytes.size() < kVm2LegacyHeaderSize + kVm2KeyContextIdSize) throw std::runtime_error("vm2: module too small");
  Vm2Module module;
  if (!std::equal(kVm2Magic.begin(), kVm2Magic.end(), bytes.begin())) throw std::runtime_error("vm2: bad magic");
  std::size_t offset = 4;
  module.version = read_u16(bytes, offset);
  const auto header_size = vm2_header_size_for_version(module.version);
  if (bytes.size() < header_size + kVm2KeyContextIdSize) throw std::runtime_error("vm2: module too small");
  module.module_flags = read_u16(bytes, offset);
  module.entry_pc = read_u32(bytes, offset);
  const auto code_size = read_u32(bytes, offset);
  const auto const_pool_size = read_u32(bytes, offset);
  module.crc32 = read_u32(bytes, offset);
  if (module.version == kVm2Version) {
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                kOpcodeMapSeedSize,
                module.opcode_map_seed.begin());
    offset += kOpcodeMapSeedSize;
  }
  if ((const_pool_size % 16u) != 0) throw std::runtime_error("vm2: const pool must be 16-byte aligned");
  const auto reverse_layout = (module.module_flags & VMP_FLAG_REVERSE_ORDER) != 0u;
  if (bytes.size() < header_size + code_size + const_pool_size + kVm2KeyContextIdSize) {
    throw std::runtime_error("vm2: truncated const pool");
  }
  const auto reverse_table_bytes = reverse_layout
                                       ? bytes.size() - header_size - code_size - const_pool_size - kVm2KeyContextIdSize
                                       : std::size_t{0};
  if (offset + code_size + reverse_table_bytes + const_pool_size + kVm2KeyContextIdSize > bytes.size()) {
    throw std::runtime_error("vm2: truncated const pool");
  }
  if ((reverse_table_bytes % sizeof(std::uint16_t)) != 0u) {
    throw std::runtime_error("vm2: reverse length table must be uint16 aligned");
  }
  const auto actual_crc32 = vmp::runtime::integrity::crc32_compute(bytes.data() + header_size,
                                                                   code_size + reverse_table_bytes + const_pool_size);
  if (actual_crc32 != module.crc32) {
    append_module_crc_mismatch_audit("expected=" + hex_u32(module.crc32) + " actual=" + hex_u32(actual_crc32));
    throw std::runtime_error("vm2: crc32 mismatch");
  }
  ByteVector serialized_code(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                             bytes.begin() + static_cast<std::ptrdiff_t>(offset + code_size));
  offset += code_size;
  std::vector<std::uint16_t> reverse_lengths;
  if (reverse_layout) {
    std::size_t table_cursor = offset;
    const auto reverse_count = reverse_table_bytes / sizeof(std::uint16_t);
    reverse_lengths.reserve(reverse_count);
    for (std::size_t i = 0; i < reverse_count; ++i) {
      reverse_lengths.push_back(read_u16(bytes, table_cursor));
    }
    offset = table_cursor;
    vmp::runtime::detail::audit_reverse_layout_active_once("vm2");
  }
  bool saw_opcode_marker = false;
  const auto const_slots = const_pool_size / 16u;
  for (std::size_t i = 0; i < const_slots; ++i) {
    Vm2ConstPoolEntry entry{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset + i * 16u), 16, entry.bytes.begin());
    std::uint32_t marker_crc32 = 0;
    if ((module.module_flags & VMP_FLAG_OPCODE_ENCRYPTED) != 0) {
      if (parse_opcode_marker_entry(entry, marker_crc32)) {
        if (saw_opcode_marker) {
          append_opcode_map_invalid_audit("vm2 duplicate opcode-map marker");
          throw std::runtime_error("vm2: duplicate opcode-map marker");
        }
        module.opcode_map_marker_crc32 = marker_crc32;
        saw_opcode_marker = true;
        continue;
      }
    }
    module.const_pool.push_back(entry);
  }
  offset += const_pool_size;
  std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), kVm2KeyContextIdSize, module.key_context_id.begin());
  if ((module.module_flags & VMP_FLAG_OPCODE_ENCRYPTED) != 0) {
    if (!saw_opcode_marker) {
      append_opcode_map_invalid_audit("vm2 missing opcode-map marker");
      throw std::runtime_error("vm2: missing opcode-map marker");
    }
    const auto cryptor = opcode_cryptor_for_module(module);
    const auto expected_marker = cryptor.sanity_marker_crc32();
    if (expected_marker != module.opcode_map_marker_crc32) {
      append_opcode_map_invalid_audit("vm2 marker mismatch expected=" + hex_u32(expected_marker) +
                                      " actual=" + hex_u32(module.opcode_map_marker_crc32));
      throw std::runtime_error("vm2: opcode map invalid");
    }
    if (reverse_layout) {
      module.code = materialize_forward_code_from_reverse_storage(serialized_code, reverse_lengths, &cryptor);
    } else {
      module.code = decode_code_stream(serialized_code, cryptor);
    }
  } else {
    if (reverse_layout) {
      module.code = materialize_forward_code_from_reverse_storage(serialized_code, reverse_lengths, nullptr);
    } else {
      module.code = std::move(serialized_code);
    }
  }
  if (module.entry_pc > module.code.size()) throw std::runtime_error("vm2: entry_pc out of range");
  module.runtime_id = g_next_vm2_module_id.fetch_add(1);
  if (reverse_layout) {
    populate_reverse_layout_cache(module, reverse_lengths);
  } else {
    clear_reverse_layout_cache(module);
  }
  module.function_entries = collect_function_entries(module.code, module.entry_pc);
  return module;
}

std::vector<std::uint8_t> Vm2Module::serialize() const {
  const bool encrypt_opcodes = (module_flags & VMP_FLAG_OPCODE_ENCRYPTED) != 0;
  const bool reverse_layout = (module_flags & VMP_FLAG_REVERSE_ORDER) != 0;
  const auto write_version = module_version_for_serialize(*this);
  const auto cryptor = encrypt_opcodes ? opcode_cryptor_for_module(*this) : OpcodeCryptor::identity();
  const auto encoded_forward_code = encrypt_opcodes ? encode_code_stream(code, cryptor) : code;
  const auto lengths = reverse_layout ? derive_instruction_lengths_from_code(code) : std::vector<std::uint16_t>{};
  const auto encoded_code = reverse_layout ? reverse_instruction_storage(encoded_forward_code, lengths) : encoded_forward_code;
  const auto marker_entry = encrypt_opcodes ? std::optional<Vm2ConstPoolEntry>(make_opcode_marker_entry(cryptor.sanity_marker_crc32()))
                                            : std::nullopt;
  const auto length_table = reverse_layout ? serialize_length_table(lengths) : ByteVector{};
  std::vector<std::uint8_t> body;
  body.reserve(encoded_code.size() + length_table.size() + (const_pool.size() + (marker_entry.has_value() ? 1u : 0u)) * 16u);
  body.insert(body.end(), encoded_code.begin(), encoded_code.end());
  body.insert(body.end(), length_table.begin(), length_table.end());
  for (const auto& entry : const_pool) body.insert(body.end(), entry.bytes.begin(), entry.bytes.end());
  if (marker_entry.has_value()) body.insert(body.end(), marker_entry->bytes.begin(), marker_entry->bytes.end());
  std::vector<std::uint8_t> out;
  const auto header_size = write_version == kVm2Version ? kVm2HeaderSize : kVm2LegacyHeaderSize;
  out.reserve(header_size + body.size() + key_context_id.size());
  out.insert(out.end(), kVm2Magic.begin(), kVm2Magic.end());
  append_u16(out, write_version);
  append_u16(out, module_flags);
  append_u32(out, entry_pc);
  append_u32(out, static_cast<std::uint32_t>(encoded_code.size()));
  append_u32(out, static_cast<std::uint32_t>((const_pool.size() + (marker_entry.has_value() ? 1u : 0u)) * 16u));
  append_u32(out, vmp::runtime::integrity::crc32_compute(body.data(), body.size()));
  if (write_version == kVm2Version) {
    out.insert(out.end(), opcode_map_seed.begin(), opcode_map_seed.end());
  }
  out.insert(out.end(), body.begin(), body.end());
  out.insert(out.end(), key_context_id.begin(), key_context_id.end());
  return out;
}

void Vm2Module::save_to_file(const std::string& path) const {
  const auto bytes = serialize();
  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream output(path, std::ios::binary);
  if (!output) throw std::runtime_error("vm2: failed to create module '" + path + "'");
  output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

Vm2Module assemble_module_text(std::string_view text, std::uint16_t module_flags) {
  AssembleOptions options;
  options.module_flags = static_cast<std::uint16_t>(module_flags & ~VMP_FLAG_OPCODE_ENCRYPTED);
  options.encrypt_opcodes = false;
  auto module = assemble_module_text(text, options);
  module.version = kVm2LegacyVersion;
  return module;
}

Vm2Module assemble_module_text(std::string_view text, const AssembleOptions& options) {
  const auto program = parse_assembly(text);
  Vm2Module module;
  module.version = options.encrypt_opcodes ? kVm2Version : kVm2LegacyVersion;
  module.module_flags = static_cast<std::uint16_t>(options.module_flags & ~VMP_FLAG_OPCODE_ENCRYPTED);
  if (options.encrypt_opcodes) {
    module.module_flags = static_cast<std::uint16_t>(module.module_flags | VMP_FLAG_OPCODE_ENCRYPTED);
    module.opcode_map_seed = options.opcode_seed.value_or(random_opcode_seed());
  }
  module.const_pool = program.const_pool;
  module.key_context_id = program.key_context_id;
  for (const auto& inst : program.instructions) {
    const auto opcode = parse_opcode(inst.op);
    append_u16(module.code, static_cast<std::uint16_t>(opcode));
    switch (opcode) {
      case Opcode::nop:
      case Opcode::brk:
      case Opcode::bret:
      case Opcode::pret:
      case Opcode::xret:
      case Opcode::ifence:
        break;
      case Opcode::ftrap:
      case Opcode::syscall_proxy:
        append_u32(module.code, static_cast<std::uint32_t>(parse_u64_value(inst.operands.at(0))));
        break;
      case Opcode::ildimm:
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        append_u64(module.code, parse_u64_or_label(inst.operands.at(1), program.labels));
        break;
      case Opcode::dldimm:
        module.code.push_back(parse_float_register(inst.operands.at(0)));
        append_u64(module.code, bit_cast_u64(parse_double_value(inst.operands.at(1))));
        break;
      case Opcode::vldimm:
        module.code.push_back(parse_vector_register(inst.operands.at(0)));
        append_u32(module.code, resolve_const(inst.operands.at(1), program.const_labels));
        break;
      case Opcode::imov:
      case Opcode::ineg:
      case Opcode::inot:
      case Opcode::ipopcnt:
      case Opcode::iclz:
      case Opcode::ictz:
      case Opcode::ibswap:
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        break;
      case Opcode::dmov:
      case Opcode::dsqrt:
        module.code.push_back(parse_float_register(inst.operands.at(0)));
        module.code.push_back(parse_float_register(inst.operands.at(1)));
        break;
      case Opcode::i64tof:
        module.code.push_back(parse_float_register(inst.operands.at(0)));
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        break;
      case Opcode::f64toi:
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_float_register(inst.operands.at(1)));
        break;
      case Opcode::isetcc:
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_predicate(inst.operands.at(1)));
        break;
      case Opcode::tsrelease:
      case Opcode::tswipe:
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        break;
      case Opcode::iadd:
      case Opcode::isub:
      case Opcode::imul:
      case Opcode::idiv:
      case Opcode::imod:
      case Opcode::iand:
      case Opcode::ior:
      case Opcode::ixor:
      case Opcode::ishl:
      case Opcode::ishr:
      case Opcode::isar:
      case Opcode::imemcpy:
      case Opcode::imemset:
      case Opcode::istrcmp:
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        module.code.push_back(parse_general_register(inst.operands.at(2)));
        break;
      case Opcode::icmp:
      case Opcode::itest:
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        break;
      case Opcode::istrlen:
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        break;
      case Opcode::dadd:
      case Opcode::dsub:
      case Opcode::dmul:
      case Opcode::ddiv:
        module.code.push_back(parse_float_register(inst.operands.at(0)));
        module.code.push_back(parse_float_register(inst.operands.at(1)));
        module.code.push_back(parse_float_register(inst.operands.at(2)));
        break;
      case Opcode::dcmp:
        module.code.push_back(parse_float_register(inst.operands.at(0)));
        module.code.push_back(parse_float_register(inst.operands.at(1)));
        break;
      case Opcode::vadd128:
      case Opcode::vsub128:
      case Opcode::vmul128:
      case Opcode::vxor128:
        module.code.push_back(parse_vector_register(inst.operands.at(0)));
        module.code.push_back(parse_vector_register(inst.operands.at(1)));
        module.code.push_back(parse_vector_register(inst.operands.at(2)));
        break;
      case Opcode::imemld8:
      case Opcode::imemld16:
      case Opcode::imemld32:
      case Opcode::imemld64: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        const auto mem = parse_memory_operand(inst.operands.at(1));
        module.code.push_back(mem.base);
        append_i32(module.code, mem.offset);
        break;
      }
      case Opcode::imemst8:
      case Opcode::imemst16:
      case Opcode::imemst32:
      case Opcode::imemst64: {
        const auto mem = parse_memory_operand(inst.operands.at(0));
        module.code.push_back(mem.base);
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        append_i32(module.code, mem.offset);
        break;
      }
      case Opcode::vmemld128: {
        module.code.push_back(parse_vector_register(inst.operands.at(0)));
        const auto mem = parse_memory_operand(inst.operands.at(1));
        module.code.push_back(mem.base);
        append_i32(module.code, mem.offset);
        break;
      }
      case Opcode::vmemst128: {
        const auto mem = parse_memory_operand(inst.operands.at(0));
        module.code.push_back(mem.base);
        module.code.push_back(parse_vector_register(inst.operands.at(1)));
        append_i32(module.code, mem.offset);
        break;
      }
      case Opcode::jmp:
        append_u32(module.code, resolve_target(inst.operands.at(0), program.labels));
        break;
      case Opcode::jp:
      case Opcode::jnp:
        module.code.push_back(parse_predicate(inst.operands.at(0)));
        append_u32(module.code, resolve_target(inst.operands.at(1), program.labels));
        break;
      case Opcode::blnk:
        append_u32(module.code, resolve_target(inst.operands.at(0), program.labels));
        module.code.push_back(static_cast<std::uint8_t>(inst.operands.size() > 1 ? parse_u64_value(inst.operands.at(1)) : 0u));
        break;
      case Opcode::pcall:
        module.code.push_back(parse_predicate(inst.operands.at(0)));
        append_u32(module.code, resolve_target(inst.operands.at(1), program.labels));
        module.code.push_back(static_cast<std::uint8_t>(inst.operands.size() > 2 ? parse_u64_value(inst.operands.at(2)) : 0u));
        break;
      case Opcode::xcall:
        module.code.push_back(parse_domain_token(inst.operands.at(0)));
        append_u32(module.code, static_cast<std::uint32_t>(parse_u64_value(inst.operands.at(1))));
        module.code.push_back(static_cast<std::uint8_t>(parse_u64_value(inst.operands.at(2))));
        module.code.push_back(static_cast<std::uint8_t>(inst.operands.size() > 3 ? parse_u64_value(inst.operands.at(3)) : 0u));
        module.code.push_back(static_cast<std::uint8_t>(inst.operands.size() > 4 ? parse_u64_value(inst.operands.at(4)) : 0u));
        break;
      case Opcode::bridgeargs:
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        module.code.push_back(static_cast<std::uint8_t>(parse_u64_value(inst.operands.at(2))));
        break;
      case Opcode::icas64: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        const auto mem = parse_memory_operand(inst.operands.at(1));
        module.code.push_back(mem.base);
        module.code.push_back(parse_general_register(inst.operands.at(2)));
        module.code.push_back(parse_general_register(inst.operands.at(3)));
        append_i32(module.code, mem.offset);
        break;
      }
      case Opcode::ixchg64: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        const auto mem = parse_memory_operand(inst.operands.at(1));
        module.code.push_back(mem.base);
        module.code.push_back(parse_general_register(inst.operands.at(2)));
        append_i32(module.code, mem.offset);
        break;
      }
      case Opcode::tsload:
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        append_u32(module.code, static_cast<std::uint32_t>(parse_u64_value(inst.operands.at(1))));
        break;
      case Opcode::tsread8:
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        module.code.push_back(parse_general_register(inst.operands.at(2)));
        break;
    }
  }
  if (auto it = program.labels.find("entry"); it != program.labels.end()) {
    module.entry_pc = it->second;
  } else {
    module.entry_pc = 0;
  }
  module.runtime_id = g_next_vm2_module_id.fetch_add(1);
  module.function_entries = collect_function_entries(module.code, module.entry_pc);
  if ((module.module_flags & VMP_FLAG_OPCODE_ENCRYPTED) != 0) {
    module.opcode_map_marker_crc32 = opcode_cryptor_for_module(module).sanity_marker_crc32();
  }
  if ((module.module_flags & VMP_FLAG_REVERSE_ORDER) != 0u) {
    populate_reverse_layout_cache(module, derive_instruction_lengths_from_code(module.code));
  } else {
    clear_reverse_layout_cache(module);
  }
  return module;
}

std::vector<std::uint16_t> instruction_lengths(const Vm2Module& module) {
  return derive_instruction_lengths_from_code(module.code);
}

std::string opcode_name(Opcode opcode) {
  switch (opcode) {
    case Opcode::nop: return "nop";
    case Opcode::ildimm: return "ildimm";
    case Opcode::vldimm: return "vldimm";
    case Opcode::imov: return "imov";
    case Opcode::dldimm: return "dldimm";
    case Opcode::dmov: return "dmov";
    case Opcode::iadd: return "iadd";
    case Opcode::isub: return "isub";
    case Opcode::imul: return "imul";
    case Opcode::idiv: return "idiv";
    case Opcode::imod: return "imod";
    case Opcode::ineg: return "ineg";
    case Opcode::iand: return "iand";
    case Opcode::ior: return "ior";
    case Opcode::ixor: return "ixor";
    case Opcode::ishl: return "ishl";
    case Opcode::ishr: return "ishr";
    case Opcode::isar: return "isar";
    case Opcode::inot: return "inot";
    case Opcode::ipopcnt: return "ipopcnt";
    case Opcode::iclz: return "iclz";
    case Opcode::ictz: return "ictz";
    case Opcode::ibswap: return "ibswap";
    case Opcode::icmp: return "icmp";
    case Opcode::itest: return "itest";
    case Opcode::isetcc: return "isetcc";
    case Opcode::imemld8: return "imemld8";
    case Opcode::imemld16: return "imemld16";
    case Opcode::imemld32: return "imemld32";
    case Opcode::imemld64: return "imemld64";
    case Opcode::imemst8: return "imemst8";
    case Opcode::imemst16: return "imemst16";
    case Opcode::imemst32: return "imemst32";
    case Opcode::imemst64: return "imemst64";
    case Opcode::vmemld128: return "vmemld128";
    case Opcode::vmemst128: return "vmemst128";
    case Opcode::jmp: return "jmp";
    case Opcode::jp: return "jp";
    case Opcode::jnp: return "jnp";
    case Opcode::blnk: return "blnk";
    case Opcode::bret: return "bret";
    case Opcode::pcall: return "pcall";
    case Opcode::pret: return "pret";
    case Opcode::dadd: return "dadd";
    case Opcode::dsub: return "dsub";
    case Opcode::dmul: return "dmul";
    case Opcode::ddiv: return "ddiv";
    case Opcode::dsqrt: return "dsqrt";
    case Opcode::i64tof: return "i64tof";
    case Opcode::f64toi: return "f64toi";
    case Opcode::dcmp: return "dcmp";
    case Opcode::vadd128: return "vadd128";
    case Opcode::vsub128: return "vsub128";
    case Opcode::vmul128: return "vmul128";
    case Opcode::vxor128: return "vxor128";
    case Opcode::imemcpy: return "imemcpy";
    case Opcode::imemset: return "imemset";
    case Opcode::istrcmp: return "istrcmp";
    case Opcode::istrlen: return "istrlen";
    case Opcode::icas64: return "icas64";
    case Opcode::ixchg64: return "ixchg64";
    case Opcode::ifence: return "ifence";
    case Opcode::brk: return "brk";
    case Opcode::ftrap: return "ftrap";
    case Opcode::syscall_proxy: return "syscall_proxy";
    case Opcode::xcall: return "xcall";
    case Opcode::xret: return "xret";
    case Opcode::bridgeargs: return "bridgeargs";
    case Opcode::tsload: return "tsload";
    case Opcode::tsrelease: return "tsrelease";
    case Opcode::tsread8: return "tsread8";
    case Opcode::tswipe: return "tswipe";
  }
  return "unknown";
}

std::string disassemble_module(const Vm2Module& module) {
  std::ostringstream out;
  if (module.key_context_id != std::array<std::uint8_t, kVm2KeyContextIdSize>{}) {
    out << ".keyctx 0x";
    for (const auto byte : module.key_context_id) {
      out << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
    }
    out << std::dec << "\n";
  }
  for (std::size_t i = 0; i < module.const_pool.size(); ++i) {
    std::uint64_t lo = 0;
    std::uint64_t hi = 0;
    for (int j = 0; j < 8; ++j) lo |= static_cast<std::uint64_t>(module.const_pool[i].bytes[static_cast<std::size_t>(j)]) << (8 * j);
    for (int j = 0; j < 8; ++j) hi |= static_cast<std::uint64_t>(module.const_pool[i].bytes[8 + static_cast<std::size_t>(j)]) << (8 * j);
    out << ".vconst c" << i << ", 0x" << std::hex << lo << ", 0x" << hi << std::dec << "\n";
  }

  std::map<std::uint32_t, std::string> labels;

  for (std::size_t pc = 0; pc < module.code.size();) {
    const auto start = static_cast<std::uint32_t>(pc);
    const auto label_it = labels.find(start);
    if (label_it != labels.end()) out << label_it->second << ":\n";
    const auto opcode = static_cast<Opcode>(read_u16(module.code, pc));
    out << "  " << opcode_name(opcode);
    switch (opcode) {
      case Opcode::nop:
      case Opcode::brk:
      case Opcode::bret:
      case Opcode::pret:
      case Opcode::xret:
      case Opcode::ifence:
        break;
      case Opcode::ftrap:
      case Opcode::syscall_proxy:
        out << ' ' << read_u32(module.code, pc);
        break;
      case Opcode::ildimm:
        out << " r" << static_cast<unsigned>(module.code.at(pc++)) << ", "
            << static_cast<std::int64_t>(read_u64(module.code, pc));
        break;
      case Opcode::dldimm:
        out << " d" << static_cast<unsigned>(module.code.at(pc++)) << ", " << bit_cast_double(read_u64(module.code, pc));
        break;
      case Opcode::vldimm:
        out << " q" << static_cast<unsigned>(module.code.at(pc++)) << ", c" << read_u32(module.code, pc);
        break;
      case Opcode::imov:
      case Opcode::ineg:
      case Opcode::inot:
      case Opcode::ipopcnt:
      case Opcode::iclz:
      case Opcode::ictz:
      case Opcode::ibswap:
        out << " r" << static_cast<unsigned>(module.code.at(pc++)) << ", r" << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::dmov:
      case Opcode::dsqrt:
        out << " d" << static_cast<unsigned>(module.code.at(pc++)) << ", d" << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::i64tof:
        out << " d" << static_cast<unsigned>(module.code.at(pc++)) << ", r" << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::f64toi:
        out << " r" << static_cast<unsigned>(module.code.at(pc++)) << ", d" << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::isetcc:
        out << " r" << static_cast<unsigned>(module.code.at(pc++)) << ", p" << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::tsrelease:
      case Opcode::tswipe:
        out << " r" << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::iadd:
      case Opcode::isub:
      case Opcode::imul:
      case Opcode::idiv:
      case Opcode::imod:
      case Opcode::iand:
      case Opcode::ior:
      case Opcode::ixor:
      case Opcode::ishl:
      case Opcode::ishr:
      case Opcode::isar:
      case Opcode::imemcpy:
      case Opcode::imemset:
      case Opcode::istrcmp:
        out << " r" << static_cast<unsigned>(module.code.at(pc++)) << ", r" << static_cast<unsigned>(module.code.at(pc++))
            << ", r" << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::icmp:
      case Opcode::itest:
        out << " r" << static_cast<unsigned>(module.code.at(pc++)) << ", r" << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::istrlen:
        out << " r" << static_cast<unsigned>(module.code.at(pc++)) << ", r" << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::dadd:
      case Opcode::dsub:
      case Opcode::dmul:
      case Opcode::ddiv:
        out << " d" << static_cast<unsigned>(module.code.at(pc++)) << ", d" << static_cast<unsigned>(module.code.at(pc++))
            << ", d" << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::dcmp:
        out << " d" << static_cast<unsigned>(module.code.at(pc++)) << ", d" << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::vadd128:
      case Opcode::vsub128:
      case Opcode::vmul128:
      case Opcode::vxor128:
        out << " q" << static_cast<unsigned>(module.code.at(pc++)) << ", q" << static_cast<unsigned>(module.code.at(pc++))
            << ", q" << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::imemld8:
      case Opcode::imemld16:
      case Opcode::imemld32:
      case Opcode::imemld64: {
        const auto dst = module.code.at(pc++);
        const auto base = module.code.at(pc++);
        const auto offset = read_i32(module.code, pc);
        out << " r" << static_cast<unsigned>(dst) << ", " << memory_operand_text(base, offset);
        break;
      }
      case Opcode::imemst8:
      case Opcode::imemst16:
      case Opcode::imemst32:
      case Opcode::imemst64: {
        const auto base = module.code.at(pc++);
        const auto src = module.code.at(pc++);
        const auto offset = read_i32(module.code, pc);
        out << ' ' << memory_operand_text(base, offset) << ", r" << static_cast<unsigned>(src);
        break;
      }
      case Opcode::vmemld128: {
        const auto dst = module.code.at(pc++);
        const auto base = module.code.at(pc++);
        const auto offset = read_i32(module.code, pc);
        out << " q" << static_cast<unsigned>(dst) << ", " << memory_operand_text(base, offset);
        break;
      }
      case Opcode::vmemst128: {
        const auto base = module.code.at(pc++);
        const auto src = module.code.at(pc++);
        const auto offset = read_i32(module.code, pc);
        out << ' ' << memory_operand_text(base, offset) << ", q" << static_cast<unsigned>(src);
        break;
      }
      case Opcode::jmp:
        out << ' ' << read_u32(module.code, pc);
        break;
      case Opcode::jp:
      case Opcode::jnp:
        out << " p" << static_cast<unsigned>(module.code.at(pc++)) << ", " << read_u32(module.code, pc);
        break;
      case Opcode::blnk:
        out << ' ' << read_u32(module.code, pc) << ", " << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::pcall:
        out << " p" << static_cast<unsigned>(module.code.at(pc++)) << ", " << read_u32(module.code, pc)
            << ", " << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::xcall:
        out << ' ' << static_cast<unsigned>(module.code.at(pc++)) << ", " << read_u32(module.code, pc)
            << ", " << static_cast<unsigned>(module.code.at(pc++))
            << ", " << static_cast<unsigned>(module.code.at(pc++))
            << ", " << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::bridgeargs:
        out << " r" << static_cast<unsigned>(module.code.at(pc++)) << ", r" << static_cast<unsigned>(module.code.at(pc++))
            << ", " << static_cast<unsigned>(module.code.at(pc++));
        break;
      case Opcode::icas64: {
        const auto dst = module.code.at(pc++);
        const auto base = module.code.at(pc++);
        const auto expected = module.code.at(pc++);
        const auto desired = module.code.at(pc++);
        const auto offset = read_i32(module.code, pc);
        out << " r" << static_cast<unsigned>(dst) << ", " << memory_operand_text(base, offset)
            << ", r" << static_cast<unsigned>(expected) << ", r" << static_cast<unsigned>(desired);
        break;
      }
      case Opcode::ixchg64: {
        const auto dst = module.code.at(pc++);
        const auto base = module.code.at(pc++);
        const auto src = module.code.at(pc++);
        const auto offset = read_i32(module.code, pc);
        out << " r" << static_cast<unsigned>(dst) << ", " << memory_operand_text(base, offset)
            << ", r" << static_cast<unsigned>(src);
        break;
      }
      case Opcode::tsload:
        out << " r" << static_cast<unsigned>(module.code.at(pc++)) << ", " << read_u32(module.code, pc);
        break;
      case Opcode::tsread8:
        out << " r" << static_cast<unsigned>(module.code.at(pc++)) << ", r" << static_cast<unsigned>(module.code.at(pc++))
            << ", r" << static_cast<unsigned>(module.code.at(pc++));
        break;
    }
    out << "\n";
  }
  return out.str();
}

const void* handler_table_identity() noexcept { return &kVm2HandlerTableIdentity; }

const char* Facade::status() const noexcept { return "vm2_ready"; }

}  // namespace vmp::runtime::vm2
