#include <vmp/runtime/vm1/vm1.h>

#include <vmp/arch/common/label_resolver.h>
#include <vmp/runtime/integrity/crc32.h>
#include <vmp/runtime/strings/cipher.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace vmp::runtime::vm1 {
namespace {

using ByteVector = std::vector<std::uint8_t>;
namespace common = vmp::arch::common;
std::atomic<std::uint64_t> g_next_vm1_module_id{1};

void append_u16(ByteVector& out, std::uint16_t value);
std::uint16_t read_u16(const ByteVector& bytes, std::size_t& offset);
void append_u32(ByteVector& out, std::uint32_t value);
std::uint32_t read_u32(const ByteVector& bytes, std::size_t& offset);
std::size_t instruction_size(Opcode opcode);

constexpr std::size_t kVm1LegacyHeaderSize = 4u + 2u + 2u + 4u + 4u + 4u + 4u;
constexpr std::size_t kVm1HeaderSize = kVm1LegacyHeaderSize + kOpcodeMapSeedSize;
constexpr char kOpcodeMapPurposeTag[] = "opcode_map_v1";
const OpcodeCryptor::MasterKey kVm1OpcodeMapMasterKey{};

std::string hex_u32(std::uint32_t value) {
  std::ostringstream oss;
  oss << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << value;
  return oss.str();
}

void append_module_crc_mismatch_audit(const std::string& note) noexcept {
  try {
    vmp::runtime::audit::AuditWriter writer(vmp::runtime::audit::AuditWriter::default_path());
    writer.append(vmp::runtime::audit::make_event("vm1_module_crc_mismatch", note, 0, "vm1"));
    writer.flush();
  } catch (...) {
  }
}

void append_opcode_map_invalid_audit(const std::string& note) noexcept {
  try {
    vmp::runtime::audit::AuditWriter writer(vmp::runtime::audit::AuditWriter::default_path());
    writer.append(vmp::runtime::audit::make_event("opcode_map_invalid", note, 0, "vm1"));
    writer.flush();
  } catch (...) {
  }
}

std::size_t vm1_header_size_for_version(std::uint16_t version) {
  if (version == kVm1LegacyVersion) return kVm1LegacyHeaderSize;
  if (version == kVm1Version) return kVm1HeaderSize;
  throw std::runtime_error("vm1: unsupported version");
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

ByteVector serialize_const_pool_section(const std::vector<ConstPoolEntry>& const_pool,
                                        std::optional<std::uint32_t> opcode_map_marker_crc32 = std::nullopt) {
  ByteVector out;
  for (const auto& entry : const_pool) {
    out.push_back(static_cast<std::uint8_t>(entry.kind));
    append_u32(out, static_cast<std::uint32_t>(entry.bytes.size()));
    out.insert(out.end(), entry.bytes.begin(), entry.bytes.end());
  }
  if (opcode_map_marker_crc32.has_value()) {
    out.push_back(static_cast<std::uint8_t>(ConstKind::opcode_map_marker));
    append_u32(out, 4u);
    append_u32(out, *opcode_map_marker_crc32);
  }
  return out;
}

std::size_t vm1_body_end_offset(const ByteVector& bytes,
                                std::size_t header_size,
                                std::size_t code_size,
                                std::uint32_t const_count) {
  if (bytes.size() < header_size) {
    throw std::runtime_error("vm1: module too small");
  }
  std::size_t offset = header_size;
  if (offset + code_size > bytes.size()) {
    throw std::runtime_error("vm1: truncated code");
  }
  offset += code_size;
  for (std::uint32_t i = 0; i < const_count; ++i) {
    if (offset >= bytes.size()) {
      throw std::runtime_error("vm1: truncated const kind");
    }
    ++offset;
    std::size_t payload_offset = offset;
    const auto payload_size = read_u32(bytes, payload_offset);
    if (payload_offset + payload_size > bytes.size()) {
      throw std::runtime_error("vm1: truncated const payload");
    }
    offset = payload_offset + payload_size;
  }
  return offset;
}

std::uint32_t vm1_body_crc32(const ByteVector& bytes,
                             std::size_t header_size,
                             std::size_t code_size,
                             std::uint32_t const_count) {
  const auto body_end = vm1_body_end_offset(bytes, header_size, code_size, const_count);
  return vmp::runtime::integrity::crc32_compute(bytes.data() + header_size,
                                                body_end - header_size);
}

OpcodeCryptor opcode_cryptor_for_seed(const std::array<std::uint8_t, kOpcodeMapSeedSize>& seed) {
  return OpcodeCryptor::from_seed(kVm1OpcodeMapMasterKey, seed);
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
      throw std::runtime_error("vm1: truncated canonical code");
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
      throw std::runtime_error("vm1: truncated encoded code");
    }
    append_u16(decoded, static_cast<std::uint16_t>(opcode));
    decoded.insert(decoded.end(),
                   encoded_code.begin() + static_cast<std::ptrdiff_t>(cursor),
                   encoded_code.begin() + static_cast<std::ptrdiff_t>(pc + size));
    pc += size;
  }
  return decoded;
}

std::uint16_t module_version_for_serialize(const Vm1Module& module) {
  if ((module.module_flags & VMP_FLAG_OPCODE_ENCRYPTED) != 0) {
    return kVm1Version;
  }
  if (module.version == kVm1LegacyVersion && seed_is_zero(module.opcode_map_seed)) {
    return kVm1LegacyVersion;
  }
  return kVm1Version;
}


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

std::uint16_t read_u16(const ByteVector& bytes, std::size_t& offset) {
  if (offset + 2 > bytes.size()) {
    throw std::runtime_error("vm1: truncated u16");
  }
  std::uint16_t value = static_cast<std::uint16_t>(bytes[offset]) |
                        static_cast<std::uint16_t>(bytes[offset + 1] << 8u);
  offset += 2;
  return value;
}

std::uint32_t read_u32(const ByteVector& bytes, std::size_t& offset) {
  if (offset + 4 > bytes.size()) {
    throw std::runtime_error("vm1: truncated u32");
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
    throw std::runtime_error("vm1: truncated u64");
  }
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(bytes[offset + static_cast<std::size_t>(i)]) << (8 * i);
  }
  offset += 8;
  return value;
}

double bit_cast_double(std::uint64_t value) {
  double out = 0.0;
  std::memcpy(&out, &value, sizeof(out));
  return out;
}

std::uint64_t bit_cast_u64(double value) {
  std::uint64_t out = 0;
  std::memcpy(&out, &value, sizeof(out));
  return out;
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

std::string unescape_string(const std::string& value) {
  if (value.size() < 2 || value.front() != '"' || value.back() != '"') {
    throw std::runtime_error("vm1 asm: expected quoted string");
  }
  std::string out;
  for (std::size_t i = 1; i + 1 < value.size(); ++i) {
    char ch = value[i];
    if (ch != '\\') {
      out.push_back(ch);
      continue;
    }
    if (i + 1 >= value.size() - 1) {
      throw std::runtime_error("vm1 asm: bad string escape");
    }
    const char esc = value[++i];
    switch (esc) {
      case 'n':
        out.push_back('\n');
        break;
      case 'r':
        out.push_back('\r');
        break;
      case 't':
        out.push_back('\t');
        break;
      case '\\':
        out.push_back('\\');
        break;
      case '"':
        out.push_back('"');
        break;
      case 'x': {
        if (i + 2 >= value.size() - 1) {
          throw std::runtime_error("vm1 asm: short hex escape");
        }
        const auto hex = value.substr(i + 1, 2);
        unsigned int parsed = 0;
        std::stringstream ss;
        ss << std::hex << hex;
        ss >> parsed;
        out.push_back(static_cast<char>(parsed));
        i += 2;
        break;
      }
      default:
        throw std::runtime_error("vm1 asm: unsupported escape");
    }
  }
  return out;
}

std::string escape_string(std::string_view value) {
  std::string out = "\"";
  for (char ch : value) {
    switch (ch) {
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      case '\\': out += "\\\\"; break;
      case '"': out += "\\\""; break;
      default:
        if (static_cast<unsigned char>(ch) < 0x20) {
          std::ostringstream oss;
          oss << "\\x" << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(static_cast<unsigned char>(ch));
          out += oss.str();
        } else {
          out.push_back(ch);
        }
    }
  }
  out.push_back('"');
  return out;
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
    throw std::runtime_error("vm1 asm: invalid integer '" + text + "'");
  }
  return static_cast<std::int64_t>(value);
}

std::uint64_t parse_u64_value(const std::string& text) {
  std::size_t idx = 0;
  int base = 10;
  if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    base = 16;
  }
  unsigned long long value = std::stoull(text, &idx, base);
  if (idx != text.size()) {
    throw std::runtime_error("vm1 asm: invalid unsigned integer '" + text + "'");
  }
  return static_cast<std::uint64_t>(value);
}

double parse_double_value(const std::string& text) {
  std::size_t idx = 0;
  const double value = std::stod(text, &idx);
  if (idx != text.size()) {
    throw std::runtime_error("vm1 asm: invalid float '" + text + "'");
  }
  return value;
}

std::uint8_t parse_general_register(const std::string& token) {
  if (token.size() < 3 || token.rfind("vr", 0) != 0) {
    throw std::runtime_error("vm1 asm: expected general register, got '" + token + "'");
  }
  const auto index = parse_u64_value(token.substr(2));
  if (index >= kVm1GeneralRegisterCount) {
    throw std::runtime_error("vm1 asm: general register out of range");
  }
  return static_cast<std::uint8_t>(index);
}

std::uint8_t parse_float_register(const std::string& token) {
  if (token.size() < 4 || token.rfind("vfr", 0) != 0) {
    throw std::runtime_error("vm1 asm: expected float register, got '" + token + "'");
  }
  const auto index = parse_u64_value(token.substr(3));
  if (index >= kVm1FloatRegisterCount) {
    throw std::runtime_error("vm1 asm: float register out of range");
  }
  return static_cast<std::uint8_t>(index);
}

std::uint8_t parse_vector_register(const std::string& token) {
  if (token.size() < 3 || token.rfind("vq", 0) != 0) {
    throw std::runtime_error("vm1 asm: expected vector register, got '" + token + "'");
  }
  const auto index = parse_u64_value(token.substr(2));
  if (index >= kVm1VectorRegisterCount) {
    throw std::runtime_error("vm1 asm: vector register out of range");
  }
  return static_cast<std::uint8_t>(index);
}

struct MemoryOperand {
  std::uint8_t base = static_cast<std::uint8_t>(MemoryBase::stack_pointer);
  std::int32_t offset = 0;
};

MemoryOperand parse_memory_operand(const std::string& token) {
  if (token.size() < 3 || token.front() != '[' || token.back() != ']') {
    throw std::runtime_error("vm1 asm: expected memory operand, got '" + token + "'");
  }
  const auto inside = trim(std::string_view(token).substr(1, token.size() - 2));
  MemoryOperand operand;
  auto plus = inside.find('+');
  auto minus = inside.find('-', 1);
  std::size_t split = std::string::npos;
  char sign = '+';
  if (plus != std::string::npos) {
    split = plus;
    sign = '+';
  } else if (minus != std::string::npos) {
    split = minus;
    sign = '-';
  }
  const auto base_token = trim(split == std::string::npos ? inside : inside.substr(0, split));
  if (base_token == "sp") {
    operand.base = static_cast<std::uint8_t>(MemoryBase::stack_pointer);
  } else {
    operand.base = parse_general_register(base_token);
  }
  if (split != std::string::npos) {
    const auto offset_token = trim(inside.substr(split + 1));
    const auto parsed = parse_i64(offset_token);
    operand.offset = static_cast<std::int32_t>(sign == '-' ? -parsed : parsed);
  }
  return operand;
}

Opcode parse_opcode(const std::string& op) {
  static const std::map<std::string, Opcode> table = {
      {"nop", Opcode::nop},
      {"ldi64", Opcode::ldi64},
      {"ldi_u64", Opcode::ldi_u64},
      {"ldi_f64", Opcode::ldi_f64},
      {"mov", Opcode::mov},
      {"add", Opcode::add},
      {"sub", Opcode::sub},
      {"mul", Opcode::mul},
      {"div", Opcode::div},
      {"mod", Opcode::mod},
      {"neg", Opcode::neg},
      {"and", Opcode::bit_and},
      {"or", Opcode::bit_or},
      {"xor", Opcode::bit_xor},
      {"shl", Opcode::shl},
      {"shr", Opcode::shr},
      {"sar", Opcode::sar},
      {"not", Opcode::bit_not},
      {"popcnt", Opcode::popcnt},
      {"clz", Opcode::clz},
      {"ctz", Opcode::ctz},
      {"bswap", Opcode::bswap},
      {"cmp", Opcode::cmp},
      {"test", Opcode::test},
      {"setcc", Opcode::setcc},
      {"load_mem8", Opcode::load_mem8},
      {"load_mem16", Opcode::load_mem16},
      {"load_mem32", Opcode::load_mem32},
      {"load_mem64", Opcode::load_mem64},
      {"store_mem8", Opcode::store_mem8},
      {"store_mem16", Opcode::store_mem16},
      {"store_mem32", Opcode::store_mem32},
      {"store_mem64", Opcode::store_mem64},
      {"load_sext8", Opcode::load_sext8},
      {"load_sext16", Opcode::load_sext16},
      {"load_sext32", Opcode::load_sext32},
      {"lea", Opcode::lea},
      {"jmp", Opcode::jmp},
      {"jeq", Opcode::jeq},
      {"jne", Opcode::jne},
      {"jlt", Opcode::jlt},
      {"jle", Opcode::jle},
      {"jgt", Opcode::jgt},
      {"jge", Opcode::jge},
      {"call", Opcode::call},
      {"ret", Opcode::ret},
      {"call_indirect", Opcode::call_indirect},
      {"jmp_indirect", Opcode::jmp_indirect},
      {"fadd", Opcode::fadd},
      {"fsub", Opcode::fsub},
      {"fmul", Opcode::fmul},
      {"fdiv", Opcode::fdiv},
      {"fsqrt", Opcode::fsqrt},
      {"i64_to_f64", Opcode::i64_to_f64},
      {"f64_to_i64", Opcode::f64_to_i64},
      {"fcmp", Opcode::fcmp},
      {"vadd128", Opcode::vadd128},
      {"vxor128", Opcode::vxor128},
      {"vshuffle128", Opcode::vshuffle128},
      {"memcpy", Opcode::memcpy},
      {"memset", Opcode::memset},
      {"strcmp", Opcode::strcmp},
      {"strlen", Opcode::strlen},
      {"cas_u64", Opcode::cas_u64},
      {"xchg_u64", Opcode::xchg_u64},
      {"fence", Opcode::fence},
      {"breakpoint", Opcode::breakpoint},
      {"trap", Opcode::trap},
      {"syscall_proxy", Opcode::syscall_proxy},
      {"domain_call", Opcode::domain_call},
      {"domain_ret", Opcode::domain_ret},
      {"bridge_args", Opcode::bridge_args},
      {"load_transient_string", Opcode::load_transient_string},
      {"load_tstr", Opcode::load_transient_string},
      {"release_transient_string", Opcode::release_transient_string},
      {"release_tstr", Opcode::release_transient_string},
      {"transient_read8", Opcode::transient_read8},
      {"transient_wipe", Opcode::transient_wipe},
  };
  const auto it = table.find(op);
  if (it == table.end()) {
    throw std::runtime_error("vm1 asm: unknown opcode '" + op + "'");
  }
  return it->second;
}

std::size_t instruction_size(Opcode opcode) {
  switch (opcode) {
    case Opcode::nop:
    case Opcode::ret:
    case Opcode::domain_ret:
    case Opcode::fence:
    case Opcode::breakpoint:
      return 2;
    case Opcode::trap:
    case Opcode::jmp:
    case Opcode::syscall_proxy:
      return 6;
    case Opcode::mov:
    case Opcode::neg:
    case Opcode::bit_not:
    case Opcode::popcnt:
    case Opcode::clz:
    case Opcode::ctz:
    case Opcode::bswap:
    case Opcode::setcc:
    case Opcode::fsqrt:
    case Opcode::i64_to_f64:
    case Opcode::f64_to_i64:
    case Opcode::strlen:
    case Opcode::call_indirect:
      return 4;
    case Opcode::jmp_indirect:
    case Opcode::release_transient_string:
    case Opcode::transient_wipe:
      return 3;
    case Opcode::ldi64:
    case Opcode::ldi_u64:
    case Opcode::ldi_f64:
      return 11;
    case Opcode::add:
    case Opcode::sub:
    case Opcode::mul:
    case Opcode::div:
    case Opcode::mod:
    case Opcode::bit_and:
    case Opcode::bit_or:
    case Opcode::bit_xor:
    case Opcode::shl:
    case Opcode::shr:
    case Opcode::sar:
    case Opcode::fadd:
    case Opcode::fsub:
    case Opcode::fmul:
    case Opcode::fdiv:
    case Opcode::vadd128:
    case Opcode::vxor128:
    case Opcode::vshuffle128:
    case Opcode::memcpy:
    case Opcode::memset:
    case Opcode::strcmp:
      return 5;
    case Opcode::cmp:
    case Opcode::test:
    case Opcode::fcmp:
      return 4;
    case Opcode::load_mem8:
    case Opcode::load_mem16:
    case Opcode::load_mem32:
    case Opcode::load_mem64:
    case Opcode::store_mem8:
    case Opcode::store_mem16:
    case Opcode::store_mem32:
    case Opcode::store_mem64:
    case Opcode::load_sext8:
    case Opcode::load_sext16:
    case Opcode::load_sext32:
    case Opcode::lea:
      return 8;
    case Opcode::jeq:
    case Opcode::jne:
    case Opcode::jlt:
    case Opcode::jle:
    case Opcode::jgt:
    case Opcode::jge:
      return 8;
    case Opcode::call:
    case Opcode::load_transient_string:
      return 7;
    case Opcode::domain_call:
      return 10;
    case Opcode::bridge_args:
      return 5;
    case Opcode::transient_read8:
      return 5;
    case Opcode::cas_u64:
      return 10;
    case Opcode::xchg_u64:
      return 9;
  }
  throw std::runtime_error("vm1 asm: size missing");
}

const std::vector<Opcode>& canonical_opcode_sequence_internal() {
  static const std::vector<Opcode> sequence{
      Opcode::nop,
      Opcode::ldi64,
      Opcode::ldi_u64,
      Opcode::ldi_f64,
      Opcode::mov,
      Opcode::add,
      Opcode::sub,
      Opcode::mul,
      Opcode::div,
      Opcode::mod,
      Opcode::neg,
      Opcode::bit_and,
      Opcode::bit_or,
      Opcode::bit_xor,
      Opcode::shl,
      Opcode::shr,
      Opcode::sar,
      Opcode::bit_not,
      Opcode::popcnt,
      Opcode::clz,
      Opcode::ctz,
      Opcode::bswap,
      Opcode::cmp,
      Opcode::test,
      Opcode::setcc,
      Opcode::load_mem8,
      Opcode::load_mem16,
      Opcode::load_mem32,
      Opcode::load_mem64,
      Opcode::store_mem8,
      Opcode::store_mem16,
      Opcode::store_mem32,
      Opcode::store_mem64,
      Opcode::load_sext8,
      Opcode::load_sext16,
      Opcode::load_sext32,
      Opcode::lea,
      Opcode::jmp,
      Opcode::jeq,
      Opcode::jne,
      Opcode::jlt,
      Opcode::jle,
      Opcode::jgt,
      Opcode::jge,
      Opcode::call,
      Opcode::ret,
      Opcode::call_indirect,
      Opcode::jmp_indirect,
      Opcode::fadd,
      Opcode::fsub,
      Opcode::fmul,
      Opcode::fdiv,
      Opcode::fsqrt,
      Opcode::i64_to_f64,
      Opcode::f64_to_i64,
      Opcode::fcmp,
      Opcode::vadd128,
      Opcode::vxor128,
      Opcode::vshuffle128,
      Opcode::memcpy,
      Opcode::memset,
      Opcode::strcmp,
      Opcode::strlen,
      Opcode::cas_u64,
      Opcode::xchg_u64,
      Opcode::fence,
      Opcode::breakpoint,
      Opcode::trap,
      Opcode::syscall_proxy,
      Opcode::domain_call,
      Opcode::domain_ret,
      Opcode::bridge_args,
      Opcode::load_transient_string,
      Opcode::release_transient_string,
      Opcode::transient_read8,
      Opcode::transient_wipe,
  };
  return sequence;
}

struct ParsedInstruction {
  std::string op;
  std::vector<std::string> operands;
  std::uint32_t pc = 0;
};

struct LabelDefinition {
  std::string name;
  std::uint32_t pc = 0;
};

struct AssemblyProgram {
  std::vector<ParsedInstruction> instructions;
  std::vector<LabelDefinition> label_definitions;
  std::map<std::string, std::uint32_t> labels;
  std::map<std::uint32_t, std::string> strings;
};

AssemblyProgram parse_assembly(std::string_view source) {
  AssemblyProgram program;
  std::uint32_t pc = 0;
  std::istringstream input{std::string(source)};
  std::string line;
  while (std::getline(input, line)) {
    line = trim(strip_comment(line));
    if (line.empty()) {
      continue;
    }
    while (!line.empty()) {
      const auto colon = line.find(':');
      if (colon == std::string::npos) {
        break;
      }
      const auto maybe_label = trim(line.substr(0, colon));
      if (maybe_label.find(' ') != std::string::npos || maybe_label.find('\t') != std::string::npos) {
        break;
      }
      program.label_definitions.push_back(LabelDefinition{maybe_label, pc});
      program.labels.emplace(maybe_label, pc);
      line = trim(line.substr(colon + 1));
      if (line.empty()) {
        break;
      }
    }
    if (line.empty()) {
      continue;
    }
    if (line.rfind(".const", 0) == 0) {
      auto operands = split_operands(line);
      if (operands.empty()) {
        throw std::runtime_error("vm1 asm: malformed .const");
      }
      std::istringstream directive(operands.front());
      std::string keyword;
      std::string kind;
      std::string id_text;
      directive >> keyword >> kind >> id_text;
      if (keyword != ".const" || kind != "string") {
        throw std::runtime_error("vm1 asm: only .const string supported");
      }
      std::string value;
      if (operands.size() >= 2) {
        value = operands[1];
      } else {
        std::getline(directive, value);
        value = trim(value);
      }
      program.strings[static_cast<std::uint32_t>(parse_u64_value(id_text))] = unescape_string(value);
      continue;
    }
    const auto space = line.find_first_of(" \t");
    ParsedInstruction inst;
    inst.pc = pc;
    inst.op = space == std::string::npos ? line : trim(line.substr(0, space));
    if (space != std::string::npos) {
      inst.operands = split_operands(trim(line.substr(space + 1)));
    }
    program.instructions.push_back(inst);
    pc += static_cast<std::uint32_t>(instruction_size(parse_opcode(inst.op)));
  }
  return program;
}

std::uint32_t parse_string_id_token(const std::string& token) {
  if (token.rfind("&sid", 0) == 0) {
    return static_cast<std::uint32_t>(parse_u64_value(token.substr(4)));
  }
  if (token.rfind("sid", 0) == 0) {
    return static_cast<std::uint32_t>(parse_u64_value(token.substr(3)));
  }
  return static_cast<std::uint32_t>(parse_u64_value(token));
}

std::uint32_t resolve_target(const std::string& token, const std::map<std::string, std::uint32_t>& labels) {
  if (!token.empty() && token[0] == '@') {
    std::vector<std::uint8_t> scratch(4u, 0u);
    common::LabelResolver resolver(&scratch);
    for (const auto& [name, pc] : labels) {
      resolver.define(common::Label{name}, pc);
    }
    resolver.reference(common::Fixup{
        0,
        common::FixupField::jump_offset_s32,
        common::Label{token.substr(1)},
        common::Range{},
        0,
        0,
    });
    const auto result = resolver.resolve();
    if (!result.ok()) {
      throw common::ResolutionError(result);
    }
    std::size_t offset = 0;
    return read_u32(scratch, offset);
  }
  return static_cast<std::uint32_t>(parse_u64_value(token));
}

std::uint64_t parse_u64_or_label(const std::string& token, const std::map<std::string, std::uint32_t>& labels) {
  if (!token.empty() && token[0] == '@') {
    return resolve_target(token, labels);
  }
  return parse_u64_value(token);
}

std::uint8_t parse_domain_token(const std::string& token) {
  if (token == "native") {
    return 0;
  }
  if (token == "vm1") {
    return 1;
  }
  if (token == "vm2") {
    return 2;
  }
  throw std::runtime_error("vm1 asm: unknown domain '" + token + "'");
}

std::uint8_t parse_condition_code(const std::string& token) {
  if (token == "eq") return 0;
  if (token == "ne") return 1;
  if (token == "lt") return 2;
  if (token == "le") return 3;
  if (token == "gt") return 4;
  if (token == "ge") return 5;
  return static_cast<std::uint8_t>(parse_u64_value(token));
}

std::string condition_name(std::uint8_t code) {
  switch (code) {
    case 0: return "eq";
    case 1: return "ne";
    case 2: return "lt";
    case 3: return "le";
    case 4: return "gt";
    case 5: return "ge";
    default: {
      std::ostringstream oss;
      oss << static_cast<unsigned>(code);
      return oss.str();
    }
  }
}

void append_i32(ByteVector& out, std::int32_t value) {
  append_u32(out, static_cast<std::uint32_t>(value));
}

std::string make_label(std::uint32_t pc) {
  std::ostringstream oss;
  oss << 'L' << std::hex << std::setw(4) << std::setfill('0') << pc;
  return oss.str();
}

std::uint16_t read_u16_code(const std::vector<std::uint8_t>& code, std::size_t& pc) {
  if (pc + 2 > code.size()) {
    throw std::runtime_error("vm1 disasm: truncated u16");
  }
  const auto value = static_cast<std::uint16_t>(code[pc]) |
                     static_cast<std::uint16_t>(code[pc + 1] << 8u);
  pc += 2;
  return value;
}

std::uint32_t read_u32_code(const std::vector<std::uint8_t>& code, std::size_t& pc) {
  if (pc + 4 > code.size()) {
    throw std::runtime_error("vm1 disasm: truncated u32");
  }
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(code[pc + static_cast<std::size_t>(i)]) << (8 * i);
  }
  pc += 4;
  return value;
}

std::uint64_t read_u64_code(const std::vector<std::uint8_t>& code, std::size_t& pc) {
  if (pc + 8 > code.size()) {
    throw std::runtime_error("vm1 disasm: truncated u64");
  }
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(code[pc + static_cast<std::size_t>(i)]) << (8 * i);
  }
  pc += 8;
  return value;
}

std::int32_t read_i32_code(const std::vector<std::uint8_t>& code, std::size_t& pc) {
  return static_cast<std::int32_t>(read_u32_code(code, pc));
}

std::string base_name(std::uint8_t base) {
  if (base == static_cast<std::uint8_t>(MemoryBase::stack_pointer)) {
    return "sp";
  }
  std::ostringstream oss;
  oss << "vr" << static_cast<unsigned>(base);
  return oss.str();
}

std::string vector_name(std::uint8_t index) {
  std::ostringstream oss;
  oss << "vq" << static_cast<unsigned>(index);
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

  const auto prk = vmp::runtime::strings::hkdf_extract_sha256(
      std::vector<std::uint8_t>(master_key.begin(), master_key.end()),
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
      throw std::runtime_error("vm1: opcode keystream exhausted");
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

VmException::VmException(VmTrapCode code, std::uint32_t pc, std::string message)
    : std::runtime_error(std::move(message)), code_(code), pc_(pc) {}

Vm1Context::Vm1Context(const Vm1Module& module_in, std::size_t stack_size)
    : pc(module_in.entry_pc), module(&module_in), stack_(stack_size, 0) {}


std::size_t Vm1Context::stack_size() const noexcept { return stack_.size(); }

std::uint64_t Vm1Context::stack_top() const noexcept { return stack_top_; }

void Vm1Context::set_stack_top(std::uint64_t value) {
  if (value > stack_.size()) {
    throw VmException(VmTrapCode::stack_overflow, pc, "vm1: stack top out of range");
  }
  stack_top_ = value;
}

void Vm1Context::ensure_memory_range(std::uint64_t address, std::size_t width) const {
  if (address > stack_.size() || width > stack_.size() || address + width > stack_.size()) {
    throw VmException(VmTrapCode::out_of_bounds, pc, "vm1: memory access out of bounds");
  }
}

std::uint64_t Vm1Context::materialize_transient_string(std::uint32_t id) {
  auto view = [this, id]() -> vmp::runtime::strings::TransientView {
    if (string_pool) {
      string_pool->set_audit_dispatcher(audit_dispatcher);
      return string_pool->decrypt(id);
    }
    if (module == nullptr || id >= module->const_pool.size() || module->const_pool[id].kind != ConstKind::transient_string) {
      throw VmException(VmTrapCode::invalid_constant, pc, "vm1: transient string id out of range");
    }
    return vmp::runtime::strings::TransientView(module->const_pool[id].bytes);
  }();
  const auto handle = next_transient_handle_++;
  released_transient_debug_.erase(handle);
  transient_strings_[handle] = std::make_unique<vmp::runtime::strings::TransientView>(std::move(view));
  register_transient_handle(handle);
  return handle;
}

void Vm1Context::release_transient_string(std::uint64_t handle) {
  const auto it = transient_strings_.find(handle);
  if (it == transient_strings_.end()) {
    throw VmException(VmTrapCode::invalid_constant, pc, "vm1: transient string handle not found");
  }
  remove_transient_handle_owner(handle);
  released_transient_debug_[handle] = it->second->debug_zeroized_snapshot();
  transient_strings_.erase(it);
}

std::string Vm1Context::transient_string(std::uint64_t handle) const {
  const auto it = transient_strings_.find(handle);
  if (it == transient_strings_.end() || it->second == nullptr) {
    throw VmException(VmTrapCode::invalid_constant, pc, "vm1: transient string handle not found");
  }
  return std::string(it->second->view());
}

std::size_t Vm1Context::active_transient_strings() const noexcept { return transient_strings_.size(); }

std::vector<std::uint8_t> Vm1Context::debug_last_released_bytes(std::uint64_t handle) const {
  auto it = released_transient_debug_.find(handle);
  return it == released_transient_debug_.end() ? std::vector<std::uint8_t>{} : it->second;
}

bool Vm1Context::debug_last_release_zeroed(std::uint64_t handle) const {
  const auto bytes = debug_last_released_bytes(handle);
  return !bytes.empty() && std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t value) { return value == 0; });
}

void Vm1Context::register_transient_handle(std::uint64_t handle) {
  if (frames_.empty()) {
    root_transient_handles_.push_back(handle);
  } else {
    frames_.back().transient_handles.push_back(handle);
  }
}

void Vm1Context::remove_transient_handle_owner(std::uint64_t handle) {
  auto erase_from = [handle](std::vector<std::uint64_t>& handles) {
    handles.erase(std::remove(handles.begin(), handles.end(), handle), handles.end());
  };
  erase_from(root_transient_handles_);
  for (auto& frame : frames_) {
    erase_from(frame.transient_handles);
  }
}

void Vm1Context::clear_frame_transient_strings() {
  std::vector<std::uint64_t> handles;
  if (frames_.empty()) {
    handles.swap(root_transient_handles_);
  } else {
    handles.swap(frames_.back().transient_handles);
  }
  for (auto handle : handles) {
    transient_strings_.erase(handle);
  }
}

void Vm1Context::clear_all_transient_strings() noexcept {
  transient_strings_.clear();
  released_transient_debug_.clear();
  root_transient_handles_.clear();
  for (auto& frame : frames_) {
    frame.transient_handles.clear();
  }
}

Vm1Module Vm1Module::load_from_file(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("vm1: failed to open module '" + path + "'");
  }
  std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  return load_from_bytes(bytes);
}

Vm1Module Vm1Module::load_from_bytes(const std::vector<std::uint8_t>& bytes) {
  if (bytes.size() < kVm1LegacyHeaderSize) {
    throw std::runtime_error("vm1: module too small");
  }
  Vm1Module module;
  module.runtime_id = g_next_vm1_module_id.fetch_add(1);
  if (!std::equal(kVm1Magic.begin(), kVm1Magic.end(), bytes.begin())) {
    throw std::runtime_error("vm1: bad magic");
  }
  std::size_t offset = 4;
  module.version = read_u16(bytes, offset);
  const auto header_size = vm1_header_size_for_version(module.version);
  if (bytes.size() < header_size) {
    throw std::runtime_error("vm1: module too small");
  }
  module.module_flags = read_u16(bytes, offset);
  module.entry_pc = read_u32(bytes, offset);
  const auto code_size = read_u32(bytes, offset);
  const auto const_count = read_u32(bytes, offset);
  module.crc32 = read_u32(bytes, offset);
  if (module.version == kVm1Version) {
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                kOpcodeMapSeedSize,
                module.opcode_map_seed.begin());
    offset += kOpcodeMapSeedSize;
  }
  const auto actual_crc32 = vm1_body_crc32(bytes, header_size, code_size, const_count);
  if (actual_crc32 != module.crc32) {
    append_module_crc_mismatch_audit("expected=" + hex_u32(module.crc32) + " actual=" + hex_u32(actual_crc32));
    throw std::runtime_error("vm1: crc32 mismatch");
  }
  if (offset + code_size > bytes.size()) {
    throw std::runtime_error("vm1: truncated code");
  }
  ByteVector serialized_code(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                             bytes.begin() + static_cast<std::ptrdiff_t>(offset + code_size));
  offset += code_size;
  bool saw_opcode_marker = false;
  for (std::uint32_t i = 0; i < const_count; ++i) {
    if (offset >= bytes.size()) {
      throw std::runtime_error("vm1: truncated const kind");
    }
    const auto kind = static_cast<ConstKind>(bytes[offset++]);
    const auto payload_size = read_u32(bytes, offset);
    if (offset + payload_size > bytes.size()) {
      throw std::runtime_error("vm1: truncated const payload");
    }
    if (kind == ConstKind::opcode_map_marker) {
      if (payload_size != 4u || saw_opcode_marker) {
        append_opcode_map_invalid_audit("vm1 malformed opcode-map marker");
        throw std::runtime_error("vm1: malformed opcode-map marker");
      }
      std::size_t marker_offset = offset;
      module.opcode_map_marker_crc32 = read_u32(bytes, marker_offset);
      saw_opcode_marker = true;
    } else {
      ConstPoolEntry entry;
      entry.kind = kind;
      entry.bytes.assign(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                         bytes.begin() + static_cast<std::ptrdiff_t>(offset + payload_size));
      module.const_pool.push_back(std::move(entry));
    }
    offset += payload_size;
  }
  if ((module.module_flags & VMP_FLAG_OPCODE_ENCRYPTED) != 0) {
    if (!saw_opcode_marker) {
      append_opcode_map_invalid_audit("vm1 missing opcode-map marker");
      throw std::runtime_error("vm1: missing opcode-map marker");
    }
    const auto cryptor = opcode_cryptor_for_seed(module.opcode_map_seed);
    const auto expected_marker = cryptor.sanity_marker_crc32();
    if (expected_marker != module.opcode_map_marker_crc32) {
      append_opcode_map_invalid_audit("vm1 marker mismatch expected=" + hex_u32(expected_marker) +
                                      " actual=" + hex_u32(module.opcode_map_marker_crc32));
      throw std::runtime_error("vm1: opcode map invalid");
    }
    module.code = decode_code_stream(serialized_code, cryptor);
  } else {
    module.code = std::move(serialized_code);
  }
  if (module.entry_pc > module.code.size()) {
    throw std::runtime_error("vm1: entry_pc out of range");
  }
  return module;
}

std::uint32_t serialized_body_crc32(const std::vector<std::uint8_t>& bytes) {
  if (bytes.size() < kVm1LegacyHeaderSize) {
    throw std::runtime_error("vm1: module too small");
  }
  if (!std::equal(kVm1Magic.begin(), kVm1Magic.end(), bytes.begin())) {
    throw std::runtime_error("vm1: bad magic");
  }
  std::size_t offset = 4;
  const auto version = read_u16(bytes, offset);
  const auto header_size = vm1_header_size_for_version(version);
  (void)read_u16(bytes, offset);
  (void)read_u32(bytes, offset);
  const auto code_size = read_u32(bytes, offset);
  const auto const_count = read_u32(bytes, offset);
  (void)read_u32(bytes, offset);
  if (version == kVm1Version) {
    offset += kOpcodeMapSeedSize;
  }
  (void)offset;
  return vm1_body_crc32(bytes, header_size, code_size, const_count);
}

std::vector<std::uint8_t> Vm1Module::serialize() const {
  const bool encrypt_opcodes = (module_flags & VMP_FLAG_OPCODE_ENCRYPTED) != 0;
  const auto write_version = module_version_for_serialize(*this);
  const auto cryptor = encrypt_opcodes ? opcode_cryptor_for_seed(opcode_map_seed) : OpcodeCryptor::identity();
  const auto encoded_code = encrypt_opcodes ? encode_code_stream(code, cryptor) : code;
  const auto marker_crc32 = encrypt_opcodes ? std::optional<std::uint32_t>(cryptor.sanity_marker_crc32()) : std::nullopt;
  const auto const_section = serialize_const_pool_section(const_pool, marker_crc32);
  std::vector<std::uint8_t> body;
  body.reserve(encoded_code.size() + const_section.size());
  body.insert(body.end(), encoded_code.begin(), encoded_code.end());
  body.insert(body.end(), const_section.begin(), const_section.end());

  std::vector<std::uint8_t> out;
  const auto header_size = write_version == kVm1Version ? kVm1HeaderSize : kVm1LegacyHeaderSize;
  out.reserve(header_size + body.size());
  out.insert(out.end(), kVm1Magic.begin(), kVm1Magic.end());
  append_u16(out, write_version);
  append_u16(out, module_flags);
  append_u32(out, entry_pc);
  append_u32(out, static_cast<std::uint32_t>(encoded_code.size()));
  append_u32(out, static_cast<std::uint32_t>(const_pool.size() + (encrypt_opcodes ? 1u : 0u)));
  append_u32(out, vmp::runtime::integrity::crc32_compute(body.data(), body.size()));
  if (write_version == kVm1Version) {
    out.insert(out.end(), opcode_map_seed.begin(), opcode_map_seed.end());
  }
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

void Vm1Module::save_to_file(const std::string& path) const {
  const auto bytes = serialize();
  std::filesystem::create_directories(std::filesystem::path(path).parent_path());
  std::ofstream output(path, std::ios::binary);
  if (!output) {
    throw std::runtime_error("vm1: failed to create module '" + path + "'");
  }
  output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

Vm1Module assemble_module_text(std::string_view text, std::uint16_t module_flags) {
  AssembleOptions options;
  options.module_flags = static_cast<std::uint16_t>(module_flags & ~VMP_FLAG_OPCODE_ENCRYPTED);
  options.encrypt_opcodes = false;
  auto module = assemble_module_text(text, options);
  module.version = kVm1LegacyVersion;
  return module;
}

Vm1Module assemble_module_text(std::string_view text, const AssembleOptions& options) {
  const auto program = parse_assembly(text);
  Vm1Module module;
  module.runtime_id = g_next_vm1_module_id.fetch_add(1);
  module.version = options.encrypt_opcodes ? kVm1Version : kVm1LegacyVersion;
  module.module_flags = static_cast<std::uint16_t>(options.module_flags & ~VMP_FLAG_OPCODE_ENCRYPTED);
  if (options.encrypt_opcodes) {
    module.module_flags = static_cast<std::uint16_t>(module.module_flags | VMP_FLAG_OPCODE_ENCRYPTED);
    module.opcode_map_seed = options.opcode_seed.value_or(random_opcode_seed());
  }
  module.entry_pc = 0;
  common::LabelResolver resolver(&module.code);
  for (const auto& [id, value] : program.strings) {
    if (module.const_pool.size() <= id) {
      module.const_pool.resize(static_cast<std::size_t>(id) + 1u);
    }
    module.const_pool[id].kind = ConstKind::transient_string;
    module.const_pool[id].bytes.assign(value.begin(), value.end());
  }
  for (const auto& definition : program.label_definitions) {
    resolver.define(common::Label{definition.name}, definition.pc);
  }
  for (std::size_t inst_index = 0; inst_index < program.instructions.size(); ++inst_index) {
    const auto& inst = program.instructions[inst_index];
    const auto opcode = parse_opcode(inst.op);
    append_u16(module.code, static_cast<std::uint16_t>(opcode));
    switch (opcode) {
      case Opcode::nop:
      case Opcode::breakpoint:
      case Opcode::ret:
      case Opcode::domain_ret:
      case Opcode::fence:
        break;
      case Opcode::trap:
      case Opcode::syscall_proxy: {
        const auto code = inst.operands.empty() ? 0u : static_cast<std::uint32_t>(parse_u64_value(inst.operands.at(0)));
        append_u32(module.code, code);
        break;
      }
      case Opcode::ldi64: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        append_u64(module.code, static_cast<std::uint64_t>(parse_i64(inst.operands.at(1))));
        break;
      }
      case Opcode::ldi_u64: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        if (!inst.operands.at(1).empty() && inst.operands.at(1).front() == '@') {
          const auto patch_offset = module.code.size();
          append_u64(module.code, 0);
          resolver.reference(common::Fixup{
              inst_index,
              common::FixupField::address_materialize_s64,
              common::Label{inst.operands.at(1).substr(1)},
              common::Range{0, std::numeric_limits<std::int64_t>::max()},
              inst.pc,
              patch_offset,
          });
        } else {
          append_u64(module.code, parse_u64_value(inst.operands.at(1)));
        }
        break;
      }
      case Opcode::ldi_f64: {
        module.code.push_back(parse_float_register(inst.operands.at(0)));
        append_u64(module.code, bit_cast_u64(parse_double_value(inst.operands.at(1))));
        break;
      }
      case Opcode::mov:
      case Opcode::neg:
      case Opcode::bit_not:
      case Opcode::popcnt:
      case Opcode::clz:
      case Opcode::ctz:
      case Opcode::bswap: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        break;
      }
      case Opcode::setcc: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_condition_code(inst.operands.at(1)));
        break;
      }
      case Opcode::release_transient_string:
      case Opcode::transient_wipe: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        break;
      }
      case Opcode::call_indirect: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(static_cast<std::uint8_t>(inst.operands.size() >= 2 ? parse_u64_value(inst.operands.at(1)) : 0u));
        break;
      }
      case Opcode::jmp_indirect: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        break;
      }
      case Opcode::fsqrt: {
        module.code.push_back(parse_float_register(inst.operands.at(0)));
        module.code.push_back(parse_float_register(inst.operands.at(1)));
        break;
      }
      case Opcode::i64_to_f64: {
        module.code.push_back(parse_float_register(inst.operands.at(0)));
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        break;
      }
      case Opcode::f64_to_i64: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_float_register(inst.operands.at(1)));
        break;
      }
      case Opcode::strlen: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        break;
      }
      case Opcode::add:
      case Opcode::sub:
      case Opcode::mul:
      case Opcode::div:
      case Opcode::mod:
      case Opcode::bit_and:
      case Opcode::bit_or:
      case Opcode::bit_xor:
      case Opcode::shl:
      case Opcode::shr:
      case Opcode::sar:
      case Opcode::memcpy:
      case Opcode::memset:
      case Opcode::strcmp: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        module.code.push_back(parse_general_register(inst.operands.at(2)));
        break;
      }
      case Opcode::cmp:
      case Opcode::test: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        break;
      }
      case Opcode::fadd:
      case Opcode::fsub:
      case Opcode::fmul:
      case Opcode::fdiv: {
        module.code.push_back(parse_float_register(inst.operands.at(0)));
        module.code.push_back(parse_float_register(inst.operands.at(1)));
        module.code.push_back(parse_float_register(inst.operands.at(2)));
        break;
      }
      case Opcode::fcmp: {
        module.code.push_back(parse_float_register(inst.operands.at(0)));
        module.code.push_back(parse_float_register(inst.operands.at(1)));
        break;
      }
      case Opcode::vadd128:
      case Opcode::vxor128:
      case Opcode::vshuffle128: {
        module.code.push_back(parse_vector_register(inst.operands.at(0)));
        module.code.push_back(parse_vector_register(inst.operands.at(1)));
        module.code.push_back(parse_vector_register(inst.operands.at(2)));
        break;
      }
      case Opcode::load_mem8:
      case Opcode::load_mem16:
      case Opcode::load_mem32:
      case Opcode::load_mem64:
      case Opcode::load_sext8:
      case Opcode::load_sext16:
      case Opcode::load_sext32:
      case Opcode::lea: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        const auto mem = parse_memory_operand(inst.operands.at(1));
        module.code.push_back(mem.base);
        append_i32(module.code, mem.offset);
        break;
      }
      case Opcode::store_mem8:
      case Opcode::store_mem16:
      case Opcode::store_mem32:
      case Opcode::store_mem64: {
        const auto mem = parse_memory_operand(inst.operands.at(0));
        module.code.push_back(mem.base);
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        append_i32(module.code, mem.offset);
        break;
      }
      case Opcode::jmp: {
        if (!inst.operands.at(0).empty() && inst.operands.at(0).front() == '@') {
          const auto patch_offset = module.code.size();
          append_u32(module.code, 0);
          resolver.reference(common::Fixup{
              inst_index,
              common::FixupField::jump_offset_s32,
              common::Label{inst.operands.at(0).substr(1)},
              common::Range{},
              inst.pc,
              patch_offset,
          });
        } else {
          append_u32(module.code, static_cast<std::uint32_t>(parse_u64_value(inst.operands.at(0))));
        }
        break;
      }
      case Opcode::jeq:
      case Opcode::jne:
      case Opcode::jlt:
      case Opcode::jle:
      case Opcode::jgt:
      case Opcode::jge: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        if (!inst.operands.at(2).empty() && inst.operands.at(2).front() == '@') {
          const auto patch_offset = module.code.size();
          append_u32(module.code, 0);
          resolver.reference(common::Fixup{
              inst_index,
              common::FixupField::jump_offset_s32,
              common::Label{inst.operands.at(2).substr(1)},
              common::Range{},
              inst.pc,
              patch_offset,
          });
        } else {
          append_u32(module.code, static_cast<std::uint32_t>(parse_u64_value(inst.operands.at(2))));
        }
        break;
      }
      case Opcode::call: {
        if (!inst.operands.at(0).empty() && inst.operands.at(0).front() == '@') {
          const auto patch_offset = module.code.size();
          append_u32(module.code, 0);
          resolver.reference(common::Fixup{
              inst_index,
              common::FixupField::call_offset_s32,
              common::Label{inst.operands.at(0).substr(1)},
              common::Range{},
              inst.pc,
              patch_offset,
          });
        } else {
          append_u32(module.code, static_cast<std::uint32_t>(parse_u64_value(inst.operands.at(0))));
        }
        module.code.push_back(static_cast<std::uint8_t>(inst.operands.size() >= 2 ? parse_u64_value(inst.operands.at(1)) : 0u));
        break;
      }
      case Opcode::domain_call: {
        module.code.push_back(parse_domain_token(inst.operands.at(0)));
        append_u32(module.code, static_cast<std::uint32_t>(parse_u64_value(inst.operands.at(1))));
        module.code.push_back(static_cast<std::uint8_t>(parse_u64_value(inst.operands.at(2))));
        module.code.push_back(static_cast<std::uint8_t>(inst.operands.size() >= 4 ? parse_u64_value(inst.operands.at(3)) : 0u));
        module.code.push_back(static_cast<std::uint8_t>(inst.operands.size() >= 5 ? parse_u64_value(inst.operands.at(4)) : 0u));
        break;
      }
      case Opcode::bridge_args: {
        module.code.push_back(static_cast<std::uint8_t>(parse_u64_value(inst.operands.at(0))));
        module.code.push_back(static_cast<std::uint8_t>(inst.operands.size() >= 2 ? parse_u64_value(inst.operands.at(1)) : 0u));
        module.code.push_back(static_cast<std::uint8_t>(inst.operands.size() >= 3 ? parse_u64_value(inst.operands.at(2)) : 0u));
        break;
      }
      case Opcode::load_transient_string: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        append_u32(module.code, parse_string_id_token(inst.operands.at(1)));
        break;
      }
      case Opcode::transient_read8: {
        module.code.push_back(parse_general_register(inst.operands.at(0)));
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        module.code.push_back(parse_general_register(inst.operands.at(2)));
        break;
      }
      case Opcode::cas_u64: {
        const auto mem = parse_memory_operand(inst.operands.at(0));
        module.code.push_back(mem.base);
        module.code.push_back(parse_general_register(inst.operands.at(3)));
        append_i32(module.code, mem.offset);
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        module.code.push_back(parse_general_register(inst.operands.at(2)));
        break;
      }
      case Opcode::xchg_u64: {
        const auto mem = parse_memory_operand(inst.operands.at(0));
        module.code.push_back(mem.base);
        module.code.push_back(parse_general_register(inst.operands.at(2)));
        append_i32(module.code, mem.offset);
        module.code.push_back(parse_general_register(inst.operands.at(1)));
        break;
      }
    }
  }
  const auto resolve_result = resolver.resolve();
  if (!resolve_result.ok()) {
    throw common::ResolutionError(resolve_result);
  }
  if ((module.module_flags & VMP_FLAG_OPCODE_ENCRYPTED) != 0) {
    module.opcode_map_marker_crc32 = opcode_cryptor_for_seed(module.opcode_map_seed).sanity_marker_crc32();
  }
  return module;
}

std::string opcode_name(Opcode opcode) {
  switch (opcode) {
    case Opcode::nop: return "nop";
    case Opcode::ldi64: return "ldi64";
    case Opcode::ldi_u64: return "ldi_u64";
    case Opcode::ldi_f64: return "ldi_f64";
    case Opcode::mov: return "mov";
    case Opcode::add: return "add";
    case Opcode::sub: return "sub";
    case Opcode::mul: return "mul";
    case Opcode::div: return "div";
    case Opcode::mod: return "mod";
    case Opcode::neg: return "neg";
    case Opcode::bit_and: return "and";
    case Opcode::bit_or: return "or";
    case Opcode::bit_xor: return "xor";
    case Opcode::shl: return "shl";
    case Opcode::shr: return "shr";
    case Opcode::sar: return "sar";
    case Opcode::bit_not: return "not";
    case Opcode::popcnt: return "popcnt";
    case Opcode::clz: return "clz";
    case Opcode::ctz: return "ctz";
    case Opcode::bswap: return "bswap";
    case Opcode::cmp: return "cmp";
    case Opcode::test: return "test";
    case Opcode::setcc: return "setcc";
    case Opcode::load_mem8: return "load_mem8";
    case Opcode::load_mem16: return "load_mem16";
    case Opcode::load_mem32: return "load_mem32";
    case Opcode::load_mem64: return "load_mem64";
    case Opcode::store_mem8: return "store_mem8";
    case Opcode::store_mem16: return "store_mem16";
    case Opcode::store_mem32: return "store_mem32";
    case Opcode::store_mem64: return "store_mem64";
    case Opcode::load_sext8: return "load_sext8";
    case Opcode::load_sext16: return "load_sext16";
    case Opcode::load_sext32: return "load_sext32";
    case Opcode::lea: return "lea";
    case Opcode::jmp: return "jmp";
    case Opcode::jeq: return "jeq";
    case Opcode::jne: return "jne";
    case Opcode::jlt: return "jlt";
    case Opcode::jle: return "jle";
    case Opcode::jgt: return "jgt";
    case Opcode::jge: return "jge";
    case Opcode::call: return "call";
    case Opcode::ret: return "ret";
    case Opcode::call_indirect: return "call_indirect";
    case Opcode::jmp_indirect: return "jmp_indirect";
    case Opcode::fadd: return "fadd";
    case Opcode::fsub: return "fsub";
    case Opcode::fmul: return "fmul";
    case Opcode::fdiv: return "fdiv";
    case Opcode::fsqrt: return "fsqrt";
    case Opcode::i64_to_f64: return "i64_to_f64";
    case Opcode::f64_to_i64: return "f64_to_i64";
    case Opcode::fcmp: return "fcmp";
    case Opcode::vadd128: return "vadd128";
    case Opcode::vxor128: return "vxor128";
    case Opcode::vshuffle128: return "vshuffle128";
    case Opcode::memcpy: return "memcpy";
    case Opcode::memset: return "memset";
    case Opcode::strcmp: return "strcmp";
    case Opcode::strlen: return "strlen";
    case Opcode::cas_u64: return "cas_u64";
    case Opcode::xchg_u64: return "xchg_u64";
    case Opcode::fence: return "fence";
    case Opcode::breakpoint: return "breakpoint";
    case Opcode::trap: return "trap";
    case Opcode::syscall_proxy: return "syscall_proxy";
    case Opcode::domain_call: return "domain_call";
    case Opcode::domain_ret: return "domain_ret";
    case Opcode::bridge_args: return "bridge_args";
    case Opcode::load_transient_string: return "load_transient_string";
    case Opcode::release_transient_string: return "release_transient_string";
    case Opcode::transient_read8: return "transient_read8";
    case Opcode::transient_wipe: return "transient_wipe";
  }
  return "unknown";
}

std::string disassemble_module(const Vm1Module& module) {
  std::map<std::uint32_t, std::string> labels;
  labels[module.entry_pc] = "entry";
  for (std::size_t pc = 0; pc < module.code.size();) {
    const auto start = static_cast<std::uint32_t>(pc);
    const auto opcode = static_cast<Opcode>(read_u16_code(module.code, pc));
    switch (opcode) {
      case Opcode::jmp:
      case Opcode::call: {
        auto cursor = pc;
        const auto target = read_u32_code(module.code, cursor);
        labels.try_emplace(target, make_label(target));
        break;
      }
      case Opcode::jeq:
      case Opcode::jne:
      case Opcode::jlt:
      case Opcode::jle:
      case Opcode::jgt:
      case Opcode::jge: {
        auto cursor = pc + 2;
        const auto target = read_u32_code(module.code, cursor);
        labels.try_emplace(target, make_label(target));
        break;
      }
      default:
        break;
    }
    pc = static_cast<std::size_t>(start + instruction_size(opcode));
  }

  std::ostringstream out;
  for (std::size_t pc = 0; pc < module.code.size();) {
    if (const auto it = labels.find(static_cast<std::uint32_t>(pc)); it != labels.end()) {
      out << it->second << ":\n";
    }
    const auto opcode = static_cast<Opcode>(read_u16_code(module.code, pc));
    out << "  " << opcode_name(opcode);
    switch (opcode) {
      case Opcode::nop:
      case Opcode::ret:
      case Opcode::domain_ret:
      case Opcode::fence:
      case Opcode::breakpoint:
        break;
      case Opcode::trap:
      case Opcode::syscall_proxy:
        out << ' ' << read_u32_code(module.code, pc);
        break;
      case Opcode::ldi64: {
        const auto reg = module.code[pc++];
        out << " vr" << static_cast<unsigned>(reg) << ", " << static_cast<std::int64_t>(read_u64_code(module.code, pc));
        break;
      }
      case Opcode::ldi_u64: {
        const auto reg = module.code[pc++];
        out << " vr" << static_cast<unsigned>(reg) << ", " << read_u64_code(module.code, pc);
        break;
      }
      case Opcode::ldi_f64: {
        const auto reg = module.code[pc++];
        out << " vfr" << static_cast<unsigned>(reg) << ", " << bit_cast_double(read_u64_code(module.code, pc));
        break;
      }
      case Opcode::mov:
      case Opcode::neg:
      case Opcode::bit_not:
      case Opcode::popcnt:
      case Opcode::clz:
      case Opcode::ctz:
      case Opcode::bswap: {
        const auto dst = module.code[pc++];
        const auto src = module.code[pc++];
        out << " vr" << static_cast<unsigned>(dst) << ", vr" << static_cast<unsigned>(src);
        break;
      }
      case Opcode::setcc: {
        const auto dst = module.code[pc++];
        const auto cc = module.code[pc++];
        out << " vr" << static_cast<unsigned>(dst) << ", " << condition_name(cc);
        break;
      }
      case Opcode::release_transient_string:
      case Opcode::transient_wipe:
      case Opcode::jmp_indirect: {
        const auto reg = module.code[pc++];
        out << " vr" << static_cast<unsigned>(reg);
        break;
      }
      case Opcode::call_indirect: {
        const auto reg = module.code[pc++];
        const auto argc = module.code[pc++];
        out << " vr" << static_cast<unsigned>(reg) << ", " << static_cast<unsigned>(argc);
        break;
      }
      case Opcode::fsqrt: {
        const auto dst = module.code[pc++];
        const auto src = module.code[pc++];
        out << " vfr" << static_cast<unsigned>(dst) << ", vfr" << static_cast<unsigned>(src);
        break;
      }
      case Opcode::i64_to_f64: {
        const auto dst = module.code[pc++];
        const auto src = module.code[pc++];
        out << " vfr" << static_cast<unsigned>(dst) << ", vr" << static_cast<unsigned>(src);
        break;
      }
      case Opcode::f64_to_i64: {
        const auto dst = module.code[pc++];
        const auto src = module.code[pc++];
        out << " vr" << static_cast<unsigned>(dst) << ", vfr" << static_cast<unsigned>(src);
        break;
      }
      case Opcode::strlen: {
        const auto dst = module.code[pc++];
        const auto src = module.code[pc++];
        out << " vr" << static_cast<unsigned>(dst) << ", vr" << static_cast<unsigned>(src);
        break;
      }
      case Opcode::add:
      case Opcode::sub:
      case Opcode::mul:
      case Opcode::div:
      case Opcode::mod:
      case Opcode::bit_and:
      case Opcode::bit_or:
      case Opcode::bit_xor:
      case Opcode::shl:
      case Opcode::shr:
      case Opcode::sar:
      case Opcode::memcpy:
      case Opcode::memset:
      case Opcode::strcmp: {
        const auto dst = module.code[pc++];
        const auto lhs = module.code[pc++];
        const auto rhs = module.code[pc++];
        out << " vr" << static_cast<unsigned>(dst) << ", vr" << static_cast<unsigned>(lhs) << ", vr" << static_cast<unsigned>(rhs);
        break;
      }
      case Opcode::cmp:
      case Opcode::test: {
        const auto lhs = module.code[pc++];
        const auto rhs = module.code[pc++];
        out << " vr" << static_cast<unsigned>(lhs) << ", vr" << static_cast<unsigned>(rhs);
        break;
      }
      case Opcode::fadd:
      case Opcode::fsub:
      case Opcode::fmul:
      case Opcode::fdiv: {
        const auto dst = module.code[pc++];
        const auto lhs = module.code[pc++];
        const auto rhs = module.code[pc++];
        out << " vfr" << static_cast<unsigned>(dst) << ", vfr" << static_cast<unsigned>(lhs) << ", vfr" << static_cast<unsigned>(rhs);
        break;
      }
      case Opcode::fcmp: {
        const auto lhs = module.code[pc++];
        const auto rhs = module.code[pc++];
        out << " vfr" << static_cast<unsigned>(lhs) << ", vfr" << static_cast<unsigned>(rhs);
        break;
      }
      case Opcode::vadd128:
      case Opcode::vxor128:
      case Opcode::vshuffle128: {
        const auto dst = module.code[pc++];
        const auto lhs = module.code[pc++];
        const auto rhs = module.code[pc++];
        out << ' ' << vector_name(dst) << ", " << vector_name(lhs) << ", " << vector_name(rhs);
        break;
      }
      case Opcode::load_mem8:
      case Opcode::load_mem16:
      case Opcode::load_mem32:
      case Opcode::load_mem64:
      case Opcode::load_sext8:
      case Opcode::load_sext16:
      case Opcode::load_sext32:
      case Opcode::lea: {
        const auto dst = module.code[pc++];
        const auto base = module.code[pc++];
        const auto offset = read_i32_code(module.code, pc);
        out << " vr" << static_cast<unsigned>(dst) << ", " << memory_operand_text(base, offset);
        break;
      }
      case Opcode::store_mem8:
      case Opcode::store_mem16:
      case Opcode::store_mem32:
      case Opcode::store_mem64: {
        const auto base = module.code[pc++];
        const auto src = module.code[pc++];
        const auto offset = read_i32_code(module.code, pc);
        out << ' ' << memory_operand_text(base, offset) << ", vr" << static_cast<unsigned>(src);
        break;
      }
      case Opcode::jmp: {
        const auto target = read_u32_code(module.code, pc);
        out << " @" << labels.at(target);
        break;
      }
      case Opcode::jeq:
      case Opcode::jne:
      case Opcode::jlt:
      case Opcode::jle:
      case Opcode::jgt:
      case Opcode::jge: {
        const auto lhs = module.code[pc++];
        const auto rhs = module.code[pc++];
        const auto target = read_u32_code(module.code, pc);
        out << " vr" << static_cast<unsigned>(lhs) << ", vr" << static_cast<unsigned>(rhs) << ", @" << labels.at(target);
        break;
      }
      case Opcode::call: {
        const auto target = read_u32_code(module.code, pc);
        const auto argc = module.code[pc++];
        out << " @" << labels.at(target) << ", " << static_cast<unsigned>(argc);
        break;
      }
      case Opcode::domain_call: {
        const auto domain = module.code[pc++];
        const auto id = read_u32_code(module.code, pc);
        const auto ic = module.code[pc++];
        const auto fc = module.code[pc++];
        const auto oc = module.code[pc++];
        const char* domain_name = domain == 0 ? "native" : (domain == 1 ? "vm1" : "vm2");
        out << ' ' << domain_name << ", " << id << ", " << static_cast<unsigned>(ic) << ", " << static_cast<unsigned>(fc) << ", " << static_cast<unsigned>(oc);
        break;
      }
      case Opcode::bridge_args: {
        const auto ic = module.code[pc++];
        const auto fc = module.code[pc++];
        const auto oc = module.code[pc++];
        out << ' ' << static_cast<unsigned>(ic) << ", " << static_cast<unsigned>(fc) << ", " << static_cast<unsigned>(oc);
        break;
      }
      case Opcode::load_transient_string: {
        const auto reg = module.code[pc++];
        out << " vr" << static_cast<unsigned>(reg) << ", &sid" << read_u32_code(module.code, pc);
        break;
      }
      case Opcode::transient_read8: {
        const auto dst = module.code[pc++];
        const auto handle = module.code[pc++];
        const auto index = module.code[pc++];
        out << " vr" << static_cast<unsigned>(dst) << ", vr" << static_cast<unsigned>(handle) << ", vr" << static_cast<unsigned>(index);
        break;
      }
      case Opcode::cas_u64: {
        const auto base = module.code[pc++];
        const auto dst = module.code[pc++];
        const auto offset = read_i32_code(module.code, pc);
        const auto expected = module.code[pc++];
        const auto desired = module.code[pc++];
        out << ' ' << memory_operand_text(base, offset) << ", vr" << static_cast<unsigned>(expected) << ", vr" << static_cast<unsigned>(desired) << ", vr" << static_cast<unsigned>(dst);
        break;
      }
      case Opcode::xchg_u64: {
        const auto base = module.code[pc++];
        const auto dst = module.code[pc++];
        const auto offset = read_i32_code(module.code, pc);
        const auto src = module.code[pc++];
        out << ' ' << memory_operand_text(base, offset) << ", vr" << static_cast<unsigned>(src) << ", vr" << static_cast<unsigned>(dst);
        break;
      }
    }
    out << '\n';
  }
  for (std::size_t i = 0; i < module.const_pool.size(); ++i) {
    if (module.const_pool[i].kind == ConstKind::transient_string) {
      out << ".const string " << i << ' ' << escape_string(std::string_view(reinterpret_cast<const char*>(module.const_pool[i].bytes.data()), module.const_pool[i].bytes.size())) << '\n';
    }
  }
  return out.str();
}


namespace {
inline constexpr int kVm1HandlerTableIdentity = 0x56314D31;
}

const void* handler_table_identity() noexcept { return &kVm1HandlerTableIdentity; }

const char* Facade::status() const noexcept { return "vm1_ready"; }

}  // namespace vmp::runtime::vm1
