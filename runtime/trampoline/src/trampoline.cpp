#include <vmp/runtime/trampoline/trampoline.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

#if defined(_MSC_VER)
#include <malloc.h>
#define VMP_TRAMPOLINE_ALLOCA _alloca
#define VMP_TRAMPOLINE_NOINLINE __declspec(noinline)
#include <intrin.h>
#else
#include <alloca.h>
#define VMP_TRAMPOLINE_ALLOCA alloca
#define VMP_TRAMPOLINE_NOINLINE __attribute__((noinline))
#endif

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/env_detectors/detectors.h>
#include <vmp/runtime/stack_probe/probe.h>
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/trusted_oracle/oracle.h>

#ifndef VMP_ARCH_STR
#define VMP_ARCH_STR "unknown"
#endif

#ifndef VMP_PLATFORM_STR
#define VMP_PLATFORM_STR "unknown"
#endif

namespace vmp::runtime::trampoline {
namespace {

constexpr std::string_view kTokenInfoV2 = "vmp.trampoline.token.v2";
constexpr std::string_view kHmacInfoV2 = "vmp.trampoline.hmac.v2";
constexpr std::string_view kStaticHmacIkmV2 = "stack-table.static.v2";
constexpr std::string_view kEphemeralHmacIkmV2 = "dispatch.ephemeral.v2";

struct BundleHeaderV1 {
  char magic[4];
  std::uint16_t version;
  std::uint8_t arch;
  std::uint8_t reserved0;
  std::uint32_t record_count;
  KeyContextId key_context_id;
  std::uint32_t code_blob_size;
  std::uint32_t reserved1;
};

using BundleHeaderV2 = BundleHeaderV1;

struct BundleRecordWireV1 {
  std::uint64_t token;
  std::uint64_t original_address;
  std::uint64_t relocated_offset;
  std::uint32_t code_size;
  std::uint16_t symbol_size;
  std::uint8_t reserved0;
  std::uint8_t reserved1;
};

struct BundleRecordWireV2 {
  TokenBytes token;
  std::uint64_t original_address;
  std::uint64_t relocated_offset;
  std::uint32_t code_size;
  std::uint16_t symbol_size;
  std::uint8_t reserved0;
  std::uint8_t reserved1;
};

struct EntrySnapshot {
  bool found = false;
  std::uint64_t relocated_address = 0;
  std::uint64_t active_seq = 0;
  std::uint64_t last_consumed_seq = 0;
  TargetPrologueFingerprint expected_fingerprint{};
};

std::uint32_t low32(std::uint64_t value) noexcept {
  return static_cast<std::uint32_t>(value & 0xffff'ffffull);
}

bool token_is_zero(const TokenBytes& token) noexcept {
  return std::all_of(token.begin(), token.end(), [](std::uint8_t byte) { return byte == 0; });
}

void append_le32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xffu));
  out.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xffu));
  out.push_back(static_cast<std::uint8_t>((value >> 16u) & 0xffu));
  out.push_back(static_cast<std::uint8_t>((value >> 24u) & 0xffu));
}

void append_le64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (unsigned shift = 0; shift < 64; shift += 8) {
    out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
  }
}

void append_bytes(std::vector<std::uint8_t>& out, const TokenBytes& value) {
  out.insert(out.end(), value.begin(), value.end());
}

void append_word32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  append_le32(out, value);
}

std::int64_t checked_rel32(std::uint64_t from_after_jmp, std::uint64_t target) {
  const auto rel = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(from_after_jmp);
  if (rel < static_cast<std::int64_t>(INT32_MIN) || rel > static_cast<std::int64_t>(INT32_MAX)) {
    throw std::runtime_error("trampoline: rel32 target out of range");
  }
  return rel;
}

std::int64_t checked_aligned_branch(std::uint64_t branch_pc, std::uint64_t target, std::int64_t min_imm, std::int64_t max_imm) {
  const auto rel = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(branch_pc);
  if ((rel & 0x3) != 0) {
    throw std::runtime_error("trampoline: branch target must be 4-byte aligned");
  }
  const auto imm = rel >> 2;
  if (imm < min_imm || imm > max_imm) {
    throw std::runtime_error("trampoline: branch target out of range");
  }
  return imm;
}

std::string hex_u64(std::uint64_t value) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::setw(16) << std::setfill('0') << value;
  return oss.str();
}

std::vector<std::uint8_t> namespaced_salt(std::vector<std::uint8_t> base, std::string_view info) {
  base.insert(base.end(), info.begin(), info.end());
  return base;
}

std::vector<std::uint8_t> token_input(const KeyContextId& key_context_id,
                                      std::uint64_t original_address,
                                      std::string_view symbol_name) {
  std::vector<std::uint8_t> input;
  input.reserve(key_context_id.size() + sizeof(original_address) + symbol_name.size());
  input.insert(input.end(), key_context_id.begin(), key_context_id.end());
  append_le64(input, original_address);
  input.insert(input.end(), symbol_name.begin(), symbol_name.end());
  return input;
}

std::vector<std::uint8_t> stack_table_message(const StackFunctionTableView& view) {
  std::vector<std::uint8_t> message;
  message.reserve(sizeof(std::uint32_t) * 2 + view.header->entry_count * sizeof(StackFunctionRecord));
  append_le32(message, view.header->version);
  append_le32(message, view.header->entry_count);
  for (std::uint32_t i = 0; i < view.header->entry_count; ++i) {
    append_bytes(message, view.records[i].token);
    append_le64(message, view.records[i].original_address);
    append_le64(message, view.records[i].relocated_address);
    append_le64(message, view.records[i].dispatch_seq);
  }
  return message;
}

std::vector<std::uint8_t> hmac_bytes_vec(const HmacBytes& bytes) {
  return std::vector<std::uint8_t>(bytes.begin(), bytes.end());
}

std::string arch_label() {
  return std::string(VMP_ARCH_STR);
}

std::string platform_label() {
  return std::string(VMP_PLATFORM_STR);
}

bool constant_time_equal(const std::uint8_t* lhs, const std::uint8_t* rhs, std::size_t size) noexcept {
  return vmp::runtime::strings::constant_time_equal(lhs, rhs, size);
}

std::vector<std::uint8_t> read_region_bytes(const void* address, std::size_t width) {
  if (address == nullptr || width == 0) {
    return {};
  }
  std::vector<std::uint8_t> out(width, 0);
  std::memcpy(out.data(), address, width);
  return out;
}

bool region_is_readable(const void* address, std::size_t width) {
  if (address == nullptr || width == 0) {
    return false;
  }
#if defined(__linux__) || defined(__ANDROID__)
  const auto target_begin = reinterpret_cast<std::uintptr_t>(address);
  const auto target_end = target_begin + width;
  int fd = vmp::runtime::trusted_oracle::DirectSyscall::open_readonly("/proc/self/maps");
  if (fd < 0) {
    return false;
  }
  std::string maps;
  std::array<char, 512> buffer{};
  for (;;) {
    const auto got = vmp::runtime::trusted_oracle::DirectSyscall::read(fd, buffer.data(), buffer.size());
    if (got <= 0) {
      break;
    }
    maps.append(buffer.data(), static_cast<std::size_t>(got));
  }
  (void)vmp::runtime::trusted_oracle::DirectSyscall::close(fd);
  std::istringstream iss(maps);
  std::string line;
  while (std::getline(iss, line)) {
    std::uintptr_t start = 0;
    std::uintptr_t end = 0;
    char perms[5] = {};
    if (std::sscanf(line.c_str(), "%lx-%lx %4s", &start, &end, perms) == 3) {
      if (perms[0] == 'r' && target_begin >= start && target_end <= end) {
        return true;
      }
    }
  }
  return false;
#else
  return true;
#endif
}

std::vector<std::uint8_t> hash_region(const void* address, std::size_t width) {
  return vmp::runtime::strings::sha256(read_region_bytes(address, width));
}

TargetPrologueFingerprint digest_prefix_16(const std::vector<std::uint8_t>& digest) {
  TargetPrologueFingerprint out{};
  if (digest.size() >= out.size()) {
    std::copy_n(digest.begin(), out.size(), out.begin());
  }
  return out;
}

std::string hex_fingerprint(const TargetPrologueFingerprint& fingerprint) {
  return vmp::runtime::strings::hex_encode(std::vector<std::uint8_t>(fingerprint.begin(), fingerprint.end()));
}

std::uintptr_t read_stack_canary_default() noexcept {
#if defined(__x86_64__) || defined(_M_X64)
  std::uintptr_t value = 0;
  asm volatile("mov %%fs:0x28, %0" : "=r"(value));
  return value;
#elif defined(__i386__) || defined(_M_IX86)
  std::uintptr_t value = 0;
  asm volatile("mov %%gs:0x14, %0" : "=r"(value));
  return value;
#else
  volatile std::uintptr_t local = reinterpret_cast<std::uintptr_t>(&local);
  return local;
#endif
}

std::uint64_t read_counter_fallback() noexcept {
#if defined(__x86_64__) || defined(_M_X64)
  unsigned aux = 0;
  return __rdtscp(&aux);
#else
  return static_cast<std::uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
#endif
}

std::uintptr_t capture_return_address_default() noexcept {
#if defined(_MSC_VER)
  return reinterpret_cast<std::uintptr_t>(_ReturnAddress());
#elif defined(__GNUC__) || defined(__clang__)
  return reinterpret_cast<std::uintptr_t>(__builtin_extract_return_addr(__builtin_return_address(0)));
#else
  return 0;
#endif
}

bool fingerprint_is_zero(const TargetPrologueFingerprint& fingerprint) noexcept {
  return std::all_of(fingerprint.begin(), fingerprint.end(), [](std::uint8_t byte) { return byte == 0; });
}

}  // namespace

struct StackFunctionTable::AuditHarness {
  explicit AuditHarness(const std::filesystem::path& path)
      : writer(path.empty() ? vmp::runtime::audit::AuditWriter::default_path() : path),
        dispatcher(writer, vmp::runtime::audit::ReactionPolicy::audit_then_delayed_exit) {}

  vmp::runtime::audit::AuditWriter writer;
  vmp::runtime::audit::ReactionDispatcher dispatcher;
};

TokenBytes token_from_low64(std::uint64_t low) noexcept {
  return token_from_halves(low, 0);
}

TokenBytes token_from_halves(std::uint64_t low, std::uint64_t high) noexcept {
  TokenBytes token{};
  for (unsigned shift = 0; shift < 64; shift += 8) {
    token[shift / 8u] = static_cast<std::uint8_t>((low >> shift) & 0xffu);
    token[8u + shift / 8u] = static_cast<std::uint8_t>((high >> shift) & 0xffu);
  }
  return token;
}

std::uint64_t token_low64(const TokenBytes& token) noexcept {
  std::uint64_t value = 0;
  for (unsigned shift = 0; shift < 64; shift += 8) {
    value |= static_cast<std::uint64_t>(token[shift / 8u]) << shift;
  }
  return value;
}

std::uint64_t token_high64(const TokenBytes& token) noexcept {
  std::uint64_t value = 0;
  for (unsigned shift = 0; shift < 64; shift += 8) {
    value |= static_cast<std::uint64_t>(token[8u + shift / 8u]) << shift;
  }
  return value;
}

std::string token_hex(const TokenBytes& token) {
  return "0x" + vmp::runtime::strings::hex_encode(std::vector<std::uint8_t>(token.begin(), token.end()));
}

bool TokenEntry::operator==(const TokenEntry& other) const noexcept {
  return token == other.token && original_address == other.original_address &&
         relocated_address == other.relocated_address && symbol_name == other.symbol_name &&
         key_context_id == other.key_context_id;
}

std::vector<std::uint8_t> TrampolineBundle::serialize() const {
  BundleHeaderV2 header{{'V', 'M', 'P', 'T'},
                        kTrampolineBundleVersion,
                        static_cast<std::uint8_t>(arch),
                        0,
                        static_cast<std::uint32_t>(records.size()),
                        key_context_id,
                        static_cast<std::uint32_t>(code_blob.size()),
                        0};
  std::vector<std::uint8_t> out(sizeof(BundleHeaderV2), 0);
  std::memcpy(out.data(), &header, sizeof(header));
  for (const auto& record : records) {
    if (record.entry.symbol_name.size() > 0xffffu) {
      throw std::runtime_error("trampoline: symbol name too large");
    }
    BundleRecordWireV2 wire{};
    wire.token = record.entry.token;
    wire.original_address = record.entry.original_address;
    wire.relocated_offset = record.relocated_offset;
    wire.code_size = record.code_size;
    wire.symbol_size = static_cast<std::uint16_t>(record.entry.symbol_name.size());
    const auto old_size = out.size();
    out.resize(old_size + sizeof(wire));
    std::memcpy(out.data() + old_size, &wire, sizeof(wire));
    out.insert(out.end(), record.entry.symbol_name.begin(), record.entry.symbol_name.end());
  }
  out.insert(out.end(), code_blob.begin(), code_blob.end());
  return out;
}

TrampolineBundle TrampolineBundle::deserialize(const std::vector<std::uint8_t>& bytes) {
  if (bytes.size() < sizeof(BundleHeaderV1)) {
    throw std::runtime_error("trampoline: serialized bundle too small");
  }
  BundleHeaderV1 header{};
  std::memcpy(&header, bytes.data(), sizeof(header));
  if (std::memcmp(header.magic, "VMPT", 4) != 0) {
    throw std::runtime_error("trampoline: bad bundle magic");
  }
  if (header.version != 1u && header.version != kTrampolineBundleVersion) {
    throw std::runtime_error("trampoline: unsupported bundle version");
  }
  TrampolineBundle bundle;
  bundle.arch = static_cast<TrampolineArch>(header.arch);
  bundle.key_context_id = header.key_context_id;
  std::size_t offset = sizeof(BundleHeaderV1);
  for (std::uint32_t i = 0; i < header.record_count; ++i) {
    TokenBytes token{};
    std::uint64_t original_address = 0;
    std::uint64_t relocated_offset = 0;
    std::uint32_t code_size = 0;
    std::uint16_t symbol_size = 0;
    if (header.version == 1u) {
      if (offset + sizeof(BundleRecordWireV1) > bytes.size()) {
        throw std::runtime_error("trampoline: truncated bundle record");
      }
      BundleRecordWireV1 wire{};
      std::memcpy(&wire, bytes.data() + offset, sizeof(wire));
      offset += sizeof(wire);
      token = token_from_low64(wire.token);
      original_address = wire.original_address;
      relocated_offset = wire.relocated_offset;
      code_size = wire.code_size;
      symbol_size = wire.symbol_size;
    } else {
      if (offset + sizeof(BundleRecordWireV2) > bytes.size()) {
        throw std::runtime_error("trampoline: truncated bundle record");
      }
      BundleRecordWireV2 wire{};
      std::memcpy(&wire, bytes.data() + offset, sizeof(wire));
      offset += sizeof(wire);
      token = wire.token;
      original_address = wire.original_address;
      relocated_offset = wire.relocated_offset;
      code_size = wire.code_size;
      symbol_size = wire.symbol_size;
    }
    if (offset + symbol_size > bytes.size()) {
      throw std::runtime_error("trampoline: truncated bundle symbol name");
    }
    TrampolineBundleRecord record;
    record.entry.token = token;
    record.entry.original_address = original_address;
    record.entry.symbol_name.assign(reinterpret_cast<const char*>(bytes.data() + offset), symbol_size);
    record.entry.key_context_id = header.key_context_id;
    record.relocated_offset = relocated_offset;
    record.code_size = code_size;
    offset += symbol_size;
    bundle.records.push_back(std::move(record));
  }
  if (offset + header.code_blob_size > bytes.size()) {
    throw std::runtime_error("trampoline: truncated bundle code blob");
  }
  bundle.code_blob.assign(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                          bytes.begin() + static_cast<std::ptrdiff_t>(offset + header.code_blob_size));
  return bundle;
}

std::vector<TokenEntry> TrampolineBundle::instantiate(std::uint64_t executable_base) const {
  std::vector<TokenEntry> out;
  out.reserve(records.size());
  for (const auto& record : records) {
    TokenEntry entry = record.entry;
    entry.relocated_address = executable_base + record.relocated_offset;
    out.push_back(std::move(entry));
  }
  return out;
}

TokenBytes TokenManager::derive_token(const KeyContextId& key_context_id,
                                      std::uint64_t original_address,
                                      std::string_view symbol_name) {
  auto salt = namespaced_salt(std::vector<std::uint8_t>(key_context_id.begin(), key_context_id.end()), kTokenInfoV2);
  auto input = token_input(key_context_id, original_address, symbol_name);
  const auto prk = vmp::runtime::strings::hkdf_extract_sha256(salt, input);
  const auto okm = vmp::runtime::strings::hkdf_expand_sha256(prk, vmp::runtime::strings::to_bytes(kTokenInfoV2), kTokenBytesSize);
  TokenBytes token{};
  std::copy(okm.begin(), okm.end(), token.begin());
  if (token_is_zero(token)) {
    token[0] = 1;
  }
  vmp::runtime::strings::secure_memzero(salt.data(), salt.size());
  vmp::runtime::strings::secure_memzero(input.data(), input.size());
  return token;
}

TokenEntry TokenManager::register_entry(const KeyContextId& key_context_id,
                                        std::uint64_t original_address,
                                        std::uint64_t relocated_address,
                                        std::string symbol_name) {
  const auto token = derive_token(key_context_id, original_address, symbol_name);
  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto& existing : entries_) {
    if (existing.token == token && existing.original_address == original_address && existing.key_context_id == key_context_id) {
      return existing;
    }
  }
  TokenEntry entry;
  entry.token = token;
  entry.original_address = original_address;
  entry.relocated_address = relocated_address;
  entry.symbol_name = std::move(symbol_name);
  entry.key_context_id = key_context_id;
  entries_.push_back(entry);
  return entry;
}

const TokenEntry* TokenManager::find(const TokenBytes& token) const noexcept {
  const auto it = std::find_if(entries_.begin(), entries_.end(), [token](const TokenEntry& entry) {
    return entry.token == token;
  });
  return it == entries_.end() ? nullptr : &*it;
}

DispatchTicket TokenManager::issue_dispatch_ticket(const TokenBytes& token) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = std::find_if(entries_.begin(), entries_.end(), [token](const TokenEntry& entry) {
    return entry.token == token;
  });
  if (it == entries_.end()) {
    return DispatchTicket{token, 0};
  }
  const auto dispatch_seq = next_dispatch_seq_.fetch_add(1, std::memory_order_relaxed);
  it->dispatch_seq = dispatch_seq;
  return DispatchTicket{token, dispatch_seq};
}

TrampolineArch trampoline_arch_from_string(std::string_view value) {
  if (value == "x86") return TrampolineArch::x86;
  if (value == "x64") return TrampolineArch::x64;
  if (value == "arm") return TrampolineArch::arm;
  if (value == "arm64") return TrampolineArch::arm64;
  throw std::runtime_error("trampoline: unsupported architecture string");
}

std::string to_string(TrampolineArch arch) {
  switch (arch) {
    case TrampolineArch::x86: return "x86";
    case TrampolineArch::x64: return "x64";
    case TrampolineArch::arm: return "arm";
    case TrampolineArch::arm64: return "arm64";
  }
  throw std::runtime_error("trampoline: unknown architecture enum");
}

TrampolineCode generate_trampoline(TrampolineArch arch,
                                   const TokenBytes& token,
                                   std::uint64_t site_address,
                                   std::uint64_t dispatcher_address) {
  TrampolineCode out;
  out.arch = arch;
  out.token = token;
  out.site_address = site_address;
  out.dispatcher_address = dispatcher_address;

  switch (arch) {
    case TrampolineArch::x64: {
      out.bytes = {0x48, 0x8B, 0x05};
      append_le32(out.bytes, 0x0cu);
      out.bytes.insert(out.bytes.end(), {0x48, 0x8B, 0x15});
      append_le32(out.bytes, 0x0du);
      out.bytes.push_back(0xE9);
      append_le32(out.bytes, static_cast<std::uint32_t>(checked_rel32(site_address + 19u, dispatcher_address)));
      append_bytes(out.bytes, token);
      break;
    }
    case TrampolineArch::x86: {
      out.bytes = {0xB8};
      append_le32(out.bytes, low32(token_low64(token)));
      out.bytes.push_back(0xE9);
      append_le32(out.bytes, static_cast<std::uint32_t>(checked_rel32(site_address + 10u, dispatcher_address)));
      out.bytes.push_back(0x90);
      break;
    }
    case TrampolineArch::arm64: {
      const auto token32 = low32(token_low64(token));
      const std::uint16_t lo = static_cast<std::uint16_t>(token32 & 0xffffu);
      const std::uint16_t hi = static_cast<std::uint16_t>((token32 >> 16u) & 0xffffu);
      const std::uint32_t movz = 0xD2800000u | (static_cast<std::uint32_t>(lo) << 5u) | 16u;
      const std::uint32_t movk = 0xF2800000u | (1u << 21u) | (static_cast<std::uint32_t>(hi) << 5u) | 16u;
      const auto imm26 = checked_aligned_branch(site_address + 8u, dispatcher_address, -(1ll << 25), (1ll << 25) - 1);
      const std::uint32_t branch = 0x14000000u | (static_cast<std::uint32_t>(imm26) & 0x03ffffffu);
      append_word32(out.bytes, movz);
      append_word32(out.bytes, movk);
      append_word32(out.bytes, branch);
      break;
    }
    case TrampolineArch::arm: {
      const auto imm24 = checked_aligned_branch(site_address + 12u, dispatcher_address, -(1ll << 23), (1ll << 23) - 1);
      append_word32(out.bytes, 0xE59FC000u);
      append_word32(out.bytes, 0xEA000000u | (static_cast<std::uint32_t>(imm24) & 0x00ffffffu));
      append_word32(out.bytes, low32(token_low64(token)));
      break;
    }
  }

  return out;
}

StackFunctionTable::StackFunctionTable(std::vector<TokenEntry> entries,
                                       KeyContextId key_context_id,
                                       std::filesystem::path audit_path)
    : entries_(std::move(entries)),
      key_context_id_(key_context_id),
      hmac_key_(derive_hmac_key(key_context_id)),
      audit_path_(std::move(audit_path)),
      audit_harness_(std::make_unique<AuditHarness>(audit_path_)) {
  initialize_target_prologue_fingerprints();
}

StackFunctionTable::~StackFunctionTable() = default;

HmacBytes StackFunctionTable::derive_hmac_key(const KeyContextId& key_context_id) {
  auto salt = namespaced_salt(std::vector<std::uint8_t>(key_context_id.begin(), key_context_id.end()), kHmacInfoV2);
  const auto prk = vmp::runtime::strings::hkdf_extract_sha256(salt, vmp::runtime::strings::to_bytes(kStaticHmacIkmV2));
  const auto okm = vmp::runtime::strings::hkdf_expand_sha256(prk, vmp::runtime::strings::to_bytes(kHmacInfoV2), kTrampolineHmacSize);
  HmacBytes out{};
  std::copy(okm.begin(), okm.end(), out.begin());
  vmp::runtime::strings::secure_memzero(salt.data(), salt.size());
  return out;
}

TargetPrologueFingerprint StackFunctionTable::fingerprint_target_prologue(std::uint64_t address) {
  if (address == 0) {
    return {};
  }
  const auto* ptr = reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address));
  if (!region_is_readable(ptr, kTargetPrologueWindowBytes)) {
    return {};
  }
  const auto digest = hash_region(ptr, kTargetPrologueWindowBytes);
  return digest_prefix_16(digest);
}

void StackFunctionTable::initialize_target_prologue_fingerprints() {
  std::lock_guard<std::mutex> lock(state_mutex_);
  for (auto& entry : entries_) {
    if (entry.relocated_address != 0 && fingerprint_is_zero(entry.target_prologue_fingerprint)) {
      entry.target_prologue_fingerprint = fingerprint_target_prologue(entry.relocated_address);
    }
  }
}

vmp::runtime::audit::ReactionDispatcher& StackFunctionTable::reaction_dispatcher() const noexcept {
  return audit_harness_->dispatcher;
}

StackFunctionTableView StackFunctionTable::materialize_into(std::uint8_t* raw, std::size_t raw_size) const {
  return materialize_into(raw, raw_size, hmac_key_);
}

StackFunctionTableView StackFunctionTable::materialize_into(std::uint8_t* raw,
                                                            std::size_t raw_size,
                                                            const HmacBytes& hmac_key) const {
  const auto expected = sizeof(StackTableHeader) + entries_.size() * sizeof(StackFunctionRecord);
  if (raw_size < expected) {
    throw std::runtime_error("trampoline: insufficient stack frame for materialized table");
  }
  auto* header = reinterpret_cast<StackTableHeader*>(raw);
  auto* records = reinterpret_cast<StackFunctionRecord*>(raw + sizeof(StackTableHeader));
  *header = StackTableHeader{};
  header->entry_count = static_cast<std::uint32_t>(entries_.size());
  {
    std::lock_guard<std::mutex> lock(state_mutex_);
    for (std::size_t i = 0; i < entries_.size(); ++i) {
      records[i].token = entries_[i].token;
      records[i].original_address = entries_[i].original_address;
      records[i].relocated_address = entries_[i].relocated_address;
      records[i].dispatch_seq = entries_[i].dispatch_seq;
    }
  }
  StackFunctionTableView view{header, records, expected};
  const auto message = stack_table_message(view);
  const auto digest = vmp::runtime::strings::hmac_sha256(hmac_bytes_vec(hmac_key), message);
  std::copy(digest.begin(), digest.end(), header->hmac.begin());
  return view;
}

bool StackFunctionTable::verify_view(const StackFunctionTableView& view) const {
  return verify_view(view, hmac_key_);
}

bool StackFunctionTable::verify_view(const StackFunctionTableView& view, const HmacBytes& hmac_key) const {
  if (view.header == nullptr || view.records == nullptr) {
    return false;
  }
  if (view.header->version != kStackFunctionTableVersion) {
    return false;
  }
  const auto message = stack_table_message(view);
  const auto digest = vmp::runtime::strings::hmac_sha256(hmac_bytes_vec(hmac_key), message);
  return constant_time_equal(digest.data(), view.header->hmac.data(), view.header->hmac.size());
}

void StackFunctionTable::with_materialized_view(const std::function<void(StackFunctionTableView&)>& visitor) const {
  const auto frame_size = sizeof(StackTableHeader) + entries_.size() * sizeof(StackFunctionRecord);
  auto* raw = static_cast<std::uint8_t*>(VMP_TRAMPOLINE_ALLOCA(frame_size == 0 ? 1 : frame_size));
  std::memset(raw, 0, frame_size == 0 ? 1 : frame_size);
  auto view = materialize_into(raw, frame_size);
  visitor(view);
  vmp::runtime::strings::secure_memzero(raw, frame_size == 0 ? 1 : frame_size);
}

DispatchTicket StackFunctionTable::issue_dispatch_ticket(const TokenBytes& token) const {
  std::lock_guard<std::mutex> lock(state_mutex_);
  auto it = std::find_if(entries_.begin(), entries_.end(), [token](const TokenEntry& entry) {
    return entry.token == token;
  });
  if (it == entries_.end()) {
    return DispatchTicket{token, 0};
  }
  const auto dispatch_seq = next_dispatch_seq_.fetch_add(1, std::memory_order_relaxed);
  it->dispatch_seq = dispatch_seq;
  return DispatchTicket{token, dispatch_seq};
}

void StackFunctionTable::report_invalid_token(const TokenBytes& token) const {
  auto record = vmp::runtime::audit::make_event(
      "invalid_token_access",
      std::string("token=") + token_hex(token),
      token_low64(token),
      "runtime/trampoline",
      "dispatcher",
      0,
      arch_label(),
      platform_label());
  audit_harness_->dispatcher.dispatch(record, vmp::runtime::audit::ReactionPolicy::audit_then_delayed_exit);
}

void StackFunctionTable::report_integrity_failure() const {
  auto record = vmp::runtime::audit::make_event(
      "stack_function_table_tamper",
      "stack function table HMAC mismatch",
      0,
      "runtime/trampoline",
      "dispatcher",
      0,
      arch_label(),
      platform_label());
  audit_harness_->dispatcher.dispatch(record, vmp::runtime::audit::ReactionPolicy::audit_then_delayed_exit);
}

void StackFunctionTable::report_replay_detected(const TokenBytes& token,
                                                std::uint64_t dispatch_seq,
                                                std::uint64_t expected_seq,
                                                std::uint64_t last_consumed_seq) const {
  auto record = vmp::runtime::audit::make_event(
      "replay_detected",
      "token=" + token_hex(token) +
          " dispatch_seq=" + hex_u64(dispatch_seq) +
          " expected_seq=" + hex_u64(expected_seq) +
          " last_consumed_seq=" + hex_u64(last_consumed_seq),
      token_low64(token),
      "runtime/trampoline",
      "dispatcher",
      0,
      arch_label(),
      platform_label());
  audit_harness_->dispatcher.dispatch(record, vmp::runtime::audit::ReactionPolicy::audit_then_delayed_exit);
}

void StackFunctionTable::report_target_prologue_tamper(const TokenBytes& token,
                                                       std::uint64_t relocated_address,
                                                       const TargetPrologueFingerprint& expected,
                                                       const TargetPrologueFingerprint& observed) const {
  auto record = vmp::runtime::audit::make_event(
      "target_prologue_tampered",
      "token=" + token_hex(token) +
          " relocated_address=" + hex_u64(relocated_address) +
          " expected=" + hex_fingerprint(expected) +
          " observed=" + hex_fingerprint(observed),
      relocated_address,
      "runtime/trampoline",
      "dispatcher",
      0,
      arch_label(),
      platform_label());
  audit_harness_->dispatcher.dispatch(record, vmp::runtime::audit::ReactionPolicy::audit_then_delayed_exit);
}

DispatcherResult StackFunctionTable::resolve(const TokenBytes& token) const {
  const auto ticket = issue_dispatch_ticket(token);
  return resolve(ticket, hmac_key_);
}

DispatcherResult StackFunctionTable::resolve(const DispatchTicket& ticket, const HmacBytes& dispatch_hmac_key) const {
  DispatcherResult result;
  result.dispatch_seq = ticket.dispatch_seq;
  result.dispatcher_self_hash_ok = true;
  result.target_prologue_ok = true;
  result.replay_ok = true;

  const auto frame_size = sizeof(StackTableHeader) + entries_.size() * sizeof(StackFunctionRecord);
  auto* raw = static_cast<std::uint8_t*>(VMP_TRAMPOLINE_ALLOCA(frame_size == 0 ? 1 : frame_size));
  std::memset(raw, 0, frame_size == 0 ? 1 : frame_size);
  auto view = materialize_into(raw, frame_size, dispatch_hmac_key);

  result.stack_table_ok = verify_view(view, dispatch_hmac_key);
  if (!result.stack_table_ok) {
    report_integrity_failure();
    vmp::runtime::strings::secure_memzero(raw, frame_size == 0 ? 1 : frame_size);
    return result;
  }

  const StackFunctionRecord* matched = nullptr;
  for (std::uint32_t i = 0; i < view.header->entry_count; ++i) {
    if (view.records[i].token == ticket.token) {
      matched = &view.records[i];
      break;
    }
  }
  if (matched == nullptr) {
    report_invalid_token(ticket.token);
    result.integrity_ok = true;
    vmp::runtime::strings::secure_memzero(raw, frame_size == 0 ? 1 : frame_size);
    return result;
  }

  result.token_found = true;
  result.resolved_address = matched->relocated_address;

  EntrySnapshot snapshot;
  {
    std::lock_guard<std::mutex> lock(state_mutex_);
    auto it = std::find_if(entries_.begin(), entries_.end(), [&](const TokenEntry& entry) {
      return entry.token == ticket.token;
    });
    if (it != entries_.end()) {
      snapshot.found = true;
      snapshot.relocated_address = it->relocated_address;
      snapshot.active_seq = it->dispatch_seq;
      snapshot.last_consumed_seq = it->last_consumed_dispatch_seq;
      snapshot.expected_fingerprint = it->target_prologue_fingerprint;
    }
  }

  const auto consume_ticket_if_current = [&]() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    auto it = std::find_if(entries_.begin(), entries_.end(), [&](const TokenEntry& entry) {
      return entry.token == ticket.token;
    });
    if (it != entries_.end() && it->dispatch_seq == ticket.dispatch_seq) {
      it->last_consumed_dispatch_seq = ticket.dispatch_seq;
      it->dispatch_seq = 0;
    }
  };

  if (!snapshot.found) {
    report_invalid_token(ticket.token);
    result.token_found = false;
    result.integrity_ok = true;
    vmp::runtime::strings::secure_memzero(raw, frame_size == 0 ? 1 : frame_size);
    return result;
  }

  const bool replay_mismatch = ticket.dispatch_seq == 0 ||
                               snapshot.active_seq != ticket.dispatch_seq ||
                               matched->dispatch_seq != ticket.dispatch_seq ||
                               ticket.dispatch_seq <= snapshot.last_consumed_seq;
  if (replay_mismatch) {
    result.replay_ok = false;
    report_replay_detected(ticket.token, ticket.dispatch_seq, snapshot.active_seq, snapshot.last_consumed_seq);
    consume_ticket_if_current();
    vmp::runtime::strings::secure_memzero(raw, frame_size == 0 ? 1 : frame_size);
    return result;
  }

  const auto observed_fingerprint = fingerprint_target_prologue(snapshot.relocated_address);
  if (!constant_time_equal(snapshot.expected_fingerprint.data(),
                           observed_fingerprint.data(),
                           snapshot.expected_fingerprint.size())) {
    result.target_prologue_ok = false;
    report_target_prologue_tamper(ticket.token,
                                  snapshot.relocated_address,
                                  snapshot.expected_fingerprint,
                                  observed_fingerprint);
    consume_ticket_if_current();
    vmp::runtime::strings::secure_memzero(raw, frame_size == 0 ? 1 : frame_size);
    return result;
  }

  (void)vmp::runtime::stack_probe::default_stack_probe().maybe_probe(
      vmp::runtime::stack_probe::ProbeRequest{
          vmp::runtime::stack_probe::selector_low12(token_low64(ticket.token)),
          vmp::runtime::stack_probe::ProbeTriggerSite::trampoline_target_prologue,
          vmp::runtime::stack_probe::kDefaultMaxFrames},
      &audit_harness_->dispatcher);
  consume_ticket_if_current();
  result.integrity_ok = true;
  vmp::runtime::strings::secure_memzero(raw, frame_size == 0 ? 1 : frame_size);
  return result;
}

Dispatcher::Dispatcher(const StackFunctionTable& table, DispatcherOptions options)
    : table_(table), options_(std::move(options)) {
  self_hash_region_ = options_.self_hash_region.address != nullptr ? options_.self_hash_region : default_self_hash_region();
  if (self_hash_region_.address != nullptr && self_hash_region_.size == 0) {
    self_hash_region_.size = kDispatcherSelfHashBytes;
  }
  if (self_hash_region_.address != nullptr && self_hash_region_.size != 0) {
    dispatcher_self_hash_ = hash_region(self_hash_region_.address, self_hash_region_.size);
  }
}

DispatchTicket Dispatcher::issue_dispatch_ticket(const TokenBytes& token) const {
  return table_.issue_dispatch_ticket(token);
}

DispatcherMonitoredRegion Dispatcher::default_self_hash_region() noexcept {
  return DispatcherMonitoredRegion{reinterpret_cast<const void*>(&Dispatcher::dispatch_entry_bridge),
                                   kDispatcherSelfHashBytes};
}

bool Dispatcher::verify_self_hash() const {
  if (self_hash_region_.address == nullptr || self_hash_region_.size == 0 || dispatcher_self_hash_.empty()) {
    return true;
  }
  const auto observed = hash_region(self_hash_region_.address, self_hash_region_.size);
  return observed.size() == dispatcher_self_hash_.size() &&
         constant_time_equal(observed.data(), dispatcher_self_hash_.data(), dispatcher_self_hash_.size());
}

void Dispatcher::report_dispatcher_tamper() const {
  auto record = vmp::runtime::audit::make_event(
      "dispatcher_tampered",
      "dispatcher self-hash mismatch",
      reinterpret_cast<std::uintptr_t>(self_hash_region_.address),
      "runtime/trampoline",
      "dispatcher",
      0,
      arch_label(),
      platform_label());
  table_.reaction_dispatcher().dispatch(record, vmp::runtime::audit::ReactionPolicy::audit_then_delayed_exit);
}

HmacBytes Dispatcher::derive_ephemeral_hmac_key(std::uintptr_t return_address) const {
  const auto stack_canary = options_.test_hooks.stack_canary_provider
                                ? options_.test_hooks.stack_canary_provider()
                                : read_stack_canary_default();
  const auto effective_return_address = options_.test_hooks.return_address_provider
                                            ? options_.test_hooks.return_address_provider()
                                            : return_address;

  std::uint64_t nonce = 0;
  if (options_.test_hooks.nonce_provider) {
    nonce = options_.test_hooks.nonce_provider();
  } else {
    const auto got = vmp::runtime::trusted_oracle::DirectSyscall::getrandom(&nonce, sizeof(nonce), 0);
    if (got != static_cast<std::ptrdiff_t>(sizeof(nonce))) {
      nonce = read_counter_fallback() ^ static_cast<std::uint64_t>(stack_canary);
    }
  }

  const auto mix = static_cast<std::uint64_t>(stack_canary) ^
                   static_cast<std::uint64_t>(effective_return_address) ^ nonce;

  auto salt = namespaced_salt(std::vector<std::uint8_t>(table_.key_context_id().begin(), table_.key_context_id().end()), kHmacInfoV2);
  std::vector<std::uint8_t> ikm;
  append_le64(ikm, mix);
  ikm.insert(ikm.end(), kEphemeralHmacIkmV2.begin(), kEphemeralHmacIkmV2.end());
  auto prk = vmp::runtime::strings::hkdf_extract_sha256(salt, ikm);
  auto okm = vmp::runtime::strings::hkdf_expand_sha256(
      prk,
      vmp::runtime::strings::to_bytes(kHmacInfoV2),
      kTrampolineHmacSize);
  HmacBytes key{};
  std::copy(okm.begin(), okm.end(), key.begin());
  if (options_.test_hooks.derived_key_observer) {
    options_.test_hooks.derived_key_observer(key);
  }
  vmp::runtime::strings::secure_memzero(salt.data(), salt.size());
  vmp::runtime::strings::secure_memzero(ikm.data(), ikm.size());
  vmp::runtime::strings::secure_memzero(prk.data(), prk.size());
  vmp::runtime::strings::secure_memzero(okm.data(), okm.size());
  return key;
}

DispatcherResult Dispatcher::dispatch_verbose(const TokenBytes& token) const {
  const auto ticket = issue_dispatch_ticket(token);
  return dispatch_verbose(ticket);
}

DispatcherResult Dispatcher::dispatch_verbose(const DispatchTicket& ticket) const {
  DispatcherResult result;
  result.dispatch_seq = ticket.dispatch_seq;
  (void)vmp::runtime::stack_probe::default_stack_probe().maybe_probe(
      vmp::runtime::stack_probe::ProbeRequest{
          vmp::runtime::stack_probe::selector_low12(token_low64(ticket.token)),
          vmp::runtime::stack_probe::ProbeTriggerSite::dispatcher_entry,
          vmp::runtime::stack_probe::kDefaultMaxFrames},
      &table_.reaction_dispatcher());
  vmp::runtime::env_detectors::default_supervisor().observe_dispatch(&table_.reaction_dispatcher());
  result.dispatcher_self_hash_ok = verify_self_hash();
  if (!result.dispatcher_self_hash_ok) {
    report_dispatcher_tamper();
    return result;
  }
  const auto return_address = capture_return_address_default();
  return dispatch_entry_bridge(this, ticket, return_address);
}

VMP_TRAMPOLINE_NOINLINE DispatcherResult Dispatcher::dispatch_entry_bridge(const Dispatcher* self,
                                                                           const DispatchTicket& ticket,
                                                                           std::uintptr_t return_address) {
  HmacBytes ephemeral_key = self->derive_ephemeral_hmac_key(return_address);
  auto result = self->table_.resolve(ticket, ephemeral_key);
  if (self->options_.test_hooks.zeroized_key_observer) {
    HmacBytes scrubbed = ephemeral_key;
    vmp::runtime::strings::secure_memzero(scrubbed.data(), scrubbed.size());
    self->options_.test_hooks.zeroized_key_observer(scrubbed);
  }
  vmp::runtime::strings::secure_memzero(ephemeral_key.data(), ephemeral_key.size());
  return result;
}

std::uint64_t Dispatcher::dispatch_or_throw(const TokenBytes& token) const {
  return dispatch_or_throw(issue_dispatch_ticket(token));
}

std::uint64_t Dispatcher::dispatch_or_throw(const DispatchTicket& ticket) const {
  const auto result = dispatch_verbose(ticket);
  if (!result.dispatcher_self_hash_ok) {
    throw std::runtime_error("trampoline: dispatcher self-hash mismatch");
  }
  if (!result.stack_table_ok) {
    throw std::runtime_error("trampoline: stack function table integrity failure");
  }
  if (!result.replay_ok) {
    throw std::runtime_error("trampoline: replay detected for dispatch request");
  }
  if (!result.target_prologue_ok) {
    throw std::runtime_error("trampoline: target prologue fingerprint mismatch");
  }
  if (!result.token_found) {
    throw std::runtime_error("trampoline: token not found: " + token_hex(ticket.token));
  }
  if (!result.integrity_ok) {
    throw std::runtime_error("trampoline: dispatcher integrity failure");
  }
  return result.resolved_address;
}

}  // namespace vmp::runtime::trampoline
