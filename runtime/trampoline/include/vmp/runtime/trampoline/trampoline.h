#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <vmp/runtime/audit/reaction.h>

namespace vmp::runtime::trampoline {

inline constexpr std::size_t kTokenKeyContextSize = 16;
inline constexpr std::size_t kTokenBytesSize = 16;
inline constexpr std::size_t kTrampolineHmacSize = 32;
inline constexpr std::size_t kDispatcherSelfHashBytes = 64;
inline constexpr std::size_t kTargetPrologueWindowBytes = 16;
inline constexpr std::size_t kTargetPrologueFingerprintSize = 16;
inline constexpr std::uint32_t kStackFunctionTableVersion = 2;
inline constexpr std::uint16_t kTrampolineBundleVersion = 2;

using KeyContextId = std::array<std::uint8_t, kTokenKeyContextSize>;
using TokenBytes = std::array<std::uint8_t, kTokenBytesSize>;
using HmacBytes = std::array<std::uint8_t, kTrampolineHmacSize>;
using TargetPrologueFingerprint = std::array<std::uint8_t, kTargetPrologueFingerprintSize>;

enum class TrampolineArch : std::uint8_t {
  x86 = 1,
  x64 = 2,
  arm = 3,
  arm64 = 4,
};

struct TokenEntry {
  TokenBytes token{};
  std::uint64_t original_address = 0;
  std::uint64_t relocated_address = 0;
  std::string symbol_name;
  KeyContextId key_context_id{};
  TargetPrologueFingerprint target_prologue_fingerprint{};
  std::uint64_t dispatch_seq = 0;
  std::uint64_t last_consumed_dispatch_seq = 0;

  bool operator==(const TokenEntry& other) const noexcept;
};

struct DispatchTicket {
  TokenBytes token{};
  std::uint64_t dispatch_seq = 0;
};

struct TrampolineCode {
  TrampolineArch arch = TrampolineArch::x64;
  TokenBytes token{};
  std::uint64_t site_address = 0;
  std::uint64_t dispatcher_address = 0;
  std::vector<std::uint8_t> bytes;
};

struct TrampolineBundleRecord {
  TokenEntry entry;
  std::uint64_t relocated_offset = 0;
  std::uint32_t code_size = 0;
};

struct TrampolineBundle {
  TrampolineArch arch = TrampolineArch::x64;
  KeyContextId key_context_id{};
  std::vector<TrampolineBundleRecord> records;
  std::vector<std::uint8_t> code_blob;

  std::vector<std::uint8_t> serialize() const;
  static TrampolineBundle deserialize(const std::vector<std::uint8_t>& bytes);
  std::vector<TokenEntry> instantiate(std::uint64_t executable_base) const;
};

class TokenManager {
 public:
  TokenManager() = default;

  static TokenBytes derive_token(const KeyContextId& key_context_id,
                                 std::uint64_t original_address,
                                 std::string_view symbol_name = {});

  TokenEntry register_entry(const KeyContextId& key_context_id,
                            std::uint64_t original_address,
                            std::uint64_t relocated_address,
                            std::string symbol_name);

  const TokenEntry* find(const TokenBytes& token) const noexcept;
  DispatchTicket issue_dispatch_ticket(const TokenBytes& token);
  const std::vector<TokenEntry>& entries() const noexcept { return entries_; }

 private:
  std::vector<TokenEntry> entries_;
  std::atomic<std::uint64_t> next_dispatch_seq_{1};
  mutable std::mutex mutex_;
};

TrampolineArch trampoline_arch_from_string(std::string_view value);
std::string to_string(TrampolineArch arch);
TrampolineCode generate_trampoline(TrampolineArch arch,
                                   const TokenBytes& token,
                                   std::uint64_t site_address,
                                   std::uint64_t dispatcher_address);
TokenBytes token_from_low64(std::uint64_t low) noexcept;
TokenBytes token_from_halves(std::uint64_t low, std::uint64_t high) noexcept;
std::uint64_t token_low64(const TokenBytes& token) noexcept;
std::uint64_t token_high64(const TokenBytes& token) noexcept;
std::string token_hex(const TokenBytes& token);

struct StackFunctionRecord {
  TokenBytes token{};
  std::uint64_t original_address = 0;
  std::uint64_t relocated_address = 0;
  std::uint64_t dispatch_seq = 0;
};

struct StackTableHeader {
  std::uint32_t version = kStackFunctionTableVersion;
  std::uint32_t entry_count = 0;
  HmacBytes hmac{};
};

struct StackFunctionTableView {
  StackTableHeader* header = nullptr;
  StackFunctionRecord* records = nullptr;
  std::size_t frame_size = 0;
};

struct DispatcherResult {
  std::uint64_t resolved_address = 0;
  std::uint64_t dispatch_seq = 0;
  bool integrity_ok = false;
  bool token_found = false;
  bool stack_table_ok = false;
  bool dispatcher_self_hash_ok = true;
  bool target_prologue_ok = true;
  bool replay_ok = true;
};

struct DispatcherMonitoredRegion {
  const void* address = nullptr;
  std::size_t size = 0;
};

struct DispatcherTestHooks {
  std::function<std::uint64_t()> nonce_provider;
  std::function<std::uintptr_t()> stack_canary_provider;
  std::function<std::uintptr_t()> return_address_provider;
  std::function<void(const HmacBytes&)> derived_key_observer;
  std::function<void(const HmacBytes&)> zeroized_key_observer;
};

struct DispatcherOptions {
  DispatcherMonitoredRegion self_hash_region{};
  DispatcherTestHooks test_hooks{};
};

class StackFunctionTable {
 public:
  explicit StackFunctionTable(std::vector<TokenEntry> entries,
                              KeyContextId key_context_id,
                              std::filesystem::path audit_path = {});
  ~StackFunctionTable();

  DispatcherResult resolve(const TokenBytes& token) const;
  DispatcherResult resolve(const DispatchTicket& ticket, const HmacBytes& dispatch_hmac_key) const;
  DispatchTicket issue_dispatch_ticket(const TokenBytes& token) const;
  bool verify_view(const StackFunctionTableView& view) const;
  void with_materialized_view(const std::function<void(StackFunctionTableView&)>& visitor) const;

  const std::vector<TokenEntry>& entries() const noexcept { return entries_; }
  const HmacBytes& hmac_key() const noexcept { return hmac_key_; }
  const KeyContextId& key_context_id() const noexcept { return key_context_id_; }
  vmp::runtime::audit::ReactionDispatcher& reaction_dispatcher() const noexcept;
  const std::filesystem::path& audit_path() const noexcept { return audit_path_; }

  static HmacBytes derive_hmac_key(const KeyContextId& key_context_id);
  static TargetPrologueFingerprint fingerprint_target_prologue(std::uint64_t address);

 private:
  StackFunctionTableView materialize_into(std::uint8_t* raw, std::size_t raw_size) const;
  StackFunctionTableView materialize_into(std::uint8_t* raw,
                                          std::size_t raw_size,
                                          const HmacBytes& hmac_key) const;
  bool verify_view(const StackFunctionTableView& view, const HmacBytes& hmac_key) const;
  void initialize_target_prologue_fingerprints();
  void report_invalid_token(const TokenBytes& token) const;
  void report_integrity_failure() const;
  void report_replay_detected(const TokenBytes& token,
                              std::uint64_t dispatch_seq,
                              std::uint64_t expected_seq,
                              std::uint64_t last_consumed_seq) const;
  void report_target_prologue_tamper(const TokenBytes& token,
                                     std::uint64_t relocated_address,
                                     const TargetPrologueFingerprint& expected,
                                     const TargetPrologueFingerprint& observed) const;

  mutable std::vector<TokenEntry> entries_;
  KeyContextId key_context_id_{};
  HmacBytes hmac_key_{};
  std::filesystem::path audit_path_;
  mutable std::atomic<std::uint64_t> next_dispatch_seq_{1};
  mutable std::mutex state_mutex_;

  struct AuditHarness;
  mutable std::unique_ptr<AuditHarness> audit_harness_;
};

class Dispatcher {
 public:
  explicit Dispatcher(const StackFunctionTable& table, DispatcherOptions options = {});

  DispatchTicket issue_dispatch_ticket(const TokenBytes& token) const;
  DispatcherResult dispatch_verbose(const TokenBytes& token) const;
  DispatcherResult dispatch_verbose(const DispatchTicket& ticket) const;
  std::uint64_t dispatch_or_throw(const TokenBytes& token) const;
  std::uint64_t dispatch_or_throw(const DispatchTicket& ticket) const;

 private:
  static DispatcherMonitoredRegion default_self_hash_region() noexcept;
  static DispatcherResult dispatch_entry_bridge(const Dispatcher* self,
                                                const DispatchTicket& ticket,
                                                std::uintptr_t return_address);

  bool verify_self_hash() const;
  void report_dispatcher_tamper() const;
  HmacBytes derive_ephemeral_hmac_key(std::uintptr_t return_address) const;

  const StackFunctionTable& table_;
  DispatcherOptions options_{};
  DispatcherMonitoredRegion self_hash_region_{};
  std::vector<std::uint8_t> dispatcher_self_hash_;
};

}  // namespace vmp::runtime::trampoline
