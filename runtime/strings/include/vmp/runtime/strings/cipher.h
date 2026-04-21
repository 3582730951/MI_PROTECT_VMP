#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <vmp/policy/policy_ir.h>
#include <vmp/runtime/audit/reaction.h>

namespace vmp::runtime::strings {

inline constexpr std::size_t kChaCha20KeySize = 32;
inline constexpr std::size_t kChaCha20NonceSize = 12;
inline constexpr std::size_t kTransientInlineLimit = 4096;
inline constexpr std::size_t kSha256DigestSize = 32;

using Nonce = std::array<std::uint8_t, kChaCha20NonceSize>;

struct StringIndexEntry {
  std::uint32_t offset = 0;
  std::uint32_t length = 0;
  Nonce nonce{};
  vmp::policy::PlaintextBudget plaintext_budget = vmp::policy::PlaintextBudget::transient_only;
};

using IndexMap = std::unordered_map<std::uint32_t, StringIndexEntry>;

struct EncryptedStringRecord {
  std::vector<std::uint8_t> ciphertext;
};

class KeyContext;

void secure_memzero(void* ptr, std::size_t size) noexcept;
std::vector<std::uint8_t> to_bytes(std::string_view text);
std::string hex_encode(const std::vector<std::uint8_t>& bytes);
std::vector<std::uint8_t> hex_decode(const std::string& hex);
Nonce u32_to_nonce(std::uint32_t value) noexcept;
bool constant_time_equal(const std::uint8_t* lhs, const std::uint8_t* rhs, std::size_t size) noexcept;
bool constant_time_equal(const std::vector<std::uint8_t>& lhs, const std::vector<std::uint8_t>& rhs) noexcept;

std::vector<std::uint8_t> sha256(const std::vector<std::uint8_t>& data);
std::vector<std::uint8_t> hmac_sha256(const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& data);
std::vector<std::uint8_t> hkdf_extract_sha256(const std::vector<std::uint8_t>& salt,
                                              const std::vector<std::uint8_t>& ikm);
std::vector<std::uint8_t> hkdf_expand_sha256(const std::vector<std::uint8_t>& prk,
                                             const std::vector<std::uint8_t>& info,
                                             std::size_t out_len);

void set_global_plaintext_budget_lock(bool locked) noexcept;
bool global_plaintext_budget_locked() noexcept;

std::vector<std::uint8_t> chacha20_xor(const std::vector<std::uint8_t>& key,
                                       const Nonce& nonce,
                                       std::uint32_t counter,
                                       const std::vector<std::uint8_t>& input);

EncryptedStringRecord encrypt_string_record(const std::array<std::uint8_t, 32>& key,
                                            const Nonce& nonce,
                                            const std::vector<std::uint8_t>& plaintext);
std::vector<std::uint8_t> decrypt_string_record(const std::array<std::uint8_t, 32>& key,
                                                const Nonce& nonce,
                                                const std::vector<std::uint8_t>& record);

class TransientView {
 public:
  TransientView() = default;
  explicit TransientView(std::vector<std::uint8_t> plaintext);
  ~TransientView();

  TransientView(const TransientView&) = delete;
  TransientView& operator=(const TransientView&) = delete;
  TransientView(TransientView&& other) noexcept;
  TransientView& operator=(TransientView&& other) noexcept;

  const char* data() const noexcept { return reinterpret_cast<const char*>(data_); }
  std::size_t size() const noexcept { return size_; }
  std::string_view view() const noexcept { return std::string_view(data(), size_); }
  explicit operator bool() const noexcept { return data_ != nullptr; }
  std::vector<std::uint8_t> debug_zeroized_snapshot();

 private:
  void reset() noexcept;
  void move_from(TransientView&& other) noexcept;
  void allocate_large(std::size_t size);

  std::array<std::uint8_t, kTransientInlineLimit> inline_storage_{};
  std::uint8_t* data_ = nullptr;
  std::size_t size_ = 0;
  bool uses_inline_ = true;
  void* mapped_region_ = nullptr;
  std::size_t mapped_size_ = 0;
};

class StringPool {
 public:
  StringPool(std::vector<std::uint8_t> ciphertext, IndexMap idx, KeyContext key);

  TransientView decrypt(std::uint32_t string_id) const;
  void set_audit_dispatcher(vmp::runtime::audit::ReactionDispatcher* dispatcher) noexcept;

 private:
  [[noreturn]] void fail(const std::string& message, const char* event_type) const;

  std::vector<std::uint8_t> ciphertext_;
  IndexMap idx_;
  std::shared_ptr<KeyContext> key_;
  std::atomic<vmp::runtime::audit::ReactionDispatcher*> audit_dispatcher_{nullptr};
};

class ScopedCurrentPool {
 public:
  explicit ScopedCurrentPool(StringPool& pool) noexcept;
  ~ScopedCurrentPool();

  ScopedCurrentPool(const ScopedCurrentPool&) = delete;
  ScopedCurrentPool& operator=(const ScopedCurrentPool&) = delete;

 private:
  StringPool* previous_ = nullptr;
};

StringPool& current_string_pool();

struct Facade {
  const char* status() const noexcept;
};

}  // namespace vmp::runtime::strings
