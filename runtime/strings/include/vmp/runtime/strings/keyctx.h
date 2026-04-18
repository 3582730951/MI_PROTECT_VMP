#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace vmp::runtime::strings {

class MasterKeyHandle {
 public:
  using Provider = std::function<std::vector<std::uint8_t>()>;

  MasterKeyHandle() = default;
  explicit MasterKeyHandle(Provider provider) : provider_(std::move(provider)) {}

  std::vector<std::uint8_t> materialize() const;
  bool valid() const noexcept { return static_cast<bool>(provider_); }

 private:
  Provider provider_;
};

class DerivedKey final {
 public:
  DerivedKey() = default;
  explicit DerivedKey(std::array<std::uint8_t, 32> bytes) : bytes_(bytes) {}
  ~DerivedKey();

  DerivedKey(const DerivedKey&) = delete;
  DerivedKey& operator=(const DerivedKey&) = delete;
  DerivedKey(DerivedKey&& other) noexcept;
  DerivedKey& operator=(DerivedKey&& other) noexcept;

  const std::array<std::uint8_t, 32>& bytes() const noexcept { return bytes_; }

 private:
  std::array<std::uint8_t, 32> bytes_{};
};

class KeyContext {
 public:
  struct SlotBook;
  KeyContext(MasterKeyHandle master_key_handle, std::vector<std::uint8_t> salt);

  DerivedKey derive_subkey(std::string_view purpose_tag) const;
  void wipe_cached_subkeys() const noexcept;
  bool debug_cached_subkeys_zeroed() const noexcept;
  const std::vector<std::uint8_t>& salt() const noexcept { return salt_; }

 private:
  MasterKeyHandle master_key_handle_;
  std::vector<std::uint8_t> salt_;
  std::shared_ptr<SlotBook> slot_book_;
};

void wipe_all_key_context_subkeys() noexcept;
bool debug_all_key_context_slots_zeroed() noexcept;

}  // namespace vmp::runtime::strings
