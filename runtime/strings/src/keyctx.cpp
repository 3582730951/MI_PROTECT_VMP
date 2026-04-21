#include <vmp/runtime/strings/keyctx.h>

#include <algorithm>
#include <mutex>
#include <stdexcept>

#include <vmp/runtime/strings/cipher.h>

namespace vmp::runtime::strings {
namespace {

std::mutex g_registry_mutex;
std::vector<std::weak_ptr<KeyContext::SlotBook>> g_registry;

std::string normalize_purpose_tag(std::string_view purpose_tag) {
  if (purpose_tag == "string-pool") {
    return "vmp.strings.key.v2";
  }
  return std::string(purpose_tag);
}

}  // namespace

struct KeyContext::SlotBook {
  mutable std::mutex mutex;
  std::vector<std::array<std::uint8_t, 32>> slots;
};

std::vector<std::uint8_t> MasterKeyHandle::materialize() const {
  if (!provider_) {
    throw std::runtime_error("strings: master key handle is empty");
  }
  auto value = provider_();
  if (value.size() != 16 && value.size() != 32) {
    secure_memzero(value.data(), value.size());
    throw std::runtime_error("strings: master key must be 16 or 32 bytes");
  }
  return value;
}

DerivedKey::~DerivedKey() { secure_memzero(bytes_.data(), bytes_.size()); }

DerivedKey::DerivedKey(DerivedKey&& other) noexcept {
  bytes_ = other.bytes_;
  secure_memzero(other.bytes_.data(), other.bytes_.size());
}

DerivedKey& DerivedKey::operator=(DerivedKey&& other) noexcept {
  if (this != &other) {
    secure_memzero(bytes_.data(), bytes_.size());
    bytes_ = other.bytes_;
    secure_memzero(other.bytes_.data(), other.bytes_.size());
  }
  return *this;
}

KeyContext::KeyContext(MasterKeyHandle master_key_handle, std::vector<std::uint8_t> salt)
    : master_key_handle_(std::move(master_key_handle)), salt_(std::move(salt)), slot_book_(std::make_shared<SlotBook>()) {
  if (!master_key_handle_.valid()) {
    throw std::runtime_error("strings: master key provider required");
  }
  if (salt_.empty()) {
    throw std::runtime_error("strings: salt required");
  }
  std::lock_guard<std::mutex> lock(g_registry_mutex);
  g_registry.push_back(slot_book_);
}

DerivedKey KeyContext::derive_subkey(std::string_view purpose_tag) const {
  auto master = master_key_handle_.materialize();
  const auto info = normalize_purpose_tag(purpose_tag);
  auto hkdf_salt = salt_;
  hkdf_salt.insert(hkdf_salt.end(), info.begin(), info.end());
  const auto prk = hkdf_extract_sha256(hkdf_salt, master);
  const auto okm = hkdf_expand_sha256(prk, to_bytes(info), 32);
  std::array<std::uint8_t, 32> out{};
  std::copy(okm.begin(), okm.end(), out.begin());
  secure_memzero(master.data(), master.size());
  secure_memzero(hkdf_salt.data(), hkdf_salt.size());
  {
    std::lock_guard<std::mutex> lock(slot_book_->mutex);
    slot_book_->slots.push_back(out);
  }
  return DerivedKey(out);
}

void KeyContext::wipe_cached_subkeys() const noexcept {
  std::lock_guard<std::mutex> lock(slot_book_->mutex);
  for (auto& slot : slot_book_->slots) {
    secure_memzero(slot.data(), slot.size());
  }
}

bool KeyContext::debug_cached_subkeys_zeroed() const noexcept {
  std::lock_guard<std::mutex> lock(slot_book_->mutex);
  for (const auto& slot : slot_book_->slots) {
    for (auto byte : slot) {
      if (byte != 0) {
        return false;
      }
    }
  }
  return true;
}

void wipe_all_key_context_subkeys() noexcept {
  std::lock_guard<std::mutex> lock(g_registry_mutex);
  for (auto it = g_registry.begin(); it != g_registry.end();) {
    if (auto book = it->lock()) {
      std::lock_guard<std::mutex> slot_lock(book->mutex);
      for (auto& slot : book->slots) {
        secure_memzero(slot.data(), slot.size());
      }
      ++it;
    } else {
      it = g_registry.erase(it);
    }
  }
}

bool debug_all_key_context_slots_zeroed() noexcept {
  std::lock_guard<std::mutex> lock(g_registry_mutex);
  for (auto it = g_registry.begin(); it != g_registry.end();) {
    if (auto book = it->lock()) {
      std::lock_guard<std::mutex> slot_lock(book->mutex);
      for (const auto& slot : book->slots) {
        for (auto byte : slot) {
          if (byte != 0) {
            return false;
          }
        }
      }
      ++it;
    } else {
      it = g_registry.erase(it);
    }
  }
  return true;
}

}  // namespace vmp::runtime::strings
