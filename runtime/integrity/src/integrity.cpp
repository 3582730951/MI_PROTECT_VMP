#include <vmp/runtime/integrity/integrity.h>

#include <algorithm>
#include <cstring>

#include <vmp/runtime/state/state.h>
#include <vmp/runtime/strings/cipher.h>

namespace vmp::runtime::integrity {
namespace {

bool digest_is_zero(const std::uint8_t digest[32]) noexcept {
  for (std::size_t i = 0; i < 32; ++i) {
    if (digest[i] != 0) {
      return false;
    }
  }
  return true;
}

}  // namespace

RegionRegistry& RegionRegistry::instance() noexcept {
  static RegionRegistry registry;
  return registry;
}

void RegionRegistry::register_region(ProtectedRegion region) {
  if (region.name.empty() || region.base == nullptr || region.size == 0) {
    throw std::runtime_error("integrity: invalid protected region");
  }
  if (digest_is_zero(region.expected_sha256)) {
    const auto digest = compute_digest(region);
    std::copy(digest.begin(), digest.end(), region.expected_sha256);
  }
  std::lock_guard<std::mutex> lock(mutex_);
  regions_[region.name] = std::move(region);
}

void RegionRegistry::unregister(const std::string& name) {
  std::lock_guard<std::mutex> lock(mutex_);
  regions_.erase(name);
}

std::vector<ProtectedRegion> RegionRegistry::all() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<ProtectedRegion> out;
  out.reserve(regions_.size());
  for (const auto& [_, region] : regions_) {
    out.push_back(region);
  }
  return out;
}

std::vector<RegionVerifyResult> RegionRegistry::verify_all() const {
  const auto snapshot = all();
  std::vector<RegionVerifyResult> out;
  out.reserve(snapshot.size());
  for (const auto& region : snapshot) {
    out.push_back(verify_one(region.name));
  }
  return out;
}

RegionVerifyResult RegionRegistry::verify_one(const std::string& name) const {
  ProtectedRegion region;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = regions_.find(name);
    if (it == regions_.end()) {
      return {name, RegionVerifyStatus::missing};
    }
    region = it->second;
  }
  if (region.base == nullptr || region.size == 0) {
    return {name, RegionVerifyStatus::invalid};
  }
  const auto digest = compute_digest(region);
  if (!std::equal(digest.begin(), digest.end(), region.expected_sha256)) {
    vmp::runtime::state::RuntimeEventPayload payload;
    payload.name = name;
    payload.note = "region=" + name;
    vmp::runtime::state::RuntimeState::instance().observe(vmp::runtime::state::RuntimeEventKind::integrity_failed,
                                                          payload);
    return {name, RegionVerifyStatus::mismatch};
  }
  return {name, RegionVerifyStatus::ok};
}

void RegionRegistry::reset_for_tests() {
  std::lock_guard<std::mutex> lock(mutex_);
  regions_.clear();
}

std::array<std::uint8_t, 32> RegionRegistry::compute_digest(const ProtectedRegion& region) {
  std::vector<std::uint8_t> material(region.size);
  std::memcpy(material.data(), region.base, region.size);
  const auto digest = vmp::runtime::strings::sha256(material);
  std::array<std::uint8_t, 32> out{};
  std::copy_n(digest.begin(), out.size(), out.begin());
  return out;
}

const char* to_string(RegionVerifyStatus status) noexcept {
  switch (status) {
    case RegionVerifyStatus::ok: return "ok";
    case RegionVerifyStatus::missing: return "missing";
    case RegionVerifyStatus::invalid: return "invalid";
    case RegionVerifyStatus::mismatch: return "mismatch";
  }
  return "invalid";
}

const char* Facade::status() const noexcept { return "runtime_integrity_ready"; }

}  // namespace vmp::runtime::integrity
