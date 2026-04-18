#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace vmp::runtime::integrity {

struct ProtectedRegion {
  std::string name;
  const void* base = nullptr;
  std::size_t size = 0;
  std::uint8_t expected_sha256[32]{};
  std::uint32_t flags = 0;
};

enum class RegionVerifyStatus {
  ok,
  missing,
  invalid,
  mismatch,
};

struct RegionVerifyResult {
  std::string name;
  RegionVerifyStatus status = RegionVerifyStatus::invalid;
};

class RegionRegistry {
 public:
  static RegionRegistry& instance() noexcept;

  RegionRegistry(const RegionRegistry&) = delete;
  RegionRegistry& operator=(const RegionRegistry&) = delete;

  void register_region(ProtectedRegion region);
  void unregister(const std::string& name);
  std::vector<ProtectedRegion> all() const;
  std::vector<RegionVerifyResult> verify_all() const;
  RegionVerifyResult verify_one(const std::string& name) const;
  void reset_for_tests();

 private:
  RegionRegistry() = default;

  static std::array<std::uint8_t, 32> compute_digest(const ProtectedRegion& region);

  mutable std::mutex mutex_;
  std::unordered_map<std::string, ProtectedRegion> regions_;
};

const char* to_string(RegionVerifyStatus status) noexcept;

}  // namespace vmp::runtime::integrity
