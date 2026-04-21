#pragma once

#include <cstddef>
#include <cstdint>

namespace vmp::runtime::cryptor {

struct JitCacheKey {
  std::uint64_t module_id = 0;
  std::uint32_t entry_pc = 0;
  std::uint32_t epoch_id = 0;

  bool operator==(const JitCacheKey& other) const noexcept {
    return module_id == other.module_id && entry_pc == other.entry_pc && epoch_id == other.epoch_id;
  }
};

struct JitCacheKeyHash {
  std::size_t operator()(const JitCacheKey& key) const noexcept {
    const auto h1 = std::hash<std::uint64_t>{}(key.module_id);
    const auto h2 = std::hash<std::uint32_t>{}(key.entry_pc);
    const auto h3 = std::hash<std::uint32_t>{}(key.epoch_id);
    return h1 ^ (h2 << 1u) ^ (h3 << 9u);
  }
};

}  // namespace vmp::runtime::cryptor
