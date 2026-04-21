#pragma once

#include <cstdint>

namespace vmp::runtime::cryptor {

enum class VmDomain : std::uint8_t {
  vm1 = 1,
  vm2 = 2,
};

enum class RotationReason : std::uint8_t {
  key_rotation = 1,
  integrity_event = 2,
  domain_switch = 3,
  dispatch_budget = 4,
};

struct RollingPolicy {
  bool rotate_on_key_rotation = true;
  bool rotate_on_integrity_event = true;
  bool rotate_on_domain_switch = true;
  std::uint64_t dispatch_budget = (1ull << 18);
};

const RollingPolicy& default_rolling_policy() noexcept;
const char* to_string(VmDomain domain) noexcept;
const char* to_string(RotationReason reason) noexcept;

}  // namespace vmp::runtime::cryptor
