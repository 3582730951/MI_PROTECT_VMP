#include "test_common.h"

#include <array>
#include <iostream>

#include <vmp/runtime/integrity/integrity.h>

using namespace vmp::tests::runtime_state_machine;

int main() {
  std::array<std::uint8_t, 8> bytes{{1,2,3,4,5,6,7,8}};
  auto& registry = vmp::runtime::integrity::RegionRegistry::instance();
  registry.reset_for_tests();
  vmp::runtime::integrity::ProtectedRegion region{};
  region.name = "region_ok";
  region.base = bytes.data();
  region.size = bytes.size();
  registry.register_region(region);
  const auto result = registry.verify_one("region_ok");
  require(result.status == vmp::runtime::integrity::RegionVerifyStatus::ok, "verify_one should succeed");
  std::cout << "integrity_register_and_verify_ok OK\n";
}
