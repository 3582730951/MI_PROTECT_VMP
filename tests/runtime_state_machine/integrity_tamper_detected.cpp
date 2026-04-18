#include "test_common.h"

#include <array>
#include <iostream>

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/integrity/integrity.h>
#include <vmp/runtime/state/state.h>

using namespace vmp::tests::runtime_state_machine;

int main() {
  const auto audit_path = temp_path("integrity_tamper", ".log");
  vmp::runtime::audit::AuditWriter writer(audit_path);
  auto& state = vmp::runtime::state::RuntimeState::instance();
  state.shutdown();
  state.init_once(&writer, {"linux", "test", false, 2000});

  std::array<std::uint8_t, 8> bytes{{1,2,3,4,5,6,7,8}};
  auto& registry = vmp::runtime::integrity::RegionRegistry::instance();
  registry.reset_for_tests();
  vmp::runtime::integrity::ProtectedRegion region{};
  region.name = "region_tamper";
  region.base = bytes.data();
  region.size = bytes.size();
  registry.register_region(region);
  bytes[3] ^= 0xFF;
  const auto result = registry.verify_one("region_tamper");
  writer.flush();
  require(result.status == vmp::runtime::integrity::RegionVerifyStatus::mismatch, "tamper should mismatch");
  require(state.current_state() == vmp::runtime::state::RuntimeStateValue::degraded, "state should degrade");
  const auto log = read_all(audit_path);
  require(log.find("integrity_failed") != std::string::npos, "integrity_failed audit missing");
  require(log.find("state_transition") != std::string::npos, "state_transition audit missing");
  std::cout << "integrity_tamper_detected OK\n";
}
