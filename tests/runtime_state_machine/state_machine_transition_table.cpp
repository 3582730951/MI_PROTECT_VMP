#include "test_common.h"

#include <iostream>
#include <vector>

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/state/state.h>

using namespace vmp::tests::runtime_state_machine;

int main() {
  const auto audit_path = temp_path("state_table", ".log");
  vmp::runtime::audit::AuditWriter writer(audit_path);
  auto& state = vmp::runtime::state::RuntimeState::instance();

  state.shutdown();
  state.init_once(&writer, {"linux", "table", false, 5000});
  require(state.current_state() == vmp::runtime::state::RuntimeStateValue::ready, "init->ready failed");
  state.observe(vmp::runtime::state::RuntimeEventKind::hot_threshold_reached);
  require(state.current_state() == vmp::runtime::state::RuntimeStateValue::ready, "hot_threshold should stay ready");
  state.observe(vmp::runtime::state::RuntimeEventKind::audit_event);
  require(state.current_state() == vmp::runtime::state::RuntimeStateValue::ready, "audit_event should stay ready");
  state.observe(vmp::runtime::state::RuntimeEventKind::key_rotated);
  require(state.current_state() == vmp::runtime::state::RuntimeStateValue::ready, "key_rotated should stay ready");
  state.observe(vmp::runtime::state::RuntimeEventKind::env_anomaly);
  require(state.current_state() == vmp::runtime::state::RuntimeStateValue::degraded, "env_anomaly should degrade");
  state.shutdown();

  state.init_once(&writer, {"linux", "table", false, 5000});
  state.observe(vmp::runtime::state::RuntimeEventKind::shutdown_requested);
  require(state.current_state() == vmp::runtime::state::RuntimeStateValue::terminating, "shutdown should terminate from ready");
  state.shutdown();

  state.init_once(&writer, {"linux", "table", false, 5000});
  state.observe(vmp::runtime::state::RuntimeEventKind::integrity_failed, {"region", "region=region"});
  require(state.current_state() == vmp::runtime::state::RuntimeStateValue::degraded, "integrity should degrade");
  state.observe(vmp::runtime::state::RuntimeEventKind::further_failure);
  require(state.current_state() == vmp::runtime::state::RuntimeStateValue::terminating, "further_failure should terminate degraded");
  std::cout << "state_machine_transition_table OK\n";
}
