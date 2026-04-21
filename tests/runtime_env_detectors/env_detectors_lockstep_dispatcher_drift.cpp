#include <chrono>
#include <filesystem>
#include <iostream>

#include <vmp/runtime/env_detectors/detectors.h>
#include <vmp/runtime/trampoline/trampoline.h>

#include "test_common.h"
#include "../runtime_dispatcher_hardening/test_common.h"

int main() {
  using namespace vmp::runtime::env_detectors;
  using namespace vmp::runtime::trampoline;
  namespace det = vmp::tests::runtime_env_detectors;
  namespace tramp = vmp::tests::runtime_dispatcher_hardening;

  const auto audit_path = det::temp_path("env_detectors_lockstep_dispatcher_drift", ".log");
  std::filesystem::remove(audit_path);

  SupervisorOptions options;
  options.dispatch_check_interval = 1;
  options.stagnant_dispatch_limit = 3;
  options.auto_start_heartbeat_threads = false;

  EnvironmentDetectorSupervisor detectors(det::bytes16(0x61), audit_path, options);
  DefaultSupervisorOverride override(detectors);
  int exit_calls = 0;
  detectors.reaction_dispatcher().set_exit_fn([&exit_calls]() { ++exit_calls; });
  detectors.reaction_dispatcher().set_scheduler([](std::chrono::milliseconds, std::function<void()> fn) { fn(); });
  detectors.reaction_dispatcher().set_delay_selector([]() { return std::chrono::milliseconds(0); });

  detectors.start();
  detectors.set_heartbeat_for_tests(DetectorKind::hardware_breakpoint, 7);
  detectors.set_heartbeat_for_tests(DetectorKind::frida, 11);
  detectors.set_heartbeat_for_tests(DetectorKind::emulator, 13);

  const KeyContextId key_context{{
      0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
      0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
  }};
  tramp::ExecutableBuffer target_region(tramp::pattern(0x30, 64));
  TokenManager manager;
  const auto entry = manager.register_entry(key_context, 0x405000u, target_region.address(), "gamma");
  StackFunctionTable table(manager.entries(), key_context, audit_path);
  table.reaction_dispatcher().set_exit_fn([&exit_calls]() { ++exit_calls; });
  table.reaction_dispatcher().set_scheduler([](std::chrono::milliseconds, std::function<void()> fn) { fn(); });
  table.reaction_dispatcher().set_delay_selector([]() { return std::chrono::milliseconds(0); });

  Dispatcher dispatcher(table);
  det::require(dispatcher.dispatch_verbose(entry.token).integrity_ok, "first dispatch should succeed");
  det::require(dispatcher.dispatch_verbose(entry.token).integrity_ok, "second dispatch should succeed");
  det::require(dispatcher.dispatch_verbose(entry.token).integrity_ok, "third dispatch should succeed");
  det::require(dispatcher.dispatch_verbose(entry.token).integrity_ok, "fourth dispatch should succeed while drift is audited");
  det::require(exit_calls == 1, "lockstep heartbeat drift should trigger delayed exit exactly once");

  const auto audit_text = det::read_all(audit_path);
  det::require(audit_text.find("detector_heartbeat_drift") != std::string::npos,
          "detector_heartbeat_drift audit event missing");
  det::require(audit_text.find("hardware_breakpoint") != std::string::npos,
          "lockstep drift note should name stalled detectors");

  std::cout << "env_detectors_lockstep_dispatcher_drift OK\n";
  return 0;
}
