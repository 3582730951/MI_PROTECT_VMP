#include <chrono>
#include <filesystem>
#include <iostream>

#include <vmp/runtime/env_detectors/detectors.h>

#include "test_common.h"

int main() {
  using namespace vmp::runtime::env_detectors;
  using namespace vmp::tests::runtime_env_detectors;

  const auto audit_path = temp_path("env_detectors_hardware_breakpoint_cross_check", ".log");
  std::filesystem::remove(audit_path);

  EnvironmentDetectorSupervisor detectors(bytes16(0x31), audit_path);
  int exit_calls = 0;
  detectors.reaction_dispatcher().set_exit_fn([&exit_calls]() { ++exit_calls; });
  detectors.reaction_dispatcher().set_scheduler([](std::chrono::milliseconds, std::function<void()> fn) { fn(); });
  detectors.reaction_dispatcher().set_delay_selector([]() { return std::chrono::milliseconds(0); });

  HardwareBreakpointReadings readings;
  readings.debug_registers_sampled = true;
  readings.debug_registers[0] = 0x41414141ull;
  readings.sigtrap_sampled = true;
  readings.sigtrap_triggered = false;

  const auto result = detectors.evaluate_hardware_breakpoints(readings);
  require(result.detected, "hardware breakpoint detector should trip on non-zero debug register");
  require(result.divergent, "hardware breakpoint detector should record DR-vs-SIGTRAP divergence");
  require(result.event_type == "hardware_breakpoint_detected", "hardware breakpoint event type mismatch");
  require(exit_calls == 1, "hardware breakpoint detector should route through delayed exit reaction");

  const auto audit_text = read_all(audit_path);
  require(audit_text.find("hardware_breakpoint_detected") != std::string::npos,
          "hardware_breakpoint_detected audit event missing");
  require(audit_text.find("sigtrap_triggered=false") != std::string::npos,
          "hardware breakpoint audit note should include SIGTRAP cross-check");

  std::cout << "env_detectors_hardware_breakpoint_cross_check OK\n";
  return 0;
}
