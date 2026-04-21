#include <chrono>
#include <filesystem>
#include <iostream>

#include <vmp/runtime/env_detectors/detectors.h>

#include "test_common.h"

int main() {
  using namespace vmp::runtime::env_detectors;
  using namespace vmp::tests::runtime_env_detectors;

  const auto audit_path = temp_path("env_detectors_frida_divergence", ".log");
  std::filesystem::remove(audit_path);

  EnvironmentDetectorSupervisor detectors(bytes16(0x41), audit_path);
  int exit_calls = 0;
  detectors.reaction_dispatcher().set_exit_fn([&exit_calls]() { ++exit_calls; });
  detectors.reaction_dispatcher().set_scheduler([](std::chrono::milliseconds, std::function<void()> fn) { fn(); });
  detectors.reaction_dispatcher().set_delay_selector([]() { return std::chrono::milliseconds(0); });

  FridaReadings readings;
  readings.maps_sampled = true;
  readings.maps_hits = {"/tmp/frida-agent-64.so"};
  readings.tls_slots_sampled = true;
  readings.tls_slot_count = 4;
  readings.tls_slot_threshold = 32;

  const auto result = detectors.evaluate_frida_injection(readings);
  require(result.detected, "Frida detector should trip on maps hit even when TLS path disagrees");
  require(result.divergent, "Frida detector should surface maps-vs-TLS divergence");
  require(result.event_type == "frida_injection_detected", "Frida detector event type mismatch");
  require(exit_calls == 1, "Frida detector should route through delayed exit reaction");

  const auto audit_text = read_all(audit_path);
  require(audit_text.find("frida_injection_detected") != std::string::npos,
          "frida_injection_detected audit event missing");
  require(audit_text.find("frida-agent-64.so") != std::string::npos,
          "Frida detector audit note should include maps keyword hit");

  std::cout << "env_detectors_frida_divergence OK\n";
  return 0;
}
