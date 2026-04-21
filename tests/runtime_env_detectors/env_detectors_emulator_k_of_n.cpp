#include <chrono>
#include <filesystem>
#include <iostream>

#include <vmp/runtime/env_detectors/detectors.h>

#include "test_common.h"

int main() {
  using namespace vmp::runtime::env_detectors;
  using namespace vmp::tests::runtime_env_detectors;

  const auto audit_path = temp_path("env_detectors_emulator_k_of_n", ".log");
  std::filesystem::remove(audit_path);

  EnvironmentDetectorSupervisor detectors(bytes16(0x51), audit_path);
  int exit_calls = 0;
  detectors.reaction_dispatcher().set_exit_fn([&exit_calls]() { ++exit_calls; });
  detectors.reaction_dispatcher().set_scheduler([](std::chrono::milliseconds, std::function<void()> fn) { fn(); });
  detectors.reaction_dispatcher().set_delay_selector([]() { return std::chrono::milliseconds(0); });

  EmulatorReadings positive;
  positive.cpuid_sampled = true;
  positive.hypervisor_vendor_present = true;
  positive.hypervisor_vendor = "TCGTCGTCGTCG";
  positive.rdtsc_sampled = true;
  positive.rdtsc_low_jitter = true;
  positive.fsbase_sampled = true;
  positive.fsbase = 0x7fff0000ull;
  positive.fsbase_suspicious = false;

  const auto detected = detectors.evaluate_emulator(positive);
  require(detected.detected, "emulator detector should fire on 2-of-3 suspicious signals");
  require(detected.vote_count == 2, "emulator detector vote count mismatch");
  require(detected.event_type == "emulator_detected", "emulator detector event type mismatch");
  require(exit_calls == 1, "emulator detector should route through delayed exit reaction");

  EmulatorReadings negative;
  negative.cpuid_sampled = true;
  negative.hypervisor_vendor_present = true;
  negative.hypervisor_vendor = "KVMKVMKVM\0\0\0";
  negative.rdtsc_sampled = true;
  negative.rdtsc_low_jitter = false;
  negative.fsbase_sampled = true;
  negative.fsbase = 0x7f0000000000ull;
  negative.fsbase_suspicious = false;

  const auto clean = detectors.evaluate_emulator(negative);
  require(!clean.detected, "single suspicious signal must not satisfy 2-of-3 threshold");
  require(clean.vote_count == 1, "single-signal emulator vote count mismatch");
  require(exit_calls == 1, "clean emulator verdict must not trigger extra exits");

  const auto audit_text = read_all(audit_path);
  require(audit_text.find("emulator_detected") != std::string::npos,
          "emulator_detected audit event missing");
  require(audit_text.find("TCGTCGTCGTCG") != std::string::npos,
          "emulator detector audit note should include vendor string");

  std::cout << "env_detectors_emulator_k_of_n OK\n";
  return 0;
}
