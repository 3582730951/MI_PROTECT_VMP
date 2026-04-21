#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <vmp/runtime/audit/reaction.h>
#include <vmp/runtime/trusted_oracle/oracle.h>

namespace vmp::runtime::env_detectors {

using KeyContextId = vmp::runtime::trusted_oracle::KeyContextId;

inline constexpr std::uint64_t kLockstepDispatchInterval = 1u << 12;

enum class DetectorKind : std::uint8_t {
  hardware_breakpoint = 0,
  frida = 1,
  emulator = 2,
};

struct DetectorEvaluation {
  DetectorKind detector = DetectorKind::hardware_breakpoint;
  bool detected = false;
  bool divergent = false;
  bool primary_suspicious = false;
  bool secondary_suspicious = false;
  std::uint32_t vote_count = 0;
  std::string event_type;
  std::string note;
};

struct HardwareBreakpointReadings {
  bool debug_registers_sampled = false;
  std::array<std::uint64_t, 8> debug_registers{};
  bool sigtrap_sampled = false;
  bool sigtrap_triggered = false;
};

struct FridaReadings {
  bool maps_sampled = false;
  std::vector<std::string> maps_hits;
  bool tls_slots_sampled = false;
  std::size_t tls_slot_count = 0;
  std::size_t tls_slot_threshold = 12;
};

struct EmulatorReadings {
  bool cpuid_sampled = false;
  bool hypervisor_vendor_present = false;
  std::string hypervisor_vendor;
  bool rdtsc_sampled = false;
  bool rdtsc_low_jitter = false;
  std::vector<std::uint64_t> rdtsc_deltas;
  bool fsbase_sampled = false;
  std::uintptr_t fsbase = 0;
  bool fsbase_suspicious = false;
  bool syscall_side_effect_sampled = false;
  bool syscall_side_effect_suspicious = false;
};

struct HeartbeatSnapshot {
  std::uint64_t hardware_breakpoint = 0;
  std::uint64_t frida = 0;
  std::uint64_t emulator = 0;
};

struct SupervisorOptions {
  std::chrono::milliseconds heartbeat_interval{50};
  std::uint64_t dispatch_check_interval = kLockstepDispatchInterval;
  unsigned stagnant_dispatch_limit = 3;
  bool auto_start_heartbeat_threads = true;
};

class EnvironmentDetectorSupervisor {
 public:
  explicit EnvironmentDetectorSupervisor(KeyContextId key_context_id = {},
                                        std::filesystem::path audit_path = {},
                                        SupervisorOptions options = {});
  ~EnvironmentDetectorSupervisor();

  EnvironmentDetectorSupervisor(const EnvironmentDetectorSupervisor&) = delete;
  EnvironmentDetectorSupervisor& operator=(const EnvironmentDetectorSupervisor&) = delete;
  EnvironmentDetectorSupervisor(EnvironmentDetectorSupervisor&&) = delete;
  EnvironmentDetectorSupervisor& operator=(EnvironmentDetectorSupervisor&&) = delete;

  vmp::runtime::audit::ReactionDispatcher& reaction_dispatcher() noexcept;
  vmp::runtime::trusted_oracle::TrustedOracle& oracle() noexcept;
  const vmp::runtime::trusted_oracle::TrustedOracle& oracle() const noexcept;

  DetectorEvaluation evaluate_hardware_breakpoints(const HardwareBreakpointReadings& readings,
                                                   vmp::runtime::audit::ReactionDispatcher* dispatcher = nullptr);
  DetectorEvaluation evaluate_frida_injection(const FridaReadings& readings,
                                              vmp::runtime::audit::ReactionDispatcher* dispatcher = nullptr);
  DetectorEvaluation evaluate_emulator(const EmulatorReadings& readings,
                                       vmp::runtime::audit::ReactionDispatcher* dispatcher = nullptr);

  HardwareBreakpointReadings sample_hardware_breakpoints();
  FridaReadings sample_frida_injection();
  EmulatorReadings sample_emulator();

  DetectorEvaluation probe_hardware_breakpoints(vmp::runtime::audit::ReactionDispatcher* dispatcher = nullptr);
  DetectorEvaluation probe_frida_injection(vmp::runtime::audit::ReactionDispatcher* dispatcher = nullptr);
  DetectorEvaluation probe_emulator(vmp::runtime::audit::ReactionDispatcher* dispatcher = nullptr);

  bool start();
  void stop();
  bool running() const noexcept;
  HeartbeatSnapshot heartbeat_snapshot() const noexcept;
  void set_heartbeat_for_tests(DetectorKind kind, std::uint64_t value) noexcept;
  void observe_dispatch(vmp::runtime::audit::ReactionDispatcher* dispatcher = nullptr);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

class DefaultSupervisorOverride {
 public:
  explicit DefaultSupervisorOverride(EnvironmentDetectorSupervisor& supervisor) noexcept;
  ~DefaultSupervisorOverride();

  DefaultSupervisorOverride(const DefaultSupervisorOverride&) = delete;
  DefaultSupervisorOverride& operator=(const DefaultSupervisorOverride&) = delete;

 private:
  EnvironmentDetectorSupervisor* previous_ = nullptr;
};

EnvironmentDetectorSupervisor& default_supervisor();

 }  // namespace vmp::runtime::env_detectors
