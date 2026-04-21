#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <vmp/runtime/audit/reaction.h>

namespace vmp::runtime::stack_probe {

inline constexpr std::uint16_t kProbeSelectorMask = 0x0fffu;
inline constexpr std::size_t kDefaultMaxFrames = 48;

enum class ProbeTriggerSite : std::uint8_t {
  dispatcher_entry = 0,
  trampoline_target_prologue = 1,
  vm1_handler_dispatch = 2,
  vm2_handler_dispatch = 3,
};

struct ProbeRequest {
  std::uint16_t token_low12 = 0;
  ProbeTriggerSite site = ProbeTriggerSite::dispatcher_entry;
  std::size_t max_frames = kDefaultMaxFrames;
};

struct MappingInfo {
  std::uintptr_t begin = 0;
  std::uintptr_t end = 0;
  std::string permissions;
  std::string description;
  bool executable = false;
  bool writable = false;
  bool private_mapping = false;
  bool file_backed = false;
  bool anonymous = false;
  bool deleted = false;
  bool allowlisted = false;
  bool violation = false;
};

struct FrameInspection {
  std::uintptr_t pc = 0;
  std::size_t frame_number = 0;
  MappingInfo mapping;
};

struct ProbeOutcome {
  std::uint64_t counter_value = 0;
  bool triggered = false;
  bool used_frame_pointer_walk = false;
  bool used_libunwind_fallback = false;
  bool event_emitted = false;
  std::size_t frames_examined = 0;
  std::vector<FrameInspection> suspicious_frames;
};

struct ProbeInvocation {
  ProbeTriggerSite site = ProbeTriggerSite::dispatcher_entry;
  std::uint16_t token_low12 = 0;
  std::uint64_t counter_value = 0;
  bool triggered = false;
};

struct ProbeDependencies {
  std::function<std::vector<std::uintptr_t>()> frame_pointer_walker;
  std::function<std::vector<std::uintptr_t>()> libunwind_walker;
  std::function<std::string()> maps_reader;
  std::function<bool(std::uint16_t token_low12, std::uint64_t counter_value)> trigger_decider;
  std::function<void(const ProbeInvocation&)> invocation_observer;
};

class StackProbeManager {
 public:
  explicit StackProbeManager(std::filesystem::path audit_path = {},
                             ProbeDependencies dependencies = {});
  ~StackProbeManager();

  StackProbeManager(const StackProbeManager&) = delete;
  StackProbeManager& operator=(const StackProbeManager&) = delete;
  StackProbeManager(StackProbeManager&&) = delete;
  StackProbeManager& operator=(StackProbeManager&&) = delete;

  ProbeOutcome maybe_probe(const ProbeRequest& request,
                           vmp::runtime::audit::ReactionDispatcher* dispatcher = nullptr);
  vmp::runtime::audit::ReactionDispatcher& reaction_dispatcher() noexcept;
  void reset_counter_for_tests() noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

class DefaultStackProbeOverride {
 public:
  explicit DefaultStackProbeOverride(StackProbeManager& probe) noexcept;
  ~DefaultStackProbeOverride();

  DefaultStackProbeOverride(const DefaultStackProbeOverride&) = delete;
  DefaultStackProbeOverride& operator=(const DefaultStackProbeOverride&) = delete;

 private:
  StackProbeManager* previous_ = nullptr;
};

StackProbeManager& default_stack_probe();

std::string to_string(ProbeTriggerSite site);
std::uint16_t selector_low12(std::uint64_t value) noexcept;

}  // namespace vmp::runtime::stack_probe
