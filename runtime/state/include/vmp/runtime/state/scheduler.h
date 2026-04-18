#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <utility>
#include <vector>

#include <vmp/runtime/state/profile.h>

namespace vmp::runtime::vm1 {
class Vm1Module;
}

namespace vmp::runtime::vm2 {
class Vm2Module;
class Vm2Context;
}

namespace vmp::runtime::state {

class RuntimeState;

enum class HotSchedulerMode {
  normal,
  conservative,
};

enum class ScheduleActionKind {
  jit_compile_now,
  jit_evict,
  trace_stitch,
  trace_break,
  cache_resize,
  warmup_kick,
};

struct ScheduleAction {
  ScheduleActionKind kind = ScheduleActionKind::jit_compile_now;
  std::uint64_t module_id = 0;
  std::uint32_t pc = 0;
  std::uint64_t arg = 0;
};

struct SchedulerModuleState {
  std::size_t current_cache_bytes = 0;
  std::size_t current_budget_bytes = 0;
};

struct SchedulerInput {
  std::map<std::uint64_t, SchedulerModuleState> modules;
  std::size_t min_budget_bytes = 1u * 1024u * 1024u;
  std::size_t max_budget_bytes = 16u * 1024u * 1024u;
  std::uint64_t jit_hot_threshold = 128;
  std::uint64_t evict_cold_threshold = 4;
  std::uint64_t trace_stitch_threshold = 32;
  double warmup_importance_threshold = 0.85;
};

struct SchedulerBindings {
  std::map<std::uint64_t, const vmp::runtime::vm1::Vm1Module*> vm1_modules;
  std::map<std::uint64_t, std::pair<const vmp::runtime::vm2::Vm2Module*, const vmp::runtime::vm2::Vm2Context*>> vm2_modules;
  std::map<std::pair<std::uint64_t, std::uint32_t>, std::vector<std::uint32_t>> trace_chains;
};

class HotScheduler {
 public:
  void set_mode(HotSchedulerMode mode) noexcept;
  HotSchedulerMode mode() const noexcept;

  std::vector<ScheduleAction> make_actions(const OfflineProfile& fused_profile,
                                           const HotRecorderSnapshot& online,
                                           const SchedulerInput& input,
                                           RuntimeState* runtime_state = nullptr) const;

  void apply_actions(const std::vector<ScheduleAction>& actions,
                     const SchedulerBindings& bindings,
                     RuntimeState* runtime_state = nullptr) const;

 private:
  mutable std::mutex mutex_;
  HotSchedulerMode mode_ = HotSchedulerMode::normal;
};

const char* to_string(ScheduleActionKind kind) noexcept;
const char* to_string(HotSchedulerMode mode) noexcept;

}  // namespace vmp::runtime::state
