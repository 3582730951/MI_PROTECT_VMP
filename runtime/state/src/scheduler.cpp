#include <vmp/runtime/state/scheduler.h>

#include <algorithm>
#include <cmath>
#include <limits>
#include <sstream>

#include <vmp/runtime/jit/vm1_jit.h>
#include <vmp/runtime/jit/vm2_jit.h>
#include <vmp/runtime/state/state.h>
#include <vmp/runtime/vm1/vm1.h>
#include <vmp/runtime/vm2/vm2.h>

namespace vmp::runtime::state {
namespace {

void emit(RuntimeState* runtime_state, const char* type, const std::string& note, std::uint64_t pc = 0) {
  if (runtime_state != nullptr) {
    runtime_state->append_audit_event(type, note, pc);
  }
}

std::uint64_t entry_score(const ProfileEntry& entry) {
  return entry.hits + static_cast<std::uint64_t>(entry.importance * 1000.0) + static_cast<std::uint64_t>(entry.hot_class) * 100;
}

}  // namespace

void HotScheduler::set_mode(HotSchedulerMode mode) noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  mode_ = mode;
}

HotSchedulerMode HotScheduler::mode() const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return mode_;
}

const char* to_string(ScheduleActionKind kind) noexcept {
  switch (kind) {
    case ScheduleActionKind::jit_compile_now: return "jit_compile_now";
    case ScheduleActionKind::jit_evict: return "jit_evict";
    case ScheduleActionKind::trace_stitch: return "trace_stitch";
    case ScheduleActionKind::trace_break: return "trace_break";
    case ScheduleActionKind::cache_resize: return "cache_resize";
    case ScheduleActionKind::warmup_kick: return "warmup_kick";
  }
  return "unknown";
}

const char* to_string(HotSchedulerMode mode) noexcept {
  switch (mode) {
    case HotSchedulerMode::normal: return "normal";
    case HotSchedulerMode::conservative: return "conservative";
  }
  return "normal";
}

std::vector<ScheduleAction> HotScheduler::make_actions(const OfflineProfile& fused_profile,
                                                       const HotRecorderSnapshot& online,
                                                       const SchedulerInput& input,
                                                       RuntimeState* runtime_state) const {
  auto local_input = input;
  if (mode() == HotSchedulerMode::conservative) {
    local_input.jit_hot_threshold = std::max<std::uint64_t>(local_input.jit_hot_threshold, 512);
    local_input.trace_stitch_threshold = std::max<std::uint64_t>(local_input.trace_stitch_threshold, 128);
    local_input.warmup_importance_threshold = 2.0;
  }

  std::vector<ScheduleAction> actions;
  std::map<std::uint64_t, double> module_heat;
  double total_heat = 0.0;
  for (const auto& entry : fused_profile.entries) {
    const double heat = static_cast<double>(entry.hits) * std::max(0.01, entry.importance) * (1.0 + entry.hot_class);
    module_heat[entry.module_id] += heat;
    total_heat += heat;
  }

  for (const auto& [module_id, state] : local_input.modules) {
    const double share = total_heat == 0.0 ? 0.0 : (module_heat[module_id] / total_heat);
    const auto desired = static_cast<std::size_t>(std::llround(static_cast<double>(local_input.min_budget_bytes) +
                                                               share * static_cast<double>(local_input.max_budget_bytes - local_input.min_budget_bytes)));
    const auto bounded = std::max(local_input.min_budget_bytes, std::min(local_input.max_budget_bytes, desired));
    if (state.current_budget_bytes != bounded) {
      actions.push_back({ScheduleActionKind::cache_resize, module_id, 0, bounded});
    }
  }

  std::map<std::uint64_t, ProfileEntry> coldest;
  for (const auto& entry : fused_profile.entries) {
    auto it = coldest.find(entry.module_id);
    if (it == coldest.end() || entry_score(entry) < entry_score(it->second)) {
      coldest[entry.module_id] = entry;
    }
    if (entry.hot_class >= 2 || entry.hits >= local_input.jit_hot_threshold) {
      actions.push_back({ScheduleActionKind::jit_compile_now, entry.module_id, entry.pc, entry.hits});
    } else if (online.uptime_seconds < 60.0 && entry.importance >= local_input.warmup_importance_threshold) {
      actions.push_back({ScheduleActionKind::warmup_kick, entry.module_id, entry.pc, entry.hits});
    }
  }

  for (const auto& [module_id, state] : local_input.modules) {
    auto it = coldest.find(module_id);
    if (it != coldest.end() && state.current_cache_bytes >= state.current_budget_bytes && it->second.hits <= local_input.evict_cold_threshold) {
      actions.push_back({ScheduleActionKind::jit_evict, module_id, it->second.pc, it->second.hits});
    }
  }

  for (const auto& [edge, count] : online.trace_edges) {
    if (count >= local_input.trace_stitch_threshold) {
      actions.push_back({ScheduleActionKind::trace_stitch, edge.module_id, edge.from_pc, edge.to_pc});
    } else if (count <= 1) {
      actions.push_back({ScheduleActionKind::trace_break, edge.module_id, edge.from_pc, edge.to_pc});
    }
  }

  if (actions.empty()) {
    emit(runtime_state, "scheduler_skipped", std::string("reason=no_actions mode=") + to_string(mode()));
  } else {
    for (const auto& action : actions) {
      std::ostringstream oss;
      oss << "kind=" << to_string(action.kind) << " module=" << action.module_id << " pc=" << action.pc << " arg=" << action.arg
          << " mode=" << to_string(mode());
      emit(runtime_state, "scheduler_decision", oss.str(), action.pc);
    }
  }
  return actions;
}

void HotScheduler::apply_actions(const std::vector<ScheduleAction>& actions,
                                 const SchedulerBindings& bindings,
                                 RuntimeState* runtime_state) const {
  for (const auto& action : actions) {
    const auto vm1_it = bindings.vm1_modules.find(action.module_id);
    const auto vm2_it = bindings.vm2_modules.find(action.module_id);
    switch (action.kind) {
      case ScheduleActionKind::jit_compile_now:
      case ScheduleActionKind::warmup_kick:
        if (vm1_it != bindings.vm1_modules.end() && vm1_it->second != nullptr) {
          (void)vmp::runtime::jit::Vm1Jit::instance().compile_if_needed(*vm1_it->second, action.pc, action.arg);
        } else if (vm2_it != bindings.vm2_modules.end() && vm2_it->second.first != nullptr && vm2_it->second.second != nullptr) {
          (void)vmp::runtime::jit::Vm2Jit::instance().compile_if_needed(*vm2_it->second.first, *vm2_it->second.second,
                                                                        action.pc, std::max<std::uint64_t>(action.arg, 1024));
        } else {
          emit(runtime_state, "scheduler_skipped", "reason=missing_binding", action.pc);
        }
        break;
      case ScheduleActionKind::jit_evict:
      case ScheduleActionKind::trace_break:
        if (vm1_it != bindings.vm1_modules.end()) {
          vmp::runtime::jit::Vm1Jit::instance().invalidate_entry(action.module_id, action.pc);
        }
        if (vm2_it != bindings.vm2_modules.end()) {
          vmp::runtime::jit::Vm2Jit::instance().invalidate_entry(action.module_id, action.pc);
        }
        break;
      case ScheduleActionKind::trace_stitch: {
        auto chain_it = bindings.trace_chains.find({action.module_id, action.pc});
        if (vm1_it != bindings.vm1_modules.end() && vm1_it->second != nullptr && chain_it != bindings.trace_chains.end()) {
          vmp::runtime::jit::Vm1Jit::instance().record_trace_observation(*vm1_it->second, chain_it->second);
          emit(runtime_state, "trace_stitch_applied", "module=" + std::to_string(action.module_id) + " pc=" + std::to_string(action.pc), action.pc);
        } else {
          emit(runtime_state, "scheduler_skipped", "reason=missing_trace_chain", action.pc);
        }
        break;
      }
      case ScheduleActionKind::cache_resize:
        if (vm1_it != bindings.vm1_modules.end()) {
          vmp::runtime::jit::Vm1Jit::instance().set_module_cache_budget_bytes(static_cast<std::size_t>(action.arg));
        }
        if (vm2_it != bindings.vm2_modules.end()) {
          vmp::runtime::jit::Vm2Jit::instance().set_module_cache_budget_bytes(static_cast<std::size_t>(action.arg));
        }
        emit(runtime_state, "cache_resize", "module=" + std::to_string(action.module_id) + " bytes=" + std::to_string(action.arg));
        break;
    }
  }
}

}  // namespace vmp::runtime::state
