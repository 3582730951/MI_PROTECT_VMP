#include <vmp/runtime/state/state.h>
#include <vmp/runtime/audit/reaction.h>

#include <algorithm>
#include <cstdlib>
#include <exception>
#include <thread>

#if VMP_WITH_JIT
#include <vmp/runtime/jit/vm1_jit.h>
#include <vmp/runtime/jit/vm2_jit.h>
#endif
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/strings/keyctx.h>

namespace vmp::runtime::state {
namespace {

std::chrono::milliseconds default_async_delay() noexcept { return std::chrono::milliseconds(0); }

void default_scheduler(std::chrono::milliseconds delay, std::function<void()> fn) {
  std::thread([delay, fn = std::move(fn)]() mutable {
    std::this_thread::sleep_for(delay);
    try {
      fn();
    } catch (...) {
    }
  }).detach();
}

void default_exit(int code) { std::exit(code); }

std::uint32_t read_grace_env() noexcept {
  if (const char* raw = std::getenv("VMP_TERMINATE_GRACE_MS"); raw != nullptr && *raw != '\0') {
    try {
      return static_cast<std::uint32_t>(std::stoul(raw));
    } catch (...) {
      return 500;
    }
  }
  return 500;
}

void audit_flush(vmp::runtime::audit::AuditWriter* audit) noexcept {
  if (audit != nullptr) {
    audit->flush();
  }
}

bool is_failure_event(RuntimeEventKind kind) noexcept {
  return kind == RuntimeEventKind::env_anomaly || kind == RuntimeEventKind::integrity_failed ||
         kind == RuntimeEventKind::detection_event || kind == RuntimeEventKind::further_failure;
}

}  // namespace

RuntimeState& RuntimeState::instance() noexcept {
  static RuntimeState state;
  return state;
}

bool RuntimeState::init_once(vmp::runtime::audit::AuditWriter* audit, RuntimeConfig config) noexcept {
  std::string offline_path;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) {
      return false;
    }
    audit_ = audit;
    config_ = std::move(config);
    initialized_ = true;
    state_ = RuntimeStateValue::init;
    flags_ |= bit_for(RuntimeFlag::loader_initialized);
    terminate_grace_ms_ = config_.terminate_grace_ms == 0 ? read_grace_env() : config_.terminate_grace_ms;
    if (const char* env_weight = std::getenv("VMP_PROFILE_ONLINE_WEIGHT"); env_weight != nullptr) {
      try {
        online_weight_ = std::stod(env_weight);
      } catch (...) {
        online_weight_ = 0.4;
      }
    }
    if (const char* env_profile = std::getenv("VMP_OFFLINE_PROFILE"); env_profile != nullptr && *env_profile != '\0') {
      offline_path = env_profile;
    }
  }
#if VMP_WITH_JIT
  vmp::runtime::jit::Vm1Jit::instance().set_audit_writer(audit);
  vmp::runtime::jit::Vm2Jit::instance().set_audit_writer(audit);
#endif
  if (!offline_path.empty()) {
    if (!load_offline_profile(offline_path)) {
      append_audit_event("profile_load_failed", std::string("path=") + offline_path);
    }
  }
  observe(RuntimeEventKind::init_done);
  return true;
}

RuntimeStateValue RuntimeState::current_state() const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return state_;
}

bool RuntimeState::initialized() const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return initialized_;
}

void RuntimeState::observe(RuntimeEventKind kind) noexcept { observe(kind, {}); }

void RuntimeState::observe(RuntimeEventKind kind, RuntimeEventPayload payload) noexcept {
  RuntimeTransition transition{};
  std::vector<TransitionCallback> callbacks;
  std::vector<std::function<void()>> wipe_callbacks;
  vmp::runtime::audit::AuditWriter* audit = nullptr;
  RuntimeConfig config;
  RuntimeStateValue state_after = RuntimeStateValue::init;
  bool schedule_timeout = false;
  bool schedule_terminate = false;
  bool lock_plaintext = false;
  bool flush_audit_now = false;
  bool emit_transition = false;
  bool key_rotated = false;

  try {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      last_event_ = kind;
      last_payload_ = payload;
      audit = audit_;
      config = config_;
      transition.from = state_;
      transition.event = kind;
      transition.payload = payload;

      if (kind == RuntimeEventKind::integrity_failed) {
        flags_ |= bit_for(RuntimeFlag::integrity_failed);
      } else if (kind == RuntimeEventKind::env_anomaly || kind == RuntimeEventKind::detection_event ||
                 kind == RuntimeEventKind::hw_breakpoint) {
        flags_ |= bit_for(RuntimeFlag::env_anomaly);
      } else if (kind == RuntimeEventKind::key_rotated) {
        flags_ |= bit_for(RuntimeFlag::key_rotated);
        key_rotated = true;
      }

      if (kind == RuntimeEventKind::integrity_failed) {
        callbacks = {};
      }

      switch (state_) {
        case RuntimeStateValue::init:
          if (kind == RuntimeEventKind::init_done) {
            state_ = RuntimeStateValue::ready;
            emit_transition = true;
          } else if (kind == RuntimeEventKind::hw_breakpoint) {
            state_ = RuntimeStateValue::terminating;
            emit_transition = true;
            schedule_terminate = !terminating_scheduled_;
            terminating_scheduled_ = true;
          }
          break;
        case RuntimeStateValue::ready:
          if (kind == RuntimeEventKind::hw_breakpoint) {
            state_ = RuntimeStateValue::terminating;
            emit_transition = true;
            schedule_terminate = !terminating_scheduled_;
            terminating_scheduled_ = true;
          } else if (kind == RuntimeEventKind::env_anomaly || kind == RuntimeEventKind::integrity_failed ||
                     kind == RuntimeEventKind::detection_event) {
            state_ = RuntimeStateValue::degraded;
            emit_transition = true;
            lock_plaintext = true;
            schedule_timeout = true;
          } else if (kind == RuntimeEventKind::shutdown_requested) {
            state_ = RuntimeStateValue::terminating;
            emit_transition = true;
            schedule_terminate = !terminating_scheduled_;
            terminating_scheduled_ = true;
          }
          break;
        case RuntimeStateValue::degraded:
          if (kind == RuntimeEventKind::shutdown_requested || kind == RuntimeEventKind::timeout ||
              kind == RuntimeEventKind::further_failure || kind == RuntimeEventKind::hw_breakpoint ||
              kind == RuntimeEventKind::env_anomaly || kind == RuntimeEventKind::integrity_failed ||
              kind == RuntimeEventKind::detection_event) {
            state_ = RuntimeStateValue::terminating;
            emit_transition = true;
            schedule_terminate = !terminating_scheduled_;
            terminating_scheduled_ = true;
          }
          break;
        case RuntimeStateValue::terminating:
          break;
      }

      if (transition.from == RuntimeStateValue::degraded && state_ == RuntimeStateValue::terminating &&
          (kind == RuntimeEventKind::env_anomaly || kind == RuntimeEventKind::integrity_failed ||
           kind == RuntimeEventKind::detection_event)) {
        transition.event = RuntimeEventKind::further_failure;
      }

      transition.to = state_;
      state_after = state_;
      if (lock_plaintext) {
        plaintext_budget_locked_ = true;
        hot_scheduler_.set_mode(HotSchedulerMode::conservative);
        vmp::runtime::strings::set_global_plaintext_budget_lock(true);
      }
      if (emit_transition) {
        for (const auto& [_, cb] : transition_callbacks_) {
          callbacks.push_back(cb);
        }
      }
      if (schedule_terminate) {
        for (const auto& [_, cb] : wipe_callbacks_) {
          wipe_callbacks.push_back(cb);
        }
        flush_audit_now = true;
      }
    }

    if (kind == RuntimeEventKind::integrity_failed) {
      append_audit_event("integrity_failed", payload.note.empty() ? ("region=" + payload.name) : payload.note,
                         payload.program_counter);
#if VMP_WITH_JIT
      vmp::runtime::jit::Vm1Jit::instance().invalidate_all();
      vmp::runtime::jit::Vm2Jit::instance().invalidate_on_event(vmp::runtime::jit::Vm2JitEventKind::integrity_failed);
#endif
    } else if (kind == RuntimeEventKind::detection_event || kind == RuntimeEventKind::env_anomaly) {
#if VMP_WITH_JIT
      vmp::runtime::jit::Vm2Jit::instance().invalidate_on_event(vmp::runtime::jit::Vm2JitEventKind::detection_event);
#endif
    }
    if (key_rotated) {
#if VMP_WITH_JIT
      vmp::runtime::jit::Vm1Jit::instance().invalidate_all();
      vmp::runtime::jit::Vm2Jit::instance().invalidate_on_event(vmp::runtime::jit::Vm2JitEventKind::key_rotated);
#endif
    }
    if (emit_transition) {
      append_audit_event("state_transition",
                         std::string("from=") + to_string(transition.from) + " to=" + to_string(transition.to) +
                             " event=" + to_string(transition.event) +
                             (transition.payload.name.empty() ? std::string() : " name=" + transition.payload.name),
                         payload.program_counter);
#if VMP_WITH_JIT
      if (transition.to == RuntimeStateValue::degraded || transition.to == RuntimeStateValue::terminating) {
        vmp::runtime::jit::Vm1Jit::instance().invalidate_all();
        vmp::runtime::jit::Vm2Jit::instance().invalidate_all();
      }
#endif
      for (const auto& cb : callbacks) {
        if (cb) {
          cb(transition);
        }
      }
    }

    if (state_after == RuntimeStateValue::degraded && schedule_timeout) {
      auto scheduler = config.scheduler ? config.scheduler : std::function<void(std::chrono::milliseconds, std::function<void()>)>(default_scheduler);
      scheduler(std::chrono::milliseconds(terminate_grace_ms_), [this]() { this->observe(RuntimeEventKind::timeout); });
    }

    if (schedule_terminate) {
#if VMP_WITH_JIT
      vmp::runtime::jit::Vm1Jit::instance().invalidate_all();
      vmp::runtime::jit::Vm2Jit::instance().invalidate_all();
#endif
      append_audit_event("terminating_grace_start", "grace_ms=" + std::to_string(terminate_grace_ms_));
      if (flush_audit_now) {
        audit_flush(audit);
      }
      auto scheduler = config.scheduler ? config.scheduler : std::function<void(std::chrono::milliseconds, std::function<void()>)>(default_scheduler);
      auto exit_fn = config.exit_fn ? config.exit_fn : std::function<void(int)>(default_exit);
      const auto grace = std::chrono::milliseconds(terminate_grace_ms_);
      scheduler(grace, [this, wipe_callbacks = std::move(wipe_callbacks), exit_fn = std::move(exit_fn)]() mutable {
        try {
          for (const auto& cb : wipe_callbacks) {
            if (cb) {
              cb();
            }
          }
          vmp::runtime::strings::wipe_all_key_context_subkeys();
          append_audit_event("terminating_done", "process_exit");
          if (auto* audit_writer = get_audit(); audit_writer != nullptr) {
            audit_writer->flush();
          }
        } catch (...) {
        }
        exit_fn(0);
      });
    }
  } catch (...) {
  }
}

std::size_t RuntimeState::on_transition(TransitionCallback cb) {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto token = next_callback_token_++;
  transition_callbacks_.push_back({token, std::move(cb)});
  return token;
}

void RuntimeState::unregister_transition_callback(std::size_t token) noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  transition_callbacks_.erase(std::remove_if(transition_callbacks_.begin(), transition_callbacks_.end(),
                                             [token](const auto& item) { return item.first == token; }),
                              transition_callbacks_.end());
}

std::size_t RuntimeState::register_wipe_callback(std::function<void()> cb) {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto token = next_callback_token_++;
  wipe_callbacks_.push_back({token, std::move(cb)});
  return token;
}

void RuntimeState::unregister_wipe_callback(std::size_t token) noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  wipe_callbacks_.erase(std::remove_if(wipe_callbacks_.begin(), wipe_callbacks_.end(),
                                       [token](const auto& item) { return item.first == token; }),
                        wipe_callbacks_.end());
}

void RuntimeState::detector_invalidate_module(std::uint64_t module_id) noexcept {
#if VMP_WITH_JIT
  vmp::runtime::jit::Vm1Jit::instance().invalidate_module(module_id);
  vmp::runtime::jit::Vm2Jit::instance().invalidate_module(module_id);
#else
  (void)module_id;
#endif
}

void RuntimeState::set_flag(RuntimeFlag flag, bool enabled) noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto bit = bit_for(flag);
  if (enabled) {
    flags_ |= bit;
  } else {
    flags_ &= ~bit;
  }
}

void RuntimeState::set_jit_capability(bool unavailable) noexcept { set_flag(RuntimeFlag::jit_execmem_unavailable, unavailable); }

bool RuntimeState::check_flag(RuntimeFlag flag) const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return (flags_ & bit_for(flag)) != 0;
}

bool RuntimeState::jit_execmem_unavailable() const noexcept { return check_flag(RuntimeFlag::jit_execmem_unavailable); }

vmp::runtime::audit::AuditWriter* RuntimeState::get_audit() const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return audit_;
}

HotScheduler& RuntimeState::get_hot_scheduler() noexcept { return hot_scheduler_; }
const HotScheduler& RuntimeState::get_hot_scheduler() const noexcept { return hot_scheduler_; }

RuntimeConfig RuntimeState::config() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return config_;
}

bool RuntimeState::load_offline_profile(const std::string& path) noexcept {
  try {
    auto loaded = vmp::runtime::state::load_from_file(path);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      offline_profile_ = std::move(loaded);
    }
    append_audit_event("profile_loaded", "path=" + path);
    return true;
  } catch (const std::exception& ex) {
    append_audit_event("profile_load_failed", std::string("path=") + path + " error=" + ex.what());
    return false;
  }
}

OfflineProfile RuntimeState::offline_profile() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return offline_profile_;
}

OfflineProfile RuntimeState::fused_profile_snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return fuse_profiles(offline_profile_, hot_recorder_.snapshot(), online_weight_);
}

HotRecorder& RuntimeState::hot_recorder() noexcept { return hot_recorder_; }
const HotRecorder& RuntimeState::hot_recorder() const noexcept { return hot_recorder_; }

double RuntimeState::online_weight() const noexcept { return online_weight_; }

void RuntimeState::append_audit_event(const std::string& event_type,
                                      const std::string& context_note,
                                      std::uint64_t program_counter) const noexcept {
  auto* audit = get_audit();
  if (audit == nullptr) {
    return;
  }
  audit->append(vmp::runtime::audit::make_event(event_type, context_note, program_counter, "runtime_state", "", 0));
}

RuntimeSnapshot RuntimeState::snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  RuntimeSnapshot out;
  out.state = state_;
  out.config = config_;
  out.flags = flags_;
  out.online_weight = online_weight_;
  out.plaintext_budget_locked = plaintext_budget_locked_;
  out.scheduler_mode = hot_scheduler_.mode();
  out.terminate_grace_ms = terminate_grace_ms_;
  out.terminating_scheduled = terminating_scheduled_;
  out.last_event = last_event_;
  out.last_payload = last_payload_;
  return out;
}

void RuntimeState::shutdown() noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  audit_ = nullptr;
  config_ = RuntimeConfig{};
  offline_profile_ = {};
  hot_recorder_.reset();
  hot_scheduler_.set_mode(HotSchedulerMode::normal);
  online_weight_ = 0.4;
  flags_ = 0;
  initialized_ = false;
  state_ = RuntimeStateValue::init;
  plaintext_budget_locked_ = false;
  terminating_scheduled_ = false;
  terminate_grace_ms_ = 500;
  transition_callbacks_.clear();
  wipe_callbacks_.clear();
  next_callback_token_ = 1;
  last_event_ = RuntimeEventKind::audit_event;
  last_payload_ = {};
  vmp::runtime::strings::set_global_plaintext_budget_lock(false);
#if VMP_WITH_JIT
  vmp::runtime::jit::Vm1Jit::instance().set_audit_writer(nullptr);
  vmp::runtime::jit::Vm2Jit::instance().set_audit_writer(nullptr);
#endif
}

std::uint32_t RuntimeState::bit_for(RuntimeFlag flag) noexcept { return static_cast<std::uint32_t>(flag); }

const char* to_string(RuntimeStateValue value) noexcept {
  switch (value) {
    case RuntimeStateValue::init: return "Init";
    case RuntimeStateValue::ready: return "Ready";
    case RuntimeStateValue::degraded: return "Degraded";
    case RuntimeStateValue::terminating: return "Terminating";
  }
  return "Init";
}

const char* to_string(RuntimeEventKind value) noexcept {
  switch (value) {
    case RuntimeEventKind::init_done: return "init_done";
    case RuntimeEventKind::env_anomaly: return "env_anomaly";
    case RuntimeEventKind::integrity_failed: return "integrity_failed";
    case RuntimeEventKind::hot_threshold_reached: return "hot_threshold_reached";
    case RuntimeEventKind::audit_event: return "audit_event";
    case RuntimeEventKind::key_rotated: return "key_rotated";
    case RuntimeEventKind::detection_event: return "detection_event";
    case RuntimeEventKind::shutdown_requested: return "shutdown_requested";
    case RuntimeEventKind::hw_breakpoint: return "hw_breakpoint";
    case RuntimeEventKind::further_failure: return "further_failure";
    case RuntimeEventKind::timeout: return "timeout";
  }
  return "audit_event";
}

const char* Facade::status() const noexcept { return "runtime_state_ready"; }

}  // namespace vmp::runtime::state

namespace vmp::runtime::audit {
bool runtime_state_bridge(const AnalysisEventRecord& record, ReactionPolicy policy) noexcept {
  vmp::runtime::state::RuntimeEventPayload payload;
  payload.name = record.event_type;
  payload.note = record.context_note;
  payload.program_counter = record.program_counter;
  auto kind = vmp::runtime::state::RuntimeEventKind::audit_event;
  switch (policy) {
    case ReactionPolicy::audit_then_delayed_exit: kind = vmp::runtime::state::RuntimeEventKind::hw_breakpoint; break;
    case ReactionPolicy::degrade: kind = vmp::runtime::state::RuntimeEventKind::env_anomaly; break;
    case ReactionPolicy::decoy_terminate: kind = vmp::runtime::state::RuntimeEventKind::shutdown_requested; break;
    case ReactionPolicy::log:
    case ReactionPolicy::audit_only: kind = vmp::runtime::state::RuntimeEventKind::audit_event; break;
  }
  auto& state = vmp::runtime::state::RuntimeState::instance();
  if (!state.initialized()) {
    return false;
  }
  state.observe(kind, payload);
  return true;
}
}  // namespace vmp::runtime::audit
