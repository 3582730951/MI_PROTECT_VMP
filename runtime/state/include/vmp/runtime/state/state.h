#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/state/hot_recorder.h>
#include <vmp/runtime/state/profile.h>
#include <vmp/runtime/state/scheduler.h>

namespace vmp::runtime::state {

enum class RuntimeFlag : std::uint32_t {
  loader_initialized = 1u << 0,
  integrity_failed = 1u << 1,
  env_anomaly = 1u << 2,
  key_rotated = 1u << 3,
  key_context_loaded = 1u << 4,
  placeholder_called = 1u << 5,
  jit_execmem_unavailable = 1u << 6,
};

enum class RuntimeStateValue {
  init,
  ready,
  degraded,
  terminating,
};

enum class RuntimeEventKind {
  init_done,
  env_anomaly,
  integrity_failed,
  hot_threshold_reached,
  audit_event,
  key_rotated,
  detection_event,
  shutdown_requested,
  hw_breakpoint,
  further_failure,
  timeout,
};

struct RuntimeEventPayload {
  std::string name;
  std::string note;
  std::uint64_t module_id = 0;
  std::uint64_t program_counter = 0;
};

struct RuntimeConfig {
  std::string platform;
  std::string loader_entrypoint;
  bool loader_disabled = false;
  std::uint32_t terminate_grace_ms = 0;
  std::function<void(int)> exit_fn;
  std::function<void(std::chrono::milliseconds, std::function<void()>)> scheduler;
};

struct RuntimeTransition {
  RuntimeStateValue from = RuntimeStateValue::init;
  RuntimeStateValue to = RuntimeStateValue::init;
  RuntimeEventKind event = RuntimeEventKind::audit_event;
  RuntimeEventPayload payload{};
};

struct RuntimeSnapshot {
  RuntimeStateValue state = RuntimeStateValue::init;
  RuntimeConfig config{};
  std::uint32_t flags = 0;
  double online_weight = 0.4;
  bool plaintext_budget_locked = false;
  HotSchedulerMode scheduler_mode = HotSchedulerMode::normal;
  std::uint32_t terminate_grace_ms = 500;
  bool terminating_scheduled = false;
  RuntimeEventKind last_event = RuntimeEventKind::audit_event;
  RuntimeEventPayload last_payload{};
};

class RuntimeState {
 public:
  using TransitionCallback = std::function<void(const RuntimeTransition&)>;

  static RuntimeState& instance() noexcept;

  bool init_once(vmp::runtime::audit::AuditWriter* audit, RuntimeConfig config) noexcept;
  RuntimeStateValue current_state() const noexcept;
  bool initialized() const noexcept;
  void observe(RuntimeEventKind kind) noexcept;
  void observe(RuntimeEventKind kind, RuntimeEventPayload payload) noexcept;
  std::size_t on_transition(TransitionCallback cb);
  void unregister_transition_callback(std::size_t token) noexcept;
  std::size_t register_wipe_callback(std::function<void()> cb);
  void unregister_wipe_callback(std::size_t token) noexcept;
  void detector_invalidate_module(std::uint64_t module_id) noexcept;
  void set_flag(RuntimeFlag flag, bool enabled = true) noexcept;
  void set_jit_capability(bool jit_execmem_unavailable) noexcept;
  bool check_flag(RuntimeFlag flag) const noexcept;
  bool jit_execmem_unavailable() const noexcept;
  vmp::runtime::audit::AuditWriter* get_audit() const noexcept;
  HotScheduler& get_hot_scheduler() noexcept;
  const HotScheduler& get_hot_scheduler() const noexcept;
  RuntimeConfig config() const;
  bool load_offline_profile(const std::string& path) noexcept;
  OfflineProfile offline_profile() const;
  OfflineProfile fused_profile_snapshot() const;
  HotRecorder& hot_recorder() noexcept;
  const HotRecorder& hot_recorder() const noexcept;
  double online_weight() const noexcept;
  void append_audit_event(const std::string& event_type,
                          const std::string& context_note,
                          std::uint64_t program_counter = 0) const noexcept;
  RuntimeSnapshot snapshot() const;
  void shutdown() noexcept;

 private:
  RuntimeState() = default;

  static std::uint32_t bit_for(RuntimeFlag flag) noexcept;

  mutable std::mutex mutex_;
  vmp::runtime::audit::AuditWriter* audit_ = nullptr;
  RuntimeConfig config_{};
  OfflineProfile offline_profile_{};
  HotRecorder hot_recorder_{};
  HotScheduler hot_scheduler_{};
  double online_weight_ = 0.4;
  std::uint32_t flags_ = 0;
  bool initialized_ = false;
  RuntimeStateValue state_ = RuntimeStateValue::init;
  RuntimeEventKind last_event_ = RuntimeEventKind::audit_event;
  RuntimeEventPayload last_payload_{};
  bool plaintext_budget_locked_ = false;
  bool terminating_scheduled_ = false;
  std::uint32_t terminate_grace_ms_ = 500;
  std::size_t next_callback_token_ = 1;
  std::vector<std::pair<std::size_t, TransitionCallback>> transition_callbacks_;
  std::vector<std::pair<std::size_t, std::function<void()>>> wipe_callbacks_;
};

const char* to_string(RuntimeStateValue value) noexcept;
const char* to_string(RuntimeEventKind value) noexcept;

struct Facade {
  const char* status() const noexcept;
};

}  // namespace vmp::runtime::state
