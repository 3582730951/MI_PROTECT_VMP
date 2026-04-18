#include <vmp/runtime/audit/reaction.h>

#include <cstdlib>
#include <thread>

namespace vmp::runtime::audit {

bool runtime_state_bridge(const AnalysisEventRecord&, ReactionPolicy) noexcept __attribute__((weak));
bool runtime_state_bridge(const AnalysisEventRecord&, ReactionPolicy) noexcept { return false; }

namespace {

std::chrono::milliseconds default_delay() noexcept {
  if (const char* raw = std::getenv("VMP_TERMINATE_GRACE_MS"); raw != nullptr && *raw != '\0') {
    try {
      return std::chrono::milliseconds(std::stoul(raw));
    } catch (...) {
    }
  }
  return std::chrono::milliseconds(500);
}

void default_exit() noexcept { std::quick_exit(0); }

void default_scheduler(std::chrono::milliseconds delay, std::function<void()> hook) noexcept {
  try {
    std::thread([delay, hook = std::move(hook)]() mutable {
      std::this_thread::sleep_for(delay);
      try {
        hook();
      } catch (...) {
      }
    }).detach();
  } catch (...) {
    try {
      hook();
    } catch (...) {
    }
  }
}

}  // namespace

ReactionDispatcher::ReactionDispatcher(AuditWriter& writer_in, ReactionPolicy default_policy_in)
    : writer(writer_in),
      default_policy(default_policy_in),
      exit_fn(default_exit),
      scheduler(default_scheduler),
      delay_selector(default_delay) {}

void ReactionDispatcher::dispatch(const AnalysisEventRecord& record) noexcept { dispatch(record, default_policy); }

void ReactionDispatcher::dispatch(const AnalysisEventRecord& record, ReactionPolicy policy) noexcept {
  try {
    writer.append(record);
    if (policy == ReactionPolicy::audit_only || policy == ReactionPolicy::log) {
      return;
    }
    writer.flush();
    const bool handled = runtime_state_bridge(record, policy);
    if (!handled && policy == ReactionPolicy::audit_then_delayed_exit) {
      auto delay = delay_selector ? delay_selector() : std::chrono::milliseconds(500);
      auto exit_copy = exit_fn;
      if (scheduler) {
        scheduler(delay, [exit_copy]() mutable { if (exit_copy) exit_copy(); });
      } else if (exit_copy) {
        exit_copy();
      }
    }
  } catch (...) {
  }
}

void ReactionDispatcher::set_exit_fn(std::function<void()> exit_fn_in) noexcept { exit_fn = std::move(exit_fn_in); }

void ReactionDispatcher::set_scheduler(
    std::function<void(std::chrono::milliseconds, std::function<void()>)> scheduler_in) noexcept {
  scheduler = std::move(scheduler_in);
}

void ReactionDispatcher::set_delay_selector(std::function<std::chrono::milliseconds()> selector) noexcept {
  delay_selector = std::move(selector);
}

}  // namespace vmp::runtime::audit
