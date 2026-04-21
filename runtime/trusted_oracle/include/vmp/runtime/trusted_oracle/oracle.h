#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <vmp/runtime/audit/reaction.h>

namespace vmp::runtime::trusted_oracle {

inline constexpr std::size_t kApiPrologueWidth = 32;
using KeyContextId = std::array<std::uint8_t, 16>;

struct DirectTimespec {
  std::int64_t tv_sec = 0;
  std::int64_t tv_nsec = 0;
};

class DirectSyscall {
 public:
  static std::intptr_t raw(std::uint64_t number,
                           std::uintptr_t a0 = 0,
                           std::uintptr_t a1 = 0,
                           std::uintptr_t a2 = 0,
                           std::uintptr_t a3 = 0,
                           std::uintptr_t a4 = 0,
                           std::uintptr_t a5 = 0) noexcept;

  static int open_readonly(const char* path) noexcept;
  static std::ptrdiff_t read(int fd, void* buffer, std::size_t count) noexcept;
  static int close(int fd) noexcept;
  static long ptrace(std::uintptr_t request,
                     std::uintptr_t pid,
                     std::uintptr_t addr,
                     std::uintptr_t data) noexcept;
  static int clock_gettime(int clock_id, DirectTimespec* out) noexcept;
  static std::ptrdiff_t getrandom(void* buffer, std::size_t count, unsigned flags = 0) noexcept;
  static int sigaction(int signum, const void* action, void* old_action) noexcept;
  static int prctl(int option,
                   unsigned long arg2 = 0,
                   unsigned long arg3 = 0,
                   unsigned long arg4 = 0,
                   unsigned long arg5 = 0) noexcept;
  static int arch_prctl(int code, std::uintptr_t* value) noexcept;
  static std::uint64_t gettid() noexcept;
  static long nt_protect_current_process(void* address, std::size_t size, unsigned long new_protect, unsigned long* old_protect) noexcept;
  static long nt_query_virtual_memory_current_process(const void* address, void* buffer, std::size_t length, std::size_t* result_length) noexcept;
};

struct BaselineVerification {
  bool ok = false;
  bool resident_matches = false;
  bool ephemeral_matches = false;
  bool current_matches = false;
  bool divergent = false;
  std::string event_type;
  std::string note;
};

class PrologueBaselineStore {
 public:
  PrologueBaselineStore(KeyContextId key_context_id,
                        std::filesystem::path audit_path = {},
                        std::chrono::seconds refresh_interval = std::chrono::seconds(60));
  ~PrologueBaselineStore();

  void register_region(std::string name, const void* address, std::size_t width = kApiPrologueWidth);
  void register_default_apis();
  std::size_t monitored_count() const noexcept;
  BaselineVerification verify_region(std::string_view name);
  BaselineVerification verify_all();
  void force_refresh_for_tests();
  vmp::runtime::audit::ReactionDispatcher& reaction_dispatcher() noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

struct VoteOutcome {
  std::string fact_name;
  bool fact_value = false;
  bool divergent = false;
  std::string event_type;
  std::string note;
};

struct PtraceReadings {
  bool status_sampled = false;
  int tracer_pid = 0;
  bool traceme_attempted = false;
  bool traceme_allowed = false;
  int traceme_errno = 0;
};

struct TimeReadings {
  std::uint64_t counter_delta = 0;
  std::uint64_t monotonic_delta_ns = 0;
  std::uint64_t max_clock_delta_ns = 2'000'000;
};

struct RandomReadings {
  bool syscall_sampled = false;
  bool syscall_ok = false;
  std::vector<std::uint8_t> syscall_bytes;
  bool hardware_sampled = false;
  bool hardware_ok = false;
  std::vector<std::uint8_t> hardware_bytes;
};

struct ThreadVerificationOptions {
  std::function<std::uint64_t()> observed_tid_provider;
};

struct ThreadVerificationResult {
  bool matched = false;
  std::uint64_t expected_tid = 0;
  std::uint64_t observed_tid = 0;
  std::string event_type;
  std::string note;
};

class TrustedOracle {
 public:
  explicit TrustedOracle(KeyContextId key_context_id = {},
                         std::filesystem::path audit_path = {});

  PrologueBaselineStore& prologue_baselines() noexcept;
  const PrologueBaselineStore& prologue_baselines() const noexcept;
  vmp::runtime::audit::ReactionDispatcher& reaction_dispatcher() noexcept;

  VoteOutcome evaluate_ptrace_status(const PtraceReadings& readings);
  VoteOutcome evaluate_time_sources(const TimeReadings& readings);
  VoteOutcome evaluate_random_sources(const RandomReadings& readings);

  PtraceReadings sample_ptrace_status();
  TimeReadings sample_time_sources() const;
  RandomReadings sample_random_sources(std::size_t size = 16) const;

  VoteOutcome probe_ptrace_status();
  VoteOutcome probe_time_sources();
  VoteOutcome probe_random_sources(std::size_t size = 16);

  ThreadVerificationResult verify_detector_thread(const ThreadVerificationOptions& options = {});

 private:
  void record_event(std::string event_type, std::string note);

  std::filesystem::path audit_path_;
  vmp::runtime::audit::AuditWriter writer_;
  vmp::runtime::audit::ReactionDispatcher dispatcher_;
  PrologueBaselineStore baselines_;
  bool ptrace_cached_ = false;
  PtraceReadings ptrace_cache_{};
};

}  // namespace vmp::runtime::trusted_oracle
