#include <vmp/runtime/env_detectors/detectors.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstring>
#include <functional>
#include <iomanip>
#include <mutex>
#include <numeric>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/trusted_oracle/syscall_nr.h>

#if defined(__linux__) || defined(__ANDROID__)
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
#include <sys/user.h>
#endif

#if defined(__linux__) && defined(__x86_64__)
#include <asm/prctl.h>
#endif

#if defined(__linux__) || defined(__ANDROID__) || defined(__APPLE__)
#include <link.h>
#include <signal.h>
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

namespace vmp::runtime::env_detectors {
namespace {

constexpr const char* kModuleName = "env_detectors";
constexpr std::array<std::string_view, 3> kFridaKeywords{{"frida-agent", "frida-gadget", "__frida"}};

struct CpuidLeaf {
  bool ok = false;
  std::uint32_t eax = 0;
  std::uint32_t ebx = 0;
  std::uint32_t ecx = 0;
  std::uint32_t edx = 0;
};

struct WorkerState {
  DetectorKind kind = DetectorKind::hardware_breakpoint;
  std::atomic<std::uint64_t> heartbeat{0};
  std::atomic<std::uint64_t> tid{0};
  std::thread worker;
};

std::mutex& default_supervisor_mutex() {
  static std::mutex mutex;
  return mutex;
}

EnvironmentDetectorSupervisor*& default_supervisor_override_slot() {
  static EnvironmentDetectorSupervisor* slot = nullptr;
  return slot;
}

std::string bool_text(bool value) { return value ? "true" : "false"; }

const char* detector_name(DetectorKind kind) noexcept {
  switch (kind) {
    case DetectorKind::hardware_breakpoint: return "hardware_breakpoint";
    case DetectorKind::frida: return "frida";
    case DetectorKind::emulator: return "emulator";
  }
  return "unknown";
}

std::string hex_u64(std::uint64_t value) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::setw(16) << std::setfill('0') << value;
  return oss.str();
}

std::string join_strings(const std::vector<std::string>& values, std::string_view sep) {
  std::ostringstream oss;
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i != 0) {
      oss << sep;
    }
    oss << values[i];
  }
  return oss.str();
}

std::string read_file_direct(const char* path) {
  const int fd = vmp::runtime::trusted_oracle::DirectSyscall::open_readonly(path);
  if (fd < 0) {
    return {};
  }
  std::string out;
  std::array<char, 512> buffer{};
  for (;;) {
    const auto got = vmp::runtime::trusted_oracle::DirectSyscall::read(fd, buffer.data(), buffer.size());
    if (got <= 0) {
      break;
    }
    out.append(buffer.data(), static_cast<std::size_t>(got));
  }
  (void)vmp::runtime::trusted_oracle::DirectSyscall::close(fd);
  return out;
}

bool address_in_readable_map(std::uintptr_t address) {
#if defined(__linux__) || defined(__ANDROID__)
  if (address == 0) {
    return false;
  }
  const auto maps = read_file_direct("/proc/self/maps");
  if (maps.empty()) {
    return false;
  }
  std::istringstream iss(maps);
  std::string line;
  while (std::getline(iss, line)) {
    std::uintptr_t begin = 0;
    std::uintptr_t end = 0;
    char perms[5] = {};
    if (std::sscanf(line.c_str(), "%lx-%lx %4s", &begin, &end, perms) == 3) {
      if (perms[0] == 'r' && address >= begin && address < end) {
        return true;
      }
    }
  }
#endif
  return false;
}

std::set<std::uint64_t> enumerate_task_tids() {
  std::set<std::uint64_t> tids;
#if defined(__linux__) || defined(__ANDROID__)
  const std::filesystem::path task_dir("/proc/self/task");
  std::error_code ec;
  for (std::filesystem::directory_iterator it(task_dir, ec), end; !ec && it != end; it.increment(ec)) {
    try {
      tids.insert(static_cast<std::uint64_t>(std::stoull(it->path().filename().string())));
    } catch (...) {
    }
  }
#endif
  return tids;
}

CpuidLeaf read_cpuid_leaf(std::uint32_t leaf) {
  CpuidLeaf out;
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
  int regs[4] = {0, 0, 0, 0};
  __cpuidex(regs, static_cast<int>(leaf), 0);
  out.ok = true;
  out.eax = static_cast<std::uint32_t>(regs[0]);
  out.ebx = static_cast<std::uint32_t>(regs[1]);
  out.ecx = static_cast<std::uint32_t>(regs[2]);
  out.edx = static_cast<std::uint32_t>(regs[3]);
#elif !defined(_MSC_VER) && (defined(__x86_64__) || defined(__i386__))
  unsigned eax = 0;
  unsigned ebx = 0;
  unsigned ecx = 0;
  unsigned edx = 0;
  if (__get_cpuid(leaf, &eax, &ebx, &ecx, &edx) != 0) {
    out.ok = true;
    out.eax = eax;
    out.ebx = ebx;
    out.ecx = ecx;
    out.edx = edx;
  }
#else
  (void)leaf;
#endif
  return out;
}

std::uint64_t read_counter() {
#if defined(__x86_64__) || defined(_M_X64)
#  if defined(_MSC_VER)
  return __rdtsc();
#  else
  unsigned aux = 0;
  return __builtin_ia32_rdtscp(&aux);
#  endif
#elif defined(__aarch64__)
  std::uint64_t value = 0;
  asm volatile("mrs %0, cntvct_el0" : "=r"(value));
  return value;
#else
  return 0;
#endif
}

bool probe_sigtrap_absence() {
#if defined(_WIN32)
  return false;
#else
  std::atomic<int> hits{0};
  struct sigaction previous {};
  struct sigaction current {};
  current.sa_handler = +[](int) {};
  sigemptyset(&current.sa_mask);
  current.sa_flags = 0;
  if (::sigaction(SIGTRAP, &current, &previous) != 0) {
    return false;
  }
  auto restore = [&]() { ::sigaction(SIGTRAP, &previous, nullptr); };
  struct Guard {
    std::function<void()> fn;
    ~Guard() { if (fn) fn(); }
  } guard{restore};
  (void)hits;
  std::atomic_signal_fence(std::memory_order_seq_cst);
  for (volatile int i = 0; i < 8; ++i) {
  }
  std::atomic_signal_fence(std::memory_order_seq_cst);
  return hits.load(std::memory_order_relaxed) != 0;
#endif
}

bool has_non_zero_debug_registers(const std::array<std::uint64_t, 8>& regs) {
  return std::any_of(regs.begin(), regs.end(), [](std::uint64_t value) { return value != 0; });
}

bool sample_linux_debug_registers_x86(std::array<std::uint64_t, 8>& regs) {
#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
  struct Payload {
    int ok = 0;
    int err = 0;
    std::uint64_t regs[8]{};
  } payload;

  int pipefd[2] = {-1, -1};
  if (::pipe(pipefd) != 0) {
    return false;
  }

  const pid_t parent_pid = ::getpid();
  const pid_t child = ::fork();
  if (child == 0) {
    ::close(pipefd[0]);
    errno = 0;
    if (vmp::runtime::trusted_oracle::DirectSyscall::ptrace(static_cast<std::uintptr_t>(PTRACE_ATTACH),
                                                            static_cast<std::uintptr_t>(parent_pid),
                                                            0,
                                                            0) != 0) {
      payload.err = errno;
    } else {
      int wait_status = 0;
      const int wait_flags =
#if defined(__WALL)
          __WALL;
#else
          0;
#endif
      if (::waitpid(parent_pid, &wait_status, wait_flags) < 0 || !WIFSTOPPED(wait_status)) {
        payload.err = errno != 0 ? errno : EIO;
      } else {
        bool ok = true;
        for (std::size_t i = 0; i < 8; ++i) {
          errno = 0;
          const auto offset = static_cast<std::uintptr_t>(offsetof(struct user, u_debugreg) + (i * sizeof(unsigned long)));
          const long value = vmp::runtime::trusted_oracle::DirectSyscall::ptrace(static_cast<std::uintptr_t>(PTRACE_PEEKUSER),
                                                                                 static_cast<std::uintptr_t>(parent_pid),
                                                                                 offset,
                                                                                 0);
          if (value == -1 && errno != 0) {
            ok = false;
            payload.err = errno;
            break;
          }
          payload.regs[i] = static_cast<std::uint64_t>(value);
        }
        payload.ok = ok ? 1 : 0;
      }
      (void)vmp::runtime::trusted_oracle::DirectSyscall::ptrace(static_cast<std::uintptr_t>(PTRACE_DETACH),
                                                                static_cast<std::uintptr_t>(parent_pid),
                                                                0,
                                                                0);
    }
    (void)::write(pipefd[1], &payload, sizeof(payload));
    ::close(pipefd[1]);
    _exit(0);
  }

  ::close(pipefd[1]);
  Payload observed{};
  const auto got = ::read(pipefd[0], &observed, sizeof(observed));
  ::close(pipefd[0]);
  int child_status = 0;
  (void)::waitpid(child, &child_status, 0);
  if (got != static_cast<ssize_t>(sizeof(observed)) || observed.ok == 0) {
    return false;
  }
  for (std::size_t i = 0; i < regs.size(); ++i) {
    regs[i] = observed.regs[i];
  }
  return true;
#else
  (void)regs;
  return false;
#endif
}

std::size_t count_tls_images() {
  std::size_t count = 0;
#if defined(__linux__) || defined(__ANDROID__) || defined(__APPLE__)
  struct Context {
    std::size_t* count = nullptr;
  } ctx{&count};
  dl_iterate_phdr(
      [](struct dl_phdr_info* info, size_t, void* data) {
        auto* ctx = static_cast<Context*>(data);
        if (ctx == nullptr || ctx->count == nullptr || info == nullptr) {
          return 0;
        }
        for (std::uint16_t i = 0; i < info->dlpi_phnum; ++i) {
          if (info->dlpi_phdr[i].p_type == PT_TLS) {
            ++(*ctx->count);
            break;
          }
        }
        return 0;
      },
      &ctx);
#endif
  return count;
}

std::vector<std::uint64_t> sample_rdtsc_deltas() {
  std::vector<std::uint64_t> deltas;
  deltas.reserve(32);
  for (int i = 0; i < 32; ++i) {
    const auto before = read_counter();
    std::atomic_signal_fence(std::memory_order_seq_cst);
    const auto after = read_counter();
    if (after >= before) {
      deltas.push_back(after - before);
    }
  }
  return deltas;
}

bool low_jitter_distribution(const std::vector<std::uint64_t>& deltas) {
  if (deltas.size() < 4) {
    return false;
  }
  std::set<std::uint64_t> unique(deltas.begin(), deltas.end());
  if (unique.size() <= 2) {
    return true;
  }
  const auto [min_it, max_it] = std::minmax_element(deltas.begin(), deltas.end());
  if (*min_it == 0 && *max_it <= 1) {
    return true;
  }
  const double mean = std::accumulate(deltas.begin(), deltas.end(), 0.0) / static_cast<double>(deltas.size());
  if (mean <= 0.0) {
    return false;
  }
  double variance = 0.0;
  for (auto delta : deltas) {
    const double diff = static_cast<double>(delta) - mean;
    variance += diff * diff;
  }
  variance /= static_cast<double>(deltas.size());
  const double cv = std::sqrt(variance) / mean;
  return cv < 0.03;
}

bool syscall_side_effect_suspicious() {
#if defined(__linux__) || defined(__ANDROID__) || defined(__APPLE__)
  errno = 0;
  const int fd = vmp::runtime::trusted_oracle::DirectSyscall::open_readonly("/tmp/vmp_env_detectors_nonexistent_probe");
  if (fd >= 0) {
    (void)vmp::runtime::trusted_oracle::DirectSyscall::close(fd);
    return true;
  }
  return errno != ENOENT;
#else
  return false;
#endif
}

void emit_detection_event(vmp::runtime::audit::ReactionDispatcher* dispatcher,
                          std::string event_type,
                          std::string note,
                          std::uint64_t pc = 0,
                          std::string symbol = "detector") {
  if (dispatcher == nullptr) {
    return;
  }
  dispatcher->dispatch(vmp::runtime::audit::make_event(std::move(event_type),
                                                       std::move(note),
                                                       pc,
                                                       kModuleName,
                                                       std::move(symbol),
                                                       0),
                       vmp::runtime::audit::ReactionPolicy::audit_then_delayed_exit);
}

HeartbeatSnapshot snapshot_from_workers(const std::array<WorkerState, 3>& workers) noexcept {
  HeartbeatSnapshot snapshot;
  snapshot.hardware_breakpoint = workers[0].heartbeat.load(std::memory_order_acquire);
  snapshot.frida = workers[1].heartbeat.load(std::memory_order_acquire);
  snapshot.emulator = workers[2].heartbeat.load(std::memory_order_acquire);
  return snapshot;
}

std::uint64_t* heartbeat_field(HeartbeatSnapshot& snapshot, DetectorKind kind) noexcept {
  switch (kind) {
    case DetectorKind::hardware_breakpoint: return &snapshot.hardware_breakpoint;
    case DetectorKind::frida: return &snapshot.frida;
    case DetectorKind::emulator: return &snapshot.emulator;
  }
  return &snapshot.hardware_breakpoint;
}

const std::uint64_t* heartbeat_field(const HeartbeatSnapshot& snapshot, DetectorKind kind) noexcept {
  switch (kind) {
    case DetectorKind::hardware_breakpoint: return &snapshot.hardware_breakpoint;
    case DetectorKind::frida: return &snapshot.frida;
    case DetectorKind::emulator: return &snapshot.emulator;
  }
  return &snapshot.hardware_breakpoint;
}

std::string format_heartbeat_note(const HeartbeatSnapshot& previous,
                                  const HeartbeatSnapshot& current,
                                  const std::vector<std::string>& stalled) {
  std::ostringstream oss;
  oss << "stalled=" << join_strings(stalled, ",")
      << " previous_hw=" << previous.hardware_breakpoint
      << " current_hw=" << current.hardware_breakpoint
      << " previous_frida=" << previous.frida
      << " current_frida=" << current.frida
      << " previous_emulator=" << previous.emulator
      << " current_emulator=" << current.emulator;
  return oss.str();
}

}  // namespace

struct EnvironmentDetectorSupervisor::Impl {
  explicit Impl(KeyContextId key_context_id, std::filesystem::path audit_path_in, SupervisorOptions options_in)
      : audit_path(audit_path_in.empty() ? vmp::runtime::audit::AuditWriter::default_path() : std::move(audit_path_in)),
        writer(audit_path),
        dispatcher(writer, vmp::runtime::audit::ReactionPolicy::audit_only),
        oracle(key_context_id, audit_path),
        options(std::move(options_in)) {
    workers[0].kind = DetectorKind::hardware_breakpoint;
    workers[1].kind = DetectorKind::frida;
    workers[2].kind = DetectorKind::emulator;
  }

  ~Impl() { stop(); }

  bool start() {
    std::lock_guard<std::mutex> lock(worker_mutex);
    if (started) {
      return true;
    }
    running.store(true, std::memory_order_release);
    started = true;
    if (!options.auto_start_heartbeat_threads) {
      return true;
    }
    const auto tasks_before = enumerate_task_tids();
    for (auto& worker : workers) {
      worker.worker = std::thread([this, &worker]() {
        worker.tid.store(vmp::runtime::trusted_oracle::DirectSyscall::gettid(), std::memory_order_release);
        while (running.load(std::memory_order_acquire)) {
          worker.heartbeat.fetch_add(1, std::memory_order_acq_rel);
          std::this_thread::sleep_for(options.heartbeat_interval);
        }
      });
    }
    auto verify_one = [&](WorkerState& worker) {
      for (int attempt = 0; attempt < 100; ++attempt) {
        const auto tid = worker.tid.load(std::memory_order_acquire);
        if (tid != 0) {
          const auto tasks = enumerate_task_tids();
          return tasks.find(tid) != tasks.end() || tasks_before.find(tid) == tasks_before.end();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
      }
      return false;
    };
    bool ok = true;
    for (auto& worker : workers) {
      ok = verify_one(worker) && ok;
    }
    if (!ok) {
      emit_detection_event(&dispatcher, "thread_creation_hijacked", "detector worker tid verification failed", 0, "lockstep");
    }
    return ok;
  }

  void stop() {
    std::lock_guard<std::mutex> lock(worker_mutex);
    if (!started) {
      return;
    }
    running.store(false, std::memory_order_release);
    for (auto& worker : workers) {
      if (worker.worker.joinable()) {
        worker.worker.join();
      }
    }
    started = false;
  }

  void set_heartbeat_for_tests(DetectorKind kind, std::uint64_t value) noexcept {
    workers[static_cast<std::size_t>(kind)].heartbeat.store(value, std::memory_order_release);
  }

  HeartbeatSnapshot heartbeat_snapshot() const noexcept { return snapshot_from_workers(workers); }

  void observe_dispatch(vmp::runtime::audit::ReactionDispatcher* override_dispatcher) {
    if (!started) {
      start();
    }
    const auto current_dispatch = dispatch_counter.fetch_add(1, std::memory_order_acq_rel) + 1;
    const auto check_interval = options.dispatch_check_interval == 0 ? kLockstepDispatchInterval : options.dispatch_check_interval;
    if ((current_dispatch % check_interval) != 0) {
      return;
    }

    const auto current = heartbeat_snapshot();
    std::lock_guard<std::mutex> lock(observation_mutex);
    if (!have_last_snapshot) {
      last_snapshot = current;
      have_last_snapshot = true;
      return;
    }

    std::vector<std::string> stalled;
    for (DetectorKind kind : {DetectorKind::hardware_breakpoint, DetectorKind::frida, DetectorKind::emulator}) {
      const auto* prev = heartbeat_field(last_snapshot, kind);
      const auto* now = heartbeat_field(current, kind);
      auto& stale_count = stagnant_counts[static_cast<std::size_t>(kind)];
      if (*now > *prev) {
        stale_count = 0;
      } else {
        ++stale_count;
      }
      if (stale_count >= options.stagnant_dispatch_limit) {
        stalled.emplace_back(detector_name(kind));
      }
    }

    if (!stalled.empty() && !drift_reported) {
      emit_detection_event(override_dispatcher != nullptr ? override_dispatcher : &dispatcher,
                           "detector_heartbeat_drift",
                           format_heartbeat_note(last_snapshot, current, stalled),
                           current_dispatch,
                           "lockstep");
      drift_reported = true;
    } else if (stalled.empty()) {
      drift_reported = false;
    }
    last_snapshot = current;
  }

  std::filesystem::path audit_path;
  vmp::runtime::audit::AuditWriter writer;
  vmp::runtime::audit::ReactionDispatcher dispatcher;
  vmp::runtime::trusted_oracle::TrustedOracle oracle;
  SupervisorOptions options{};

  mutable std::mutex worker_mutex;
  mutable std::mutex observation_mutex;
  std::array<WorkerState, 3> workers{};
  std::atomic<bool> running{false};
  bool started = false;
  std::atomic<std::uint64_t> dispatch_counter{0};
  HeartbeatSnapshot last_snapshot{};
  bool have_last_snapshot = false;
  std::array<unsigned, 3> stagnant_counts{{0, 0, 0}};
  bool drift_reported = false;
};

EnvironmentDetectorSupervisor::EnvironmentDetectorSupervisor(KeyContextId key_context_id,
                                                             std::filesystem::path audit_path,
                                                             SupervisorOptions options)
    : impl_(std::make_unique<Impl>(key_context_id, std::move(audit_path), std::move(options))) {}

EnvironmentDetectorSupervisor::~EnvironmentDetectorSupervisor() = default;

vmp::runtime::audit::ReactionDispatcher& EnvironmentDetectorSupervisor::reaction_dispatcher() noexcept {
  return impl_->dispatcher;
}

vmp::runtime::trusted_oracle::TrustedOracle& EnvironmentDetectorSupervisor::oracle() noexcept { return impl_->oracle; }
const vmp::runtime::trusted_oracle::TrustedOracle& EnvironmentDetectorSupervisor::oracle() const noexcept { return impl_->oracle; }

DetectorEvaluation EnvironmentDetectorSupervisor::evaluate_hardware_breakpoints(
    const HardwareBreakpointReadings& readings,
    vmp::runtime::audit::ReactionDispatcher* dispatcher) {
  DetectorEvaluation out;
  out.detector = DetectorKind::hardware_breakpoint;
  out.primary_suspicious = readings.debug_registers_sampled && has_non_zero_debug_registers(readings.debug_registers);
  out.secondary_suspicious = readings.sigtrap_sampled && readings.sigtrap_triggered;
  out.divergent = readings.debug_registers_sampled && readings.sigtrap_sampled &&
                  (out.primary_suspicious != out.secondary_suspicious);
  out.detected = out.primary_suspicious || out.secondary_suspicious;
  out.vote_count = static_cast<std::uint32_t>(out.primary_suspicious) + static_cast<std::uint32_t>(out.secondary_suspicious);
  if (out.detected) {
    out.event_type = "hardware_breakpoint_detected";
    std::ostringstream oss;
    oss << "debug_registers_sampled=" << bool_text(readings.debug_registers_sampled)
        << " sigtrap_sampled=" << bool_text(readings.sigtrap_sampled)
        << " sigtrap_triggered=" << bool_text(readings.sigtrap_triggered)
        << " dr0=" << hex_u64(readings.debug_registers[0])
        << " dr1=" << hex_u64(readings.debug_registers[1])
        << " dr2=" << hex_u64(readings.debug_registers[2])
        << " dr3=" << hex_u64(readings.debug_registers[3])
        << " dr6=" << hex_u64(readings.debug_registers[6])
        << " dr7=" << hex_u64(readings.debug_registers[7]);
    out.note = oss.str();
    emit_detection_event(dispatcher != nullptr ? dispatcher : &impl_->dispatcher,
                         out.event_type,
                         out.note,
                         readings.debug_registers[0],
                         "hardware_breakpoint");
  }
  return out;
}

DetectorEvaluation EnvironmentDetectorSupervisor::evaluate_frida_injection(const FridaReadings& readings,
                                                                           vmp::runtime::audit::ReactionDispatcher* dispatcher) {
  DetectorEvaluation out;
  out.detector = DetectorKind::frida;
  out.primary_suspicious = readings.maps_sampled && !readings.maps_hits.empty();
  out.secondary_suspicious = readings.tls_slots_sampled && readings.tls_slot_count >= readings.tls_slot_threshold;
  out.divergent = readings.maps_sampled && readings.tls_slots_sampled &&
                  (out.primary_suspicious != out.secondary_suspicious);
  out.detected = out.primary_suspicious || out.secondary_suspicious || out.divergent;
  out.vote_count = static_cast<std::uint32_t>(out.primary_suspicious) + static_cast<std::uint32_t>(out.secondary_suspicious);
  if (out.detected) {
    out.event_type = "frida_injection_detected";
    std::ostringstream oss;
    oss << "maps_hits=" << (readings.maps_hits.empty() ? std::string("none") : join_strings(readings.maps_hits, ","))
        << " tls_slot_count=" << readings.tls_slot_count
        << " tls_slot_threshold=" << readings.tls_slot_threshold
        << " divergent=" << bool_text(out.divergent);
    out.note = oss.str();
    emit_detection_event(dispatcher != nullptr ? dispatcher : &impl_->dispatcher,
                         out.event_type,
                         out.note,
                         0,
                         "frida");
  }
  return out;
}

DetectorEvaluation EnvironmentDetectorSupervisor::evaluate_emulator(const EmulatorReadings& readings,
                                                                    vmp::runtime::audit::ReactionDispatcher* dispatcher) {
  DetectorEvaluation out;
  out.detector = DetectorKind::emulator;
#if defined(__APPLE__)
  out.primary_suspicious = readings.syscall_side_effect_sampled && readings.syscall_side_effect_suspicious;
  out.secondary_suspicious = false;
  out.vote_count = out.primary_suspicious ? 1u : 0u;
  out.detected = out.primary_suspicious;
#else
  const bool cpuid_suspicious = readings.cpuid_sampled && readings.hypervisor_vendor_present;
  const bool rdtsc_suspicious = readings.rdtsc_sampled && readings.rdtsc_low_jitter;
  const bool fsbase_suspicious = readings.fsbase_sampled && readings.fsbase_suspicious;
  out.primary_suspicious = cpuid_suspicious;
  out.secondary_suspicious = rdtsc_suspicious;
  out.vote_count = static_cast<std::uint32_t>(cpuid_suspicious) +
                   static_cast<std::uint32_t>(rdtsc_suspicious) +
                   static_cast<std::uint32_t>(fsbase_suspicious);
  out.detected = out.vote_count >= 2;
#endif
  if (out.detected) {
    out.event_type = "emulator_detected";
    std::ostringstream oss;
    oss << "vendor=" << (readings.hypervisor_vendor.empty() ? std::string("none") : readings.hypervisor_vendor)
        << " rdtsc_low_jitter=" << bool_text(readings.rdtsc_low_jitter)
        << " fsbase=" << hex_u64(readings.fsbase)
        << " fsbase_suspicious=" << bool_text(readings.fsbase_suspicious)
        << " vote_count=" << out.vote_count;
    out.note = oss.str();
    emit_detection_event(dispatcher != nullptr ? dispatcher : &impl_->dispatcher,
                         out.event_type,
                         out.note,
                         readings.fsbase,
                         "emulator");
  }
  return out;
}

HardwareBreakpointReadings EnvironmentDetectorSupervisor::sample_hardware_breakpoints() {
  HardwareBreakpointReadings out;
  out.debug_registers_sampled = sample_linux_debug_registers_x86(out.debug_registers);
  out.sigtrap_sampled = true;
  out.sigtrap_triggered = probe_sigtrap_absence();
  return out;
}

FridaReadings EnvironmentDetectorSupervisor::sample_frida_injection() {
  FridaReadings out;
#if defined(__linux__) || defined(__ANDROID__)
  const auto maps = read_file_direct("/proc/self/maps");
  out.maps_sampled = !maps.empty();
  if (!maps.empty()) {
    std::istringstream iss(maps);
    std::string line;
    while (std::getline(iss, line)) {
      for (const auto keyword : kFridaKeywords) {
        if (line.find(keyword) != std::string::npos) {
          out.maps_hits.push_back(line);
          break;
        }
      }
    }
  }
#endif
  out.tls_slots_sampled = true;
  out.tls_slot_count = count_tls_images();
  return out;
}

EmulatorReadings EnvironmentDetectorSupervisor::sample_emulator() {
  EmulatorReadings out;
#if !defined(__APPLE__)
  const auto leaf1 = read_cpuid_leaf(1);
  const auto leaf4000 = read_cpuid_leaf(0x40000000u);
  out.cpuid_sampled = leaf1.ok || leaf4000.ok;
  if (leaf1.ok && ((leaf1.ecx >> 31u) & 1u) != 0u) {
    out.hypervisor_vendor_present = true;
  }
  if (leaf4000.ok) {
    std::array<char, 13> vendor{};
    std::memcpy(vendor.data() + 0, &leaf4000.ebx, sizeof(leaf4000.ebx));
    std::memcpy(vendor.data() + 4, &leaf4000.ecx, sizeof(leaf4000.ecx));
    std::memcpy(vendor.data() + 8, &leaf4000.edx, sizeof(leaf4000.edx));
    out.hypervisor_vendor = std::string(vendor.data());
    out.hypervisor_vendor.erase(std::find(out.hypervisor_vendor.begin(), out.hypervisor_vendor.end(), '\0'),
                                out.hypervisor_vendor.end());
    if (!out.hypervisor_vendor.empty()) {
      out.hypervisor_vendor_present = true;
    }
  }

  out.rdtsc_deltas = sample_rdtsc_deltas();
  out.rdtsc_sampled = !out.rdtsc_deltas.empty();
  out.rdtsc_low_jitter = low_jitter_distribution(out.rdtsc_deltas);

#  if defined(__linux__) && defined(__x86_64__)
  std::uintptr_t fsbase = 0;
  out.fsbase_sampled = vmp::runtime::trusted_oracle::DirectSyscall::arch_prctl(ARCH_GET_FS, &fsbase) == 0;
  out.fsbase = fsbase;
  out.fsbase_suspicious = !out.fsbase_sampled || fsbase == 0 || !address_in_readable_map(fsbase);
#  endif
#endif
  out.syscall_side_effect_sampled = true;
  out.syscall_side_effect_suspicious = syscall_side_effect_suspicious();
  return out;
}

DetectorEvaluation EnvironmentDetectorSupervisor::probe_hardware_breakpoints(vmp::runtime::audit::ReactionDispatcher* dispatcher) {
  return evaluate_hardware_breakpoints(sample_hardware_breakpoints(), dispatcher);
}

DetectorEvaluation EnvironmentDetectorSupervisor::probe_frida_injection(vmp::runtime::audit::ReactionDispatcher* dispatcher) {
  return evaluate_frida_injection(sample_frida_injection(), dispatcher);
}

DetectorEvaluation EnvironmentDetectorSupervisor::probe_emulator(vmp::runtime::audit::ReactionDispatcher* dispatcher) {
  return evaluate_emulator(sample_emulator(), dispatcher);
}

bool EnvironmentDetectorSupervisor::start() { return impl_->start(); }
void EnvironmentDetectorSupervisor::stop() { impl_->stop(); }
bool EnvironmentDetectorSupervisor::running() const noexcept { return impl_->running.load(std::memory_order_acquire); }
HeartbeatSnapshot EnvironmentDetectorSupervisor::heartbeat_snapshot() const noexcept { return impl_->heartbeat_snapshot(); }
void EnvironmentDetectorSupervisor::set_heartbeat_for_tests(DetectorKind kind, std::uint64_t value) noexcept {
  impl_->set_heartbeat_for_tests(kind, value);
}
void EnvironmentDetectorSupervisor::observe_dispatch(vmp::runtime::audit::ReactionDispatcher* dispatcher) {
  impl_->observe_dispatch(dispatcher);
}

DefaultSupervisorOverride::DefaultSupervisorOverride(EnvironmentDetectorSupervisor& supervisor) noexcept {
  std::lock_guard<std::mutex> lock(default_supervisor_mutex());
  previous_ = default_supervisor_override_slot();
  default_supervisor_override_slot() = &supervisor;
}

DefaultSupervisorOverride::~DefaultSupervisorOverride() {
  std::lock_guard<std::mutex> lock(default_supervisor_mutex());
  default_supervisor_override_slot() = previous_;
}

EnvironmentDetectorSupervisor& default_supervisor() {
  std::lock_guard<std::mutex> lock(default_supervisor_mutex());
  if (auto* override = default_supervisor_override_slot(); override != nullptr) {
    return *override;
  }
  static EnvironmentDetectorSupervisor supervisor;
  return supervisor;
}

}  // namespace vmp::runtime::env_detectors
