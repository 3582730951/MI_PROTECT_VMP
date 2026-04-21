#include <vmp/runtime/env_integrity/monitor.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/strings/cipher.h>

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/random.h>
#include <unistd.h>
#endif

namespace vmp::runtime::env_integrity {
namespace {

constexpr const char* kModuleName = "env_integrity";

struct SignalEntry {
  int signum = 0;
  std::string label;
  std::vector<std::uint8_t> baseline;
};

enum class ImportSlotKind { got, iat };

struct ImportEntry {
  std::string name;
  const void* slot_address = nullptr;
  std::uintptr_t baseline_value = 0;
  ImportSlotKind kind = ImportSlotKind::got;
};

struct BootstrapRegistry {
  std::once_flag once;
  std::vector<SignalEntry> signal_entries;
  std::vector<ImportEntry> import_entries;
};

BootstrapRegistry& bootstrap_registry() {
  static BootstrapRegistry registry;
  return registry;
}

std::mutex& default_monitor_mutex() {
  static std::mutex mutex;
  return mutex;
}

EnvIntegrityMonitor*& default_monitor_override_slot() {
  static EnvIntegrityMonitor* slot = nullptr;
  return slot;
}

void set_writer_exit_noop(vmp::runtime::audit::ReactionDispatcher& dispatcher) {
  dispatcher.set_exit_fn([]() {});
  dispatcher.set_scheduler([](std::chrono::milliseconds, std::function<void()> fn) {
    if (fn) {
      fn();
    }
  });
  dispatcher.set_delay_selector([]() { return std::chrono::milliseconds(0); });
}

std::string hex_u64(std::uint64_t value) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::setw(16) << std::setfill('0') << value;
  return oss.str();
}

std::string signal_name(int signum) {
  switch (signum) {
#if defined(SIGILL)
    case SIGILL: return "SIGILL";
#endif
#if defined(SIGTRAP)
    case SIGTRAP: return "SIGTRAP";
#endif
#if defined(SIGBUS)
    case SIGBUS: return "SIGBUS";
#endif
#if defined(SIGSEGV)
    case SIGSEGV: return "SIGSEGV";
#endif
#if defined(SIGABRT)
    case SIGABRT: return "SIGABRT";
#endif
#if defined(SIGUSR1)
    case SIGUSR1: return "SIGUSR1";
#endif
#if defined(SIGUSR2)
    case SIGUSR2: return "SIGUSR2";
#endif
    default: return "SIG" + std::to_string(signum);
  }
}

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (unsigned shift = 0; shift < 64; shift += 8u) {
    out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
  }
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

bool address_is_mapped(const void* address, std::size_t width) {
#if defined(__linux__) || defined(__ANDROID__)
  if (address == nullptr || width == 0) {
    return false;
  }
  const auto begin = reinterpret_cast<std::uintptr_t>(address);
  const auto end = begin + width;
  const auto maps = read_file_direct("/proc/self/maps");
  std::istringstream iss(maps);
  std::string line;
  while (std::getline(iss, line)) {
    std::uintptr_t map_begin = 0;
    std::uintptr_t map_end = 0;
    char perms[5] = {};
    if (std::sscanf(line.c_str(), "%lx-%lx %4s", &map_begin, &map_end, perms) == 3) {
      if (begin >= map_begin && end <= map_end) {
        return true;
      }
    }
  }
  return false;
#else
  (void)address;
  (void)width;
  return true;
#endif
}

std::uintptr_t read_import_slot_value(const void* slot_address) {
  if (slot_address == nullptr) {
    throw std::runtime_error("env_integrity: null import slot address");
  }
  if (!address_is_mapped(slot_address, sizeof(std::uintptr_t))) {
    throw std::runtime_error("env_integrity: import slot address not mapped");
  }
  std::uintptr_t value = 0;
  std::memcpy(&value, slot_address, sizeof(value));
  return value;
}

#if defined(__linux__) || defined(__ANDROID__)
struct KernelSigaction {
  std::uintptr_t handler = 0;
  unsigned long flags = 0;
  std::uintptr_t restorer = 0;
  std::uint64_t mask = 0;
};

std::vector<std::uint8_t> capture_signal_snapshot(int signum) {
  KernelSigaction action{};
  if (vmp::runtime::trusted_oracle::DirectSyscall::sigaction(signum, nullptr, &action) != 0) {
    throw std::runtime_error("env_integrity: direct sigaction snapshot failed for " + signal_name(signum));
  }
  std::vector<std::uint8_t> out;
  out.reserve(sizeof(action));
  append_u64(out, static_cast<std::uint64_t>(action.handler));
  append_u64(out, static_cast<std::uint64_t>(action.flags));
  append_u64(out, static_cast<std::uint64_t>(action.restorer));
  append_u64(out, action.mask);
  return out;
}
#elif defined(_WIN32)
std::vector<std::uint8_t> capture_signal_snapshot(int signum) {
  void (*previous)(int) = std::signal(signum, SIG_IGN);
  std::signal(signum, previous);
  std::vector<std::uint8_t> out;
  out.reserve(sizeof(std::uintptr_t));
  append_u64(out, static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(previous)));
  return out;
}
#else
std::vector<std::uint8_t> capture_signal_snapshot(int signum) {
  struct sigaction current {};
  if (::sigaction(signum, nullptr, &current) != 0) {
    throw std::runtime_error("env_integrity: sigaction snapshot failed for " + signal_name(signum));
  }
  std::vector<std::uint8_t> out;
  out.reserve(sizeof(std::uintptr_t) * 2);
  append_u64(out, static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(current.sa_handler)));
  append_u64(out, static_cast<std::uint64_t>(current.sa_flags));
  return out;
}
#endif

std::vector<std::uint8_t> default_signal_snapshot_bytes(int signum) {
  try {
    return capture_signal_snapshot(signum);
  } catch (...) {
    return {};
  }
}

void emit_event(vmp::runtime::audit::ReactionDispatcher* dispatcher,
                std::string event_type,
                std::string note,
                std::uint64_t pc = 0) {
  if (dispatcher == nullptr) {
    return;
  }
  dispatcher->dispatch(vmp::runtime::audit::make_event(std::move(event_type),
                                                       std::move(note),
                                                       pc,
                                                       kModuleName,
                                                       "baseline_monitor",
                                                       0));
}

std::vector<SignalEntry> default_signal_entries_now() {
  std::vector<SignalEntry> out;
  struct SignalSpec {
    int signum;
    const char* label;
  };
  const std::array<SignalSpec, 5> specs{{
#if defined(SIGILL)
      {SIGILL, "dispatcher_sigill"},
#else
      {0, ""},
#endif
#if defined(SIGTRAP)
      {SIGTRAP, "dispatcher_sigtrap"},
#else
      {0, ""},
#endif
#if defined(SIGBUS)
      {SIGBUS, "dispatcher_sigbus"},
#else
      {0, ""},
#endif
#if defined(SIGSEGV)
      {SIGSEGV, "dispatcher_sigsegv"},
#else
      {0, ""},
#endif
#if defined(SIGABRT)
      {SIGABRT, "audit_sigabrt"},
#else
      {0, ""},
#endif
  }};
  for (const auto& spec : specs) {
    if (spec.signum == 0 || spec.label[0] == '\0') {
      continue;
    }
    auto snapshot = default_signal_snapshot_bytes(spec.signum);
    if (snapshot.empty()) {
      continue;
    }
    out.push_back(SignalEntry{spec.signum, spec.label, std::move(snapshot)});
  }
  return out;
}

#if defined(__x86_64__) && (defined(__linux__) || defined(__ANDROID__))
const void* got_slot_for_write() {
  const void* slot = nullptr;
  asm("lea write@GOTPCREL(%%rip), %0" : "=r"(slot));
  return slot;
}

const void* got_slot_for_fsync() {
  const void* slot = nullptr;
  asm("lea fsync@GOTPCREL(%%rip), %0" : "=r"(slot));
  return slot;
}

const void* got_slot_for_quick_exit() {
  const void* slot = nullptr;
  asm("lea quick_exit@GOTPCREL(%%rip), %0" : "=r"(slot));
  return slot;
}

const void* got_slot_for_getrandom() {
  const void* slot = nullptr;
  asm("lea getrandom@GOTPCREL(%%rip), %0" : "=r"(slot));
  return slot;
}
#endif

std::vector<ImportEntry> default_import_entries_now() {
  std::vector<ImportEntry> out;
#if defined(__x86_64__) && (defined(__linux__) || defined(__ANDROID__))
  struct SlotSpec {
    const char* name;
    const void* (*resolver)();
    ImportSlotKind kind;
  };
  const std::array<SlotSpec, 4> specs{{
      {"audit.write", got_slot_for_write, ImportSlotKind::got},
      {"audit.fsync", got_slot_for_fsync, ImportSlotKind::got},
      {"dispatcher.quick_exit", got_slot_for_quick_exit, ImportSlotKind::got},
      {"dispatcher.getrandom", got_slot_for_getrandom, ImportSlotKind::got},
  }};
  for (const auto& spec : specs) {
    const void* slot = spec.resolver ? spec.resolver() : nullptr;
    if (slot == nullptr || !address_is_mapped(slot, sizeof(std::uintptr_t))) {
      continue;
    }
    out.push_back(ImportEntry{spec.name, slot, read_import_slot_value(slot), spec.kind});
  }
#elif defined(_WIN32)
  // IAT defaults are intentionally narrow; Windows-specific import parsing can extend this later.
#endif
  return out;
}

void capture_bootstrap() {
  auto& registry = bootstrap_registry();
  std::call_once(registry.once, [&]() {
    registry.signal_entries = default_signal_entries_now();
    registry.import_entries = default_import_entries_now();
  });
}

#if defined(__linux__) || defined(__ANDROID__)
extern "C" __attribute__((visibility("default"), constructor(103))) void vmp_env_integrity_bootstrap_ctor(void);
extern "C" __attribute__((visibility("default"), constructor(103))) void vmp_env_integrity_bootstrap_ctor(void) {
  capture_bootstrap();
}
using vmp_env_integrity_ctor_fn = void (*)(void);
__attribute__((used, section(".init_array"))) static vmp_env_integrity_ctor_fn vmp_env_integrity_bootstrap_fallback =
    vmp_env_integrity_bootstrap_ctor;
#elif defined(__APPLE__)
extern "C" __attribute__((visibility("default"), constructor(103))) void vmp_env_integrity_bootstrap_ctor(void) {
  capture_bootstrap();
}
#endif

void register_or_replace_signal(std::vector<SignalEntry>& entries,
                                int signum,
                                std::string label,
                                std::vector<std::uint8_t> baseline) {
  auto it = std::find_if(entries.begin(), entries.end(), [&](const SignalEntry& entry) {
    return entry.signum == signum || entry.label == label;
  });
  SignalEntry next{signum, std::move(label), std::move(baseline)};
  if (it == entries.end()) {
    entries.push_back(std::move(next));
  } else {
    *it = std::move(next);
  }
}

void register_or_replace_import(std::vector<ImportEntry>& entries,
                                std::string name,
                                const void* slot_address,
                                ImportSlotKind kind) {
  const auto baseline = read_import_slot_value(slot_address);
  auto it = std::find_if(entries.begin(), entries.end(), [&](const ImportEntry& entry) {
    return entry.name == name;
  });
  ImportEntry next{std::move(name), slot_address, baseline, kind};
  if (it == entries.end()) {
    entries.push_back(std::move(next));
  } else {
    *it = std::move(next);
  }
}

void register_or_replace_import_seed(std::vector<ImportEntry>& entries,
                                     std::string name,
                                     const void* slot_address,
                                     std::uintptr_t baseline_value,
                                     ImportSlotKind kind) {
  auto it = std::find_if(entries.begin(), entries.end(), [&](const ImportEntry& entry) {
    return entry.name == name;
  });
  ImportEntry next{std::move(name), slot_address, baseline_value, kind};
  if (it == entries.end()) {
    entries.push_back(std::move(next));
  } else {
    *it = std::move(next);
  }
}

}  // namespace

struct ExceptionBaselineMonitor::Impl {
  std::mutex mutex;
  std::vector<SignalEntry> entries;
  bool defaults_loaded = false;
};

ExceptionBaselineMonitor::ExceptionBaselineMonitor() : impl_(std::make_unique<Impl>()) {}
ExceptionBaselineMonitor::~ExceptionBaselineMonitor() = default;
ExceptionBaselineMonitor::ExceptionBaselineMonitor(ExceptionBaselineMonitor&&) noexcept = default;
ExceptionBaselineMonitor& ExceptionBaselineMonitor::operator=(ExceptionBaselineMonitor&&) noexcept = default;

void ExceptionBaselineMonitor::register_signal(int signum, std::string label) {
  auto baseline = capture_signal_snapshot(signum);
  std::lock_guard<std::mutex> lock(impl_->mutex);
  register_or_replace_signal(impl_->entries, signum, std::move(label), std::move(baseline));
}

std::size_t ExceptionBaselineMonitor::monitored_count() const noexcept {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->entries.size();
}

void ExceptionBaselineMonitor::register_default_signals() {
  capture_bootstrap();
  std::lock_guard<std::mutex> lock(impl_->mutex);
  if (impl_->defaults_loaded) {
    return;
  }
  for (const auto& entry : bootstrap_registry().signal_entries) {
    register_or_replace_signal(impl_->entries, entry.signum, entry.label, entry.baseline);
  }
  impl_->defaults_loaded = true;
}

VerificationSummary ExceptionBaselineMonitor::verify(
    std::string_view domain,
    vmp::runtime::audit::ReactionDispatcher* dispatcher) {
  VerificationSummary summary;
  summary.ok = true;
  summary.exception_handlers_ok = true;

  std::vector<SignalEntry> entries;
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    entries = impl_->entries;
  }

  for (const auto& entry : entries) {
    const auto current = capture_signal_snapshot(entry.signum);
    if (current != entry.baseline) {
      summary.ok = false;
      summary.exception_handlers_ok = false;
      summary.event_types.push_back("exception_chain_modified");
      emit_event(dispatcher,
                 "exception_chain_modified",
                 "domain=" + std::string(domain) +
                     " label=" + entry.label +
                     " signal=" + signal_name(entry.signum) +
                     " baseline=" + vmp::runtime::strings::hex_encode(entry.baseline) +
                     " current=" + vmp::runtime::strings::hex_encode(current));
    }
  }

  return summary;
}

struct ImportTableBaselineMonitor::Impl {
  std::mutex mutex;
  std::vector<ImportEntry> entries;
  bool defaults_loaded = false;
};

ImportTableBaselineMonitor::ImportTableBaselineMonitor() : impl_(std::make_unique<Impl>()) {}
ImportTableBaselineMonitor::~ImportTableBaselineMonitor() = default;
ImportTableBaselineMonitor::ImportTableBaselineMonitor(ImportTableBaselineMonitor&&) noexcept = default;
ImportTableBaselineMonitor& ImportTableBaselineMonitor::operator=(ImportTableBaselineMonitor&&) noexcept = default;

void ImportTableBaselineMonitor::register_got_slot(std::string name, const void* slot_address) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  register_or_replace_import(impl_->entries, std::move(name), slot_address, ImportSlotKind::got);
}

void ImportTableBaselineMonitor::register_iat_slot(std::string name, const void* slot_address) {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  register_or_replace_import(impl_->entries, std::move(name), slot_address, ImportSlotKind::iat);
}

std::size_t ImportTableBaselineMonitor::monitored_count() const noexcept {
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->entries.size();
}

void ImportTableBaselineMonitor::register_default_slots() {
  capture_bootstrap();
  std::lock_guard<std::mutex> lock(impl_->mutex);
  if (impl_->defaults_loaded) {
    return;
  }
  for (const auto& entry : bootstrap_registry().import_entries) {
    register_or_replace_import_seed(impl_->entries, entry.name, entry.slot_address, entry.baseline_value, entry.kind);
  }
  impl_->defaults_loaded = true;
}

VerificationSummary ImportTableBaselineMonitor::verify(
    std::string_view domain,
    vmp::runtime::audit::ReactionDispatcher* dispatcher) {
  VerificationSummary summary;
  summary.ok = true;
  summary.import_table_ok = true;

  std::vector<ImportEntry> entries;
  {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    entries = impl_->entries;
  }

  for (const auto& entry : entries) {
    const auto current = read_import_slot_value(entry.slot_address);
    if (current != entry.baseline_value) {
      summary.ok = false;
      summary.import_table_ok = false;
      const auto* event_type = entry.kind == ImportSlotKind::got ? "got_entry_tampered" : "iat_entry_tampered";
      summary.event_types.push_back(event_type);
      emit_event(dispatcher,
                 event_type,
                 "domain=" + std::string(domain) +
                     " name=" + entry.name +
                     " slot=" + hex_u64(reinterpret_cast<std::uintptr_t>(entry.slot_address)) +
                     " expected=" + hex_u64(entry.baseline_value) +
                     " observed=" + hex_u64(current),
                 reinterpret_cast<std::uintptr_t>(entry.slot_address));
    }
  }

  return summary;
}

EnvIntegrityMonitor::EnvIntegrityMonitor(KeyContextId key_context_id, std::filesystem::path audit_path)
    : key_context_id_(std::move(key_context_id)),
      audit_path_(audit_path.empty() ? vmp::runtime::audit::AuditWriter::default_path() : std::move(audit_path)),
      writer_(audit_path_),
      dispatcher_(writer_, vmp::runtime::audit::ReactionPolicy::audit_only),
      exception_handlers_(),
      import_table_() {
  set_writer_exit_noop(dispatcher_);
  exception_handlers_.register_default_signals();
  import_table_.register_default_slots();
}

EnvIntegrityMonitor::~EnvIntegrityMonitor() = default;

ExceptionBaselineMonitor& EnvIntegrityMonitor::exception_handlers() noexcept { return exception_handlers_; }
const ExceptionBaselineMonitor& EnvIntegrityMonitor::exception_handlers() const noexcept { return exception_handlers_; }
ImportTableBaselineMonitor& EnvIntegrityMonitor::import_table() noexcept { return import_table_; }
const ImportTableBaselineMonitor& EnvIntegrityMonitor::import_table() const noexcept { return import_table_; }
vmp::runtime::audit::ReactionDispatcher& EnvIntegrityMonitor::reaction_dispatcher() noexcept { return dispatcher_; }

VerificationSummary EnvIntegrityMonitor::verify_sensitive_domain(
    std::string_view domain,
    vmp::runtime::audit::ReactionDispatcher* dispatcher) {
  auto* active_dispatcher = dispatcher != nullptr ? dispatcher : &dispatcher_;
  auto exception_summary = exception_handlers_.verify(domain, active_dispatcher);
  auto import_summary = import_table_.verify(domain, active_dispatcher);

  VerificationSummary merged;
  merged.ok = exception_summary.ok && import_summary.ok;
  merged.exception_handlers_ok = exception_summary.exception_handlers_ok;
  merged.import_table_ok = import_summary.import_table_ok;
  merged.event_types = std::move(exception_summary.event_types);
  merged.event_types.insert(merged.event_types.end(),
                            import_summary.event_types.begin(),
                            import_summary.event_types.end());
  return merged;
}

DefaultMonitorOverride::DefaultMonitorOverride(EnvIntegrityMonitor& monitor) noexcept {
  std::lock_guard<std::mutex> lock(default_monitor_mutex());
  previous_ = default_monitor_override_slot();
  default_monitor_override_slot() = &monitor;
}

DefaultMonitorOverride::~DefaultMonitorOverride() {
  std::lock_guard<std::mutex> lock(default_monitor_mutex());
  default_monitor_override_slot() = previous_;
}

EnvIntegrityMonitor& default_monitor() {
  std::lock_guard<std::mutex> lock(default_monitor_mutex());
  if (default_monitor_override_slot() != nullptr) {
    return *default_monitor_override_slot();
  }
  static EnvIntegrityMonitor monitor{};
  return monitor;
}

VerificationSummary verify_sensitive_domain_entry(
    std::string_view domain,
    vmp::runtime::audit::ReactionDispatcher* dispatcher) {
  return default_monitor().verify_sensitive_domain(domain, dispatcher);
}

}  // namespace vmp::runtime::env_integrity
