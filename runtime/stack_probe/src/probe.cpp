#include <vmp/runtime/stack_probe/probe.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string_view>
#include <utility>

#include <vmp/runtime/audit/audit.h>
#include <vmp/runtime/trusted_oracle/oracle.h>

#ifndef VMP_ARCH_STR
#define VMP_ARCH_STR "unknown"
#endif

#ifndef VMP_PLATFORM_STR
#define VMP_PLATFORM_STR "unknown"
#endif

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif

#if __has_include(<libunwind.h>)
#include <libunwind.h>
#define VMP_STACK_PROBE_HAS_LIBUNWIND 1
#elif __has_include(<unwind.h>)
#include <unwind.h>
#define VMP_STACK_PROBE_HAS_LIBUNWIND 0
#define VMP_STACK_PROBE_HAS_ABI_UNWIND 1
#else
#define VMP_STACK_PROBE_HAS_LIBUNWIND 0
#define VMP_STACK_PROBE_HAS_ABI_UNWIND 0
#endif

namespace vmp::runtime::stack_probe {
namespace {

constexpr const char* kModuleName = "runtime/stack_probe";

struct StackBounds {
  std::uintptr_t begin = 0;
  std::uintptr_t end = 0;

  bool contains(std::uintptr_t address, std::size_t width = 1) const noexcept {
    if (begin == 0 || end <= begin || address < begin) {
      return false;
    }
    const auto limit = address + width;
    return limit >= address && limit <= end;
  }
};

struct FrameNode {
  FrameNode* previous = nullptr;
  void* return_address = nullptr;
};

std::mutex& default_probe_mutex() {
  static std::mutex mutex;
  return mutex;
}

StackProbeManager*& default_probe_override_slot() {
  static StackProbeManager* slot = nullptr;
  return slot;
}

std::string arch_label() {
  return std::string(VMP_ARCH_STR);
}

std::string platform_label() {
  return std::string(VMP_PLATFORM_STR);
}

std::string trim_copy(std::string value) {
  auto first = std::find_if(value.begin(), value.end(), [](unsigned char ch) { return !std::isspace(ch); });
  auto last = std::find_if(value.rbegin(), value.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base();
  if (first >= last) {
    return {};
  }
  return std::string(first, last);
}

std::string hex_u64(std::uint64_t value) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::setw(16) << std::setfill('0') << value;
  return oss.str();
}

std::string mapping_description_text(const MappingInfo& mapping) {
  if (!mapping.description.empty()) {
    return mapping.description;
  }
  return mapping.anonymous ? "[anonymous]" : "[unknown]";
}

void set_dispatcher_exit_noop(vmp::runtime::audit::ReactionDispatcher& dispatcher) {
  dispatcher.set_exit_fn([]() {});
  dispatcher.set_scheduler([](std::chrono::milliseconds, std::function<void()> fn) {
    if (fn) {
      fn();
    }
  });
  dispatcher.set_delay_selector([]() { return std::chrono::milliseconds(0); });
}

std::string read_maps_direct() {
#if defined(__linux__) || defined(__ANDROID__)
  const int fd = vmp::runtime::trusted_oracle::DirectSyscall::open_readonly("/proc/self/maps");
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
#else
  return {};
#endif
}

StackBounds find_stack_bounds(std::string_view maps_text) {
  StackBounds bounds;
#if defined(__linux__) || defined(__ANDROID__)
  std::istringstream lines{std::string(maps_text)};
  std::string line;
  while (std::getline(lines, line)) {
    if (line.find("[stack]") == std::string::npos) {
      continue;
    }
    std::string range;
    std::istringstream iss(line);
    if (!(iss >> range)) {
      continue;
    }
    const auto dash = range.find('-');
    if (dash == std::string::npos) {
      continue;
    }
    bounds.begin = static_cast<std::uintptr_t>(std::stoull(range.substr(0, dash), nullptr, 16));
    bounds.end = static_cast<std::uintptr_t>(std::stoull(range.substr(dash + 1), nullptr, 16));
    return bounds;
  }
#else
  (void)maps_text;
#endif
  return bounds;
}

std::vector<std::uintptr_t> walk_with_frame_pointer(std::size_t max_frames) {
  std::vector<std::uintptr_t> frames;
#if defined(__GNUC__) || defined(__clang__)
  const auto maps = read_maps_direct();
  const auto bounds = find_stack_bounds(maps);
  auto* frame = reinterpret_cast<FrameNode*>(__builtin_frame_address(0));
  while (frame != nullptr && frames.size() < max_frames) {
    const auto frame_address = reinterpret_cast<std::uintptr_t>(frame);
    if (bounds.begin != 0 &&
        (!bounds.contains(frame_address, sizeof(FrameNode)) ||
         (frame->previous != nullptr && !bounds.contains(reinterpret_cast<std::uintptr_t>(frame->previous), sizeof(FrameNode))))) {
      break;
    }
    const auto pc = reinterpret_cast<std::uintptr_t>(frame->return_address);
    if (pc != 0) {
      frames.push_back(pc);
    }
    auto* next = frame->previous;
    if (next == nullptr) {
      break;
    }
    const auto next_address = reinterpret_cast<std::uintptr_t>(next);
    if (next_address <= frame_address || next_address - frame_address > (1u << 20)) {
      break;
    }
    frame = next;
  }
  if (frames.size() > 2) {
    frames.erase(frames.begin(), frames.begin() + 2);
  } else {
    frames.clear();
  }
#else
  (void)max_frames;
#endif
  return frames;
}

std::vector<std::uintptr_t> walk_with_libunwind(std::size_t max_frames) {
  std::vector<std::uintptr_t> frames;
#if VMP_STACK_PROBE_HAS_LIBUNWIND
  unw_context_t context;
  unw_cursor_t cursor;
  if (unw_getcontext(&context) != 0 || unw_init_local(&cursor, &context) != 0) {
    return frames;
  }
  std::size_t skip = 0;
  while (unw_step(&cursor) > 0 && frames.size() < max_frames) {
    unw_word_t ip = 0;
    if (unw_get_reg(&cursor, UNW_REG_IP, &ip) != 0) {
      break;
    }
    if (skip < 1) {
      ++skip;
      continue;
    }
    if (ip != 0) {
      frames.push_back(static_cast<std::uintptr_t>(ip));
    }
  }
#elif VMP_STACK_PROBE_HAS_ABI_UNWIND
  struct Collector {
    std::vector<std::uintptr_t>* frames = nullptr;
    std::size_t max_frames = 0;
    std::size_t skip = 0;
  } collector{&frames, max_frames, 1};
  _Unwind_Backtrace(
      [](_Unwind_Context* context, void* arg) {
        auto* collector = static_cast<Collector*>(arg);
        if (collector == nullptr || collector->frames == nullptr) {
          return _URC_END_OF_STACK;
        }
        const auto ip = static_cast<std::uintptr_t>(_Unwind_GetIP(context));
        if (collector->skip > 0) {
          --collector->skip;
          return _URC_NO_REASON;
        }
        if (ip != 0) {
          collector->frames->push_back(ip);
        }
        return collector->frames->size() >= collector->max_frames ? _URC_END_OF_STACK : _URC_NO_REASON;
      },
      &collector);
#else
  (void)max_frames;
#endif
  return frames;
}

MappingInfo inspect_mapping_linux(std::uintptr_t pc, std::string_view maps_text) {
  MappingInfo info;
  std::istringstream lines{std::string(maps_text)};
  std::string line;
  while (std::getline(lines, line)) {
    std::string range;
    std::string perms;
    std::string offset;
    std::string dev;
    std::string inode;
    std::istringstream iss(line);
    if (!(iss >> range >> perms >> offset >> dev >> inode)) {
      continue;
    }
    std::string desc;
    std::getline(iss, desc);
    desc = trim_copy(desc);
    const auto dash = range.find('-');
    if (dash == std::string::npos) {
      continue;
    }
    const auto begin = static_cast<std::uintptr_t>(std::stoull(range.substr(0, dash), nullptr, 16));
    const auto end = static_cast<std::uintptr_t>(std::stoull(range.substr(dash + 1), nullptr, 16));
    if (pc < begin || pc >= end) {
      continue;
    }
    info.begin = begin;
    info.end = end;
    info.permissions = perms;
    info.description = desc.empty() ? std::string("[anonymous]") : desc;
    info.executable = perms.size() > 2 && perms[2] == 'x';
    info.writable = perms.size() > 1 && perms[1] == 'w';
    info.private_mapping = perms.size() > 3 && perms[3] == 'p';
    info.file_backed = !desc.empty() && desc.front() != '[';
    info.anonymous = desc.empty() || (!info.file_backed && info.description != "[vdso]" && info.description != "[vsyscall]");
    info.deleted = info.description.find("(deleted)") != std::string::npos ||
                   info.description.find("[deleted]") != std::string::npos;
    const bool android_jit_whitelist =
#if defined(__ANDROID__)
        info.description == "[anon:dalvik-jit-code-cache]";
#else
        false;
#endif
    info.allowlisted = (info.description == "[vdso]" || info.description == "[vsyscall]" || android_jit_whitelist) ||
                       (info.file_backed && info.executable && !info.writable);
    info.violation = info.executable && (info.writable || info.deleted || (info.anonymous && !info.allowlisted));
    return info;
  }
  return info;
}

#if defined(_WIN32)
MappingInfo inspect_mapping_windows(std::uintptr_t pc) {
  MappingInfo info;
  MEMORY_BASIC_INFORMATION mbi{};
  std::size_t result_length = 0;
  if (vmp::runtime::trusted_oracle::DirectSyscall::nt_query_virtual_memory_current_process(reinterpret_cast<const void*>(pc), &mbi, sizeof(mbi), &result_length) != 0) {
    return info;
  }
  info.begin = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
  info.end = info.begin + mbi.RegionSize;
  info.executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
  info.writable = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
  info.file_backed = mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED;
  info.anonymous = mbi.Type == MEM_PRIVATE;
  info.description = mbi.Type == MEM_IMAGE ? "SEC_IMAGE" : (mbi.Type == MEM_PRIVATE ? "[anonymous]" : "[mapped]");
  info.allowlisted = mbi.Type == MEM_IMAGE;
  info.violation = info.executable && (info.writable || (info.anonymous && !info.allowlisted));
  return info;
}
#endif

#if defined(__APPLE__)
MappingInfo inspect_mapping_apple(std::uintptr_t pc) {
  MappingInfo info;
  mach_vm_address_t address = static_cast<mach_vm_address_t>(pc);
  mach_vm_size_t size = 0;
  vm_region_basic_info_data_64_t basic_info{};
  mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
  mach_port_t object_name = MACH_PORT_NULL;
  if (mach_vm_region(mach_task_self(),
                     &address,
                     &size,
                     VM_REGION_BASIC_INFO_64,
                     reinterpret_cast<vm_region_info_t>(&basic_info),
                     &count,
                     &object_name) != KERN_SUCCESS) {
    return info;
  }
  info.begin = static_cast<std::uintptr_t>(address);
  info.end = static_cast<std::uintptr_t>(address + size);
  info.executable = (basic_info.protection & VM_PROT_EXECUTE) != 0;
  info.writable = (basic_info.protection & VM_PROT_WRITE) != 0;
  Dl_info dl_info{};
  if (dladdr(reinterpret_cast<const void*>(pc), &dl_info) != 0 && dl_info.dli_fname != nullptr) {
    info.file_backed = true;
    info.description = dl_info.dli_fname;
  } else {
    info.anonymous = true;
    info.description = "[anonymous]";
  }
  info.allowlisted = info.file_backed && info.executable && !info.writable;
  info.violation = info.executable && (info.writable || (info.anonymous && !info.allowlisted));
  return info;
}
#endif

MappingInfo inspect_mapping(std::uintptr_t pc, std::string_view maps_text) {
#if defined(__linux__) || defined(__ANDROID__)
  return inspect_mapping_linux(pc, maps_text);
#elif defined(_WIN32)
  (void)maps_text;
  return inspect_mapping_windows(pc);
#elif defined(__APPLE__)
  (void)maps_text;
  return inspect_mapping_apple(pc);
#else
  (void)pc;
  (void)maps_text;
  return {};
#endif
}

void emit_event(vmp::runtime::audit::ReactionDispatcher* dispatcher,
                std::uintptr_t pc,
                std::size_t frame_number,
                const MappingInfo& mapping,
                ProbeTriggerSite site) {
  if (dispatcher == nullptr) {
    return;
  }
  dispatcher->dispatch(
      vmp::runtime::audit::make_event(
          "anon_executable_frame",
          "pc=" + hex_u64(pc) +
              " frame_number=" + std::to_string(frame_number) +
              " mapping_description=" + mapping_description_text(mapping) +
              " probe_trigger_site=" + to_string(site),
          pc,
          kModuleName,
          to_string(site),
          0,
          arch_label(),
          platform_label()),
      vmp::runtime::audit::ReactionPolicy::audit_then_delayed_exit);
}

}  // namespace

struct StackProbeManager::Impl {
  explicit Impl(std::filesystem::path audit_path_in, ProbeDependencies dependencies_in)
      : audit_path(audit_path_in.empty() ? vmp::runtime::audit::AuditWriter::default_path() : std::move(audit_path_in)),
        writer(audit_path),
        dispatcher(writer, vmp::runtime::audit::ReactionPolicy::audit_only),
        dependencies(std::move(dependencies_in)) {
    set_dispatcher_exit_noop(dispatcher);
  }

  std::filesystem::path audit_path;
  vmp::runtime::audit::AuditWriter writer;
  vmp::runtime::audit::ReactionDispatcher dispatcher;
  ProbeDependencies dependencies;
  std::atomic<std::uint64_t> counter{0};
};

StackProbeManager::StackProbeManager(std::filesystem::path audit_path, ProbeDependencies dependencies)
    : impl_(std::make_unique<Impl>(std::move(audit_path), std::move(dependencies))) {}

StackProbeManager::~StackProbeManager() = default;

ProbeOutcome StackProbeManager::maybe_probe(const ProbeRequest& request,
                                            vmp::runtime::audit::ReactionDispatcher* dispatcher) {
  ProbeOutcome outcome;
  outcome.counter_value = impl_->counter.fetch_add(1, std::memory_order_relaxed);
  const auto selector = static_cast<std::uint16_t>(request.token_low12 & kProbeSelectorMask);
  outcome.triggered = impl_->dependencies.trigger_decider
                          ? impl_->dependencies.trigger_decider(selector, outcome.counter_value)
                          : static_cast<std::uint16_t>(outcome.counter_value & kProbeSelectorMask) == selector;
  if (impl_->dependencies.invocation_observer) {
    impl_->dependencies.invocation_observer(ProbeInvocation{request.site, selector, outcome.counter_value, outcome.triggered});
  }
  if (!outcome.triggered) {
    return outcome;
  }

  const auto maps_text = impl_->dependencies.maps_reader ? impl_->dependencies.maps_reader() : read_maps_direct();
  auto* active_dispatcher = dispatcher != nullptr ? dispatcher : &impl_->dispatcher;
  const auto collect_suspicious = [&](const std::vector<std::uintptr_t>& frames) {
    std::vector<FrameInspection> suspicious;
    suspicious.reserve(frames.size());
    for (std::size_t i = 0; i < frames.size(); ++i) {
      auto mapping = inspect_mapping(frames[i], maps_text);
      if (!mapping.violation) {
        continue;
      }
      suspicious.push_back(FrameInspection{frames[i], i, std::move(mapping)});
    }
    return suspicious;
  };

  auto frames = impl_->dependencies.frame_pointer_walker
                    ? impl_->dependencies.frame_pointer_walker()
                    : walk_with_frame_pointer(request.max_frames);
  outcome.used_frame_pointer_walk = !frames.empty();
  outcome.frames_examined = frames.size();
  outcome.suspicious_frames = collect_suspicious(frames);

  if (frames.empty()) {
    frames = impl_->dependencies.libunwind_walker
                 ? impl_->dependencies.libunwind_walker()
                 : walk_with_libunwind(request.max_frames);
    outcome.used_libunwind_fallback = !frames.empty();
    outcome.frames_examined = frames.size();
    outcome.suspicious_frames = collect_suspicious(frames);
  } else if (!outcome.suspicious_frames.empty() && !impl_->dependencies.frame_pointer_walker) {
    auto crosscheck_frames = impl_->dependencies.libunwind_walker
                                 ? impl_->dependencies.libunwind_walker()
                                 : walk_with_libunwind(request.max_frames);
    if (!crosscheck_frames.empty()) {
      outcome.used_libunwind_fallback = true;
      const auto crosscheck_suspicious = collect_suspicious(crosscheck_frames);
      if (crosscheck_suspicious.empty()) {
        outcome.suspicious_frames.clear();
      } else {
        outcome.suspicious_frames = crosscheck_suspicious;
      }
    }
  }

  for (const auto& frame : outcome.suspicious_frames) {
    emit_event(active_dispatcher, frame.pc, frame.frame_number, frame.mapping, request.site);
    outcome.event_emitted = true;
  }
  return outcome;
}

vmp::runtime::audit::ReactionDispatcher& StackProbeManager::reaction_dispatcher() noexcept {
  return impl_->dispatcher;
}

void StackProbeManager::reset_counter_for_tests() noexcept {
  impl_->counter.store(0, std::memory_order_release);
}

DefaultStackProbeOverride::DefaultStackProbeOverride(StackProbeManager& probe) noexcept {
  std::lock_guard<std::mutex> lock(default_probe_mutex());
  previous_ = default_probe_override_slot();
  default_probe_override_slot() = &probe;
}

DefaultStackProbeOverride::~DefaultStackProbeOverride() {
  std::lock_guard<std::mutex> lock(default_probe_mutex());
  default_probe_override_slot() = previous_;
}

StackProbeManager& default_stack_probe() {
  std::lock_guard<std::mutex> lock(default_probe_mutex());
  if (auto* override = default_probe_override_slot(); override != nullptr) {
    return *override;
  }
  static StackProbeManager probe;
  return probe;
}

std::string to_string(ProbeTriggerSite site) {
  switch (site) {
    case ProbeTriggerSite::dispatcher_entry: return "dispatcher_entry";
    case ProbeTriggerSite::trampoline_target_prologue: return "trampoline_target_prologue";
    case ProbeTriggerSite::vm1_handler_dispatch: return "vm1_handler_dispatch";
    case ProbeTriggerSite::vm2_handler_dispatch: return "vm2_handler_dispatch";
  }
  return "unknown";
}

std::uint16_t selector_low12(std::uint64_t value) noexcept {
  return static_cast<std::uint16_t>(value & kProbeSelectorMask);
}

}  // namespace vmp::runtime::stack_probe
