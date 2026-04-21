#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

namespace vmp::runtime::audit {
class AuditWriter;
}

namespace vmp::runtime::vm2 {
class Vm2Context;
class Vm2Module;
}

namespace vmp::runtime::jit {

enum class Vm2JitBackend {
  off,
  c,
  x64,
};

enum class Vm2JitLifecycleState {
  compiling,
  ready,
  invalidated,
  evicted,
};

enum class Vm2JitEventKind {
  key_rotated,
  integrity_failed,
  detection_event,
};

using Vm2JitEntry = std::uint32_t (*)(vmp::runtime::vm2::Vm2Context*);

struct Vm2JitConfig {
  std::size_t module_cache_budget_bytes = 4u * 1024u * 1024u;
  std::uint64_t function_hot_threshold = 32;
  bool verbose = false;
};

struct Vm2JitEntryStats {
  std::uint64_t compile_count = 0;
  std::uint64_t hit_count = 0;
  std::uint64_t entry_trampoline_hits = 0;
  std::uint64_t native_degrade_count = 0;
  std::size_t code_size = 0;
  Vm2JitLifecycleState state = Vm2JitLifecycleState::evicted;
};

class Vm2Jit {
 public:
  static Vm2Jit& instance();

  Vm2Jit(const Vm2Jit&) = delete;
  Vm2Jit& operator=(const Vm2Jit&) = delete;

  Vm2JitBackend selected_backend() const;
  std::string selected_backend_name() const;
  bool enabled() const;

  void set_audit_writer(vmp::runtime::audit::AuditWriter* writer);
  void set_module_cache_budget_bytes(std::size_t value);
  std::size_t module_cache_budget_bytes() const;

  Vm2JitEntry compile_if_needed(const vmp::runtime::vm2::Vm2Module& module,
                                const vmp::runtime::vm2::Vm2Context& context,
                                std::uint32_t entry_pc,
                                std::uint64_t hit_count);
  std::uint32_t dispatch(vmp::runtime::vm2::Vm2Context& context, std::uint32_t entry_pc);

  void invalidate_all();
  void invalidate_module(std::uint64_t module_id);
  void invalidate_entry(std::uint64_t module_id, std::uint32_t entry_pc);
  void invalidate_on_event(Vm2JitEventKind kind);
  void invalidate_module_for_key_context_change(const vmp::runtime::vm2::Vm2Module& module);
  void invalidate_module_for_epoch_change(std::uint64_t module_id, std::uint32_t current_epoch_id);

  Vm2JitEntryStats entry_stats(std::uint64_t module_id, std::uint32_t entry_pc) const;
  std::size_t module_entry_count(std::uint64_t module_id) const;
  std::size_t module_cache_bytes(std::uint64_t module_id) const;
  bool has_entry(std::uint64_t module_id, std::uint32_t entry_pc) const;
  std::uint32_t entry_epoch_id(std::uint64_t module_id, std::uint32_t entry_pc) const;

  bool debug_patch_code_byte(std::uint64_t module_id, std::uint32_t entry_pc, std::size_t offset, std::uint8_t value);

  void reset_for_tests();

 private:
  Vm2JitBackend backend_requested() const;

 private:
  Vm2Jit();
  ~Vm2Jit();

  struct Impl;
  Impl* impl_ = nullptr;
};

extern "C" std::uint32_t vmp_vm2_jit_execute_function(vmp::runtime::vm2::Vm2Context* context, std::uint32_t entry_pc);

}  // namespace vmp::runtime::jit
