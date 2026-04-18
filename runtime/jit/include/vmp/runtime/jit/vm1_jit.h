#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace vmp::runtime::audit {
class AuditWriter;
}

namespace vmp::runtime::vm1 {
class Vm1Context;
class Vm1Module;
}

namespace vmp::runtime::jit {

enum class Vm1JitBackend {
  off,
  c,
  x64,
};

using JitEntry = std::uint32_t (*)(vmp::runtime::vm1::Vm1Context*);

struct Vm1JitConfig {
  std::size_t module_cache_budget_bytes = 8u * 1024u * 1024u;
  std::uint64_t trace_hot_threshold = 64;
  std::uint64_t trace_stable_threshold = 16;
  bool verbose = false;
};

struct Vm1JitEntryStats {
  std::uint64_t compile_count = 0;
  std::uint64_t hit_count = 0;
  std::uint64_t entry_trampoline_hits = 0;
  bool trace = false;
  std::size_t code_size = 0;
};

class Vm1Jit {
 public:
  static Vm1Jit& instance();

  Vm1Jit(const Vm1Jit&) = delete;
  Vm1Jit& operator=(const Vm1Jit&) = delete;

  Vm1JitBackend selected_backend() const;
  std::string selected_backend_name() const;
  bool enabled() const;

  void set_audit_writer(vmp::runtime::audit::AuditWriter* writer);
  void set_module_cache_budget_bytes(std::size_t value);
  std::size_t module_cache_budget_bytes() const;

  JitEntry compile_if_needed(const vmp::runtime::vm1::Vm1Module& module,
                             std::uint32_t block_start_pc,
                             std::uint64_t hit_count);
  void record_entry_trampoline_hit(const vmp::runtime::vm1::Vm1Module& module,
                                   std::uint32_t block_start_pc);
  void record_trace_observation(const vmp::runtime::vm1::Vm1Module& module,
                                const std::vector<std::uint32_t>& block_chain);

  void invalidate_all();
  void invalidate_module(std::uint64_t module_id);
  void invalidate_entry(std::uint64_t module_id, std::uint32_t block_start_pc);

  Vm1JitEntryStats entry_stats(std::uint64_t module_id, std::uint32_t block_start_pc) const;
  std::size_t module_entry_count(std::uint64_t module_id) const;
  std::size_t module_cache_bytes(std::uint64_t module_id) const;
  bool has_entry(std::uint64_t module_id, std::uint32_t block_start_pc) const;
  bool debug_patch_code_byte(std::uint64_t module_id, std::uint32_t block_start_pc, std::size_t offset, std::uint8_t value);

  void reset_for_tests();

 private:
  Vm1JitBackend backend_requested() const;

 private:
  Vm1Jit();
  ~Vm1Jit();

  struct Impl;
  Impl* impl_ = nullptr;
};

struct Facade {
  const char* status() const noexcept;
};

}  // namespace vmp::runtime::jit
