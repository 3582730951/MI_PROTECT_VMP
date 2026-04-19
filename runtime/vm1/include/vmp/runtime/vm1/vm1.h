#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <vmp/runtime/audit/reaction.h>
#include <vmp/runtime/bridge/bridge.h>
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/vm1/isa.h>

namespace vmp::runtime::vm1 {

struct KeyContext {
  std::uint64_t primary = 0;
  std::uint64_t secondary = 0;
};

struct VmFlags {
  bool zero = false;
  bool neg = false;
  bool carry = false;
  bool overflow = false;
};

enum class VmTrapCode {
  trap_instruction,
  out_of_bounds,
  divide_by_zero,
  unknown_opcode,
  stack_overflow,
  invalid_module,
  invalid_constant,
  invalid_register,
  bridge_error,
  string_pool_error,
  plaintext_budget_violation,
};

class VmException : public std::runtime_error {
 public:
  VmException(VmTrapCode code, std::uint32_t pc, std::string message);

  VmTrapCode code() const noexcept { return code_; }
  std::uint32_t pc() const noexcept { return pc_; }

 private:
  VmTrapCode code_;
  std::uint32_t pc_;
};

struct ConstPoolEntry {
  ConstKind kind = ConstKind::none;
  std::vector<std::uint8_t> bytes;
};

class OpcodeCryptor {
 public:
  using MasterKey = std::array<std::uint8_t, 16>;
  using Seed = std::array<std::uint8_t, kOpcodeMapSeedSize>;

  static OpcodeCryptor identity();
  static OpcodeCryptor from_seed(const MasterKey& master_key, const Seed& seed);

  std::uint16_t encode(Opcode opcode) const;
  Opcode decode(std::uint16_t on_disk) const;
  std::uint32_t sanity_marker_crc32() const;

  const std::vector<std::uint16_t>& encoded_words() const noexcept { return encoded_words_; }
  const std::vector<std::uint16_t>& decoded_words() const noexcept { return decoded_words_; }

 private:
  OpcodeCryptor() = default;

  std::vector<std::uint16_t> canonical_words_;
  std::vector<std::uint16_t> encoded_words_;
  std::vector<std::uint16_t> decoded_words_;
  std::unordered_map<std::uint16_t, std::size_t> canonical_index_by_word_;
  std::unordered_map<std::uint16_t, std::size_t> encoded_index_by_word_;
};

class Vm1Module {
 public:
  std::uint16_t version = kVm1Version;
  std::uint16_t module_flags = 0;
  std::uint32_t entry_pc = 0;
  std::uint32_t crc32 = 0;
  std::array<std::uint8_t, kOpcodeMapSeedSize> opcode_map_seed{};
  std::uint32_t opcode_map_marker_crc32 = 0;
  std::vector<std::uint8_t> code;
  std::vector<ConstPoolEntry> const_pool;
  std::uint64_t runtime_id = 0;
  mutable std::unordered_map<std::uint32_t, std::uint64_t> block_hit_counters;

  std::uint64_t id() const noexcept { return runtime_id; }
  std::uint64_t note_block_hit(std::uint32_t pc) const { return ++block_hit_counters[pc]; }
  std::uint64_t block_hit_count(std::uint32_t pc) const { auto it = block_hit_counters.find(pc); return it == block_hit_counters.end() ? 0u : it->second; }

  static Vm1Module load_from_file(const std::string& path);
  static Vm1Module load_from_bytes(const std::vector<std::uint8_t>& bytes);

  std::vector<std::uint8_t> serialize() const;
  void save_to_file(const std::string& path) const;
};

struct ExecutionResult {
  std::uint64_t ret_int = 0;
  double ret_float = 0.0;
};

class Vm1Context {
 public:
  explicit Vm1Context(const Vm1Module& module, std::size_t stack_size = kVm1DefaultStackSize);

  std::array<std::uint64_t, kVm1GeneralRegisterCount> vr{};
  std::array<double, kVm1FloatRegisterCount> vfr{};
  std::uint32_t pc = 0;
  std::uint64_t sp = 0;
  VmFlags flags{};
  const Vm1Module* module = nullptr;
  KeyContext key_context{};
  vmp::runtime::bridge::BridgeRegistry* bridge_registry = nullptr;
  vmp::runtime::audit::ReactionDispatcher* audit_dispatcher = nullptr;
  std::shared_ptr<vmp::runtime::strings::StringPool> string_pool;
  int max_bridge_depth = 64;

  std::size_t stack_size() const noexcept;
  std::uint64_t stack_top() const noexcept;
  void set_stack_top(std::uint64_t value);

  template <typename T>
  T read_memory(std::uint64_t address) const;

  template <typename T>
  void write_memory(std::uint64_t address, T value);

  std::uint64_t materialize_transient_string(std::uint32_t id);
  void release_transient_string(std::uint64_t handle);
  std::string transient_string(std::uint64_t handle) const;
  std::size_t active_transient_strings() const noexcept;
  std::vector<std::uint8_t> debug_last_released_bytes(std::uint64_t handle) const;
  bool debug_last_release_zeroed(std::uint64_t handle) const;

 public:
  friend class Vm1Interpreter;

  struct CallFrame {
    std::array<std::uint64_t, kVm1GeneralRegisterCount> vr{};
    std::array<double, kVm1FloatRegisterCount> vfr{};
    VmFlags flags{};
    std::uint32_t return_pc = 0;
    std::uint64_t caller_sp = 0;
    std::uint64_t caller_stack_top = 0;
    std::uint8_t arg_count = 0;
    std::vector<std::uint64_t> transient_handles;
  };

  void ensure_memory_range(std::uint64_t address, std::size_t width) const;

  void register_transient_handle(std::uint64_t handle);
  void remove_transient_handle_owner(std::uint64_t handle);
  void clear_frame_transient_strings();
  void clear_all_transient_strings() noexcept;

  std::vector<std::uint8_t> stack_;
  std::uint64_t stack_top_ = 0;
  std::vector<CallFrame> frames_;
  std::vector<std::uint64_t> root_transient_handles_;
  std::unordered_map<std::uint64_t, std::unique_ptr<vmp::runtime::strings::TransientView>> transient_strings_;
  std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> released_transient_debug_;
  std::uint64_t next_transient_handle_ = 1;
  bool execution_halted = false;
};

class Vm1Interpreter {
 public:
  ExecutionResult execute(Vm1Context& context);
};

extern "C" std::uint32_t vmp_vm1_jit_execute_block(Vm1Context* context, std::uint32_t start_pc);
extern "C" std::uint32_t vmp_vm1_jit_execute_trace(Vm1Context* context, const std::uint32_t* block_pcs, std::size_t block_count);

struct AssembleOptions {
  std::uint16_t module_flags = 0;
  bool encrypt_opcodes = false;
  std::optional<std::array<std::uint8_t, kOpcodeMapSeedSize>> opcode_seed;
};

Vm1Module assemble_module_text(std::string_view text, std::uint16_t module_flags = 0);
Vm1Module assemble_module_text(std::string_view text, const AssembleOptions& options);
std::uint32_t serialized_body_crc32(const std::vector<std::uint8_t>& bytes);
std::string disassemble_module(const Vm1Module& module);
std::string opcode_name(Opcode opcode);
const std::vector<Opcode>& canonical_opcode_sequence();
const void* handler_table_identity() noexcept;

struct Facade {
  const char* status() const noexcept;
};

template <typename T>
T Vm1Context::read_memory(std::uint64_t address) const {
  ensure_memory_range(address, sizeof(T));
  T value{};
  for (std::size_t i = 0; i < sizeof(T); ++i) {
    value = static_cast<T>(value | (static_cast<T>(stack_[static_cast<std::size_t>(address + i)]) << (i * 8)));
  }
  return value;
}

template <typename T>
void Vm1Context::write_memory(std::uint64_t address, T value) {
  ensure_memory_range(address, sizeof(T));
  for (std::size_t i = 0; i < sizeof(T); ++i) {
    stack_[static_cast<std::size_t>(address + i)] =
        static_cast<std::uint8_t>((static_cast<std::uint64_t>(value) >> (i * 8)) & 0xFFu);
  }
}

}  // namespace vmp::runtime::vm1
