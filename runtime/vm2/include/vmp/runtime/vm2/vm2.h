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
#include <unordered_set>
#include <vector>

#include <vmp/runtime/audit/reaction.h>
#include <vmp/runtime/bridge/bridge.h>
#include <vmp/runtime/strings/cipher.h>
#include <vmp/runtime/strings/keyctx.h>
#include <vmp/runtime/vm2/isa.h>

namespace vmp::runtime::vm2 {

struct Vm2ConstPoolEntry {
  std::array<std::uint8_t, 16> bytes{};
};

class OpcodeCryptor {
 public:
  using MasterKey = std::array<std::uint8_t, kVm2KeyContextIdSize>;
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

class Vm2Module {
 public:
  std::uint16_t version = kVm2Version;
  std::uint16_t module_flags = 0;
  std::uint32_t entry_pc = 0;
  std::uint32_t crc32 = 0;
  std::array<std::uint8_t, kOpcodeMapSeedSize> opcode_map_seed{};
  std::uint32_t opcode_map_marker_crc32 = 0;
  std::vector<std::uint8_t> code;
  std::vector<std::uint8_t> reverse_code;
  std::vector<std::uint16_t> reverse_insn_lengths;
  std::vector<std::uint32_t> forward_instruction_start_by_pc;
  std::vector<std::uint16_t> forward_instruction_length_by_pc;
  std::vector<std::uint64_t> reverse_pc_to_forward_pc;
  std::vector<Vm2ConstPoolEntry> const_pool;
  std::array<std::uint8_t, kVm2KeyContextIdSize> key_context_id{};
  std::uint64_t runtime_id = 0;
  std::unordered_set<std::uint32_t> function_entries;
  mutable std::unordered_map<std::uint32_t, std::uint64_t> function_hit_counters;
  mutable std::unordered_map<std::uint32_t, std::uintptr_t> function_jit_table;

  std::uint64_t id() const noexcept { return runtime_id; }
  std::uint64_t note_function_hit(std::uint32_t pc) const { return ++function_hit_counters[pc]; }
  std::uint64_t function_hit_count(std::uint32_t pc) const {
    auto it = function_hit_counters.find(pc);
    return it == function_hit_counters.end() ? 0u : it->second;
  }
  bool is_function_entry_pc(std::uint32_t pc) const noexcept { return function_entries.find(pc) != function_entries.end(); }
  void set_function_jit_entry(std::uint32_t pc, std::uintptr_t entry) const { function_jit_table[pc] = entry; }
  void clear_function_jit_entry(std::uint32_t pc) const { function_jit_table.erase(pc); }
  void clear_function_jit_entries() const { function_jit_table.clear(); }
  std::uintptr_t function_jit_entry(std::uint32_t pc) const {
    auto it = function_jit_table.find(pc);
    return it == function_jit_table.end() ? 0u : it->second;
  }

  static Vm2Module load_from_file(const std::string& path);
  static Vm2Module load_from_bytes(const std::vector<std::uint8_t>& bytes);

  std::vector<std::uint8_t> serialize() const;
  void save_to_file(const std::string& path) const;
};

class Vm2Exception : public std::runtime_error {
 public:
  Vm2Exception(std::uint32_t pc, std::string message);
  std::uint32_t pc() const noexcept { return pc_; }

 private:
  std::uint32_t pc_ = 0;
};

class Vm2DivByZero : public Vm2Exception {
 public:
  explicit Vm2DivByZero(std::uint32_t pc, std::string message) : Vm2Exception(pc, std::move(message)) {}
};

class Vm2StackOverflow : public Vm2Exception {
 public:
  explicit Vm2StackOverflow(std::uint32_t pc, std::string message) : Vm2Exception(pc, std::move(message)) {}
};

class Vm2UnknownOpcode : public Vm2Exception {
 public:
  explicit Vm2UnknownOpcode(std::uint32_t pc, std::string message) : Vm2Exception(pc, std::move(message)) {}
};

struct ExecutionResult {
  std::uint64_t ret_int = 0;
  double ret_float = 0.0;
  Vec128 ret_vec{};
};

class Vm2Context {
 public:
  explicit Vm2Context(const Vm2Module& module, std::size_t stack_size = kVm2DefaultStackSize);

  std::array<std::uint64_t, kVm2GeneralRegisterCount> r{};
  std::array<Vec128, kVm2VectorRegisterCount> q{};
  std::array<double, kVm2FloatRegisterCount> d{};
  std::array<bool, kVm2PredicateCount> p{};
  std::uint32_t pc = 0;
  std::uint64_t sp = 0;
  std::uint32_t lr = 0;
  const Vm2Module* module = nullptr;
  std::shared_ptr<vmp::runtime::strings::KeyContext> key_context;
  vmp::runtime::bridge::BridgeRegistry* bridge_registry = nullptr;
  vmp::runtime::audit::ReactionDispatcher* audit_dispatcher = nullptr;
  std::shared_ptr<vmp::runtime::strings::StringPool> string_pool;
  int max_bridge_depth = 64;

  std::size_t stack_size() const noexcept;
  void set_sp(std::uint64_t value);

  template <typename T>
  T read_memory(std::uint64_t address) const;

  template <typename T>
  void write_memory(std::uint64_t address, T value);

  Vec128 read_vec128(std::uint64_t address) const;
  void write_vec128(std::uint64_t address, const Vec128& value);

  std::uint64_t materialize_transient_string(std::uint32_t id);
  void release_transient_string(std::uint64_t handle);
  std::string transient_string(std::uint64_t handle) const;
  std::size_t active_transient_strings() const noexcept;
  std::array<std::uint8_t, kVm2KeyContextIdSize> current_key_context_id() const;

 public:
  friend class Vm2Interpreter;

  struct CallFrame {
    std::array<std::uint64_t, kVm2GeneralRegisterCount> r{};
    std::array<Vec128, kVm2VectorRegisterCount> q{};
    std::array<double, kVm2FloatRegisterCount> d{};
    std::array<bool, kVm2PredicateCount> p{};
    std::uint32_t caller_lr = 0;
    std::uint64_t caller_sp = 0;
    std::vector<std::uint64_t> transient_handles;
  };

  void ensure_memory_range(std::uint64_t address, std::size_t width) const;
  std::uint64_t allocate_spill(std::size_t bytes, const char* reason);
  void register_transient_handle(std::uint64_t handle);
  void remove_transient_handle_owner(std::uint64_t handle);
  void clear_frame_transient_strings();
  void clear_all_transient_strings() noexcept;

  std::vector<std::uint8_t> stack_;
  std::vector<CallFrame> frames_;
  std::vector<std::uint64_t> root_transient_handles_;
  std::unordered_map<std::uint64_t, std::unique_ptr<vmp::runtime::strings::TransientView>> transient_strings_;
  std::uint64_t next_transient_handle_ = 1;
  bool execution_halted = false;
  std::uint32_t jit_skip_entry_once_pc = 0xFFFFFFFFu;
};

class Vm2Interpreter {
 public:
  Vm2Interpreter();
  ExecutionResult execute(Vm2Context& context);
};

struct AssembleOptions {
  std::uint16_t module_flags = 0;
  bool encrypt_opcodes = false;
  std::optional<std::array<std::uint8_t, kOpcodeMapSeedSize>> opcode_seed;
};

Vm2Module assemble_module_text(std::string_view text, std::uint16_t module_flags = 0);
Vm2Module assemble_module_text(std::string_view text, const AssembleOptions& options);
std::vector<std::uint16_t> instruction_lengths(const Vm2Module& module);
std::string disassemble_module(const Vm2Module& module);
std::string opcode_name(Opcode opcode);
const std::vector<Opcode>& canonical_opcode_sequence();
const void* handler_table_identity() noexcept;

struct Facade {
  const char* status() const noexcept;
};

template <typename T>
T Vm2Context::read_memory(std::uint64_t address) const {
  ensure_memory_range(address, sizeof(T));
  T value{};
  for (std::size_t i = 0; i < sizeof(T); ++i) {
    value = static_cast<T>(value | (static_cast<T>(stack_[static_cast<std::size_t>(address + i)]) << (i * 8)));
  }
  return value;
}

template <typename T>
void Vm2Context::write_memory(std::uint64_t address, T value) {
  ensure_memory_range(address, sizeof(T));
  for (std::size_t i = 0; i < sizeof(T); ++i) {
    stack_[static_cast<std::size_t>(address + i)] =
        static_cast<std::uint8_t>((static_cast<std::uint64_t>(value) >> (i * 8)) & 0xFFu);
  }
}

}  // namespace vmp::runtime::vm2
