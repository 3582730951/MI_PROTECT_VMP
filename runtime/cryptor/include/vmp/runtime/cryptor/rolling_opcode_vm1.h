#pragma once

#include <optional>
#include <vector>

#include <vmp/runtime/cryptor/rolling_opcode.h>
#include <vmp/runtime/vm1/vm1.h>

namespace vmp::runtime::cryptor::vm1 {

namespace detail {

inline std::size_t instruction_size(vmp::runtime::vm1::Opcode opcode) {
  using Opcode = vmp::runtime::vm1::Opcode;
  switch (opcode) {
    case Opcode::nop:
    case Opcode::ret:
    case Opcode::domain_ret:
    case Opcode::fence:
    case Opcode::breakpoint: return 2;
    case Opcode::trap:
    case Opcode::jmp:
    case Opcode::syscall_proxy: return 6;
    case Opcode::mov:
    case Opcode::neg:
    case Opcode::bit_not:
    case Opcode::popcnt:
    case Opcode::clz:
    case Opcode::ctz:
    case Opcode::bswap:
    case Opcode::setcc:
    case Opcode::fsqrt:
    case Opcode::i64_to_f64:
    case Opcode::f64_to_i64:
    case Opcode::strlen:
    case Opcode::call_indirect: return 4;
    case Opcode::jmp_indirect:
    case Opcode::release_transient_string:
    case Opcode::transient_wipe: return 3;
    case Opcode::ldi64:
    case Opcode::ldi_u64:
    case Opcode::ldi_f64: return 11;
    case Opcode::add:
    case Opcode::sub:
    case Opcode::mul:
    case Opcode::div:
    case Opcode::mod:
    case Opcode::bit_and:
    case Opcode::bit_or:
    case Opcode::bit_xor:
    case Opcode::shl:
    case Opcode::shr:
    case Opcode::sar:
    case Opcode::fadd:
    case Opcode::fsub:
    case Opcode::fmul:
    case Opcode::fdiv:
    case Opcode::vadd128:
    case Opcode::vxor128:
    case Opcode::vshuffle128:
    case Opcode::memcpy:
    case Opcode::memset:
    case Opcode::strcmp: return 5;
    case Opcode::cmp:
    case Opcode::test:
    case Opcode::fcmp: return 4;
    case Opcode::load_mem8:
    case Opcode::load_mem16:
    case Opcode::load_mem32:
    case Opcode::load_mem64:
    case Opcode::store_mem8:
    case Opcode::store_mem16:
    case Opcode::store_mem32:
    case Opcode::store_mem64:
    case Opcode::load_sext8:
    case Opcode::load_sext16:
    case Opcode::load_sext32:
    case Opcode::lea: return 8;
    case Opcode::jeq:
    case Opcode::jne:
    case Opcode::jlt:
    case Opcode::jle:
    case Opcode::jgt:
    case Opcode::jge: return 8;
    case Opcode::call:
    case Opcode::load_transient_string: return 7;
    case Opcode::domain_call: return 10;
    case Opcode::bridge_args:
    case Opcode::transient_read8: return 5;
    case Opcode::cas_u64: return 10;
    case Opcode::xchg_u64: return 9;
  }
  throw std::runtime_error("rolling_opcode_vm1: unknown opcode size");
}

inline std::vector<std::uint16_t> canonical_opcode_words() {
  using Opcode = vmp::runtime::vm1::Opcode;
  static const std::vector<std::uint16_t> words{
      static_cast<std::uint16_t>(Opcode::nop),
      static_cast<std::uint16_t>(Opcode::ldi64),
      static_cast<std::uint16_t>(Opcode::ldi_u64),
      static_cast<std::uint16_t>(Opcode::ldi_f64),
      static_cast<std::uint16_t>(Opcode::mov),
      static_cast<std::uint16_t>(Opcode::add),
      static_cast<std::uint16_t>(Opcode::sub),
      static_cast<std::uint16_t>(Opcode::mul),
      static_cast<std::uint16_t>(Opcode::div),
      static_cast<std::uint16_t>(Opcode::mod),
      static_cast<std::uint16_t>(Opcode::neg),
      static_cast<std::uint16_t>(Opcode::bit_and),
      static_cast<std::uint16_t>(Opcode::bit_or),
      static_cast<std::uint16_t>(Opcode::bit_xor),
      static_cast<std::uint16_t>(Opcode::shl),
      static_cast<std::uint16_t>(Opcode::shr),
      static_cast<std::uint16_t>(Opcode::sar),
      static_cast<std::uint16_t>(Opcode::bit_not),
      static_cast<std::uint16_t>(Opcode::popcnt),
      static_cast<std::uint16_t>(Opcode::clz),
      static_cast<std::uint16_t>(Opcode::ctz),
      static_cast<std::uint16_t>(Opcode::bswap),
      static_cast<std::uint16_t>(Opcode::cmp),
      static_cast<std::uint16_t>(Opcode::test),
      static_cast<std::uint16_t>(Opcode::setcc),
      static_cast<std::uint16_t>(Opcode::load_mem8),
      static_cast<std::uint16_t>(Opcode::load_mem16),
      static_cast<std::uint16_t>(Opcode::load_mem32),
      static_cast<std::uint16_t>(Opcode::load_mem64),
      static_cast<std::uint16_t>(Opcode::store_mem8),
      static_cast<std::uint16_t>(Opcode::store_mem16),
      static_cast<std::uint16_t>(Opcode::store_mem32),
      static_cast<std::uint16_t>(Opcode::store_mem64),
      static_cast<std::uint16_t>(Opcode::load_sext8),
      static_cast<std::uint16_t>(Opcode::load_sext16),
      static_cast<std::uint16_t>(Opcode::load_sext32),
      static_cast<std::uint16_t>(Opcode::lea),
      static_cast<std::uint16_t>(Opcode::jmp),
      static_cast<std::uint16_t>(Opcode::jeq),
      static_cast<std::uint16_t>(Opcode::jne),
      static_cast<std::uint16_t>(Opcode::jlt),
      static_cast<std::uint16_t>(Opcode::jle),
      static_cast<std::uint16_t>(Opcode::jgt),
      static_cast<std::uint16_t>(Opcode::jge),
      static_cast<std::uint16_t>(Opcode::call),
      static_cast<std::uint16_t>(Opcode::ret),
      static_cast<std::uint16_t>(Opcode::call_indirect),
      static_cast<std::uint16_t>(Opcode::jmp_indirect),
      static_cast<std::uint16_t>(Opcode::fadd),
      static_cast<std::uint16_t>(Opcode::fsub),
      static_cast<std::uint16_t>(Opcode::fmul),
      static_cast<std::uint16_t>(Opcode::fdiv),
      static_cast<std::uint16_t>(Opcode::fsqrt),
      static_cast<std::uint16_t>(Opcode::i64_to_f64),
      static_cast<std::uint16_t>(Opcode::f64_to_i64),
      static_cast<std::uint16_t>(Opcode::fcmp),
      static_cast<std::uint16_t>(Opcode::vadd128),
      static_cast<std::uint16_t>(Opcode::vxor128),
      static_cast<std::uint16_t>(Opcode::vshuffle128),
      static_cast<std::uint16_t>(Opcode::memcpy),
      static_cast<std::uint16_t>(Opcode::memset),
      static_cast<std::uint16_t>(Opcode::strcmp),
      static_cast<std::uint16_t>(Opcode::strlen),
      static_cast<std::uint16_t>(Opcode::cas_u64),
      static_cast<std::uint16_t>(Opcode::xchg_u64),
      static_cast<std::uint16_t>(Opcode::fence),
      static_cast<std::uint16_t>(Opcode::breakpoint),
      static_cast<std::uint16_t>(Opcode::trap),
      static_cast<std::uint16_t>(Opcode::syscall_proxy),
      static_cast<std::uint16_t>(Opcode::domain_call),
      static_cast<std::uint16_t>(Opcode::domain_ret),
      static_cast<std::uint16_t>(Opcode::bridge_args),
      static_cast<std::uint16_t>(Opcode::load_transient_string),
      static_cast<std::uint16_t>(Opcode::release_transient_string),
      static_cast<std::uint16_t>(Opcode::transient_read8),
      static_cast<std::uint16_t>(Opcode::transient_wipe),
  };
  return words;
}

inline std::vector<std::uint16_t> instruction_lengths(const vmp::runtime::vm1::Vm1Module& module) {
  if (!module.reverse_insn_lengths.empty()) {
    return module.reverse_insn_lengths;
  }
  std::vector<std::uint16_t> lengths;
  std::size_t pc = 0;
  while (pc < module.code.size()) {
    const auto opcode = static_cast<vmp::runtime::vm1::Opcode>(
        static_cast<std::uint16_t>(module.code[pc]) | static_cast<std::uint16_t>(module.code[pc + 1] << 8u));
    const auto size = instruction_size(opcode);
    lengths.push_back(static_cast<std::uint16_t>(size));
    pc += size;
  }
  return lengths;
}

}  // namespace detail

inline bool opcode_encrypted(const vmp::runtime::vm1::Vm1Module& module) {
  return (module.module_flags & vmp::runtime::vm1::VMP_FLAG_OPCODE_ENCRYPTED) != 0u;
}

inline ModuleDescriptor describe_module(const vmp::runtime::vm1::Vm1Module& module) {
  ModuleDescriptor descriptor;
  descriptor.module_id = module.id();
  descriptor.domain = VmDomain::vm1;
  descriptor.module_name = "vm1";
  descriptor.opcode_encrypted = (module.module_flags & vmp::runtime::vm1::VMP_FLAG_OPCODE_ENCRYPTED) != 0u;
  descriptor.reverse_order = (module.module_flags & vmp::runtime::vm1::VMP_FLAG_REVERSE_ORDER) != 0u;
  descriptor.canonical_forward_code = module.code;
  descriptor.instruction_lengths = detail::instruction_lengths(module);
  descriptor.forward_instruction_start_by_pc = module.forward_instruction_start_by_pc;
  descriptor.forward_instruction_length_by_pc = module.forward_instruction_length_by_pc;
  if (descriptor.forward_instruction_start_by_pc.empty() ||
      descriptor.forward_instruction_start_by_pc.size() != module.code.size() ||
      descriptor.forward_instruction_length_by_pc.size() != module.code.size()) {
    descriptor.forward_instruction_start_by_pc.assign(module.code.size(), 0u);
    descriptor.forward_instruction_length_by_pc.assign(module.code.size(), 0u);
    std::size_t forward_pc = 0;
    for (const auto length : descriptor.instruction_lengths) {
      for (std::size_t i = 0; i < length; ++i) {
        descriptor.forward_instruction_start_by_pc[forward_pc + i] = static_cast<std::uint32_t>(forward_pc);
        descriptor.forward_instruction_length_by_pc[forward_pc + i] = length;
      }
      forward_pc += length;
    }
  }
  descriptor.canonical_opcode_words = detail::canonical_opcode_words();
  descriptor.master_key_material.assign(vmp::runtime::vm1::kOpcodeMapSeedSize, 0u);
  descriptor.base_seed.assign(module.opcode_map_seed.begin(), module.opcode_map_seed.end());
  descriptor.key_context_material = descriptor.base_seed;
  return descriptor;
}

inline void ensure_registered(const vmp::runtime::vm1::Vm1Module& module) {
  if (!opcode_encrypted(module)) {
    return;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().ensure_module(descriptor);
}

inline DispatchEpochScope begin_dispatch(const vmp::runtime::vm1::Vm1Module& module) {
  if (!opcode_encrypted(module)) {
    return {};
  }
  const auto descriptor = describe_module(module);
  return RollingOpcodeRegistry::instance().begin_dispatch(descriptor);
}

inline std::uint8_t fetch_byte(const vmp::runtime::vm1::Vm1Module& module, std::size_t forward_pc) {
  ensure_registered(module);
  return RollingOpcodeRegistry::instance().fetch_decoded_byte(describe_module(module), forward_pc);
}

inline std::uint8_t fetch_byte_for_epoch(const vmp::runtime::vm1::Vm1Module& module,
                                         std::size_t forward_pc,
                                         std::uint32_t epoch_id) {
  ensure_registered(module);
  return RollingOpcodeRegistry::instance().fetch_decoded_byte_for_epoch(describe_module(module), forward_pc, epoch_id);
}

inline void notify_key_rotation(const vmp::runtime::vm1::Vm1Module& module,
                                std::vector<std::uint8_t> key_material_override = {}) {
  if (!opcode_encrypted(module)) {
    return;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().rotate_module(descriptor, RotationReason::key_rotation, std::move(key_material_override));
}

inline void notify_integrity_event(const vmp::runtime::vm1::Vm1Module& module) {
  if (!opcode_encrypted(module)) {
    return;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().rotate_module(descriptor, RotationReason::integrity_event);
}

inline void notify_domain_switch(const vmp::runtime::vm1::Vm1Module& module) {
  if (!opcode_encrypted(module)) {
    return;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().rotate_module(descriptor, RotationReason::domain_switch);
}

inline std::uint32_t current_epoch_id(const vmp::runtime::vm1::Vm1Module& module) {
  if (!opcode_encrypted(module)) {
    return 0u;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().ensure_module(descriptor);
  return RollingOpcodeRegistry::instance().current_epoch_id(descriptor);
}

inline std::optional<std::uint32_t> previous_epoch_id(const vmp::runtime::vm1::Vm1Module& module) {
  if (!opcode_encrypted(module)) {
    return std::nullopt;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().ensure_module(descriptor);
  return RollingOpcodeRegistry::instance().previous_epoch_id(descriptor);
}

inline std::uint64_t dispatch_count(const vmp::runtime::vm1::Vm1Module& module) {
  if (!opcode_encrypted(module)) {
    return 0u;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().ensure_module(descriptor);
  return RollingOpcodeRegistry::instance().dispatch_count(descriptor);
}

inline void set_policy(const vmp::runtime::vm1::Vm1Module& module, const RollingPolicy& policy) {
  if (!opcode_encrypted(module)) {
    return;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().set_policy(descriptor, policy);
}

inline std::vector<std::uint8_t> debug_forward_storage(const vmp::runtime::vm1::Vm1Module& module) {
  if (!opcode_encrypted(module)) {
    return module.code;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().ensure_module(descriptor);
  return RollingOpcodeRegistry::instance().debug_forward_storage(descriptor);
}

inline std::vector<std::uint8_t> debug_forward_storage_for_epoch(const vmp::runtime::vm1::Vm1Module& module,
                                                                 std::uint32_t epoch_id) {
  if (!opcode_encrypted(module)) {
    return epoch_id == 0u ? module.code : std::vector<std::uint8_t>{};
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().ensure_module(descriptor);
  return RollingOpcodeRegistry::instance().debug_forward_storage_for_epoch(descriptor, epoch_id);
}

}  // namespace vmp::runtime::cryptor::vm1
