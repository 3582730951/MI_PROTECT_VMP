#pragma once

#include <optional>
#include <vector>

#include <vmp/runtime/cryptor/rolling_opcode.h>
#include <vmp/runtime/vm2/vm2.h>

namespace vmp::runtime::cryptor::vm2 {

namespace detail {

inline std::size_t instruction_size(vmp::runtime::vm2::Opcode opcode) {
  using Opcode = vmp::runtime::vm2::Opcode;
  switch (opcode) {
    case Opcode::nop:
    case Opcode::bret:
    case Opcode::pret:
    case Opcode::xret:
    case Opcode::ifence:
    case Opcode::brk: return 2;
    case Opcode::ftrap:
    case Opcode::jmp:
    case Opcode::syscall_proxy: return 6;
    case Opcode::ildimm:
    case Opcode::dldimm: return 11;
    case Opcode::vldimm:
    case Opcode::tsload: return 7;
    case Opcode::imov:
    case Opcode::ineg:
    case Opcode::inot:
    case Opcode::dmov:
    case Opcode::ipopcnt:
    case Opcode::iclz:
    case Opcode::ictz:
    case Opcode::ibswap:
    case Opcode::isetcc:
    case Opcode::istrlen:
    case Opcode::dsqrt:
    case Opcode::i64tof:
    case Opcode::f64toi:
    case Opcode::icmp:
    case Opcode::itest:
    case Opcode::dcmp: return 4;
    case Opcode::tsrelease:
    case Opcode::tswipe: return 3;
    case Opcode::iadd:
    case Opcode::isub:
    case Opcode::imul:
    case Opcode::idiv:
    case Opcode::imod:
    case Opcode::iand:
    case Opcode::ior:
    case Opcode::ixor:
    case Opcode::ishl:
    case Opcode::ishr:
    case Opcode::isar:
    case Opcode::dadd:
    case Opcode::dsub:
    case Opcode::dmul:
    case Opcode::ddiv:
    case Opcode::vadd128:
    case Opcode::vsub128:
    case Opcode::vmul128:
    case Opcode::vxor128:
    case Opcode::imemcpy:
    case Opcode::imemset:
    case Opcode::istrcmp: return 5;
    case Opcode::imemld8:
    case Opcode::imemld16:
    case Opcode::imemld32:
    case Opcode::imemld64:
    case Opcode::imemst8:
    case Opcode::imemst16:
    case Opcode::imemst32:
    case Opcode::imemst64:
    case Opcode::vmemld128:
    case Opcode::vmemst128: return 8;
    case Opcode::jp:
    case Opcode::jnp: return 7;
    case Opcode::blnk: return 7;
    case Opcode::pcall: return 8;
    case Opcode::xcall:
    case Opcode::icas64: return 10;
    case Opcode::ixchg64: return 9;
    case Opcode::bridgeargs:
    case Opcode::tsread8: return 5;
  }
  throw std::runtime_error("rolling_opcode_vm2: unknown opcode size");
}

inline std::vector<std::uint16_t> canonical_opcode_words() {
  using Opcode = vmp::runtime::vm2::Opcode;
  static const std::vector<std::uint16_t> words{
      static_cast<std::uint16_t>(Opcode::nop),       static_cast<std::uint16_t>(Opcode::ildimm),
      static_cast<std::uint16_t>(Opcode::vldimm),    static_cast<std::uint16_t>(Opcode::imov),
      static_cast<std::uint16_t>(Opcode::dldimm),    static_cast<std::uint16_t>(Opcode::dmov),
      static_cast<std::uint16_t>(Opcode::iadd),      static_cast<std::uint16_t>(Opcode::isub),
      static_cast<std::uint16_t>(Opcode::imul),      static_cast<std::uint16_t>(Opcode::idiv),
      static_cast<std::uint16_t>(Opcode::imod),      static_cast<std::uint16_t>(Opcode::ineg),
      static_cast<std::uint16_t>(Opcode::iand),      static_cast<std::uint16_t>(Opcode::ior),
      static_cast<std::uint16_t>(Opcode::ixor),      static_cast<std::uint16_t>(Opcode::ishl),
      static_cast<std::uint16_t>(Opcode::ishr),      static_cast<std::uint16_t>(Opcode::isar),
      static_cast<std::uint16_t>(Opcode::inot),      static_cast<std::uint16_t>(Opcode::ipopcnt),
      static_cast<std::uint16_t>(Opcode::iclz),      static_cast<std::uint16_t>(Opcode::ictz),
      static_cast<std::uint16_t>(Opcode::ibswap),    static_cast<std::uint16_t>(Opcode::icmp),
      static_cast<std::uint16_t>(Opcode::itest),     static_cast<std::uint16_t>(Opcode::isetcc),
      static_cast<std::uint16_t>(Opcode::imemld8),   static_cast<std::uint16_t>(Opcode::imemld16),
      static_cast<std::uint16_t>(Opcode::imemld32),  static_cast<std::uint16_t>(Opcode::imemld64),
      static_cast<std::uint16_t>(Opcode::imemst8),   static_cast<std::uint16_t>(Opcode::imemst16),
      static_cast<std::uint16_t>(Opcode::imemst32),  static_cast<std::uint16_t>(Opcode::imemst64),
      static_cast<std::uint16_t>(Opcode::vmemld128), static_cast<std::uint16_t>(Opcode::vmemst128),
      static_cast<std::uint16_t>(Opcode::jmp),       static_cast<std::uint16_t>(Opcode::jp),
      static_cast<std::uint16_t>(Opcode::jnp),       static_cast<std::uint16_t>(Opcode::blnk),
      static_cast<std::uint16_t>(Opcode::bret),      static_cast<std::uint16_t>(Opcode::pcall),
      static_cast<std::uint16_t>(Opcode::pret),      static_cast<std::uint16_t>(Opcode::dadd),
      static_cast<std::uint16_t>(Opcode::dsub),      static_cast<std::uint16_t>(Opcode::dmul),
      static_cast<std::uint16_t>(Opcode::ddiv),      static_cast<std::uint16_t>(Opcode::dsqrt),
      static_cast<std::uint16_t>(Opcode::i64tof),    static_cast<std::uint16_t>(Opcode::f64toi),
      static_cast<std::uint16_t>(Opcode::dcmp),      static_cast<std::uint16_t>(Opcode::vadd128),
      static_cast<std::uint16_t>(Opcode::vsub128),   static_cast<std::uint16_t>(Opcode::vmul128),
      static_cast<std::uint16_t>(Opcode::vxor128),   static_cast<std::uint16_t>(Opcode::imemcpy),
      static_cast<std::uint16_t>(Opcode::imemset),   static_cast<std::uint16_t>(Opcode::istrcmp),
      static_cast<std::uint16_t>(Opcode::istrlen),   static_cast<std::uint16_t>(Opcode::icas64),
      static_cast<std::uint16_t>(Opcode::ixchg64),   static_cast<std::uint16_t>(Opcode::ifence),
      static_cast<std::uint16_t>(Opcode::brk),       static_cast<std::uint16_t>(Opcode::ftrap),
      static_cast<std::uint16_t>(Opcode::syscall_proxy),
      static_cast<std::uint16_t>(Opcode::xcall),     static_cast<std::uint16_t>(Opcode::xret),
      static_cast<std::uint16_t>(Opcode::bridgeargs), static_cast<std::uint16_t>(Opcode::tsload),
      static_cast<std::uint16_t>(Opcode::tsrelease), static_cast<std::uint16_t>(Opcode::tsread8),
      static_cast<std::uint16_t>(Opcode::tswipe),
  };
  return words;
}

inline std::vector<std::uint16_t> instruction_lengths(const vmp::runtime::vm2::Vm2Module& module) {
  if (!module.reverse_insn_lengths.empty()) {
    return module.reverse_insn_lengths;
  }
  std::vector<std::uint16_t> lengths;
  std::size_t pc = 0;
  while (pc < module.code.size()) {
    const auto opcode = static_cast<vmp::runtime::vm2::Opcode>(
        static_cast<std::uint16_t>(module.code[pc]) | static_cast<std::uint16_t>(module.code[pc + 1] << 8u));
    const auto size = instruction_size(opcode);
    lengths.push_back(static_cast<std::uint16_t>(size));
    pc += size;
  }
  return lengths;
}

}  // namespace detail

inline bool opcode_encrypted(const vmp::runtime::vm2::Vm2Module& module) {
  return (module.module_flags & vmp::runtime::vm2::VMP_FLAG_OPCODE_ENCRYPTED) != 0u;
}

inline ModuleDescriptor describe_module(const vmp::runtime::vm2::Vm2Module& module) {
  ModuleDescriptor descriptor;
  descriptor.module_id = module.id();
  descriptor.domain = VmDomain::vm2;
  descriptor.module_name = "vm2";
  descriptor.opcode_encrypted = (module.module_flags & vmp::runtime::vm2::VMP_FLAG_OPCODE_ENCRYPTED) != 0u;
  descriptor.reverse_order = (module.module_flags & vmp::runtime::vm2::VMP_FLAG_REVERSE_ORDER) != 0u;
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
  descriptor.master_key_material.assign(module.key_context_id.begin(), module.key_context_id.end());
  descriptor.base_seed.assign(module.opcode_map_seed.begin(), module.opcode_map_seed.end());
  descriptor.key_context_material = descriptor.master_key_material;
  return descriptor;
}

inline void ensure_registered(const vmp::runtime::vm2::Vm2Module& module) {
  if (!opcode_encrypted(module)) {
    return;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().ensure_module(descriptor);
}

inline DispatchEpochScope begin_dispatch(const vmp::runtime::vm2::Vm2Module& module) {
  if (!opcode_encrypted(module)) {
    return {};
  }
  const auto descriptor = describe_module(module);
  return RollingOpcodeRegistry::instance().begin_dispatch(descriptor);
}

inline std::uint8_t fetch_byte(const vmp::runtime::vm2::Vm2Module& module, std::size_t forward_pc) {
  ensure_registered(module);
  return RollingOpcodeRegistry::instance().fetch_decoded_byte(describe_module(module), forward_pc);
}

inline void notify_key_rotation(const vmp::runtime::vm2::Vm2Module& module,
                                std::vector<std::uint8_t> key_material_override = {}) {
  if (!opcode_encrypted(module)) {
    return;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().rotate_module(descriptor, RotationReason::key_rotation, std::move(key_material_override));
}

inline void notify_integrity_event(const vmp::runtime::vm2::Vm2Module& module) {
  if (!opcode_encrypted(module)) {
    return;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().rotate_module(descriptor, RotationReason::integrity_event);
}

inline void notify_domain_switch(const vmp::runtime::vm2::Vm2Module& module) {
  if (!opcode_encrypted(module)) {
    return;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().rotate_module(descriptor, RotationReason::domain_switch);
}

inline std::uint32_t current_epoch_id(const vmp::runtime::vm2::Vm2Module& module) {
  if (!opcode_encrypted(module)) {
    return 0u;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().ensure_module(descriptor);
  return RollingOpcodeRegistry::instance().current_epoch_id(descriptor);
}

inline std::optional<std::uint32_t> previous_epoch_id(const vmp::runtime::vm2::Vm2Module& module) {
  if (!opcode_encrypted(module)) {
    return std::nullopt;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().ensure_module(descriptor);
  return RollingOpcodeRegistry::instance().previous_epoch_id(descriptor);
}

inline std::uint64_t dispatch_count(const vmp::runtime::vm2::Vm2Module& module) {
  if (!opcode_encrypted(module)) {
    return 0u;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().ensure_module(descriptor);
  return RollingOpcodeRegistry::instance().dispatch_count(descriptor);
}

inline void set_policy(const vmp::runtime::vm2::Vm2Module& module, const RollingPolicy& policy) {
  if (!opcode_encrypted(module)) {
    return;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().set_policy(descriptor, policy);
}

inline std::vector<std::uint8_t> debug_forward_storage(const vmp::runtime::vm2::Vm2Module& module) {
  if (!opcode_encrypted(module)) {
    return module.code;
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().ensure_module(descriptor);
  return RollingOpcodeRegistry::instance().debug_forward_storage(descriptor);
}

inline std::vector<std::uint8_t> debug_forward_storage_for_epoch(const vmp::runtime::vm2::Vm2Module& module,
                                                                 std::uint32_t epoch_id) {
  if (!opcode_encrypted(module)) {
    return epoch_id == 0u ? module.code : std::vector<std::uint8_t>{};
  }
  const auto descriptor = describe_module(module);
  RollingOpcodeRegistry::instance().ensure_module(descriptor);
  return RollingOpcodeRegistry::instance().debug_forward_storage_for_epoch(descriptor, epoch_id);
}

}  // namespace vmp::runtime::cryptor::vm2
